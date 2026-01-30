#!/bin/bash
## Last Updated 2026-01-30
## updates_optimized.sh - Fully Integrated & Optimized
## Combines update/download functionality with database management
## Usage: ./updates_optimized.sh [command] [options]
##
## Commands:
##   refresh         - Update all script files
##   full-update     - Complete system and Pi-hole update
##   allow-update    - Update only allow lists
##   quick-update    - Update configs without full system upgrade
##   block-regex-update - Update only regex block lists
##   purge-and-update - Clear all lists and rebuild from scratch
##   help            - Show this help message
##
## Options:
##   --no-reboot     - Skip system reboot check
##   --verbose       - Enable verbose output
##
## Pi-hole Version Support:
##   - Version 5: Uses legacy CLI commands (pihole -w, pihole -b, etc.)
##   - Version 6: Uses new CLI commands (pihole allow, pihole deny, etc.)
##   - Both versions use the same database schema (domainlist table)
##
## Database Schema (domainlist table - v5 and v6):
##   Type 0 = exact allowlist
##   Type 1 = exact denylist  
##   Type 2 = regex allowlist
##   Type 3 = regex denylist

set -euo pipefail  # Exit on error, undefined vars, pipe failures

#======================================================================================
# CONFIGURATION
#======================================================================================

readonly FINISHED=/scripts/Finished
readonly TEMPDIR=/scripts/temp
readonly PIDIR=/etc/pihole
readonly CONFIG=/scripts/Finished/CONFIG
readonly GRAVITY_DB="/etc/pihole/gravity.db"
readonly LOGFILE=/var/log/pihole-updates.log

# Options (set defaults before config loading)
VERBOSE=0
NO_REBOOT=0
DEBUG=0

# Global error tracking
declare -a DOWNLOAD_ERRORS=()
declare -a GPG_ERRORS=()
declare -a SQL_ERRORS=()
declare -a DEPLOY_ERRORS=()
declare -a VALIDATION_ERRORS=()

# Configuration variables (will be loaded)
Type=""
test_system=""
is_cloudflared=""
version=""

#======================================================================================
# CLEANUP TRAP - ENSURES /scripts/temp/* IS ALWAYS CLEANED
#======================================================================================

# Global flag to track if cleanup has run
CLEANUP_DONE=0

cleanup_temp() {
    # Prevent multiple cleanup runs
    [[ "$CLEANUP_DONE" -eq 1 ]] && return 0
    CLEANUP_DONE=1
    
    local exit_code="${1:-$?}"
    
    log "Performing cleanup of temporary files..."
    
    # Clean up all temp files
    if [[ -d "$TEMPDIR" ]]; then
        rm -f "$TEMPDIR"/*.regex 2>/dev/null || true
        rm -f "$TEMPDIR"/*.temp 2>/dev/null || true
        rm -f "$TEMPDIR"/*.gpg 2>/dev/null || true
        rm -f "$TEMPDIR"/*.sql 2>/dev/null || true
        rm -f "$TEMPDIR"/*.log 2>/dev/null || true
        rm -f "$TEMPDIR"/curl_error_* 2>/dev/null || true
        rm -f "$TEMPDIR"/gpg_error_* 2>/dev/null || true
        rm -f "$TEMPDIR"/sql_error_* 2>/dev/null || true
        
        # Remove any remaining files in temp
        find "$TEMPDIR" -type f -name "*.temp" -delete 2>/dev/null || true
        find "$TEMPDIR" -type f -name "*.gpg" -delete 2>/dev/null || true
        
        log_success "Cleanup completed: $TEMPDIR"
    fi
    
    if [[ "$exit_code" -ne 0 ]]; then
        log_error "Script exited with error code: $exit_code"
    fi
    
    return "$exit_code"
}

# Set trap for cleanup on EXIT, INT, TERM, ERR
trap 'cleanup_temp $?' EXIT
trap 'cleanup_temp 130' INT
trap 'cleanup_temp 143' TERM

#======================================================================================
# VALIDATION FUNCTIONS
#======================================================================================

validate_config_files() {
    local errors=0
    
    debug_log "Validating configuration files..."
    
    # Check CONFIG directory exists
    if [[ ! -d "$CONFIG" ]]; then
        log_error "Configuration directory not found: $CONFIG"
        VALIDATION_ERRORS+=("CONFIG directory missing: $CONFIG")
        return 1
    fi
    
    # Validate type.conf
    if [[ ! -f "$CONFIG/type.conf" ]]; then
        log_error "Missing configuration: $CONFIG/type.conf"
        VALIDATION_ERRORS+=("Missing: type.conf")
        ((errors++))
    elif [[ ! -s "$CONFIG/type.conf" ]]; then
        log_error "Empty configuration: $CONFIG/type.conf"
        VALIDATION_ERRORS+=("Empty: type.conf")
        ((errors++))
    fi
    
    # Validate test.conf
    if [[ ! -f "$CONFIG/test.conf" ]]; then
        log_warning "Missing configuration: $CONFIG/test.conf (defaulting to 'no')"
        echo "no" > "$CONFIG/test.conf" 2>/dev/null || {
            VALIDATION_ERRORS+=("Cannot create default: test.conf")
            ((errors++))
        }
    fi
    
    # Validate dns_type.conf
    if [[ ! -f "$CONFIG/dns_type.conf" ]]; then
        log_warning "Missing configuration: $CONFIG/dns_type.conf (defaulting to 'standard')"
        echo "standard" > "$CONFIG/dns_type.conf" 2>/dev/null || {
            VALIDATION_ERRORS+=("Cannot create default: dns_type.conf")
            ((errors++))
        }
    fi
    
    # Validate ver.conf (critical)
    if [[ ! -f "$CONFIG/ver.conf" ]]; then
        log_error "Missing critical configuration: $CONFIG/ver.conf"
        log_error "Please create $CONFIG/ver.conf with value '5' or '6'"
        VALIDATION_ERRORS+=("Missing critical: ver.conf")
        ((errors++))
    elif [[ ! -s "$CONFIG/ver.conf" ]]; then
        log_error "Empty critical configuration: $CONFIG/ver.conf"
        VALIDATION_ERRORS+=("Empty critical: ver.conf")
        ((errors++))
    fi
    
    if [[ $errors -gt 0 ]]; then
        log_error "Configuration validation failed with $errors errors"
        return 1
    fi
    
    debug_success "Configuration files validated"
    return 0
}

load_configuration() {
    debug_log "Loading configuration files..."
    
    # Load with validation
    Type=$(<"$CONFIG/type.conf") || { log_error "Failed to read type.conf"; return 1; }
    test_system=$(<"$CONFIG/test.conf") || { log_warning "Failed to read test.conf, using 'no'"; test_system="no"; }
    is_cloudflared=$(<"$CONFIG/dns_type.conf") || { log_warning "Failed to read dns_type.conf, using 'standard'"; is_cloudflared="standard"; }
    version=$(<"$CONFIG/ver.conf") || { log_error "Failed to read ver.conf"; return 1; }
    
    # Trim whitespace
    Type="${Type//[$'\t\r\n ']/}"
    test_system="${test_system//[$'\t\r\n ']/}"
    is_cloudflared="${is_cloudflared//[$'\t\r\n ']/}"
    version="${version//[$'\t\r\n ']/}"
    
    # Validate version
    if [[ "$version" != "5" && "$version" != "6" ]]; then
        log_error "Invalid Pi-hole version in ver.conf: '$version'"
        log_error "Supported versions: 5, 6"
        VALIDATION_ERRORS+=("Invalid Pi-hole version: $version")
        return 1
    fi
    
    # Validate type
    if [[ "$Type" != "security" && "$Type" != "full" && "$Type" != "standard" ]]; then
        log_warning "Unrecognized type in type.conf: '$Type' (using as-is)"
    fi
    
    debug_log "Configuration loaded:"
    debug_log "  Type: $Type"
    debug_log "  test_system: $test_system"
    debug_log "  is_cloudflared: $is_cloudflared"
    debug_log "  version: $version"
    
    return 0
}

validate_pihole_installation() {
    debug_log "Validating Pi-hole installation..."
    
    # Check if pihole command exists
    if ! command -v pihole &> /dev/null; then
        log_error "Pi-hole command not found in PATH"
        VALIDATION_ERRORS+=("pihole command not found")
        return 1
    fi
    
    # Check gravity database exists
    if [[ ! -f "$GRAVITY_DB" ]]; then
        log_error "Gravity database not found: $GRAVITY_DB"
        VALIDATION_ERRORS+=("Gravity database missing: $GRAVITY_DB")
        return 1
    fi
    
    # Check database is readable
    if ! sqlite3 "$GRAVITY_DB" "SELECT 1" &>/dev/null; then
        log_error "Cannot read gravity database: $GRAVITY_DB"
        VALIDATION_ERRORS+=("Gravity database unreadable")
        return 1
    fi
    
    # Verify domainlist table exists
    local table_check
    table_check=$(sqlite3 "$GRAVITY_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='domainlist';" 2>/dev/null)
    if [[ -z "$table_check" ]]; then
        log_error "domainlist table not found in gravity database"
        VALIDATION_ERRORS+=("domainlist table missing from database")
        return 1
    fi
    
    # Verify adlist table exists
    table_check=$(sqlite3 "$GRAVITY_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='adlist';" 2>/dev/null)
    if [[ -z "$table_check" ]]; then
        log_error "adlist table not found in gravity database"
        VALIDATION_ERRORS+=("adlist table missing from database")
        return 1
    fi
    
    debug_success "Pi-hole installation validated"
    return 0
}

validate_directories() {
    debug_log "Validating directory structure..."
    
    # Check/create TEMPDIR
    if [[ ! -d "$TEMPDIR" ]]; then
        log "Creating temp directory: $TEMPDIR"
        if ! mkdir -p "$TEMPDIR"; then
            log_error "Failed to create temp directory: $TEMPDIR"
            VALIDATION_ERRORS+=("Cannot create: $TEMPDIR")
            return 1
        fi
    fi
    
    # Check TEMPDIR is writable
    if ! touch "$TEMPDIR/.write_test" 2>/dev/null; then
        log_error "Temp directory not writable: $TEMPDIR"
        VALIDATION_ERRORS+=("Not writable: $TEMPDIR")
        return 1
    fi
    rm -f "$TEMPDIR/.write_test"
    
    # Check PIDIR exists
    if [[ ! -d "$PIDIR" ]]; then
        log_error "Pi-hole directory not found: $PIDIR"
        VALIDATION_ERRORS+=("Missing: $PIDIR")
        return 1
    fi
    
    # Check PIDIR is writable
    if ! touch "$PIDIR/.write_test" 2>/dev/null; then
        log_error "Pi-hole directory not writable: $PIDIR"
        VALIDATION_ERRORS+=("Not writable: $PIDIR")
        return 1
    fi
    rm -f "$PIDIR/.write_test"
    
    # Check FINISHED exists
    if [[ ! -d "$FINISHED" ]]; then
        log_warning "Finished directory not found, creating: $FINISHED"
        if ! mkdir -p "$FINISHED"; then
            log_error "Failed to create finished directory: $FINISHED"
            VALIDATION_ERRORS+=("Cannot create: $FINISHED")
            return 1
        fi
    fi
    
    debug_success "Directory structure validated"
    return 0
}

# GitHub base URLs
readonly GH_RAW="https://raw.githubusercontent.com/IcedComputer"
readonly REPO_BASE="${GH_RAW}/Personal-Pi-Hole-configs/master"
readonly AZURE_REPO="${GH_RAW}/Azure-Pihole-VPN-setup/master"

#======================================================================================
# UTILITY FUNCTIONS
#======================================================================================

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

log_success() {
    printf "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] ✓ %s\033[0m\n" "$*" | tee -a "$LOGFILE"
}

log_error() {
    printf "\033[1;31m[$(date +'%Y-%m-%d %H:%M:%S')] ✗ ERROR: %s\033[0m\n" "$*" | tee -a "$LOGFILE"
}

log_warning() {
    printf "\033[0;33m[$(date +'%Y-%m-%d %H:%M:%S')] ⚠ WARNING: %s\033[0m\n" "$*" | tee -a "$LOGFILE"
}

verbose_log() {
    [[ $VERBOSE -eq 1 ]] && log "$*"
}

debug_log() {
    if [[ $DEBUG -eq 1 ]]; then
        echo "[DEBUG $(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
    fi
}

debug_success() {
    if [[ $DEBUG -eq 1 ]]; then
        printf "\033[0;32m[DEBUG $(date +'%Y-%m-%d %H:%M:%S')] ✓ %s\033[0m\n" "$*" | tee -a "$LOGFILE"
    fi
}

debug_error() {
    if [[ $DEBUG -eq 1 ]]; then
        printf "\033[1;31m[DEBUG $(date +'%Y-%m-%d %H:%M:%S')] ✗ %s\033[0m\n" "$*" | tee -a "$LOGFILE"
    fi
}

check_network() {
    debug_log "Checking network connectivity..."
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        log "ERROR: No network connectivity detected"
        return 1
    fi
    if ! ping -c 1 raw.githubusercontent.com &> /dev/null; then
        log "ERROR: Cannot reach GitHub (raw.githubusercontent.com)"
        return 1
    fi
    debug_log "Network connectivity OK"
    return 0
}

check_gpg_keys() {
    debug_log "Checking GPG configuration..."
    
    if ! command -v gpg &> /dev/null; then
        log "ERROR: GPG is not installed"
        log "ERROR: Install with: apt-get install gnupg"
        return 1
    fi
    
    local key_count=$(gpg --list-keys 2>/dev/null | grep -c "^pub" || echo "0")
    debug_log "GPG public keys available: $key_count"
    
    local secret_key_count=$(gpg --list-secret-keys 2>/dev/null | grep -c "^sec" || echo "0")
    debug_log "GPG secret keys available: $secret_key_count"
    
    if [[ "$secret_key_count" -eq 0 ]]; then
        log "WARNING: No GPG secret keys found"
        log "WARNING: Encrypted file decryption will fail"
        log "WARNING: Import your private key with: gpg --import /path/to/private.key"
        return 1
    fi
    
    debug_log "GPG configuration OK"
    return 0
}

print_banner() {
    local color="$1"
    local message="$2"
    
    case "$color" in
        green)
            printf '\033[0;32m%s\033[0m\n' "============================================"
            printf '\033[1;32m%s\033[0m\n' "$message"
            printf '\033[0;32m%s\033[0m\n' "============================================"
            ;;
        red)
            printf '\033[0;31m%s\033[0m\n' "============================================"
            printf '\033[1;31m%s\033[0m\n' "$message"
            printf '\033[0;31m%s\033[0m\n' "============================================"
            ;;
        yellow)
            printf '\033[0;33m%s\033[0m\n' "============================================"
            printf '\033[1;33m%s\033[0m\n' "$message"
            printf '\033[0;33m%s\033[0m\n' "============================================"
            ;;
    esac
}

show_error_summary() {
    local total_errors=0
    ((total_errors = ${#DOWNLOAD_ERRORS[@]} + ${#GPG_ERRORS[@]} + ${#SQL_ERRORS[@]} + ${#DEPLOY_ERRORS[@]} + ${#VALIDATION_ERRORS[@]}))
    
    if [[ $total_errors -eq 0 ]]; then
        print_banner green "✓ Update Completed Successfully - No Errors"
        return 0
    fi
    
    # Display big red error summary
    echo ""
    echo ""
    printf '\033[1;41;97m%s\033[0m\n' "╔══════════════════════════════════════════════════════════════════════════════╗"
    printf '\033[1;41;97m%s\033[0m\n' "║                                                                              ║"
    printf '\033[1;41;97m%s\033[0m\n' "║                        ⚠️  ERROR SUMMARY - ATTENTION REQUIRED ⚠️              ║"
    printf '\033[1;41;97m%s\033[0m\n' "║                                                                              ║"
    printf '\033[1;41;97m%-80s\033[0m\n' "║  Total Errors: $total_errors"
    printf '\033[1;41;97m%s\033[0m\n' "║                                                                              ║"
    printf '\033[1;41;97m%s\033[0m\n' "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    if [[ ${#VALIDATION_ERRORS[@]} -gt 0 ]]; then
        printf '\033[1;31m%s\033[0m\n' "🔍 VALIDATION FAILURES (${#VALIDATION_ERRORS[@]}):"
        for error in "${VALIDATION_ERRORS[@]}"; do
            printf '\033[0;31m%s\033[0m\n' "   ✗ $error"
        done
        echo ""
    fi
    
    if [[ ${#DOWNLOAD_ERRORS[@]} -gt 0 ]]; then
        printf '\033[1;31m%s\033[0m\n' "📥 DOWNLOAD FAILURES (${#DOWNLOAD_ERRORS[@]}):" 
        for error in "${DOWNLOAD_ERRORS[@]}"; do
            printf '\033[0;31m%s\033[0m\n' "   ✗ $error"
        done
        echo ""
    fi
    
    if [[ ${#GPG_ERRORS[@]} -gt 0 ]]; then
        printf '\033[1;31m%s\033[0m\n' "🔐 GPG DECRYPTION FAILURES (${#GPG_ERRORS[@]}):"
        for error in "${GPG_ERRORS[@]}"; do
            printf '\033[0;31m%s\033[0m\n' "   ✗ $error"
        done
        echo ""
    fi
    
    if [[ ${#SQL_ERRORS[@]} -gt 0 ]]; then
        printf '\033[1;31m%s\033[0m\n' "💾 DATABASE FAILURES (${#SQL_ERRORS[@]}):"
        for error in "${SQL_ERRORS[@]}"; do
            printf '\033[0;31m%s\033[0m\n' "   ✗ $error"
        done
        echo ""
    fi
    
    if [[ ${#DEPLOY_ERRORS[@]} -gt 0 ]]; then
        printf '\033[1;31m%s\033[0m\n' "📦 DEPLOYMENT FAILURES (${#DEPLOY_ERRORS[@]}):"
        for error in "${DEPLOY_ERRORS[@]}"; do
            printf '\033[0;31m%s\033[0m\n' "   ✗ $error"
        done
        echo ""
    fi
    
    printf '\033[1;33m%s\033[0m\n' "💡 RECOMMENDED ACTIONS:"
    printf '\033[0;33m%s\033[0m\n' "   1. Run with --debug flag for detailed diagnostics"
    printf '\033[0;33m%s\033[0m\n' "   2. Check network connectivity to GitHub"
    printf '\033[0;33m%s\033[0m\n' "   3. Review log file: $LOGFILE"
    printf '\033[0;33m%s\033[0m\n' "   4. Verify GPG keys are imported (for GPG errors)"
    printf '\033[0;33m%s\033[0m\n' "   5. Check disk space and permissions"
    printf '\033[0;33m%s\033[0m\n' "   6. Verify Pi-hole installation: pihole -v"
    echo ""
    
    return 1
}

download_file() {
    local url="$1"
    local output="$2"
    local retries=3
    local error_log="$TEMPDIR/curl_error_$$.log"
    
    debug_log "Starting download: $url"
    debug_log "Output destination: $output"
    
    for i in $(seq 1 $retries); do
        debug_log "Download attempt $i of $retries for: $url"
        
        if curl --tlsv1.3 --fail --location --connect-timeout 10 --max-time 60 \
            --show-error --silent -o "$output" "$url" 2>"$error_log"; then
            verbose_log "Downloaded: $url -> $output"
            debug_success "Downloaded: $url ($(stat -c%s "$output" 2>/dev/null || echo 'unknown') bytes)"
            rm -f "$error_log"
            return 0
        fi
        
        local error_msg=$(cat "$error_log" 2>/dev/null || echo "Unknown error")
        log_warning "Download attempt $i failed for: $url"
        debug_error "Download failed: $error_msg"
        debug_log "Waiting 3 seconds before retry..."
        sleep 3
    done
    
    log_error "Failed to download after $retries attempts"
    log_error "URL: $url"
    log_error "Output: $output"
    if [[ -f "$error_log" ]]; then
        log_error "$(cat "$error_log")"
        rm -f "$error_log"
    fi
    
    # Track error globally
    DOWNLOAD_ERRORS+=("DOWNLOAD FAILED: $url")
    
    return 1
}

download_gpg_file() {
    local url="$1"
    local output_base="$2"
    local gpg_error="$TEMPDIR/gpg_error_$$.log"
    
    debug_log "Downloading GPG file: $url"
    download_file "$url" "${output_base}.gpg" || return 1
    
    # Check if GPG file was actually downloaded and has content
    if [[ ! -f "${output_base}.gpg" ]]; then
        log "ERROR: GPG file was not downloaded: ${output_base}.gpg"
        return 1
    fi
    
    local gpg_size=$(stat -c%s "${output_base}.gpg" 2>/dev/null || echo "0")
    debug_log "Downloaded GPG file size: $gpg_size bytes"
    
    if [[ "$gpg_size" -eq 0 ]]; then
        log "ERROR: Downloaded GPG file is empty: ${output_base}.gpg"
        return 1
    fi
    
    debug_log "Decrypting: ${output_base}.gpg"
    debug_log "GPG command: gpg --batch --yes --decrypt ${output_base}.gpg"
    
    if ! gpg --batch --yes --decrypt "${output_base}.gpg" > "$output_base" 2>"$gpg_error"; then
        log_error "Failed to decrypt ${output_base}.gpg"
        log_error "GPG file size: $gpg_size bytes"
        if [[ -f "$gpg_error" ]]; then
            log_error "GPG output: $(cat "$gpg_error")"
            # Check for common GPG errors
            if grep -q "no secret key" "$gpg_error"; then
                log "ERROR: GPG key not found. You may need to import the decryption key."
                log "ERROR: Run: gpg --list-keys to see available keys"
            elif grep -q "decryption failed" "$gpg_error"; then
                log "ERROR: File may be corrupted or encrypted with different key"
            fi
        else
            log "ERROR: No GPG error output available"
        fi
        log "ERROR: Keeping ${output_base}.gpg for manual inspection"
        
        # Track error globally
        GPG_ERRORS+=("GPG DECRYPT FAILED: ${output_base}.gpg")
        
        return 1
    fi
    
    # Check if decrypted file has content
    local decrypted_size=$(stat -c%s "$output_base" 2>/dev/null || echo "0")
    debug_log "Decrypted file size: $decrypted_size bytes"
    
    if [[ "$decrypted_size" -eq 0 ]]; then
        log "ERROR: Decrypted file is empty: $output_base"
        return 1
    fi
    
    sed -i -e "s/\r//g" "$output_base"
    rm -f "${output_base}.gpg" "$gpg_error"
    verbose_log "Decrypted and cleaned: $output_base"
    debug_success "Decrypted: $output_base ($decrypted_size bytes)"
}

parallel_download() {
    local -n urls=$1
    local pids=()
    local pid_urls=()
    local failed=0
    
    debug_log "Starting ${#urls[@]} parallel downloads"
    
    for item in "${urls[@]}"; do
        IFS='|' read -r url output <<< "$item"
        debug_log "Queuing download: $url"
        download_file "$url" "$output" &
        local pid=$!
        pids+=("$pid")
        pid_urls[$pid]="$url|$output"
    done
    
    # Wait for all downloads to complete and track failures
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            IFS='|' read -r failed_url failed_output <<< "${pid_urls[$pid]}"
            log_error "Download failed for URL: $failed_url"
            log_error "Expected output: $failed_output"
            ((failed++))
        fi
    done
    
    if [[ $failed -gt 0 ]]; then
        log_warning "$failed out of ${#urls[@]} downloads failed"
        return 1
    fi
    
    debug_success "All ${#urls[@]} parallel downloads completed successfully"
    
    debug_log "All parallel downloads completed successfully"
    return 0
}

#======================================================================================
# DATABASE UPDATE FUNCTIONS - PI-HOLE VERSION 5
# Note: Pi-hole v5 and v6 use the same database schema for domainlist:
#   Type 0 = exact allowlist (whitelist)
#   Type 1 = exact denylist (blacklist)
#   Type 2 = regex allowlist (white-regex)
#   Type 3 = regex denylist (regex blacklist)
#
# v5 CLI commands: pihole -w, pihole -b, pihole --regex, pihole --white-regex
# v6 CLI commands: pihole allow, pihole deny, pihole --regex, pihole --allow-regex
#======================================================================================

verify_database_insert() {
    # Verify that entries were actually added to the database
    local table="$1"
    local type_val="$2"
    local expected_min="$3"
    local description="$4"
    
    local actual_count
    actual_count=$(sqlite3 "$GRAVITY_DB" "SELECT COUNT(*) FROM $table WHERE type=$type_val AND enabled=1;" 2>/dev/null || echo "0")
    
    if [[ "$actual_count" -lt "$expected_min" ]]; then
        log_warning "Verification: Expected at least $expected_min $description entries, found $actual_count"
        return 1
    fi
    
    debug_success "Verification: Found $actual_count $description entries (expected >= $expected_min)"
    return 0
}

update_allow_regex_v5() {
    local file="$TEMPDIR/final.allow.regex.temp"
    
    debug_log "update_allow_regex_v5: Starting function"
    debug_log "update_allow_regex_v5: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No allow regex file found, skipping"
        debug_log "update_allow_regex_v5: File does not exist, skipping"
        return 0
    fi
    
    # Check if file has content
    if [[ ! -s "$file" ]]; then
        log "Allow regex file is empty, skipping"
        debug_log "update_allow_regex_v5: File is empty, skipping"
        return 0
    fi
    
    debug_log "update_allow_regex_v5: File found, size: $(stat -c%s "$file" 2>/dev/null || echo 'unknown') bytes"
    
    print_banner green "Starting Allow Regex List (v5)"
    
    # Validate database is accessible
    if ! sqlite3 "$GRAVITY_DB" "SELECT 1" &>/dev/null; then
        log_error "Cannot access gravity database"
        SQL_ERRORS+=("DATABASE ACCESS FAILED: $GRAVITY_DB")
        return 1
    fi
    
    local count=0
    local temp_sql="$TEMPDIR/allow_regex_insert.sql"
    debug_log "update_allow_regex_v5: Creating SQL file: $temp_sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r pattern || [[ -n "$pattern" ]]; do
        # Skip empty lines and comments
        [[ -z "$pattern" ]] && continue
        [[ "$pattern" =~ ^[[:space:]]*# ]] && continue
        [[ "$pattern" =~ ^[[:space:]]*$ ]] && continue
        
        # Trim whitespace
        pattern="${pattern#"${pattern%%[![:space:]]*}"}"
        pattern="${pattern%"${pattern##*[![:space:]]}"}"
        
        # Skip if still empty after trimming
        [[ -z "$pattern" ]] && continue
        
        # Type 2 = regex allowlist (whitelist), enabled = 1
        # Escape single quotes for SQL
        local escaped_pattern="${pattern//\'/\'\'}"
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled, comment) VALUES (2, '${escaped_pattern}', 1, 'Added by updates_optimized.sh');" >> "$temp_sql"
        ((count++))
        verbose_log "Queued allow regex: $pattern"
    done < "$file"
    
    debug_log "update_allow_regex_v5: Queued $count regex patterns"
    
    if [[ $count -eq 0 ]]; then
        log "No valid allow regex patterns found to add"
        rm -f "$temp_sql"
        return 0
    fi
    
    echo "COMMIT;" >> "$temp_sql"
    
    debug_log "update_allow_regex_v5: Executing SQL transaction"
    local sql_error="$TEMPDIR/sql_error_regex_v5_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log_error "Failed to insert allow regex"
        if [[ -f "$sql_error" && -s "$sql_error" ]]; then
            local err_msg=$(cat "$sql_error")
            log_error "SQL error: $err_msg"
            SQL_ERRORS+=("SQL FAILED (v5 allow-regex): $err_msg")
        else
            SQL_ERRORS+=("SQL FAILED (v5 allow-regex): Unknown error")
        fi
        rm -f "$sql_error"
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error"
    
    # Verify the entries were actually added
    verify_database_insert "domainlist" 2 "$count" "allow regex" || {
        log_warning "Allow regex verification found fewer entries than expected"
        # Don't fail, just warn - some may have been duplicates
    }
    
    log_success "Added $count allow regex patterns via direct SQL (type=2, v5)"
    debug_success "update_allow_regex_v5: Completed successfully"
    print_banner yellow "Completed Allow Regex List"
}

update_allow_v5() {
    local file="$PIDIR/whitelist.txt"
    
    debug_log "update_allow_v5: Starting function"
    debug_log "update_allow_v5: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No whitelist file found, skipping"
        debug_log "update_allow_v5: File does not exist: $file"
        return 0
    fi
    
    # Check if file has content
    if [[ ! -s "$file" ]]; then
        log "Whitelist file is empty, skipping"
        debug_log "update_allow_v5: File is empty: $file"
        return 0
    fi
    
    debug_log "update_allow_v5: File found, size: $(stat -c%s "$file" 2>/dev/null || echo 'unknown') bytes"
    
    print_banner green "Starting Allow List (v5)"
    
    # Validate database exists and is accessible
    if [[ ! -f "$GRAVITY_DB" ]]; then
        log_error "Gravity database not found: $GRAVITY_DB"
        SQL_ERRORS+=("DATABASE MISSING: $GRAVITY_DB")
        debug_log "update_allow_v5: Database missing, aborting"
        return 1
    fi
    
    if ! sqlite3 "$GRAVITY_DB" "SELECT 1" &>/dev/null; then
        log_error "Cannot access gravity database"
        SQL_ERRORS+=("DATABASE ACCESS FAILED: $GRAVITY_DB")
        return 1
    fi
    
    debug_log "update_allow_v5: Database exists and accessible: $GRAVITY_DB"
    
    # Use direct SQL INSERT for massive performance improvement
    # This is 50-100x faster than calling pihole -w for each domain
    local count=0
    local skipped=0
    local temp_sql="$TEMPDIR/allow_insert.sql"
    debug_log "update_allow_v5: Creating SQL transaction file: $temp_sql"
    
    # Start SQL transaction
    echo "BEGIN TRANSACTION;" > "$temp_sql" || {
        log_error "Failed to create SQL transaction file: $temp_sql"
        SQL_ERRORS+=("CANNOT CREATE SQL FILE: $temp_sql")
        debug_log "update_allow_v5: Cannot write to temp directory"
        return 1
    }
    
    debug_log "update_allow_v5: Reading domains from $file"
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        # Skip empty lines and comments
        [[ -z "$domain" ]] && continue
        [[ "$domain" =~ ^[[:space:]]*# ]] && { ((skipped++)); continue; }
        [[ "$domain" =~ ^[[:space:]]*$ ]] && continue
        
        # Trim whitespace
        domain="${domain#"${domain%%[![:space:]]*}"}"
        domain="${domain%"${domain##*[![:space:]]}"}"
        
        # Skip if still empty after trimming
        [[ -z "$domain" ]] && continue
        
        # Basic domain validation (allow subdomains, no spaces)
        if [[ "$domain" =~ [[:space:]] ]]; then
            log_warning "Skipping invalid domain (contains spaces): $domain"
            ((skipped++))
            continue
        fi
        
        # Escape single quotes for SQL
        local escaped_domain="${domain//\'/\'\'}"
        
        # Type 0 = exact allowlist (whitelist), enabled = 1
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled, comment) VALUES (0, '${escaped_domain}', 1, 'Added by updates_optimized.sh');" >> "$temp_sql"
        ((count++))
        verbose_log "Queued allow domain: $domain"
    done < "$file"
    
    debug_log "update_allow_v5: Queued $count domains for insertion, skipped $skipped"
    
    if [[ $count -eq 0 ]]; then
        log "No valid domains found to add"
        rm -f "$temp_sql"
        return 0
    fi
    
    echo "COMMIT;" >> "$temp_sql"
    
    local sql_size=$(stat -c%s "$temp_sql" 2>/dev/null || echo '0')
    debug_log "update_allow_v5: SQL file size: $sql_size bytes"
    debug_log "update_allow_v5: Executing SQL transaction"
    
    # Execute all inserts in one transaction
    local sql_error="$TEMPDIR/sql_error_v5_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log_error "Failed to insert allow list"
        if [[ -f "$sql_error" && -s "$sql_error" ]]; then
            local error_msg=$(cat "$sql_error")
            log_error "SQL error: $error_msg"
            SQL_ERRORS+=("SQL FAILED (v5 allow): $error_msg")
        else
            SQL_ERRORS+=("SQL FAILED (v5 allow): Unknown error")
        fi
        rm -f "$sql_error"
        debug_log "update_allow_v5: SQL execution failed, keeping $temp_sql for inspection"
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error"
    
    # Verify the entries were actually added
    verify_database_insert "domainlist" 0 "$count" "exact allow" || {
        log_warning "Allow list verification found fewer entries than expected (may be duplicates)"
    }
    
    log_success "Added $count allow domains via direct SQL (type=0, v5)"
    if [[ $skipped -gt 0 ]]; then
        log "Skipped $skipped entries (comments or invalid)"
    fi
    debug_success "update_allow_v5: Completed successfully"
    print_banner yellow "Completed Allow List"
}

update_regex_v5() {
    local file="$PIDIR/regex.list"
    
    debug_log "update_regex_v5: Starting function"
    debug_log "update_regex_v5: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No regex block file found, skipping"
        debug_log "update_regex_v5: File does not exist, skipping"
        return 0
    fi
    
    # Check if file has content
    if [[ ! -s "$file" ]]; then
        log "Regex block file is empty, skipping"
        debug_log "update_regex_v5: File is empty, skipping"
        return 0
    fi
    
    debug_log "update_regex_v5: File found, size: $(stat -c%s "$file" 2>/dev/null || echo 'unknown') bytes"
    
    print_banner green "Starting Regex Block List (v5)"
    
    # Validate database is accessible
    if ! sqlite3 "$GRAVITY_DB" "SELECT 1" &>/dev/null; then
        log_error "Cannot access gravity database"
        SQL_ERRORS+=("DATABASE ACCESS FAILED: $GRAVITY_DB")
        return 1
    fi
    
    local count=0
    local skipped=0
    local temp_sql="$TEMPDIR/block_regex_insert.sql"
    debug_log "update_regex_v5: Creating SQL file: $temp_sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r pattern || [[ -n "$pattern" ]]; do
        # Skip empty lines and comments
        [[ -z "$pattern" ]] && continue
        [[ "$pattern" =~ ^[[:space:]]*# ]] && { ((skipped++)); continue; }
        [[ "$pattern" =~ ^[[:space:]]*$ ]] && continue
        
        # Trim whitespace
        pattern="${pattern#"${pattern%%[![:space:]]*}"}"
        pattern="${pattern%"${pattern##*[![:space:]]}"}"
        
        # Skip if still empty after trimming
        [[ -z "$pattern" ]] && continue
        
        # Type 3 = regex denylist (blacklist), enabled = 1
        local escaped_pattern="${pattern//\'/\'\'}"
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled, comment) VALUES (3, '${escaped_pattern}', 1, 'Added by updates_optimized.sh');" >> "$temp_sql"
        ((count++))
        verbose_log "Queued block regex: $pattern"
    done < "$file"
    
    debug_log "update_regex_v5: Queued $count block regex patterns, skipped $skipped"
    
    if [[ $count -eq 0 ]]; then
        log "No valid block regex patterns found to add"
        rm -f "$temp_sql"
        return 0
    fi
    
    echo "COMMIT;" >> "$temp_sql"
    
    debug_log "update_regex_v5: Executing SQL transaction"
    local sql_error="$TEMPDIR/sql_error_block_v5_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log_error "Failed to insert block regex"
        if [[ -f "$sql_error" && -s "$sql_error" ]]; then
            local err_msg=$(cat "$sql_error")
            log_error "SQL error: $err_msg"
            SQL_ERRORS+=("SQL FAILED (v5 block-regex): $err_msg")
        else
            SQL_ERRORS+=("SQL FAILED (v5 block-regex): Unknown error")
        fi
        rm -f "$sql_error"
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error"
    
    # Verify the entries were actually added
    verify_database_insert "domainlist" 3 "$count" "regex deny" || {
        log_warning "Block regex verification found fewer entries than expected"
    }
    
    log_success "Added $count block regex patterns via direct SQL (type=3, v5)"
    if [[ $skipped -gt 0 ]]; then
        log "Skipped $skipped entries (comments)"
    fi
    debug_success "update_regex_v5: Completed successfully"
    print_banner yellow "Completed Regex Block List"
}

#======================================================================================
# DATABASE UPDATE FUNCTIONS - PI-HOLE VERSION 6
# Note: Pi-hole v6 uses the SAME database schema as v5:
#   Type 0 = exact allowlist
#   Type 1 = exact denylist
#   Type 2 = regex allowlist
#   Type 3 = regex denylist
#
# The only difference is CLI commands:
#   v6: pihole allow, pihole deny, pihole --allow-regex, pihole --regex
# But since we use direct SQL, both versions work identically.
#======================================================================================

update_allow_regex_v6() {
    local file="$TEMPDIR/final.allow.regex.temp"
    
    debug_log "update_allow_regex_v6: Starting function"
    debug_log "update_allow_regex_v6: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No allow regex file found, skipping"
        debug_log "update_allow_regex_v6: File does not exist, skipping"
        return 0
    fi
    
    # Check if file has content
    if [[ ! -s "$file" ]]; then
        log "Allow regex file is empty, skipping"
        debug_log "update_allow_regex_v6: File is empty, skipping"
        return 0
    fi
    
    debug_log "update_allow_regex_v6: File found, size: $(stat -c%s "$file" 2>/dev/null || echo 'unknown') bytes"
    
    print_banner green "Starting Allow Regex List (v6)"
    
    # Validate database is accessible
    if ! sqlite3 "$GRAVITY_DB" "SELECT 1" &>/dev/null; then
        log_error "Cannot access gravity database"
        SQL_ERRORS+=("DATABASE ACCESS FAILED: $GRAVITY_DB")
        return 1
    fi
    
    local count=0
    local skipped=0
    local temp_sql="$TEMPDIR/allow_regex_insert.sql"
    debug_log "update_allow_regex_v6: Creating SQL file: $temp_sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r pattern || [[ -n "$pattern" ]]; do
        # Skip empty lines and comments
        [[ -z "$pattern" ]] && continue
        [[ "$pattern" =~ ^[[:space:]]*# ]] && { ((skipped++)); continue; }
        [[ "$pattern" =~ ^[[:space:]]*$ ]] && continue
        
        # Trim whitespace
        pattern="${pattern#"${pattern%%[![:space:]]*}"}"
        pattern="${pattern%"${pattern##*[![:space:]]}"}"
        
        # Skip if still empty after trimming
        [[ -z "$pattern" ]] && continue
        
        # Type 2 = regex allowlist, enabled = 1
        local escaped_pattern="${pattern//\'/\'\'}"
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled, comment) VALUES (2, '${escaped_pattern}', 1, 'Added by updates_optimized.sh');" >> "$temp_sql"
        ((count++))
        verbose_log "Queued allow regex: $pattern"
    done < "$file"
    
    debug_log "update_allow_regex_v6: Queued $count regex patterns, skipped $skipped"
    
    if [[ $count -eq 0 ]]; then
        log "No valid allow regex patterns found to add"
        rm -f "$temp_sql"
        return 0
    fi
    
    echo "COMMIT;" >> "$temp_sql"
    
    debug_log "update_allow_regex_v6: Executing SQL transaction"
    local sql_error="$TEMPDIR/sql_error_regex_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log_error "Failed to insert allow regex"
        if [[ -f "$sql_error" && -s "$sql_error" ]]; then
            local err_msg=$(cat "$sql_error")
            log_error "SQL error: $err_msg"
            SQL_ERRORS+=("SQL FAILED (v6 allow-regex): $err_msg")
        else
            SQL_ERRORS+=("SQL FAILED (v6 allow-regex): Unknown error")
        fi
        rm -f "$sql_error"
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error"
    
    # Verify the entries were actually added
    verify_database_insert "domainlist" 2 "$count" "allow regex" || {
        log_warning "Allow regex verification found fewer entries than expected"
    }
    
    log_success "Added $count allow regex patterns via direct SQL (type=2, v6)"
    if [[ $skipped -gt 0 ]]; then
        log "Skipped $skipped entries (comments)"
    fi
    debug_success "update_allow_regex_v6: Completed successfully"
    print_banner yellow "Completed Allow Regex List"
}

update_allow_v6() {
    local file="$PIDIR/whitelist.txt"
    
    debug_log "update_allow_v6: Starting function"
    debug_log "update_allow_v6: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No whitelist file found, skipping"
        debug_log "update_allow_v6: File does not exist: $file"
        return 0
    fi
    
    # Check if file has content
    if [[ ! -s "$file" ]]; then
        log "Whitelist file is empty, skipping"
        debug_log "update_allow_v6: File is empty: $file"
        return 0
    fi
    
    debug_log "update_allow_v6: File found, size: $(stat -c%s "$file" 2>/dev/null || echo 'unknown') bytes"
    
    print_banner green "Starting Allow List (v6)"
    
    # Validate database exists and is accessible
    if [[ ! -f "$GRAVITY_DB" ]]; then
        log_error "Gravity database not found: $GRAVITY_DB"
        SQL_ERRORS+=("DATABASE MISSING: $GRAVITY_DB")
        debug_log "update_allow_v6: Database missing, aborting"
        return 1
    fi
    
    if ! sqlite3 "$GRAVITY_DB" "SELECT 1" &>/dev/null; then
        log_error "Cannot access gravity database"
        SQL_ERRORS+=("DATABASE ACCESS FAILED: $GRAVITY_DB")
        return 1
    fi
    
    debug_log "update_allow_v6: Database exists and accessible: $GRAVITY_DB"
    
    # Use direct SQL INSERT for massive performance improvement
    local count=0
    local skipped=0
    local temp_sql="$TEMPDIR/allow_insert.sql"
    debug_log "update_allow_v6: Creating SQL transaction file: $temp_sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql" || {
        log_error "Failed to create SQL transaction file: $temp_sql"
        SQL_ERRORS+=("CANNOT CREATE SQL FILE: $temp_sql")
        debug_log "update_allow_v6: Cannot write to temp directory"
        return 1
    }
    
    debug_log "update_allow_v6: Reading domains from $file"
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        # Skip empty lines and comments
        [[ -z "$domain" ]] && continue
        [[ "$domain" =~ ^[[:space:]]*# ]] && { ((skipped++)); continue; }
        [[ "$domain" =~ ^[[:space:]]*$ ]] && continue
        
        # Trim whitespace
        domain="${domain#"${domain%%[![:space:]]*}"}"
        domain="${domain%"${domain##*[![:space:]]}"}"
        
        # Skip if still empty after trimming
        [[ -z "$domain" ]] && continue
        
        # Basic domain validation
        if [[ "$domain" =~ [[:space:]] ]]; then
            log_warning "Skipping invalid domain (contains spaces): $domain"
            ((skipped++))
            continue
        fi
        
        # Escape single quotes for SQL
        local escaped_domain="${domain//\'/\'\'}"
        
        # Type 0 = exact allowlist, enabled = 1
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled, comment) VALUES (0, '${escaped_domain}', 1, 'Added by updates_optimized.sh');" >> "$temp_sql"
        ((count++))
        verbose_log "Queued allow domain: $domain"
    done < "$file"
    
    debug_log "update_allow_v6: Queued $count domains for insertion, skipped $skipped"
    
    if [[ $count -eq 0 ]]; then
        log "No valid domains found to add"
        rm -f "$temp_sql"
        return 0
    fi
    
    echo "COMMIT;" >> "$temp_sql"
    
    local sql_size=$(stat -c%s "$temp_sql" 2>/dev/null || echo '0')
    debug_log "update_allow_v6: SQL file size: $sql_size bytes"
    debug_log "update_allow_v6: Executing SQL transaction"
    
    local sql_error="$TEMPDIR/sql_error_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log_error "Failed to insert allow list"
        if [[ -f "$sql_error" && -s "$sql_error" ]]; then
            local err_msg=$(cat "$sql_error")
            log_error "SQL error: $err_msg"
            SQL_ERRORS+=("SQL FAILED (v6 allow): $err_msg")
        else
            SQL_ERRORS+=("SQL FAILED (v6 allow): Unknown error")
        fi
        rm -f "$sql_error"
        debug_log "update_allow_v6: SQL execution failed, keeping $temp_sql for inspection"
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error"
    
    # Verify the entries were actually added
    verify_database_insert "domainlist" 0 "$count" "exact allow" || {
        log_warning "Allow list verification found fewer entries than expected (may be duplicates)"
    }
    
    log_success "Added $count allow domains via direct SQL (type=0, v6)"
    if [[ $skipped -gt 0 ]]; then
        log "Skipped $skipped entries (comments or invalid)"
    fi
    debug_success "update_allow_v6: Completed successfully"
    print_banner yellow "Completed Allow List"
}

update_regex_v6() {
    local file="$PIDIR/regex.list"
    
    debug_log "update_regex_v6: Starting function"
    debug_log "update_regex_v6: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No regex block file found, skipping"
        debug_log "update_regex_v6: File does not exist, skipping"
        return 0
    fi
    
    # Check if file has content
    if [[ ! -s "$file" ]]; then
        log "Regex block file is empty, skipping"
        debug_log "update_regex_v6: File is empty, skipping"
        return 0
    fi
    
    debug_log "update_regex_v6: File found, size: $(stat -c%s "$file" 2>/dev/null || echo 'unknown') bytes"
    
    print_banner green "Starting Regex Block List (v6)"
    
    # Validate database is accessible
    if ! sqlite3 "$GRAVITY_DB" "SELECT 1" &>/dev/null; then
        log_error "Cannot access gravity database"
        SQL_ERRORS+=("DATABASE ACCESS FAILED: $GRAVITY_DB")
        return 1
    fi
    
    local count=0
    local skipped=0
    local temp_sql="$TEMPDIR/block_regex_insert.sql"
    debug_log "update_regex_v6: Creating SQL file: $temp_sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r pattern || [[ -n "$pattern" ]]; do
        # Skip empty lines and comments
        [[ -z "$pattern" ]] && continue
        [[ "$pattern" =~ ^[[:space:]]*# ]] && { ((skipped++)); continue; }
        [[ "$pattern" =~ ^[[:space:]]*$ ]] && continue
        
        # Trim whitespace
        pattern="${pattern#"${pattern%%[![:space:]]*}"}"
        pattern="${pattern%"${pattern##*[![:space:]]}"}"
        
        # Skip if still empty after trimming
        [[ -z "$pattern" ]] && continue
        
        # Type 3 = regex denylist, enabled = 1
        local escaped_pattern="${pattern//\'/\'\'}"
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled, comment) VALUES (3, '${escaped_pattern}', 1, 'Added by updates_optimized.sh');" >> "$temp_sql"
        ((count++))
        verbose_log "Queued block regex: $pattern"
    done < "$file"
    
    debug_log "update_regex_v6: Queued $count block regex patterns, skipped $skipped"
    
    if [[ $count -eq 0 ]]; then
        log "No valid block regex patterns found to add"
        rm -f "$temp_sql"
        return 0
    fi
    
    echo "COMMIT;" >> "$temp_sql"
    
    debug_log "update_regex_v6: Executing SQL transaction"
    local sql_error="$TEMPDIR/sql_error_block_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log_error "Failed to insert block regex"
        if [[ -f "$sql_error" && -s "$sql_error" ]]; then
            local err_msg=$(cat "$sql_error")
            log_error "SQL error: $err_msg"
            SQL_ERRORS+=("SQL FAILED (v6 block-regex): $err_msg")
        else
            SQL_ERRORS+=("SQL FAILED (v6 block-regex): Unknown error")
        fi
        rm -f "$sql_error"
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error"
    
    # Verify the entries were actually added
    verify_database_insert "domainlist" 3 "$count" "regex deny" || {
        log_warning "Block regex verification found fewer entries than expected"
    }
    
    log_success "Added $count block regex patterns via direct SQL (type=3, v6)"
    if [[ $skipped -gt 0 ]]; then
        log "Skipped $skipped entries (comments)"
    fi
    debug_success "update_regex_v6: Completed successfully"
    print_banner yellow "Completed Regex Block List"
}

#======================================================================================
# DATABASE UPDATE FUNCTIONS - VERSION INDEPENDENT
#======================================================================================

update_adlists() {
    local file="$PIDIR/adlists.list"
    
    debug_log "update_adlists: Starting function"
    debug_log "update_adlists: Looking for file: $file"
    
    if [[ ! -f "$file" ]]; then
        log "No adlists file found, skipping"
        debug_log "update_adlists: File does not exist: $file"
        return 0
    fi
    
    # Check if file has content
    if [[ ! -s "$file" ]]; then
        log "Adlists file is empty, skipping"
        debug_log "update_adlists: File is empty: $file"
        return 0
    fi
    
    print_banner green "Starting Adlist Database Update"
    
    # Validate database is accessible
    if ! sqlite3 "$GRAVITY_DB" "SELECT 1" &>/dev/null; then
        log_error "Cannot access gravity database"
        SQL_ERRORS+=("DATABASE ACCESS FAILED: $GRAVITY_DB")
        return 1
    fi
    
    # Clear existing adlist database
    debug_log "update_adlists: Clearing existing adlist entries"
    local sql_error="$TEMPDIR/sql_error_adlist_$$.log"
    if ! sqlite3 "$GRAVITY_DB" "DELETE FROM adlist" 2>"$sql_error"; then
        log_error "Failed to clear adlist database"
        if [[ -f "$sql_error" && -s "$sql_error" ]]; then
            local err_msg=$(cat "$sql_error")
            log_error "SQL error: $err_msg"
            SQL_ERRORS+=("SQL FAILED (clear adlist): $err_msg")
        fi
        rm -f "$sql_error"
        return 1
    fi
    rm -f "$sql_error"
    
    # Format and prepare adlist - filter out comments and invalid lines
    debug_log "update_adlists: Formatting adlist file"
    if ! grep -v '^[[:space:]]*#' "$file" | grep -v '^[[:space:]]*$' | grep "/" | sort | uniq > "$TEMPDIR/formatted_adlist.temp" 2>/dev/null; then
        log_warning "No valid adlists found after filtering"
        return 0
    fi
    
    # Check if we have any valid URLs
    if [[ ! -s "$TEMPDIR/formatted_adlist.temp" ]]; then
        log_warning "No valid adlist URLs found in $file"
        return 0
    fi
    
    # Insert URLs into database using a transaction for better performance
    local count=0
    local id=1
    local temp_sql="$TEMPDIR/adlist_insert.sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r url || [[ -n "$url" ]]; do
        [[ -z "$url" ]] && continue
        
        # Trim whitespace
        url="${url#"${url%%[![:space:]]*}"}"
        url="${url%"${url##*[![:space:]]}"}"
        
        [[ -z "$url" ]] && continue
        
        # Basic URL validation
        if [[ ! "$url" =~ ^https?:// ]]; then
            log_warning "Skipping invalid URL (no http/https): $url"
            continue
        fi
        
        # Escape single quotes for SQL
        local escaped_url="${url//\'/\'\'}"
        echo "INSERT INTO adlist (id, address, enabled, comment) VALUES($id, '$escaped_url', 1, 'Added by updates_optimized.sh');" >> "$temp_sql"
        ((count++))
        ((id++))
        verbose_log "Added adlist: $url"
    done < "$TEMPDIR/formatted_adlist.temp"
    
    echo "COMMIT;" >> "$temp_sql"
    
    if [[ $count -eq 0 ]]; then
        log "No valid adlist URLs found to add"
        rm -f "$temp_sql" "$TEMPDIR/formatted_adlist.temp"
        return 0
    fi
    
    # Execute the transaction
    debug_log "update_adlists: Executing SQL transaction with $count URLs"
    sql_error="$TEMPDIR/sql_error_adlist_insert_$$.log"
    if ! sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>"$sql_error"; then
        log_error "Failed to insert adlists"
        if [[ -f "$sql_error" && -s "$sql_error" ]]; then
            local err_msg=$(cat "$sql_error")
            log_error "SQL error: $err_msg"
            SQL_ERRORS+=("SQL FAILED (adlist insert): $err_msg")
        fi
        rm -f "$sql_error"
        return 1
    fi
    
    rm -f "$temp_sql" "$sql_error" "$TEMPDIR/formatted_adlist.temp"
    
    # Verify entries were added
    local actual_count
    actual_count=$(sqlite3 "$GRAVITY_DB" "SELECT COUNT(*) FROM adlist WHERE enabled=1;" 2>/dev/null || echo "0")
    
    if [[ "$actual_count" -lt "$count" ]]; then
        log_warning "Adlist verification: Expected $count, found $actual_count"
    fi
    
    log_success "Added $count adlists to database"
    print_banner yellow "Completed Adlist Database Update"
}

#======================================================================================
# DATABASE UPDATE DISPATCHER FUNCTIONS
#======================================================================================

update_allow() {
    log "Updating allow lists..."
    debug_log "update_allow: Dispatching to version $version"
    case "$version" in
        5) 
            debug_log "update_allow: Calling update_allow_v5"
            update_allow_v5
            local result=$?
            debug_log "update_allow: update_allow_v5 returned: $result"
            return $result
            ;;
        6) 
            debug_log "update_allow: Calling update_allow_v6"
            update_allow_v6
            local result=$?
            debug_log "update_allow: update_allow_v6 returned: $result"
            return $result
            ;;
        *) 
            log "ERROR: Unknown Pi-hole version: $version"
            debug_log "update_allow: Invalid version detected"
            return 1
            ;;
    esac
}

update_allow_regex() {
    log "Updating allow regex..."
    debug_log "update_allow_regex: Dispatching to version $version"
    case "$version" in
        5) 
            debug_log "update_allow_regex: Calling update_allow_regex_v5"
            update_allow_regex_v5
            local result=$?
            debug_log "update_allow_regex: update_allow_regex_v5 returned: $result"
            return $result
            ;;
        6) 
            debug_log "update_allow_regex: Calling update_allow_regex_v6"
            update_allow_regex_v6
            local result=$?
            debug_log "update_allow_regex: update_allow_regex_v6 returned: $result"
            return $result
            ;;
        *) 
            log "ERROR: Unknown Pi-hole version: $version"
            debug_log "update_allow_regex: Invalid version detected"
            return 1
            ;;
    esac
}

update_block_regex() {
    log "Updating block regex..."
    debug_log "update_block_regex: Dispatching to version $version"
    case "$version" in
        5) 
            debug_log "update_block_regex: Calling update_regex_v5"
            update_regex_v5
            local result=$?
            debug_log "update_block_regex: update_regex_v5 returned: $result"
            return $result
            ;;
        6) 
            debug_log "update_block_regex: Calling update_regex_v6"
            update_regex_v6
            local result=$?
            debug_log "update_block_regex: update_regex_v6 returned: $result"
            return $result
            ;;
        *) 
            log "ERROR: Unknown Pi-hole version: $version"
            debug_log "update_block_regex: Invalid version detected"
            return 1
            ;;
    esac
}

#======================================================================================
# DATABASE UPDATE WRAPPER FUNCTIONS
#======================================================================================

update_pihole_database() {
    log "=== Starting full database update ==="
    log "Pi-hole version: $version"
    debug_log "update_pihole_database: Function called"
    debug_log "update_pihole_database: GRAVITY_DB=$GRAVITY_DB"
    debug_log "update_pihole_database: PIDIR=$PIDIR"
    debug_log "update_pihole_database: TEMPDIR=$TEMPDIR"
    
    debug_log "update_pihole_database: Step 1 - Calling update_allow"
    update_allow || {
        log "ERROR: update_allow failed"
        debug_log "update_pihole_database: update_allow returned error"
        return 1
    }
    debug_log "update_pihole_database: Step 1 complete"
    
    debug_log "update_pihole_database: Step 2 - Calling update_allow_regex"
    update_allow_regex || {
        log "ERROR: update_allow_regex failed"
        debug_log "update_pihole_database: update_allow_regex returned error"
        return 1
    }
    debug_log "update_pihole_database: Step 2 complete"
    
    debug_log "update_pihole_database: Step 3 - Calling update_adlists"
    update_adlists || {
        log "ERROR: update_adlists failed"
        debug_log "update_pihole_database: update_adlists returned error"
        return 1
    }
    debug_log "update_pihole_database: Step 3 complete"
    
    debug_log "update_pihole_database: Step 4 - Calling update_block_regex"
    update_block_regex || {
        log "ERROR: update_block_regex failed"
        debug_log "update_pihole_database: update_block_regex returned error"
        return 1
    }
    debug_log "update_pihole_database: Step 4 complete"
    
    log "=== Full database update completed ==="
    debug_log "update_pihole_database: All steps completed successfully"
}

update_pihole_database_allow_only() {
    log "=== Starting allow list database update ==="
    log "Pi-hole version: $version"
    
    update_allow
    update_allow_regex
    
    log "=== Allow list database update completed ==="
}

update_pihole_database_regex_only() {
    log "=== Starting regex block database update ==="
    log "Pi-hole version: $version"
    
    update_block_regex
    
    log "=== Regex block database update completed ==="
}

#======================================================================================
# CORE FUNCTIONS
#======================================================================================

system_update() {
    log "Starting system update..."
    apt-get update && apt-get dist-upgrade -y
    apt autoremove -y
    log "System update completed"
}

download_scripts() {
    log "Downloading configuration and scripts..."
    debug_log "download_scripts: Starting script downloads"
    
    local downloads=(
        "${AZURE_REPO}/Configuration%20Files/CFconfig|$TEMPDIR/CFconfig"
        "${REPO_BASE}/Updates/refresh.sh|$TEMPDIR/refresh.sh"
        "${REPO_BASE}/Updates/updates.sh|$TEMPDIR/updates.sh"
        "${REPO_BASE}/Updates/configuration_changes.sh|$TEMPDIR/configuration_changes.sh"
        "${REPO_BASE}/Updates/Research.sh|$TEMPDIR/Research.sh"
        "${REPO_BASE}/Updates/allow_update.sh|$TEMPDIR/allow_update.sh"
    )
    
    debug_log "download_scripts: Downloading ${#downloads[@]} files"
    if ! parallel_download downloads; then
        log_warning "Some script downloads failed, but continuing..."
        debug_log "download_scripts: parallel_download returned error, checking which files succeeded"
        
        # Log which files were successfully downloaded
        for item in "${downloads[@]}"; do
            IFS='|' read -r url output <<< "$item"
            if [[ -f "$output" ]]; then
                debug_success "download_scripts: $output exists"
            else
                log_warning "Failed to download: $output"
                debug_error "download_scripts: $output does not exist"
            fi
        done
    else
        debug_success "All ${#downloads[@]} scripts downloaded successfully"
    fi
    
    debug_log "download_scripts: Making scripts executable"
    chmod 755 $TEMPDIR/*.sh 2>/dev/null || true
    debug_log "download_scripts: Completed"
}

download_full_config() {
    log "Downloading full configuration..."
    
    # Download adlists
    download_file "${REPO_BASE}/adlists/main.adlist.list" "$TEMPDIR/adlists.list" || {
        log "ERROR: Failed to download adlists"
        return 1
    }
    
    # Download regex lists in parallel
    local regex_files=(
        "${REPO_BASE}/Regex%20Files/main.regex|$TEMPDIR/main.regex"
        "${REPO_BASE}/Regex%20Files/oTLD.regex|$TEMPDIR/oTLD.regex"
        "${REPO_BASE}/Regex%20Files/uslocal.regex|$TEMPDIR/uslocal.regex"
    )
    parallel_download regex_files || {
        log "ERROR: Failed to download regex files"
        return 1
    }
    
    # Clean line endings
    sed -i -e "s/\r//g" $TEMPDIR/*.regex 2>/dev/null || true
    
    # Download encrypted country regex
    download_gpg_file "${REPO_BASE}/Regex%20Files/country.regex.gpg" "$TEMPDIR/country.regex" || {
        log "ERROR: Failed to download/decrypt country.regex.gpg"
        log "ERROR: This is likely a GPG key issue"
        return 1
    }
}

download_security_config() {
    log "Downloading security configuration..."
    debug_log "download_security_config: Starting"
    
    if ! download_file "${REPO_BASE}/adlists/security_basic_adlist.list" "$TEMPDIR/adlists.list"; then
        log_error "Failed to download security adlist"
        touch "$TEMPDIR/adlists.list" || {
            log_error "Cannot create adlists.list"
            return 1
        }
    fi
    
    local security_files=(
        "${REPO_BASE}/Regex%20Files/basic_security.regex|$TEMPDIR/basic_security.regex"
        "${REPO_BASE}/Regex%20Files/oTLD.regex|$TEMPDIR/oTLD.regex"
    )
    
    debug_log "download_security_config: Downloading ${#security_files[@]} regex files"
    if ! parallel_download security_files; then
        log_warning "Some security regex downloads failed, continuing..."
        debug_log "download_security_config: Checking which files succeeded"
    else
        debug_success "All ${#security_files[@]} security regex files downloaded successfully"
    fi
    
    sed -i -e "s/\r//g" $TEMPDIR/*.regex 2>/dev/null || true
    
    # Download encrypted files
    debug_log "download_security_config: Downloading encrypted regex files"
    if ! download_gpg_file "${REPO_BASE}/Regex%20Files/basic_country.regex.gpg" "$TEMPDIR/basic_country.regex"; then
        log_warning "Failed to download basic_country.regex.gpg, creating empty file"
        touch "$TEMPDIR/basic_country.regex" || log_error "Cannot create basic_country.regex"
    fi
    
    if ! download_gpg_file "${REPO_BASE}/Regex%20Files/encrypted.regex.gpg" "$TEMPDIR/encrypted.regex"; then
        log_warning "Failed to download encrypted.regex.gpg, creating empty file"
        touch "$TEMPDIR/encrypted.regex" || log_error "Cannot create encrypted.regex"
    fi
    
    debug_log "download_security_config: Completed"
}

download_test_lists() {
    [[ "$test_system" != "yes" ]] && { debug_log "Test system disabled, skipping test lists"; return 0; }
    
    log "Downloading test lists..."
    debug_log "download_test_lists: Starting"
    
    if ! download_file "${REPO_BASE}/adlists/trial.adlist.list" "$TEMPDIR/adlists.list.trial.temp"; then
        log_warning "Failed to download trial.adlist.list, creating empty file"
        touch "$TEMPDIR/adlists.list.trial.temp" || {
            log_error "Cannot create trial.adlist.list"
            return 1
        }
    fi
    
    debug_log "download_test_lists: Merging trial adlists with main adlists"
    cat "$TEMPDIR/adlists.list.trial.temp" "$TEMPDIR/adlists.list" 2>/dev/null | \
        grep -v "##" | sort | uniq > "$TEMPDIR/adlists.list.temp" || {
        log_warning "Failed to merge adlists, using original"
        cp "$TEMPDIR/adlists.list" "$TEMPDIR/adlists.list.temp" 2>/dev/null
    }
    mv "$TEMPDIR/adlists.list.temp" "$TEMPDIR/adlists.list" || log_warning "Failed to update adlists.list"
    
    if ! download_file "${REPO_BASE}/Regex%20Files/test.regex" "$TEMPDIR/test.regex"; then
        log_warning "Failed to download test.regex, creating empty file"
        touch "$TEMPDIR/test.regex" || log_error "Cannot create test.regex"
    fi
    
    if ! download_gpg_file "${REPO_BASE}/Allow%20Lists/test.allow.gpg" "$TEMPDIR/test.allow.temp"; then
        log_warning "Failed to download test.allow.gpg, creating empty file"
        touch "$TEMPDIR/test.allow.temp" || log_error "Cannot create test.allow.temp"
    fi
    
    if ! download_gpg_file "${REPO_BASE}/Block_Lists/test.block.encrypt.gpg" "$TEMPDIR/test.block.encrypt.temp"; then
        log_warning "Failed to download test.block.encrypt.gpg, creating empty file"
        touch "$TEMPDIR/test.block.encrypt.temp" || log_error "Cannot create test.block.encrypt.temp"
    fi
    
    debug_log "download_test_lists: Completed"
}

download_public_allowlists() {
    log "Downloading public allow lists..."
    debug_log "download_public_allowlists: Starting"
    
    local allow_files=(
        "${REPO_BASE}/Allow%20Lists/basic.allow|$TEMPDIR/basic.allow.temp"
        "${REPO_BASE}/Allow%20Lists/adlist.allow|$TEMPDIR/adlist.allow.temp"
    )
    
    debug_log "download_public_allowlists: Downloading ${#allow_files[@]} files"
    if ! parallel_download allow_files; then
        log_warning "Some allow list downloads failed"
        debug_log "download_public_allowlists: parallel_download returned error"
        
        # Check which files exist
        for item in "${allow_files[@]}"; do
            IFS='|' read -r url output <<< "$item"
            if [[ ! -f "$output" ]]; then
                log_warning "Missing file: $output"
                debug_log "download_public_allowlists: Creating empty placeholder for $output"
                touch "$output" || log_error "Cannot create $output"
            fi
        done
    else
        debug_success "All ${#allow_files[@]} allow lists downloaded successfully"
    fi
    
    # Add newlines and copy local config
    echo " " >> "$TEMPDIR/basic.allow.temp" 2>/dev/null || log "WARNING: Cannot append to basic.allow.temp"
    echo " " >> "$TEMPDIR/adlist.allow.temp" 2>/dev/null || log "WARNING: Cannot append to adlist.allow.temp"
    cp "$CONFIG/perm_allow.conf" "$TEMPDIR/perm.allow.temp" 2>/dev/null || {
        debug_log "download_public_allowlists: perm_allow.conf not found or cannot copy"
        touch "$TEMPDIR/perm.allow.temp" || log "WARNING: Cannot create perm.allow.temp"
    }
    debug_log "download_public_allowlists: Completed"
}

download_security_allowlists() {
    log "Downloading security allow lists..."
    debug_log "download_security_allowlists: Starting"
    
    if ! download_file "${REPO_BASE}/Allow%20Lists/security_only.allow" "$TEMPDIR/security_only.allow.temp"; then
        log "WARNING: Failed to download security_only.allow, creating empty file"
        touch "$TEMPDIR/security_only.allow.temp" || log "ERROR: Cannot create security_only.allow.temp"
    fi
    
    debug_log "download_security_allowlists: Completed"
}

download_encrypted_allowlists() {
    log "Downloading encrypted allow lists..."
    debug_log "download_encrypted_allowlists: Starting"
    
    local encrypted_lists=(
        encrypt financial civic international medical tech
    )
    
    local pids=()
    for list in "${encrypted_lists[@]}"; do
        debug_log "download_encrypted_allowlists: Downloading ${list}.allow.gpg"
        (
            if ! download_gpg_file "${REPO_BASE}/Allow%20Lists/${list}.allow.gpg" "$TEMPDIR/${list}.allow.temp"; then
                log "WARNING: Failed to download ${list}.allow.gpg, creating empty file"
                touch "$TEMPDIR/${list}.allow.temp" 2>/dev/null
            fi
        ) &
        pids+=("$!")
    done
    
    debug_log "download_encrypted_allowlists: Waiting for ${#pids[@]} downloads to complete"
    for pid in "${pids[@]}"; do
        wait "$pid" || debug_log "download_encrypted_allowlists: A download process failed (non-fatal)"
    done
    
    debug_log "download_encrypted_allowlists: Completed"
}

download_regex_allowlists() {
    log "Downloading regex allow lists..."
    debug_log "download_regex_allowlists: Starting"
    
    if ! download_file "${REPO_BASE}/Allow%20Lists/regex.allow" "$TEMPDIR/regex.allow.regex.temp"; then
        log "WARNING: Failed to download regex.allow, creating empty file"
        touch "$TEMPDIR/regex.allow.regex.temp" || log "ERROR: Cannot create regex.allow.regex.temp"
    fi
    
    if ! cp "$CONFIG/allow_wild.conf" "$TEMPDIR/allow_wild.allow.regex.temp" 2>/dev/null; then
        debug_log "download_regex_allowlists: allow_wild.conf not found, creating empty file"
        touch "$TEMPDIR/allow_wild.allow.regex.temp" || log "WARNING: Cannot create allow_wild.allow.regex.temp"
    fi
    
    if ! download_gpg_file "${REPO_BASE}/Allow%20Lists/encrypt.regex.allow.gpg" "$TEMPDIR/encrypt.regex.allow.regex.temp"; then
        log "WARNING: Failed to download/decrypt encrypt.regex.allow.gpg, creating empty file"
        touch "$TEMPDIR/encrypt.regex.allow.regex.temp" || log "ERROR: Cannot create encrypt.regex.allow.regex.temp"
    fi
    
    debug_log "download_regex_allowlists: Completed"
}

download_encrypted_blocklists() {
    log "Downloading encrypted block lists..."
    debug_log "download_encrypted_blocklists: Starting"
    
    local block_lists=(
        custom propaganda spam media
    )
    
    local pids=()
    for list in "${block_lists[@]}"; do
        debug_log "download_encrypted_blocklists: Downloading ${list}.block.encrypt.gpg"
        (
            if ! download_gpg_file "${REPO_BASE}/Block_Lists/${list}.block.encrypt.gpg" "$TEMPDIR/${list}.block.encrypt.temp"; then
                log "WARNING: Failed to download ${list}.block.encrypt.gpg, creating empty file"
                touch "$TEMPDIR/${list}.block.encrypt.temp" 2>/dev/null
            fi
        ) &
        pids+=("$!")
    done
    
    debug_log "download_encrypted_blocklists: Waiting for ${#pids[@]} downloads to complete"
    for pid in "${pids[@]}"; do
        wait "$pid" || debug_log "download_encrypted_blocklists: A download process failed (non-fatal)"
    done
    
    debug_log "download_encrypted_blocklists: Completed"
}

assemble_and_deploy() {
    log "Assembling and deploying configurations..."
    local errors=0
    
    # Assemble final files with better error handling
    debug_log "assemble_and_deploy: Assembling allow regex files"
    if ! cat $TEMPDIR/*.allow.regex.temp 2>/dev/null | \
        grep -v '^[[:space:]]*#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/final.allow.regex.temp" 2>/dev/null; then
        log_warning "No allow regex files to assemble"
        touch "$TEMPDIR/final.allow.regex.temp"
    fi
    
    debug_log "assemble_and_deploy: Assembling allow files"
    if ! cat $TEMPDIR/*.allow.temp 2>/dev/null | \
        grep -v '^[[:space:]]*#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/final.allow.temp" 2>/dev/null; then
        log_warning "No allow files to assemble"
        touch "$TEMPDIR/final.allow.temp"
    fi
    
    debug_log "assemble_and_deploy: Assembling regex files"
    if ! cat $TEMPDIR/*.regex 2>/dev/null | \
        grep -v '^[[:space:]]*#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/regex.list" 2>/dev/null; then
        log_warning "No regex files to assemble"
        touch "$TEMPDIR/regex.list"
    fi
    
    debug_log "assemble_and_deploy: Assembling encrypted block files"
    if ! cat $TEMPDIR/*.block.encrypt.temp 2>/dev/null | \
        grep -v '^[[:space:]]*#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$CONFIG/encrypt.list" 2>/dev/null; then
        log_warning "No encrypted block files to assemble"
        # Don't fail on this, it may not exist
    fi
    
    # Deploy files with verification
    debug_log "assemble_and_deploy: Deploying configuration files"
    
    if [[ -s "$TEMPDIR/regex.list" ]]; then
        if mv "$TEMPDIR/regex.list" "$PIDIR/regex.list"; then
            log "Deployed regex.list ($(wc -l < "$PIDIR/regex.list" 2>/dev/null || echo 0) entries)"
        else
            log_error "Failed to deploy regex.list"
            DEPLOY_ERRORS+=("DEPLOY FAILED: regex.list to $PIDIR/regex.list")
            ((errors++))
        fi
    else
        log_warning "regex.list is empty, skipping deployment"
    fi
    
    if [[ -s "$TEMPDIR/final.allow.temp" ]]; then
        if mv "$TEMPDIR/final.allow.temp" "$PIDIR/whitelist.txt"; then
            log "Deployed whitelist.txt ($(wc -l < "$PIDIR/whitelist.txt" 2>/dev/null || echo 0) entries)"
        else
            log_error "Failed to deploy whitelist.txt"
            DEPLOY_ERRORS+=("DEPLOY FAILED: whitelist.txt to $PIDIR/whitelist.txt")
            ((errors++))
        fi
    else
        log_warning "whitelist.txt is empty, skipping deployment"
    fi
    
    if [[ -s "$TEMPDIR/adlists.list" ]]; then
        if mv "$TEMPDIR/adlists.list" "$PIDIR/adlists.list"; then
            log "Deployed adlists.list ($(wc -l < "$PIDIR/adlists.list" 2>/dev/null || echo 0) entries)"
        else
            log_error "Failed to deploy adlists.list"
            DEPLOY_ERRORS+=("DEPLOY FAILED: adlists.list to $PIDIR/adlists.list")
            ((errors++))
        fi
    else
        log_warning "adlists.list not found or empty, skipping deployment"
    fi
    
    if [[ -f "$TEMPDIR/CFconfig" ]]; then
        debug_log "assemble_and_deploy: Deploying CFconfig"
        mv "$TEMPDIR/CFconfig" "$FINISHED/cloudflared" || log_warning "Failed to deploy CFconfig"
    else
        debug_log "assemble_and_deploy: CFconfig not found, skipping"
    fi
    
    if [[ -f "$TEMPDIR/refresh.sh" ]]; then
        debug_log "assemble_and_deploy: Deploying refresh.sh"
        mv "$TEMPDIR/refresh.sh" "$FINISHED/refresh.sh" || log_warning "Failed to deploy refresh.sh"
    else
        debug_log "assemble_and_deploy: refresh.sh not found, skipping"
    fi
    
    # Update database directly (integrated functionality)
    debug_log "assemble_and_deploy: Starting database update"
    if ! update_pihole_database; then
        log_error "Database update failed"
        ((errors++))
    fi
    
    # Verify database entries
    verify_allow_list_entries || log_warning "Allow list verification had issues"
    
    debug_log "assemble_and_deploy: Completed with $errors errors"
    
    if [[ $errors -gt 0 ]]; then
        return 1
    fi
    return 0
}

assemble_and_deploy_regex_only() {
    log "Assembling and deploying regex configurations..."
    local errors=0
    
    # Assemble only regex block lists
    debug_log "assemble_and_deploy_regex_only: Assembling regex files"
    if ! cat $TEMPDIR/*.regex 2>/dev/null | \
        grep -v '^[[:space:]]*#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/regex.list" 2>/dev/null; then
        log_warning "No regex files to assemble"
        touch "$TEMPDIR/regex.list"
    fi
    
    # Deploy regex file
    if [[ -s "$TEMPDIR/regex.list" ]]; then
        if mv "$TEMPDIR/regex.list" "$PIDIR/regex.list"; then
            log "Deployed regex.list ($(wc -l < "$PIDIR/regex.list" 2>/dev/null || echo 0) entries)"
        else
            log_error "Failed to deploy regex.list"
            DEPLOY_ERRORS+=("DEPLOY FAILED: regex.list")
            ((errors++))
        fi
    else
        log_warning "regex.list is empty, skipping deployment"
    fi
    
    # Update database with regex only (integrated functionality)
    if ! update_pihole_database_regex_only; then
        log_error "Regex database update failed"
        ((errors++))
    fi
    
    # Verify regex entries
    local regex_count
    regex_count=$(sqlite3 "$GRAVITY_DB" "SELECT COUNT(*) FROM domainlist WHERE type=3 AND enabled=1;" 2>/dev/null || echo "0")
    log "Database verification: $regex_count regex deny entries (type 3)"
    
    if [[ $errors -gt 0 ]]; then
        return 1
    fi
    return 0
}

restart_services() {
    log "Restarting Pi-hole services..."
    local errors=0
    
    # Send SIGHUP to pihole-FTL to reload configuration
    debug_log "restart_services: Sending SIGHUP to pihole-FTL"
    if ! killall -SIGHUP pihole-FTL 2>/dev/null; then
        log_warning "Could not send SIGHUP to pihole-FTL (may not be running)"
    fi
    
    # Restart DNS service
    debug_log "restart_services: Restarting DNS"
    if ! pihole restartdns 2>/dev/null; then
        log_warning "pihole restartdns failed"
        ((errors++))
    fi
    
    # Run gravity to update blocking lists
    debug_log "restart_services: Running gravity update"
    if ! pihole -g 2>/dev/null; then
        log_warning "pihole -g (gravity) failed"
        ((errors++))
    fi
    
    # Restart cloudflared if configured
    if [[ "$is_cloudflared" == "cloudflared" ]]; then
        debug_log "restart_services: Restarting cloudflared"
        if systemctl restart cloudflared 2>/dev/null; then
            log "Cloudflared restarted"
        else
            log_warning "Failed to restart cloudflared"
            ((errors++))
        fi
    fi
    
    # Verify Pi-hole is running after restart
    if pihole status 2>/dev/null | grep -q "enabled"; then
        log_success "Pi-hole services restarted successfully"
    else
        log_warning "Pi-hole status check returned unexpected result"
        ((errors++))
    fi
    
    if [[ $errors -gt 0 ]]; then
        return 1
    fi
    return 0
}

cleanup() {
    # This function is for in-process cleanup (not the trap-based cleanup)
    log "Cleaning up temporary files..."
    
    # Remove specific file patterns
    rm -f "$TEMPDIR"/*.regex 2>/dev/null || true
    rm -f "$TEMPDIR"/*.temp 2>/dev/null || true
    rm -f "$TEMPDIR"/*.gpg 2>/dev/null || true
    rm -f "$TEMPDIR"/*.sql 2>/dev/null || true
    rm -f "$TEMPDIR"/*.log 2>/dev/null || true
    rm -f "$TEMPDIR"/curl_error_* 2>/dev/null || true
    rm -f "$TEMPDIR"/gpg_error_* 2>/dev/null || true
    rm -f "$TEMPDIR"/sql_error_* 2>/dev/null || true
    rm -f "$TEMPDIR"/formatted_adlist.temp 2>/dev/null || true
    
    # List any remaining files (for debugging)
    if [[ "$DEBUG" -eq 1 ]]; then
        local remaining
        remaining=$(find "$TEMPDIR" -type f 2>/dev/null | wc -l)
        if [[ "$remaining" -gt 0 ]]; then
            debug_log "Remaining files in $TEMPDIR: $remaining"
            find "$TEMPDIR" -type f 2>/dev/null | while read -r f; do
                debug_log "  - $f"
            done
        else
            debug_log "Temp directory is clean"
        fi
    fi
    
    log_success "Cleanup completed"
}

purge_database() {
    log "Purging Pi-hole database..."
    debug_log "purge_database: Starting with version=$version"
    
    # Validate database is accessible
    if ! sqlite3 "$GRAVITY_DB" "SELECT 1" &>/dev/null; then
        log_error "Cannot access gravity database"
        SQL_ERRORS+=("DATABASE ACCESS FAILED: $GRAVITY_DB")
        return 1
    fi
    
    # Clear adlists
    local sql_error="$TEMPDIR/sql_error_purge_$$.log"
    if ! sqlite3 "$GRAVITY_DB" "DELETE FROM adlist" 2>"$sql_error"; then
        log_error "Failed to clear adlist table"
        if [[ -f "$sql_error" && -s "$sql_error" ]]; then
            SQL_ERRORS+=("SQL FAILED (purge adlist): $(cat "$sql_error")")
        fi
        rm -f "$sql_error"
        return 1
    fi
    log "Cleared adlist table"
    
    if [[ "$version" == "5" ]]; then
        log "Purging Pi-hole v5 lists..."
        debug_log "purge_database: Using v5 CLI commands"
        
        # Pi-hole v5 CLI commands for purging lists
        # Note: These commands may not all exist in all v5 installations
        # Using --nuke flag to remove all entries
        
        # Purge existing regex deny list
        if pihole --regex --nuke 2>/dev/null; then
            log "Cleared regex deny list"
        else
            log_warning "Failed to nuke regex deny list (may not exist)"
        fi
        
        # Purge existing wildcard deny list  
        if pihole --wild --nuke 2>/dev/null; then
            log "Cleared wildcard deny list"
        else
            log_warning "Failed to nuke wildcard deny list (may not exist)"
        fi
        
        # Purge existing allow list (whitelist)
        if pihole -w --nuke 2>/dev/null; then
            log "Cleared allow list (whitelist)"
        else
            log_warning "Failed to nuke allow list (may not exist)"
        fi
        
        # Purge existing allow list regex (white-regex)
        if pihole --white-regex --nuke 2>/dev/null; then
            log "Cleared allow regex list"
        else
            log_warning "Failed to nuke allow regex list (may not exist)"
        fi
        
        # Purge existing deny list (blacklist)
        if pihole -b --nuke 2>/dev/null; then
            log "Cleared deny list (blacklist)"
        else
            log_warning "Failed to nuke deny list (may not exist)"
        fi
        
        # Purge existing wildcard allow list
        if pihole --white-wild --nuke 2>/dev/null; then
            log "Cleared wildcard allow list"
        else
            log_warning "Failed to nuke wildcard allow list (may not exist)"
        fi
        
        log "Pi-hole v5 database purged"
        
    elif [[ "$version" == "6" ]]; then
        log "Purging Pi-hole v6 lists..."
        debug_log "purge_database: Using direct SQL for v6 (more reliable)"
        
        # For v6, direct SQL is more reliable than CLI
        # Clear entire domainlist table
        if ! sqlite3 "$GRAVITY_DB" "DELETE FROM domainlist;" 2>"$sql_error"; then
            log_error "Failed to clear domainlist table"
            if [[ -f "$sql_error" && -s "$sql_error" ]]; then
                SQL_ERRORS+=("SQL FAILED (purge domainlist): $(cat "$sql_error")")
            fi
            rm -f "$sql_error"
            return 1
        fi
        
        # Verify the table is empty
        local remaining
        remaining=$(sqlite3 "$GRAVITY_DB" "SELECT COUNT(*) FROM domainlist;" 2>/dev/null || echo "unknown")
        if [[ "$remaining" != "0" ]]; then
            log_warning "domainlist table still has $remaining entries after purge"
        fi
        
        log "Pi-hole v6 database purged (domainlist table cleared)"
    else
        log_error "Unknown Pi-hole version: $version"
        VALIDATION_ERRORS+=("Unknown Pi-hole version: $version")
        return 1
    fi
    
    rm -f "$sql_error"
    log_success "Database purge completed successfully"
}

#======================================================================================
# COMMAND FUNCTIONS
#======================================================================================

cmd_refresh() {
    log "=== Starting script refresh ==="
    download_scripts || log_warning "Some script downloads had issues"
    
    # Move scripts to final location (note: db_updates_optimized.sh no longer needed)
    local deployed=0
    for script in updates.sh configuration_changes.sh Research.sh allow_update.sh; do
        if [[ -f "$TEMPDIR/$script" ]]; then
            chmod 755 "$TEMPDIR/$script"
            if mv "$TEMPDIR/$script" "$FINISHED/$script"; then
                verbose_log "Installed: $script"
                ((deployed++))
            else
                log_warning "Failed to install: $script"
                DEPLOY_ERRORS+=("DEPLOY FAILED: $script")
            fi
        else
            debug_log "Script not found: $TEMPDIR/$script"
        fi
    done
    
    log "Deployed $deployed scripts to $FINISHED"
    cleanup
    
    log "=== Script refresh completed ==="
    
    # Show error summary
    show_error_summary
}

cmd_full_update() {
    log "=== Starting full update ==="
    debug_log "cmd_full_update: Comprehensive update with all components"
    
    # System update
    system_update || log_warning "System update had issues"
    
    # Download scripts
    download_scripts || log_warning "Script download had issues"
    
    # Download configurations based on type
    if [[ "$Type" == "security" ]]; then
        download_security_config || log_warning "Security config download had issues"
        download_security_allowlists || log_warning "Security allowlist download had issues"
    else
        download_full_config || log_warning "Full config download had issues"
        download_test_lists || log_warning "Test list download had issues"
    fi
    
    # Download all allow and block lists (comprehensive)
    download_public_allowlists || log_warning "Public allowlist download had issues"
    download_regex_allowlists || log_warning "Regex allowlist download had issues"
    download_encrypted_allowlists || log_warning "Encrypted allowlist download had issues"
    download_encrypted_blocklists || log_warning "Encrypted blocklist download had issues"
    
    # Deploy and update database
    assemble_and_deploy || {
        log_error "Assembly and deployment failed"
        cleanup
        show_error_summary
        return 1
    }
    
    # Restart services
    restart_services || log_warning "Service restart had issues"
    
    # Cleanup
    cleanup
    
    log "=== Full update completed ==="
    
    # Show error summary
    show_error_summary
}

cmd_allow_update() {
    log "=== Starting allow list update ==="
    
    if [[ "$Type" == "security" ]]; then
        download_security_allowlists || log_warning "Security allowlist download had issues"
    fi
    
    download_public_allowlists || log_warning "Public allowlist download had issues"
    download_regex_allowlists || log_warning "Regex allowlist download had issues"
    download_encrypted_allowlists || log_warning "Encrypted allowlist download had issues"
    
    # Assemble allow lists
    cat $TEMPDIR/*.allow.regex.temp 2>/dev/null | \
        grep -v '^[[:space:]]*#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/final.allow.regex.temp" || {
        log_warning "No allow regex entries to assemble"
        touch "$TEMPDIR/final.allow.regex.temp"
    }
    
    cat $TEMPDIR/*.allow.temp 2>/dev/null | \
        grep -v '^[[:space:]]*#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/final.allow.temp" || {
        log_warning "No allow entries to assemble"
        touch "$TEMPDIR/final.allow.temp"
    }
    
    # Deploy allow lists
    if [[ -s "$TEMPDIR/final.allow.temp" ]]; then
        mv "$TEMPDIR/final.allow.temp" "$PIDIR/whitelist.txt" || {
            log_error "Failed to deploy whitelist.txt"
            DEPLOY_ERRORS+=("DEPLOY FAILED: whitelist.txt")
        }
    else
        log_warning "No allow entries to deploy"
    fi
    
    # Update database with allow lists only (integrated functionality)
    update_pihole_database_allow_only || {
        log_error "Allow list database update failed"
    }
    
    # Verify entries were added
    verify_allow_list_entries
    
    restart_services || log_warning "Service restart had issues"
    cleanup
    
    log "=== Allow list update completed ==="
    
    # Show error summary
    show_error_summary
}

# Function to verify allow list entries were actually added
verify_allow_list_entries() {
    log "Verifying allow list entries in database..."
    
    if ! sqlite3 "$GRAVITY_DB" "SELECT 1" &>/dev/null; then
        log_error "Cannot access database for verification"
        return 1
    fi
    
    # Count exact allowlist entries (type 0)
    local exact_count
    exact_count=$(sqlite3 "$GRAVITY_DB" "SELECT COUNT(*) FROM domainlist WHERE type=0 AND enabled=1;" 2>/dev/null || echo "0")
    
    # Count regex allowlist entries (type 2)
    local regex_count
    regex_count=$(sqlite3 "$GRAVITY_DB" "SELECT COUNT(*) FROM domainlist WHERE type=2 AND enabled=1;" 2>/dev/null || echo "0")
    
    log "Database verification:"
    log "  Exact allow entries (type 0): $exact_count"
    log "  Regex allow entries (type 2): $regex_count"
    
    if [[ "$exact_count" -eq 0 && "$regex_count" -eq 0 ]]; then
        log_warning "No allow list entries found in database!"
        log_warning "This may indicate a problem with the update"
        VALIDATION_ERRORS+=("No allow entries in database after update")
        return 1
    fi
    
    # Show a few sample entries for verification
    if [[ "$DEBUG" -eq 1 ]]; then
        debug_log "Sample exact allow entries (type 0):"
        sqlite3 "$GRAVITY_DB" "SELECT domain FROM domainlist WHERE type=0 AND enabled=1 LIMIT 5;" 2>/dev/null | while read -r d; do
            debug_log "  - $d"
        done
        
        debug_log "Sample regex allow entries (type 2):"
        sqlite3 "$GRAVITY_DB" "SELECT domain FROM domainlist WHERE type=2 AND enabled=1 LIMIT 5;" 2>/dev/null | while read -r d; do
            debug_log "  - $d"
        done
    fi
    
    log_success "Allow list verification complete"
    return 0
}

cmd_quick_update() {
    log "=== Starting quick update (no system upgrade) ==="
    
    download_scripts || log_warning "Script download had issues"
    
    if [[ "$Type" == "security" ]]; then
        download_security_config || log_warning "Security config download had issues"
        download_security_allowlists || log_warning "Security allowlist download had issues"
    else
        download_full_config || log_warning "Full config download had issues"
        download_test_lists || log_warning "Test list download had issues"
    fi
    
    download_public_allowlists || log_warning "Public allowlist download had issues"
    download_regex_allowlists || log_warning "Regex allowlist download had issues"
    download_encrypted_allowlists || log_warning "Encrypted allowlist download had issues"
    download_encrypted_blocklists || log_warning "Encrypted blocklist download had issues"
    
    assemble_and_deploy || {
        log_error "Assembly and deployment failed"
        cleanup
        show_error_summary
        return 1
    }
    
    restart_services || log_warning "Service restart had issues"
    cleanup
    
    log "=== Quick update completed ==="
    
    # Show error summary
    show_error_summary
}

cmd_purge_and_update() {
    log "=== Starting purge and full update ==="
    log_warning "This will clear all existing Pi-hole lists and rebuild from scratch"
    
    # Purge existing database
    purge_database || {
        log_error "Database purge failed, aborting update"
        cleanup
        show_error_summary
        return 1
    }
    
    # Run full update to repopulate
    log "Starting full update to repopulate database..."
    system_update || log_warning "System update had issues"
    download_scripts || log_warning "Script download had issues"
    
    if [[ "$Type" == "security" ]]; then
        download_security_config || log_warning "Security config download had issues"
        download_security_allowlists || log_warning "Security allowlist download had issues"
    else
        download_full_config || log_warning "Full config download had issues"
        download_test_lists || log_warning "Test list download had issues"
    fi
    
    download_public_allowlists || log_warning "Public allowlist download had issues"
    download_regex_allowlists || log_warning "Regex allowlist download had issues"
    download_encrypted_allowlists || log_warning "Encrypted allowlist download had issues"
    download_encrypted_blocklists || log_warning "Encrypted blocklist download had issues"
    
    assemble_and_deploy || {
        log_error "Assembly and deployment failed"
        cleanup
        show_error_summary
        return 1
    }
    
    restart_services || log_warning "Service restart had issues"
    cleanup
    
    log "=== Purge and full update completed ==="
    
    # Show error summary
    show_error_summary
}

cmd_block_regex_update() {
    log "=== Starting block regex update ==="
    
    if [[ "$Type" == "security" ]]; then
        download_security_config || log_warning "Security config download had issues"
    else
        download_full_config || log_warning "Full config download had issues"
        download_test_lists || log_warning "Test list download had issues"
    fi
    
    assemble_and_deploy_regex_only || {
        log_error "Regex assembly and deployment failed"
        cleanup
        show_error_summary
        return 1
    }
    
    restart_services || log_warning "Service restart had issues"
    cleanup
    
    log "=== Block regex update completed ==="
    
    # Show error summary
    show_error_summary
}

show_help() {
    cat << 'EOF'
Pi-hole Update Script - Fully Integrated & Optimized Version

DESCRIPTION:
    Combines update/download functionality with database management in a single script.
    No separate database update script needed - all functionality is integrated.
    Supports both Pi-hole v5 and v6 with automatic cleanup on exit/error.

DATABASE SCHEMA (domainlist table - same for v5 and v6):
    Type 0 = exact allowlist (whitelist)
    Type 1 = exact denylist (blacklist)
    Type 2 = regex allowlist (white-regex)
    Type 3 = regex denylist (regex blacklist)

CLI DIFFERENCES:
    Pi-hole v5: pihole -w, pihole -b, pihole --regex, pihole --white-regex
    Pi-hole v6: pihole allow, pihole deny, pihole --regex, pihole --allow-regex
    (This script uses direct SQL for better performance and compatibility)

USAGE:
    ./updates_optimized.sh [command] [options]

COMMANDS:
    refresh             Update all script files from repository
    full-update         Complete system and Pi-hole update (default)
    allow-update        Update only allow/whitelist configurations
    block-regex-update  Update only regex block lists
    quick-update        Update Pi-hole configs without system upgrade
    purge-and-update    Clear all Pi-hole lists and rebuild from scratch
    help                Show this help message

OPTIONS:
    --verbose       Enable verbose logging
    --debug         Enable debug mode (includes verbose + detailed error tracking)
    --no-reboot     Skip automatic reboot check

FEATURES:
    - Automatic cleanup of /scripts/temp/* on exit (normal or error)
    - Validates Pi-hole installation before making changes
    - Validates configuration files exist and are readable
    - Verifies database operations completed successfully
    - Comprehensive error tracking and summary
    - Supports both Pi-hole v5 and v6

CONFIGURATION FILES (in /scripts/Finished/CONFIG/):
    type.conf       - Type of configuration (security, full, standard)
    test.conf       - Whether this is a test system (yes/no)
    dns_type.conf   - DNS type (cloudflared, standard)
    ver.conf        - Pi-hole version (5 or 6) - REQUIRED

EXAMPLES:
    # Full update (default behavior)
    ./updates_optimized.sh full-update

    # Update only allow lists
    ./updates_optimized.sh allow-update

    # Update only block regex lists
    ./updates_optimized.sh block-regex-update

    # Purge all lists and rebuild (use when lists are corrupted)
    ./updates_optimized.sh purge-and-update

    # Refresh scripts with verbose output
    ./updates_optimized.sh refresh --verbose

    # Full update with debug logging
    ./updates_optimized.sh full-update --debug

CRON EXAMPLES:
    # Daily full update at 3 AM
    0 3 * * * /scripts/Finished/updates_optimized.sh full-update >> /var/log/pihole-cron.log 2>&1

    # Update allow lists every 6 hours
    0 */6 * * * /scripts/Finished/updates_optimized.sh allow-update

    # Update block regex lists every 4 hours
    0 */4 * * * /scripts/Finished/updates_optimized.sh block-regex-update

    # Refresh scripts weekly on Sunday at 2 AM
    0 2 * * 0 /scripts/Finished/updates_optimized.sh refresh

    # Quick update twice daily
    0 8,20 * * * /scripts/Finished/updates_optimized.sh quick-update

    # Monthly purge and rebuild (first Sunday at 4 AM)
    0 4 1-7 * 0 /scripts/Finished/updates_optimized.sh purge-and-update

TROUBLESHOOTING:
    - Run with --debug flag for detailed diagnostics
    - Check /var/log/pihole-updates.log for error details
    - Verify Pi-hole installation: pihole -v
    - Verify GPG keys: gpg --list-keys
    - Check database: sqlite3 /etc/pihole/gravity.db ".tables"
    - Verify temp cleanup: ls -la /scripts/temp/

NOTES:
    - Automatically detects Pi-hole version from ver.conf
    - All database updates are handled via direct SQL for performance
    - Temp files are always cleaned up, even on errors or interrupts
    - Logs to /var/log/pihole-updates.log

EOF
}

#======================================================================================
# MAIN EXECUTION
#======================================================================================

main() {
    # Parse options
    local command="${1:-full-update}"
    shift || true
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --verbose)
                VERBOSE=1
                log "Verbose mode enabled"
                ;;
            --debug)
                DEBUG=1
                VERBOSE=1
                log "Debug mode enabled (includes verbose)"
                ;;
            --no-reboot)
                NO_REBOOT=1
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done
    
    # Handle help command early (before any validation)
    if [[ "$command" == "help" ]] || [[ "$command" == "--help" ]] || [[ "$command" == "-h" ]]; then
        show_help
        exit 0
    fi
    
    log "============================================"
    log "Pi-hole Update Script - Starting"
    log "Command: $command"
    log "============================================"
    
    # Validate directories first (creates TEMPDIR if needed)
    validate_directories || {
        log_error "Directory validation failed, cannot proceed"
        show_error_summary
        exit 1
    }
    
    # Validate and load configuration
    validate_config_files || {
        log_error "Configuration validation failed, cannot proceed"
        show_error_summary
        exit 1
    }
    
    load_configuration || {
        log_error "Configuration loading failed, cannot proceed"
        show_error_summary
        exit 1
    }
    
    log "Loaded configuration:"
    log "  Pi-hole version: $version"
    log "  Type: $Type"
    log "  Test system: $test_system"
    log "  DNS type: $is_cloudflared"
    
    # Check network connectivity if downloading
    check_network || {
        log_error "Network check failed, cannot proceed with $command"
        show_error_summary
        exit 1
    }
    
    # Validate Pi-hole installation
    validate_pihole_installation || {
        log_error "Pi-hole validation failed"
        show_error_summary
        exit 1
    }
    
    # Check GPG configuration for commands that need decryption
    if [[ "$command" == "full-update" ]] || [[ "$command" == "quick-update" ]] || \
       [[ "$command" == "purge-and-update" ]] || [[ "$command" == "allow-update" ]]; then
        check_gpg_keys || {
            log_warning "GPG check failed - encrypted files may not decrypt properly"
            log_warning "Continuing anyway, but encrypted downloads may fail"
        }
    fi
    
    # Execute command
    local exit_code=0
    case "$command" in
        refresh)
            cmd_refresh || exit_code=$?
            ;;
        full-update)
            cmd_full_update || exit_code=$?
            ;;
        allow-update)
            cmd_allow_update || exit_code=$?
            ;;
        block-regex-update)
            cmd_block_regex_update || exit_code=$?
            ;;
        quick-update)
            cmd_quick_update || exit_code=$?
            ;;
        purge-and-update)
            cmd_purge_and_update || exit_code=$?
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
    
    # Note: cleanup_temp will be called automatically by the EXIT trap
    # but we explicitly run cleanup here for the standard non-error path
    # The trap will handle error/interrupt cases
    
    exit $exit_code
}

# Run main function with all arguments
main "$@"
