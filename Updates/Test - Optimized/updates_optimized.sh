#!/bin/bash
## Last Updated 2025-12-05
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

# Load configuration files
Type=$(<"$CONFIG/type.conf")
test_system=$(<"$CONFIG/test.conf") 
is_cloudflared=$(<"$CONFIG/dns_type.conf")
version=$(<"$CONFIG/ver.conf")

# GitHub base URLs
readonly GH_RAW="https://raw.githubusercontent.com/IcedComputer"
readonly REPO_BASE="${GH_RAW}/Personal-Pi-Hole-configs/master"
readonly AZURE_REPO="${GH_RAW}/Azure-Pihole-VPN-setup/master"

# Options
VERBOSE=0
NO_REBOOT=0
DEBUG=0

#======================================================================================
# UTILITY FUNCTIONS
#======================================================================================

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
}

verbose_log() {
    [[ $VERBOSE -eq 1 ]] && log "$*"
}

debug_log() {
    if [[ $DEBUG -eq 1 ]]; then
        echo "[DEBUG $(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"
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
            debug_log "File size: $(stat -c%s "$output" 2>/dev/null || echo 'unknown') bytes"
            rm -f "$error_log"
            return 0
        fi
        
        local error_msg=$(cat "$error_log" 2>/dev/null || echo "Unknown error")
        log "Download attempt $i failed for: $url"
        log "Error details: $error_msg"
        debug_log "Waiting 3 seconds before retry..."
        sleep 3
    done
    
    log "ERROR: Failed to download after $retries attempts"
    log "ERROR: URL: $url"
    log "ERROR: Output: $output"
    if [[ -f "$error_log" ]]; then
        log "ERROR: $(cat "$error_log")"
        rm -f "$error_log"
    fi
    return 1
}

download_gpg_file() {
    local url="$1"
    local output_base="$2"
    local gpg_error="$TEMPDIR/gpg_error_$$.log"
    
    debug_log "Downloading GPG file: $url"
    download_file "$url" "${output_base}.gpg" || return 1
    
    debug_log "Decrypting: ${output_base}.gpg"
    if ! gpg --batch --yes --decrypt "${output_base}.gpg" > "$output_base" 2>"$gpg_error"; then
        log "ERROR: Failed to decrypt ${output_base}.gpg"
        if [[ -f "$gpg_error" ]]; then
            log "ERROR: GPG output: $(cat "$gpg_error")"
            rm -f "$gpg_error"
        fi
        return 1
    fi
    
    sed -i -e "s/\r//g" "$output_base"
    rm -f "${output_base}.gpg" "$gpg_error"
    verbose_log "Decrypted and cleaned: $output_base"
    debug_log "Final file size: $(stat -c%s "$output_base" 2>/dev/null || echo 'unknown') bytes"
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
            log "ERROR: Download failed for URL: $failed_url"
            log "ERROR: Expected output: $failed_output"
            ((failed++))
        fi
    done
    
    if [[ $failed -gt 0 ]]; then
        log "WARNING: $failed out of ${#urls[@]} downloads failed"
        return 1
    fi
    
    debug_log "All parallel downloads completed successfully"
    return 0
}

#======================================================================================
# DATABASE UPDATE FUNCTIONS - PI-HOLE VERSION 5
#======================================================================================

update_allow_regex_v5() {
    local file="$TEMPDIR/final.allow.regex.temp"
    
    [[ ! -f "$file" ]] && { log "No allow regex file found, skipping"; return 0; }
    
    print_banner green "Starting Allow Regex List (v5)"
    
    local count=0
    local temp_sql="$TEMPDIR/allow_regex_insert.sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        # Type 2 = regex whitelist, enabled = 1
        # Escape single quotes for SQL
        local escaped_pattern="${pattern//\'/\'\'}"
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled) VALUES (2, '${escaped_pattern}', 1);" >> "$temp_sql"
        ((count++))
        verbose_log "Queued allow regex: $pattern"
    done < "$file"
    
    echo "COMMIT;" >> "$temp_sql"
    
    sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>/dev/null || {
        log "ERROR: Failed to insert allow regex"
        return 1
    }
    
    rm -f "$temp_sql"
    log "Added $count allow regex patterns via direct SQL (fast)"
    print_banner yellow "Completed Allow Regex List"
}

update_allow_v5() {
    local file="$PIDIR/whitelist.txt"
    
    [[ ! -f "$file" ]] && { log "No whitelist file found, skipping"; return 0; }
    
    print_banner green "Starting Allow List (v5)"
    
    # Use direct SQL INSERT for massive performance improvement
    # This is 50-100x faster than calling pihole -w for each domain
    local count=0
    local temp_sql="$TEMPDIR/allow_insert.sql"
    
    # Start SQL transaction
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        # Type 0 = exact whitelist, enabled = 1
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled) VALUES (0, '${domain}', 1);" >> "$temp_sql"
        ((count++))
        verbose_log "Queued allow domain: $domain"
    done < "$file"
    
    echo "COMMIT;" >> "$temp_sql"
    
    # Execute all inserts in one transaction
    sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>/dev/null || {
        log "ERROR: Failed to insert allow list"
        return 1
    }
    
    rm -f "$temp_sql"
    log "Added $count allow domains via direct SQL (fast)"
    print_banner yellow "Completed Allow List"
}

update_regex_v5() {
    local file="$PIDIR/regex.list"
    
    [[ ! -f "$file" ]] && { log "No regex block file found, skipping"; return 0; }
    
    print_banner green "Starting Regex Block List (v5)"
    
    local count=0
    local temp_sql="$TEMPDIR/block_regex_insert.sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        # Type 3 = regex blacklist, enabled = 1
        local escaped_pattern="${pattern//\'/\'\'}"
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled) VALUES (3, '${escaped_pattern}', 1);" >> "$temp_sql"
        ((count++))
        verbose_log "Queued block regex: $pattern"
    done < "$file"
    
    echo "COMMIT;" >> "$temp_sql"
    
    sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>/dev/null || {
        log "ERROR: Failed to insert block regex"
        return 1
    }
    
    rm -f "$temp_sql"
    log "Added $count block regex patterns via direct SQL (fast)"
    print_banner yellow "Completed Regex Block List"
}

#======================================================================================
# DATABASE UPDATE FUNCTIONS - PI-HOLE VERSION 6
#======================================================================================

update_allow_regex_v6() {
    local file="$TEMPDIR/final.allow.regex.temp"
    
    [[ ! -f "$file" ]] && { log "No allow regex file found, skipping"; return 0; }
    
    print_banner green "Starting Allow Regex List (v6)"
    
    local count=0
    local temp_sql="$TEMPDIR/allow_regex_insert.sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        # Type 2 = regex whitelist, enabled = 1
        local escaped_pattern="${pattern//\'/\'\'}"
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled) VALUES (2, '${escaped_pattern}', 1);" >> "$temp_sql"
        ((count++))
        verbose_log "Queued allow regex: $pattern"
    done < "$file"
    
    echo "COMMIT;" >> "$temp_sql"
    
    sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>/dev/null || {
        log "ERROR: Failed to insert allow regex"
        return 1
    }
    
    rm -f "$temp_sql"
    log "Added $count allow regex patterns via direct SQL (fast)"
    print_banner yellow "Completed Allow Regex List"
}

update_allow_v6() {
    local file="$PIDIR/whitelist.txt"
    
    [[ ! -f "$file" ]] && { log "No whitelist file found, skipping"; return 0; }
    
    print_banner green "Starting Allow List (v6)"
    
    # Use direct SQL INSERT for massive performance improvement
    local count=0
    local temp_sql="$TEMPDIR/allow_insert.sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        # Type 0 = exact whitelist, enabled = 1
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled) VALUES (0, '${domain}', 1);" >> "$temp_sql"
        ((count++))
        verbose_log "Queued allow domain: $domain"
    done < "$file"
    
    echo "COMMIT;" >> "$temp_sql"
    
    sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>/dev/null || {
        log "ERROR: Failed to insert allow list"
        return 1
    }
    
    rm -f "$temp_sql"
    log "Added $count allow domains via direct SQL (fast)"
    print_banner yellow "Completed Allow List"
}

update_regex_v6() {
    local file="$PIDIR/regex.list"
    
    [[ ! -f "$file" ]] && { log "No regex block file found, skipping"; return 0; }
    
    print_banner green "Starting Regex Block List (v6)"
    
    local count=0
    local temp_sql="$TEMPDIR/block_regex_insert.sql"
    
    echo "BEGIN TRANSACTION;" > "$temp_sql"
    
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        # Type 3 = regex blacklist, enabled = 1
        local escaped_pattern="${pattern//\'/\'\'}"
        echo "INSERT OR IGNORE INTO domainlist (type, domain, enabled) VALUES (3, '${escaped_pattern}', 1);" >> "$temp_sql"
        ((count++))
        verbose_log "Queued block regex: $pattern"
    done < "$file"
    
    echo "COMMIT;" >> "$temp_sql"
    
    sqlite3 "$GRAVITY_DB" < "$temp_sql" 2>/dev/null || {
        log "ERROR: Failed to insert block regex"
        return 1
    }
    
    rm -f "$temp_sql"
    log "Added $count block regex patterns via direct SQL (fast)"
    print_banner yellow "Completed Regex Block List"
}

#======================================================================================
# DATABASE UPDATE FUNCTIONS - VERSION INDEPENDENT
#======================================================================================

update_adlists() {
    local file="$PIDIR/adlists.list"
    
    [[ ! -f "$file" ]] && { log "No adlists file found, skipping"; return 0; }
    
    print_banner green "Starting Adlist Database Update"
    
    # Clear existing adlist database
    sqlite3 "$GRAVITY_DB" "DELETE FROM adlist" 2>/dev/null || {
        log "ERROR: Failed to clear adlist database"
        return 1
    }
    
    # Format and prepare adlist
    grep -v '#' "$file" | grep "/" | sort | uniq > "$TEMPDIR/formatted_adlist.temp" || {
        log "WARNING: No valid adlists found"
        return 0
    }
    
    # Insert URLs into database
    local count=0
    local id=1
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        sqlite3 "$GRAVITY_DB" "INSERT INTO adlist (id, address, enabled) VALUES($id, '$url', 1)" 2>/dev/null || {
            log "WARNING: Failed to insert adlist: $url"
            continue
        }
        ((count++))
        ((id++))
        verbose_log "Added adlist: $url"
    done < "$TEMPDIR/formatted_adlist.temp"
    
    log "Added $count adlists to database"
    print_banner yellow "Completed Adlist Database Update"
}

#======================================================================================
# DATABASE UPDATE DISPATCHER FUNCTIONS
#======================================================================================

update_allow() {
    log "Updating allow lists..."
    case "$version" in
        5) update_allow_v5 ;;
        6) update_allow_v6 ;;
        *) log "ERROR: Unknown Pi-hole version: $version"; return 1 ;;
    esac
}

update_allow_regex() {
    log "Updating allow regex..."
    case "$version" in
        5) update_allow_regex_v5 ;;
        6) update_allow_regex_v6 ;;
        *) log "ERROR: Unknown Pi-hole version: $version"; return 1 ;;
    esac
}

update_block_regex() {
    log "Updating block regex..."
    case "$version" in
        5) update_regex_v5 ;;
        6) update_regex_v6 ;;
        *) log "ERROR: Unknown Pi-hole version: $version"; return 1 ;;
    esac
}

#======================================================================================
# DATABASE UPDATE WRAPPER FUNCTIONS
#======================================================================================

update_pihole_database() {
    log "=== Starting full database update ==="
    log "Pi-hole version: $version"
    
    update_allow
    update_allow_regex
    update_adlists
    update_block_regex
    
    log "=== Full database update completed ==="
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
    
    local downloads=(
        "${AZURE_REPO}/Configuration%20Files/CFconfig|$TEMPDIR/CFconfig"
        "${REPO_BASE}/Updates/refresh.sh|$TEMPDIR/refresh.sh"
        "${REPO_BASE}/Updates/updates.sh|$TEMPDIR/updates.sh"
        "${REPO_BASE}/Updates/configuration_changes.sh|$TEMPDIR/configuration_changes.sh"
        "${REPO_BASE}/Updates/Research.sh|$TEMPDIR/Research.sh"
        "${REPO_BASE}/Updates/allow_update.sh|$TEMPDIR/allow_update.sh"
    )
    
    parallel_download downloads
    chmod 755 $TEMPDIR/*.sh 2>/dev/null || true
}

download_full_config() {
    log "Downloading full configuration..."
    
    # Download adlists
    download_file "${REPO_BASE}/adlists/main.adlist.list" "$TEMPDIR/adlists.list"
    
    # Download regex lists in parallel
    local regex_files=(
        "${REPO_BASE}/Regex%20Files/main.regex|$TEMPDIR/main.regex"
        "${REPO_BASE}/Regex%20Files/oTLD.regex|$TEMPDIR/oTLD.regex"
        "${REPO_BASE}/Regex%20Files/uslocal.regex|$TEMPDIR/uslocal.regex"
    )
    parallel_download regex_files
    
    # Clean line endings
    sed -i -e "s/\r//g" $TEMPDIR/*.regex 2>/dev/null || true
    
    # Download encrypted country regex
    download_gpg_file "${REPO_BASE}/Regex%20Files/country.regex.gpg" "$TEMPDIR/country.regex"
}

download_security_config() {
    log "Downloading security configuration..."
    
    download_file "${REPO_BASE}/adlists/security_basic_adlist.list" "$TEMPDIR/adlists.list"
    
    local security_files=(
        "${REPO_BASE}/Regex%20Files/basic_security.regex|$TEMPDIR/basic_security.regex"
        "${REPO_BASE}/Regex%20Files/oTLD.regex|$TEMPDIR/oTLD.regex"
    )
    parallel_download security_files
    
    sed -i -e "s/\r//g" $TEMPDIR/*.regex 2>/dev/null || true
    
    # Download encrypted files
    download_gpg_file "${REPO_BASE}/Regex%20Files/basic_country.regex.gpg" "$TEMPDIR/basic_country.regex"
    download_gpg_file "${REPO_BASE}/Regex%20Files/encrypted.regex.gpg" "$TEMPDIR/encrypted.regex"
}

download_test_lists() {
    [[ "$test_system" != "yes" ]] && return 0
    
    log "Downloading test lists..."
    download_file "${REPO_BASE}/adlists/trial.adlist.list" "$TEMPDIR/adlists.list.trial.temp"
    
    cat "$TEMPDIR/adlists.list.trial.temp" "$TEMPDIR/adlists.list" | \
        grep -v "##" | sort | uniq > "$TEMPDIR/adlists.list.temp"
    mv "$TEMPDIR/adlists.list.temp" "$TEMPDIR/adlists.list"
    
    download_file "${REPO_BASE}/Regex%20Files/test.regex" "$TEMPDIR/test.regex"
    download_gpg_file "${REPO_BASE}/Allow%20Lists/test.allow.gpg" "$TEMPDIR/test.allow.temp"
    download_gpg_file "${REPO_BASE}/Block_Lists/test.block.encrypt.gpg" "$TEMPDIR/test.block.encrypt.temp"
}

download_public_allowlists() {
    log "Downloading public allow lists..."
    
    local allow_files=(
        "${REPO_BASE}/Allow%20Lists/basic.allow|$TEMPDIR/basic.allow.temp"
        "${REPO_BASE}/Allow%20Lists/adlist.allow|$TEMPDIR/adlist.allow.temp"
    )
    parallel_download allow_files
    
    # Add newlines and copy local config
    echo " " >> "$TEMPDIR/basic.allow.temp"
    echo " " >> "$TEMPDIR/adlist.allow.temp"
    cp "$CONFIG/perm_allow.conf" "$TEMPDIR/perm.allow.temp" 2>/dev/null || true
}

download_security_allowlists() {
    log "Downloading security allow lists..."
    download_file "${REPO_BASE}/Allow%20Lists/security_only.allow" "$TEMPDIR/security_only.allow.temp"
}

download_encrypted_allowlists() {
    log "Downloading encrypted allow lists..."
    
    local encrypted_lists=(
        encrypt financial civic international medical tech
    )
    
    for list in "${encrypted_lists[@]}"; do
        download_gpg_file "${REPO_BASE}/Allow%20Lists/${list}.allow.gpg" "$TEMPDIR/${list}.allow.temp" &
    done
    wait
}

download_regex_allowlists() {
    log "Downloading regex allow lists..."
    
    download_file "${REPO_BASE}/Allow%20Lists/regex.allow" "$TEMPDIR/regex.allow.regex.temp"
    cp "$CONFIG/allow_wild.conf" "$TEMPDIR/allow_wild.allow.regex.temp" 2>/dev/null || true
    
    download_gpg_file "${REPO_BASE}/Allow%20Lists/encrypt.regex.allow.gpg" "$TEMPDIR/encrypt.regex.allow.regex.temp"
}

download_encrypted_blocklists() {
    log "Downloading encrypted block lists..."
    
    local block_lists=(
        custom propaganda spam media
    )
    
    for list in "${block_lists[@]}"; do
        download_gpg_file "${REPO_BASE}/Block_Lists/${list}.block.encrypt.gpg" "$TEMPDIR/${list}.block.encrypt.temp" &
    done
    wait
}

assemble_and_deploy() {
    log "Assembling and deploying configurations..."
    
    # Assemble final files
    cat $TEMPDIR/*.allow.regex.temp 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/final.allow.regex.temp"
    
    cat $TEMPDIR/*.allow.temp 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/final.allow.temp"
    
    cat $TEMPDIR/*.regex 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/regex.list"
    
    cat $TEMPDIR/*.block.encrypt.temp 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$CONFIG/encrypt.list"
    
    # Deploy files
    mv "$TEMPDIR/regex.list" "$PIDIR/regex.list"
    mv "$TEMPDIR/final.allow.temp" "$PIDIR/whitelist.txt"
    mv "$TEMPDIR/adlists.list" "$PIDIR/adlists.list"
    
    [[ -f "$TEMPDIR/CFconfig" ]] && mv "$TEMPDIR/CFconfig" "$FINISHED/cloudflared"
    [[ -f "$TEMPDIR/refresh.sh" ]] && mv "$TEMPDIR/refresh.sh" "$FINISHED/refresh.sh"
    
    # Update database directly (integrated functionality)
    update_pihole_database
}

assemble_and_deploy_regex_only() {
    log "Assembling and deploying regex configurations..."
    
    # Assemble only regex block lists
    cat $TEMPDIR/*.regex 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/regex.list"
    
    # Deploy regex file
    mv "$TEMPDIR/regex.list" "$PIDIR/regex.list"
    
    # Update database with regex only (integrated functionality)
    update_pihole_database_regex_only
}

restart_services() {
    log "Restarting Pi-hole services..."
    
    killall -SIGHUP pihole-FTL 2>/dev/null || true
    pihole restartdns
    pihole -g
    
    if [[ "$is_cloudflared" == "cloudflared" ]]; then
        systemctl restart cloudflared
        log "Cloudflared restarted"
    fi
}

cleanup() {
    log "Cleaning up temporary files..."
    rm -f $TEMPDIR/*.regex $TEMPDIR/*.temp $TEMPDIR/*.gpg 2>/dev/null || true
}

purge_database() {
    log "Purging Pi-hole database..."
    
    # Clear adlists
    sqlite3 "$GRAVITY_DB" "DELETE FROM adlist" 2>/dev/null || {
        log "ERROR: Failed to clear adlist table"
        return 1
    }
    log "Cleared adlist table"
    
    if [[ "$version" == "5" ]]; then
        log "Purging Pi-hole v5 lists..."
        
        # Purge existing regex list
        pihole --regex --nuke 2>/dev/null || log "WARNING: Failed to nuke regex list"
        
        # Purge existing wildcard deny list
        pihole --wild --nuke 2>/dev/null || log "WARNING: Failed to nuke wildcard deny list"
        
        # Purge existing allow list
        pihole -w --nuke 2>/dev/null || log "WARNING: Failed to nuke allow list"
        
        # Purge existing allow list regex
        pihole --white-regex --nuke 2>/dev/null || log "WARNING: Failed to nuke allow regex"
        
        # Purge existing deny list
        pihole -b --nuke 2>/dev/null || log "WARNING: Failed to nuke deny list"
        
        # Purge existing wildcard allow list
        pihole --white-wild --nuke 2>/dev/null || log "WARNING: Failed to nuke wildcard allow"
        
        log "Pi-hole v5 database purged"
        
    elif [[ "$version" == "6" ]]; then
        log "Purging Pi-hole v6 lists..."
        
        # Clear domainlist table
        sqlite3 "$GRAVITY_DB" "DELETE FROM domainlist;" 2>/dev/null || {
            log "ERROR: Failed to clear domainlist table"
            return 1
        }
        
        log "Pi-hole v6 database purged (domainlist table cleared)"
    else
        log "ERROR: Unknown Pi-hole version: $version"
        return 1
    fi
    
    log "Database purge completed successfully"
}

#======================================================================================
# COMMAND FUNCTIONS
#======================================================================================

cmd_refresh() {
    log "=== Starting script refresh ==="
    download_scripts
    
    # Move scripts to final location (note: db_updates_optimized.sh no longer needed)
    for script in updates.sh configuration_changes.sh Research.sh allow_update.sh; do
        if [[ -f "$TEMPDIR/$script" ]]; then
            chmod 755 "$TEMPDIR/$script"
            mv "$TEMPDIR/$script" "$FINISHED/$script"
            verbose_log "Installed: $script"
        fi
    done
    
    log "=== Script refresh completed ==="
}

cmd_full_update() {
    log "=== Starting full update ==="
    
    system_update
    download_scripts
    
    if [[ "$Type" == "security" ]]; then
        download_security_config
        download_security_allowlists
    else
        download_full_config
        download_test_lists
    fi
    
    download_public_allowlists
    download_regex_allowlists
    download_encrypted_allowlists
    download_encrypted_blocklists
    
    assemble_and_deploy
    restart_services
    cleanup
    
    log "=== Full update completed ==="
}

cmd_allow_update() {
    log "=== Starting allow list update ==="
    
    if [[ "$Type" == "security" ]]; then
        download_security_allowlists
    fi
    
    download_public_allowlists
    download_regex_allowlists
    download_encrypted_allowlists
    
    # Assemble allow lists
    cat $TEMPDIR/*.allow.regex.temp 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/final.allow.regex.temp"
    
    cat $TEMPDIR/*.allow.temp 2>/dev/null | \
        grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | \
        sort | uniq > "$TEMPDIR/final.allow.temp"
    
    # Deploy allow lists
    mv "$TEMPDIR/final.allow.temp" "$PIDIR/whitelist.txt"
    
    # Update database with allow lists only (integrated functionality)
    update_pihole_database_allow_only
    
    restart_services
    cleanup
    
    log "=== Allow list update completed ==="
}

cmd_quick_update() {
    log "=== Starting quick update (no system upgrade) ==="
    
    download_scripts
    
    if [[ "$Type" == "security" ]]; then
        download_security_config
        download_security_allowlists
    else
        download_full_config
        download_test_lists
    fi
    
    download_public_allowlists
    download_regex_allowlists
    download_encrypted_allowlists
    download_encrypted_blocklists
    
    assemble_and_deploy
    restart_services
    cleanup
    
    log "=== Quick update completed ==="
}

cmd_purge_and_update() {
    log "=== Starting purge and full update ==="
    log "WARNING: This will clear all existing Pi-hole lists and rebuild from scratch"
    
    # Purge existing database
    purge_database || {
        log "ERROR: Database purge failed, aborting update"
        return 1
    }
    
    # Run full update to repopulate
    log "Starting full update to repopulate database..."
    system_update
    download_scripts
    
    if [[ "$Type" == "security" ]]; then
        download_security_config
        download_security_allowlists
    else
        download_full_config
        download_test_lists
    fi
    
    download_public_allowlists
    download_regex_allowlists
    download_encrypted_allowlists
    download_encrypted_blocklists
    
    assemble_and_deploy
    restart_services
    cleanup
    
    log "=== Purge and full update completed ==="
}

cmd_block_regex_update() {
    log "=== Starting block regex update ==="
    
    if [[ "$Type" == "security" ]]; then
        download_security_config
    else
        download_full_config
        download_test_lists
    fi
    
    assemble_and_deploy_regex_only
    restart_services
    cleanup
    
    log "=== Block regex update completed ==="
}

show_help() {
    cat << 'EOF'
Pi-hole Update Script - Fully Integrated & Optimized Version

DESCRIPTION:
    Combines update/download functionality with database management in a single script.
    No separate database update script needed - all functionality is integrated.

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

NOTES:
    - Automatically detects Pi-hole version (5 or 6)
    - All database updates are handled internally
    - No external db_updates_optimized.sh script required
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
                log "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done
    
    # Create temp directory if needed
    mkdir -p "$TEMPDIR"
    
    # Check network connectivity if downloading
    if [[ "$command" != "help" ]] && [[ "$command" != "--help" ]] && [[ "$command" != "-h" ]]; then
        check_network || {
            log "ERROR: Network check failed, cannot proceed with $command"
            exit 1
        }
    fi
    
    # Execute command
    case "$command" in
        refresh)
            cmd_refresh
            ;;
        full-update)
            cmd_full_update
            ;;
        allow-update)
            cmd_allow_update
            ;;
        block-regex-update)
            cmd_block_regex_update
            ;;
        quick-update)
            cmd_quick_update
            ;;
        purge-and-update)
            cmd_purge_and_update
            ;;
        help|--help|-h)
            show_help
            exit 0
            ;;
        *)
            log "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
