## Last Updated 2025-03-19
## purge.sh
## This script is designed to keep the pihole updated and linked to any changes made.
## This script should be run once to purge existing DB entries so they can be freshly reloaded from scratch.
## Automatically kicks off update at the end
##

#!/bin/bash

#Vars
FINISHED=/scripts/Finished
TEMPDIR=/scripts/temp
PIDIR=/etc/pihole
CONFIG=/scripts/Finished/CONFIG
version=$(<"$CONFIG/ver.conf")
DATABASE="/etc/pihole/gravity.db"

# Clears the existing adlist database
sqlite3 "/etc/pihole/gravity.db" "DELETE FROM adlist"


	if [ $version = "5" ];
		then
			# Purge existing regex list
			pihole --regex --nuke

			# Purge existing wildcard deny list
			pihole --wild --nuke

			# Purge existing allow list
			pihole -w --nuke

			# Purge existing allow list regex
			pihole --white-regex --nuke

			# Purge existing deny list
			pihole -b --nuke
			
			# Purge existing wildcard allow list
			pihole --white-wild --nuke
	fi


	if [ $version = "6" ];
		then
		# Run the SQLite query and save the results to the output file
sqlite3 $DATABASE <<EOF
.headers on
.mode column
DELETE FROM domainlist;


EOF

## Prints Red
 bash -c 'echo -e "\033[0;31m******All rows have been deleted from the domainlist table.*********\x1b[39m"'

	fi



bash $FINISHED/updates.sh