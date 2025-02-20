## Last Updated 2025-02-20
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
version=$(<"$CONFIG/ver.conf")

# Clears the existing adlist database
sqlite3 "/etc/pihole/gravity.db" "DELETE FROM adlist"

# Purge existing regex list
pihole --regex --nuke

# Purge existing wildcard deny list
pihole --wild --nuke


	if [ $version = "5" ]
		then
			# Purge existing allow list
			pihole -w --nuke

			# Purge existing allow list regex
			pihole --white-regex --nuke

			# Purge existing deny list
			pihole -b --nuke
			
			# Purge existing wildcard allow list
			pihole --white-wild --nuke

	fi


	if [ $version = "6" ]
		then
			# Purge existing allow list
			pihole allow --nuke

			# Purge existing allow list regex
			pihole --allow-regex --nuke

			# Purge existing deny list
			pihole deny --nuke
			
			# Purge existing wildcard allow list
			pihole --allow-wild --nuke

	fi



bash $FINISHED/updates.sh