## Last Updated 21 Sep 2021
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

# Clears the existing adlist database
sqlite3 "/etc/pihole/gravity.db" "DELETE FROM adlist"

# Purge existing regex list
pihole --regex --nuke

# Purge existing allow list
pihole -w --nuke

# Purge existing allow list regex
pihole --white-regex --nuke

# Purge existing deny list
pihole -b --nuke

# Purge existing wildcard deny list
pihole --wild --nuke

# Purge existing wildcard allow list
pihole --white-wild --nuke

bash $FINISHED/updates.sh