## Last Updated 21 Sep 2021
## DB_Updates.sh
## This script is designed to keep the pihole updated and linked to any changes made
##

#!/bin/bash

#Vars
FINISHED=/scripts/Finished
TEMPDIR=/scripts/temp
PIDIR=/etc/pihole
A='"'

function adlist()
{
# Clears the existing adlist database
sqlite3 "/etc/pihole/gravity.db" "DELETE FROM adlist"

# Preps the adlist
cat $PIDIR/adlists.list | grep -v '#' | grep "http" | sort | uniq > $TEMPDIR/formatted_adlist.temp

# Inserts URLs into the adlist database
file=$TEMPDIR/formatted_adlist.temp
i=1
while read line; do
        sqlite3 "/etc/pihole/gravity.db" "INSERT INTO adlist (id, address, enabled) VALUES($i, $A$line$A, 1)"
        i=$((i+1))
done < $file
}

function regex()
{
# Purge existing regex list
#pihole --regex --nuke

#adds regex from following file
file3=$PIDIR/regex.list

while read -r regex; do
	pihole --regex -nr $regex
	wait
done < $file3
}

function allow()
{
# Purge existing allow list
#pihole -w --nuke

#adds allow list from following file
file1=$PIDIR/whitelist.txt

while read allow; do
	pihole -w -nr $allow
	wait
done < $file1
}

function allow_regex()
{
# Purge existing allow list
pihole --white-regex --nuke

#adds allow list from following file
file2=$TEMPDIR/WL_regex.list

while read -r WLallow; do
	pihole --white-regex -nr $WLallow
	wait
done < $file2
}

function cleanup()
{
pihole restartdns
}

## Main Program
allow
#allow_regex
adlist
regex
cleanup