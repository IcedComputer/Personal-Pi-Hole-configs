## Last Updated 2024-08-14
## DB_Updates.sh
## This script is designed to keep the pihole updated and linked to any changes made
##

#!/bin/bash

#Vars
FINISHED=/scripts/Finished
CONFIG=/scripts/Finished/CONFIG
TEMPDIR=/scripts/temp
PIDIR=/etc/pihole
A='"'

function adlist()
{
# Clears the existing adlist database
sqlite3 "/etc/pihole/gravity.db" "DELETE FROM adlist"

# Preps the adlist
cat $PIDIR/adlists.list | grep -v '#' | grep "/" | sort | uniq > $TEMPDIR/formatted_adlist.temp

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

 echo "********************************************"
 echo "********************************************"
 echo Starting Regex
 echo "********************************************"
 echo "********************************************"
 
#adds regex from following file
file3=$PIDIR/regex.list
while read -r regex; do
	pihole --regex -nr $regex
	wait
done < $file3

 echo "********************************************"
 echo "********************************************"
 echo Ending Regex
 echo "********************************************"
 echo "********************************************"
}

function allow()
{
 echo "********************************************"
 echo "********************************************"
 echo Start Allow List
 echo "********************************************"
 echo "********************************************"
 
 #adds allow list from following file
file1=$PIDIR/whitelist.txt


while read allow; do
	pihole -w -nr $allow
	wait
done < $file1

 echo "********************************************"
 echo "********************************************"
 echo End Allow List
 echo "********************************************"
 echo "********************************************"
}

function allow_regex()
{
 echo "********************************************"
 echo "********************************************"
 echo Start Allow Regex
 echo "********************************************"
 echo "********************************************"
 
#adds allow list from following file
file2=$TEMPDIR/final.allow.regex.temp

while read -r WLallow; do
	pihole --white-regex -nr $WLallow
	wait
done < $file2

 echo "********************************************"
 echo "********************************************"
 echo End Allow List
 echo "********************************************"
 echo "********************************************"
}

function cleanup()
{
pihole restartdns
}

## Main Program
allow
adlist
regex
allow_regex
cleanup