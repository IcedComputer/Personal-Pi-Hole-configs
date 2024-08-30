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

function Start_Banner()
{
## Prints Green
 bash -c 'echo -e "\033[0;32m********************************************\x1b[39m"'
 bash -c 'echo -e "\033[0;32m********************************************\x1b[39m"'
 bash -c 'echo -e "\033[0;32m********************************************\x1b[39m"'
 bash -c 'echo -e "\033[0;32m********************************************\x1b[39m"'

}

function End_Banner()
{
## Prints Red
 bash -c 'echo -e "\033[0;31m********************************************\x1b[39m"'
 bash -c 'echo -e "\033[0;31m********************************************\x1b[39m"'
 bash -c 'echo -e "\\033[0;31m********************************************\x1b[39m"'
 bash -c 'echo -e "\\033[0;31m********************************************\x1b[39m"'

}

function regex()
{

 Start_Banner
 bash -c 'echo -e "\033[1;32mStarting Regex Block List\x1b[39m"'
 Start_Banner
 
#adds regex from following file
file3=$PIDIR/regex.list
while read -r regex; do
	pihole --regex -nr $regex
	wait
done < $file3

 End_Banner
 bash -c 'echo -e "\033[1;33mEnding Regex Block List\x1b[39m"'
 End_Banner
}

function allow()
{
 Start_Banner
 echo Start Allow List
 Start_Banner

 
 #adds allow list from following file
file1=$PIDIR/whitelist.txt


while read allow; do
	pihole -w -nr $allow
	wait
done < $file1

 End_Banner
 echo End Allow List
 End_Banner
}

function allow_regex()
{
 Start_Banner
 echo Start Allow Regex
 Start_Banner
 
#adds allow list from following file
file2=$TEMPDIR/final.allow.regex.temp

while read -r WLallow; do
	pihole --white-regex -nr $WLallow
	wait
done < $file2

 End_Banner
 echo End Allow List
 End_Banner
}

function cleanup()
{
pihole restartdns
}

## Main Program
allow
adlist
allow_regex
regex
cleanup