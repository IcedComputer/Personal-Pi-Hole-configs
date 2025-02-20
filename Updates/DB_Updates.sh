## Last Updated 2025-02-20
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
version=$(<"$CONFIG/ver.conf")



## Banners


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


## Version 5



function allow_regex_5()
{
 Start_Banner
 bash -c 'echo -e "\033[1;32mStarting Allow Regex List\x1b[39m"'
 Start_Banner
 
#adds allow list from following file
file2=$TEMPDIR/final.allow.regex.temp

while read -r WLallow; do
	pihole --white-regex -nr $WLallow
	wait
done < $file2

 End_Banner
 bash -c 'echo -e "\033[1;33mEnd Allow Regex List\x1b[39m"'
 End_Banner
  sleep 2
}

function allow_v5()
{
 Start_Banner
 bash -c 'echo -e "\033[1;32mStarting Allow List\x1b[39m"'
 Start_Banner

 
 #adds allow list from following file
file1=$PIDIR/whitelist.txt


while read allow; do
	pihole -w -nr $allow
	wait
done < $file1

 End_Banner
 bash -c 'echo -e "\033[1;33mEnd Allow List\x1b[39m"'
 End_Banner
  sleep 2
}

## Version 6


function allow_regex_v6()
{
 Start_Banner
 bash -c 'echo -e "\033[1;32mStarting Allow Regex List\x1b[39m"'
 Start_Banner
 
#adds allow list from following file
file2=$TEMPDIR/final.allow.regex.temp

while read -r WLallow; do
	pihole --allow-regex -nr $WLallow
	wait
done < $file2

 End_Banner
 bash -c 'echo -e "\033[1;33mEnd Allow Regex List\x1b[39m"'
 End_Banner
  sleep 2
}

function allow_v6()
{
 Start_Banner
 bash -c 'echo -e "\033[1;32mStarting Allow List\x1b[39m"'
 Start_Banner

 
 #adds allow list from following file
file1=$PIDIR/whitelist.txt


while read allow; do
	pihole allow -nr $allow
	wait
done < $file1

 End_Banner
 bash -c 'echo -e "\033[1;33mEnd Allow List\x1b[39m"'
 End_Banner
  sleep 2
}


## Stays the Same in both versions

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
 sleep 2
}

function cleanup()
{
pihole restartdns
}







## Main Program


	if [ $version = "5" ]
		then
			allow_v5
			allow_regex_v5
			adlist
			regex
	fi
	
	if [ $version = "6" ]
		then
			allow_v6
			allow_regex_v6
			adlist
			regex
	fi	

cleanup