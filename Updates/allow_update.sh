## Last Updated 2025-10-06
## allow_updates.sh
## A smaller launcher to update the allow list manually
##



#!/bin/bash

#Vars
FINISHED=/scripts/Finished
TEMPDIR=/scripts/temp
PIDIR=/etc/pihole
CONFIG=/scripts/Finished/CONFIG
Type=$(<"$CONFIG/type.conf")
test_system=$(<"$CONFIG/test.conf") 
is_cloudflared=$(<"$CONFIG/dns_type.conf")
version=$(<"$CONFIG/ver.conf")


function base()
{
	 apt-get update && apt-get dist-upgrade -y
	 wait
	 apt autoremove -y
	 wait
}
	 
function public_allowlist()
{
	##Get allowlist
	#Public
	curl --tlsv1.3 -o $TEMPDIR/basic.allow.temp 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Allow%20Lists/basic.allow'
	chmod 777 $TEMPDIR/basic.allow.temp
	echo " " >> $TEMPDIR/basic.allow.temp
	wait
	curl --tlsv1.3 -o $TEMPDIR/adlist.allow.temp 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Allow%20Lists/adlist.allow'
	chmod 777 $TEMPDIR/basic.allow.temp
	echo " " >> $TEMPDIR/adlist.allow.temp

	## Local Allow List from On System
	cp $CONFIG/perm_allow.conf $TEMPDIR/perm.allow.temp
	
	
}

function security_allowlist()
{
	##Get Whitelists
	#Public
	curl --tlsv1.3 -o $TEMPDIR/security_only.allow.temp 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Allow%20Lists/security_only.allow'

}

function encrypted_allowlist()
{

	wget -O $TEMPDIR/encrypt.allow.temp.gpg 'https://github.com/IcedComputer/Personal-Pi-Hole-configs/raw/master/Allow%20Lists/encrypt.allow.gpg'
	gpg $TEMPDIR/encrypt.allow.temp.gpg
	wait
	sed -i -e "s/\r//g" $TEMPDIR/encrypt.allow.temp
	
	wget -O $TEMPDIR/civic.allow.temp.gpg 'https://github.com/IcedComputer/Personal-Pi-Hole-configs/raw/master/Allow%20Lists/civic.allow.gpg'
	gpg $TEMPDIR/civic.allow.temp.gpg
	wait
	sed -i -e "s/\r//g" $TEMPDIR/civic.allow.temp
	
	wget -O $TEMPDIR/financial.allow.temp.gpg 'https://github.com/IcedComputer/Personal-Pi-Hole-configs/raw/master/Allow%20Lists/financial.allow.gpg'
	gpg $TEMPDIR/financial.allow.temp.gpg
	wait
	sed -i -e "s/\r//g" $TEMPDIR/financial.allow.temp

	wget -O $TEMPDIR/international.allow.temp.gpg 'https://github.com/IcedComputer/Personal-Pi-Hole-configs/raw/master/Allow%20Lists/international.allow.gpg'
	gpg $TEMPDIR/international.allow.temp.gpg
	wait
	sed -i -e "s/\r//g" $TEMPDIR/international.allow.temp
	
	wget -O $TEMPDIR/medical.allow.temp.gpg 'https://github.com/IcedComputer/Personal-Pi-Hole-configs/raw/master/Allow%20Lists/medical.allow.gpg'
	gpg $TEMPDIR/medical.allow.temp.gpg
	wait
	sed -i -e "s/\r//g" $TEMPDIR/medical.allow.temp
	
	wget -O $TEMPDIR/tech.allow.temp.gpg 'https://github.com/IcedComputer/Personal-Pi-Hole-configs/raw/master/Allow%20Lists/tech.allow.gpg'
	gpg $TEMPDIR/tech.allow.temp.gpg
	wait
	sed -i -e "s/\r//g" $TEMPDIR/tech.allow.temp
}

function regex_allowlist()
{

	curl --tlsv1.3 -o $TEMPDIR/regex.allow.regex.temp 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Allow%20Lists/regex.allow'
	cp $CONFIG/allow_wild.conf $TEMPDIR/allow_wild.allow.regex.temp
}

function encrypted_regex_allowlist()
{

	wget -O $TEMPDIR/encrypt.regex.allow.regex.temp.gpg 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Allow%20Lists/encrypt.regex.allow.gpg'
	gpg $TEMPDIR/encrypt.regex.allow.regex.temp.gpg
	wait
	sed -i -e "s/\r//g" $TEMPDIR/encrypt.regex.allow.regex.temp
	
}	 
	 
	 
function assemble()
{
	cat $TEMPDIR/*.allow.regex.temp | grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' |sort | uniq > $TEMPDIR/final.allow.regex.temp
	cat $TEMPDIR/*.allow.temp | grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | sort | uniq > $TEMPDIR/final.allow.temp
	
	mv $TEMPDIR/final.allow.temp $PIDIR/whitelist.txt

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

function allow_regex_v5()
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

function allow_regex_v6()
{
 Start_Banner
 bash -c 'echo -e "\033[1;32mStarting Allow Regex List\x1b[39m"'
 Start_Banner
 
#adds allow list from following file
file2=$TEMPDIR/final.allow.regex.temp

while read -r WLallow; do
	pihole --allow-regex $WLallow
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
	pihole allow $allow
done < $file1

 End_Banner
 bash -c 'echo -e "\033[1;33mEnd Allow List\x1b[39m"'
 End_Banner
  sleep 2
}
	 

function clean()
{
 rm -f $TEMPDIR/*.regex
 rm -f $TEMPDIR/*.temp
 rm -f $TEMPDIR/*.gpg
 
 pihole restartdns
 
 if [ $is_cloudflared = "cloudflared" ]
	then
		sudo systemctl restart cloudflared
	fi
}

## Main script
base
public_allowlist
security_allowlist
encrypted_allowlist
regex_allowlist
encrypted_regex_allowlist
assemble


if [ $Type = "security" ]
	then
		security_allowlist
		
	fi	

if [ $version = "5" ];
	then
			allow_v5
			allow_regex_v5

	fi
	
if [ $version = "6" ];
	then
			allow_v6
			allow_regex_v6

	fi	
	
	
clean	