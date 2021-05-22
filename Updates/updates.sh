## Last Updated 12 May 2021
## updates.sh
## This script is designed to keep the pihole updated and linked to any changes made
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
is_v5=$(<"$CONFIG/ver.conf")

#Some basic functions including updating the box & getting new configuration files
function base()
{
	 apt-get update && apt-get dist-upgrade -y
	 wait
	 apt autoremove -y
	 wait
	 
	 download new cloudflared configs
	curl --tlsv1.2 -o $TEMPDIR/CFconfig 'https://raw.githubusercontent.com/IcedComputer/Azure-Pihole-VPN-setup/master/Configuration%20Files/CFconfig'
		
	#download a new refresh.sh
	curl --tlsv1.2 -o $TEMPDIR/refresh.sh 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Updates/refresh.sh'
	
	#refresh.sh
	chmod 777 $TEMPDIR/refresh.sh
}

function full()
{

	#adlists.list 
	curl --tlsv1.2 -o $TEMPDIR/adlists.list 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/adlists/main.adlist.list'

	# Regex Lists
	curl --tlsv1.2 -o $TEMPDIR/main.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/main.regex'
	wait
	curl --tlsv1.2 -o $TEMPDIR/country.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/country.regex'
	wait
	curl --tlsv1.2 -o $TEMPDIR/oTLD.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/oTLD.regex'
	wait
	curl --tlsv1.2 -o $TEMPDIR/uslocal.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/uslocal.regex'
	wait

}

function security()
{

	#adlists.list 
	curl --tlsv1.2 -o $TEMPDIR/adlists.list 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/adlists/security_basic_adlist.list'

	# Regex Lists
	curl --tlsv1.2 -o $TEMPDIR/basic_security.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/basic)security.regex'
	wait
	curl --tlsv1.2 -o $TEMPDIR/basic_country.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/basic_country.regex'
	wait
	curl --tlsv1.2 -o $TEMPDIR/oTLD.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/oTLD.regex'
	wait

}

function test_list()
{

echo "******This is test server********"
 curl --tlsv1.2 -o $TEMPDIR/adlists.list.trial.temp 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/adlists/trial.adlist.list'
 cat $TEMPDIR/adlists.list.trial.temp $TEMPDIR/adlists.list | grep -v "##" | sort | uniq > $TEMPDIR/adlists.list.temp
 mv $TEMPDIR/adlists.list.temp $TEMPDIR/adlists.list
 
 curl --tlsv1.2 -o $TEMPDIR/test.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/test.regex'
}

function scripts()
{
 killall -SIGHUP pihole-FTL
 wait
 pihole -g
}

function public_allowlist()
{
	##Get allowlist
	#Public
	curl --tlsv1.2 -o $TEMPDIR/basic.allow.temp 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Allow%20Lists/basic.allow'
	echo " " >> $TEMPDIR/basic.allow.temp
	wait
	curl --tlsv1.2 -o $TEMPDIR/adlist.allow.temp 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Allow%20Lists/adlist.allow'
	#On System
	cp $PIDIR/whitelist.txt $TEMPDIR/current.allow.temp
	echo " " >> $TEMPDIR/current.allow.temp
	
}

function security_allowlist()
{
	##Get Whitelists
	#Public
	curl --tlsv1.2 -o $TEMPDIR/security_only.allow.temp 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Allow%20Lists/security_only.allow'
}

#function encrypted_allowlist()
#{

	#curl --tlsv1.2 -o $TEMPDIR/encrypt.allow.temp.gpg 'https://github.com/IcedComputer/Personal-Pi-Hole-configs/raw/master/Allow%20Lists/encrypt.allow.gpg'
	
	#gpg $TEMPDIR/encrypt.allow.temp.gpg
#}

function assemble()
{
	cat $TEMPDIR/*.allow.temp  | sort | uniq > $TEMPDIR/final.allow.temp
	cat $TEMPDIR/*.regex | grep -v '#' |sort | uniq > $TEMPDIR/regex.list
	mv $TEMPDIR/regex.list  $PIDIR/regex.list
	mv $TEMPDIR/final.allow.temp $PIDIR/whitelist.txt
	mv $TEMPDIR/adlists.list $PIDIR/adlists.list
	mv $TEMPDIR/CFconfig $FINISHED/cloudflared
	mv $TEMPDIR/refresh.sh $FINISHED/refresh.sh
	
	
	if [ $is_v5 = "yes" ]
		then
			sudo bash $FINISHED/DB_Updates.sh
	fi
	

}

#cleanup
function clean()
{
 rm -f $TEMPDIR/*.regex
 rm -f $TEMPDIR/*.temp
 rm -f $TEMPDIR/*.gpg
 
 if [ $is_cloudflared = "cloudflared" ]
	then
		sudo systemctl restart cloudflared
 fi
}


## Main Script
base

if [ $Type = "security" ]
	then
		security
		security_allowlist
	else
		full
		if [ $test_system = "yes" ]
			then
				test_list

		fi
fi


public_allowlist
#encrypted_allowlist
assemble
scripts
clean