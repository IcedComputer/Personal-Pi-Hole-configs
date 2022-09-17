## Last Updated 27 July 2020
## security_updates.sh
## This script is designed to keep the pihole updated and linked to any changes made
## This version is for the security blocking functionality only
##



#!/bin/bash

#Vars
FINISHED=/scripts/Finished
TEMPDIR=/scripts/temp
PIDIR=/etc/pihole


#Based update and upgrade on the box
function base()
{
 apt-get update && apt-get dist-upgrade -y
 wait
 apt autoremove -y
 wait
}

#download files
function download()
{

	#adlists.list 
	curl -o $TEMPDIR/adlists.list 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/adlists/security_basic_adlist.list'

	# Regex Lists
	curl -o $TEMPDIR/basic_security.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/basic)security.regex'
	wait
	curl -o $TEMPDIR/basic_country.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/basic_country.regex'
	wait
	curl -o $TEMPDIR/oTLD.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/oTLD.regex'
	wait

	
		
	#download new cloudflared configs
	curl -o $TEMPDIR/CFconfig 'https://raw.githubusercontent.com/IcedComputer/Azure-Pihole-VPN-setup/master/Configuration%20Files/CFconfig'
	
	#download a new refresh.sh
	curl -o $TEMPDIR/security_refresh.sh 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Updates/security_refresh.sh'


}


function modify()
{
	## Create Regex 
	cat $TEMPDIR/basic_security.regex $TEMPDIR/basic_country.regex $TEMPDIR/oTLD.regex | grep -v '#' | sort | uniq > $TEMPDIR/regex.list
	wait
	
	#refresh.sh
	chmod 777 $TEMPDIR/security_refresh.sh
	
}


#move
function move()
{
	#adlists.list
	mv $TEMPDIR/adlists.list $PIDIR/adlists.list
	mv $TEMPDIR/regex.list  $PIDIR/regex.list
	mv $TEMPDIR/CFconfig $FINISHED/cloudflared
	mv $TEMPDIR/security_refresh.sh $FINISHED/security_refresh.sh
	
}


function scripts()
{
 killall -SIGHUP pihole-FTL
 wait
 pihole restartdns
 wait
 pihole -g
}


function allowlist()
{
	##Get Whitelists
	#Public
	curl -o $TEMPDIR/basic.allow.temp 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Allow%20Lists/basic.allow'
	wait
	curl -o $TEMPDIR/adlist.allow.temp 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Allow%20Lists/adlist.allow'
	wait
	curl -o $TEMPDIR/security_only.allow.temp 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Allow%20Lists/security_only.allow'
	
	#On System
	cp $PIDIR/whitelist.txt $TEMPDIR/current.allow.temp
	
	#Private
	#curl -o $TEMPDIR/encrypt_basic.allow.temp.gpg 'https://github.com/IcedComputer/Personal-Pi-Hole-configs/raw/master/Allow%20Lists/encrypt_basic.allow.gpg'
	
	#decrypt Private list
	#gpg $TEMPDIR/encrypt_basic.allow.temp.gpg

	##make whitelist
	#cat $TEMPDIR/current.wl.temp $TEMPDIR/basic.allow.temp $TEMPDIR/adlist.allow.temp $TEMPDIR/encrypt_basic.allow.temp $TEMPDIR/security_only.allow.temp | sort | uniq > $TEMPDIR/final.wl.temp
	cat $TEMPDIR/current.allow.temp $TEMPDIR/basic.allow.temp $TEMPDIR/adlist.allow.temp $TEMPDIR/security_only.allow.temp | sort | uniq > $TEMPDIR/final.allow.temp
	mv $TEMPDIR/final.allow.temp $PIDIR/whitelist.txt


}

#cleanup
function clean()
{
 rm -f $TEMPDIR/*.regex
 rm -f $TEMPDIR/*.temp
 rm -f $TEMPDIR/*.gpg
 sudo systemctl restart cloudflared
}

base
download
modify
move
allowlist
scripts
clean