## Last Updated 2025-04-26
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
version=$(<"$CONFIG/ver.conf")

#Some basic functions including updating the box & getting new configuration files
function base()
{
	 apt-get update && apt-get dist-upgrade -y
	 wait
	 apt autoremove -y
	 wait
	 
	#download new cloudflared configs
	curl --tlsv1.3 -o $TEMPDIR/CFconfig 'https://raw.githubusercontent.com/IcedComputer/Azure-Pihole-VPN-setup/master/Configuration%20Files/CFconfig'
		
	#download a new refresh.sh
	curl --tlsv1.3 -o $TEMPDIR/refresh.sh 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Updates/refresh.sh'
	
	#refresh.sh
	chmod 777 $TEMPDIR/refresh.sh
}

function full()
{
	#adlists.list 
	curl --tlsv1.3 -o $TEMPDIR/adlists.list 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/adlists/main.adlist.list'

	# Regex Lists
	curl --tlsv1.3 -o $TEMPDIR/main.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/main.regex'
	sed -i -e "s/\r//g" $TEMPDIR/main.regex
	wait
	curl --tlsv1.3 -o $TEMPDIR/oTLD.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/oTLD.regex'
	sed -i -e "s/\r//g" $TEMPDIR/oTLD.regex
	wait
	curl --tlsv1.3 -o $TEMPDIR/uslocal.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/uslocal.regex'
	sed -i -e "s/\r//g" $TEMPDIR/uslocal.regex
	wait
	
	wget -O $TEMPDIR/country.regex.gpg 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/country.regex.gpg'
	gpg $TEMPDIR/country.regex.gpg
	sed -i -e "s/\r//g" $TEMPDIR/country.regex
	wait
	## replaced from above
	#curl --tlsv1.3 -o $TEMPDIR/country.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/country.regex'
	#wait

}

function security()
{

	#adlists.list 
	curl --tlsv1.3 -o $TEMPDIR/adlists.list 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/adlists/security_basic_adlist.list'

	# Regex Lists
	curl --tlsv1.3 -o $TEMPDIR/basic_security.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/basic_security.regex'
	sed -i -e "s/\r//g" $TEMPDIR/basic_security.regex
	wait
	
	curl --tlsv1.3 -o $TEMPDIR/oTLD.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/oTLD.regex'
	sed -i -e "s/\r//g" $TEMPDIR/oTLD.regex
	wait
	
	wget -O $TEMPDIR/basic_country.regex.gpg 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/basic_country.regex.gpg'
	gpg $TEMPDIR/basic_country.regex.gpg
	wait
	sed -i -e "s/\r//g" $TEMPDIR/basic_country.regex
	## replaced from above
	#curl --tlsv1.3 -o $TEMPDIR/basic_country.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/basic_country.regex'
	#wait


}

function test_list()
{

echo "******This is test server********"
 curl --tlsv1.3 -o $TEMPDIR/adlists.list.trial.temp 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/adlists/trial.adlist.list'
 cat $TEMPDIR/adlists.list.trial.temp $TEMPDIR/adlists.list | grep -v "##" | sort | uniq > $TEMPDIR/adlists.list.temp
 mv $TEMPDIR/adlists.list.temp $TEMPDIR/adlists.list
 
 curl --tlsv1.3 -o $TEMPDIR/test.regex 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Regex%20Files/test.regex'
}

function scripts()
{
 killall -SIGHUP pihole-FTL
 wait
 pihole restartdns
 wait
 pihole -g
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

function encrypted_block_list()
{


	wget -O $TEMPDIR/custom.block.encrypt.temp.gpg 'https://github.com/IcedComputer/Personal-Pi-Hole-configs/raw/master/Block_Lists/custom.block.encrypt.gpg'
	gpg $TEMPDIR/custom.block.encrypt.temp.gpg
	wait
	sed -i -e "s/\r//g" $TEMPDIR/custom.block.encrypt.temp
	
	wget -O $TEMPDIR/propaganda.block.encrypt.temp.gpg 'https://github.com/IcedComputer/Personal-Pi-Hole-configs/raw/master/Block_Lists/propaganda.block.encrypt.gpg'
	gpg $TEMPDIR/propaganda.block.encrypt.temp.gpg
	wait
	sed -i -e "s/\r//g" $TEMPDIR/propaganda.block.encrypt.temp
	
	wget -O $TEMPDIR/spam.block.encrypt.temp.gpg 'https://github.com/IcedComputer/Personal-Pi-Hole-configs/raw/master/Block_Lists/spam.block.encrypt.gpg'
	gpg $TEMPDIR/spam.block.encrypt.temp.gpg
	wait
	sed -i -e "s/\r//g" $TEMPDIR/spam.block.encrypt.temp
	
	wget -O $TEMPDIR/media.block.encrypt.temp.gpg 'https://github.com/IcedComputer/Personal-Pi-Hole-configs/raw/master/Block_Lists/media.block.encrypt.gpg'
	gpg $TEMPDIR/media.block.encrypt.temp.gpg
	wait
	sed -i -e "s/\r//g" $TEMPDIR/spam.block.encrypt.temp
			
}


function assemble()
{
	cat $TEMPDIR/*.allow.regex.temp | grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' |sort | uniq > $TEMPDIR/final.allow.regex.temp
	cat $TEMPDIR/*.allow.temp | grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | sort | uniq > $TEMPDIR/final.allow.temp
	cat $TEMPDIR/*.regex | grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' | sort | uniq > $TEMPDIR/regex.list
	cat $TEMPDIR/*.block.encrypt.temp | grep -v '#' | grep -v '^$' | grep -v '^[[:space:]]*$' |sort | uniq > $CONFIG/encrypt.list
	
	
	mv $TEMPDIR/regex.list  $PIDIR/regex.list
	mv $TEMPDIR/final.allow.temp $PIDIR/whitelist.txt
	mv $TEMPDIR/adlists.list $PIDIR/adlists.list
	mv $TEMPDIR/CFconfig $FINISHED/cloudflared
	mv $TEMPDIR/refresh.sh $FINISHED/refresh.sh
	
		
	sudo bash $FINISHED/DB_Updates.sh
	

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


## Main Script ############################################################################################################################################
clean
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
regex_allowlist
encrypted_allowlist
encrypted_regex_allowlist
encrypted_block_list
assemble
scripts
clean

###########################################################################################################################################################