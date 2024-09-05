## Created 25 July 2020
## Updated 2024-09-05
## refresh.sh
## This script simply updates the various update script to ensure the local copy on the machine is up to date
##



#!/bin/bash

#Vars
FINISHED=/scripts/Finished
TEMPDIR=/scripts/temp
#CONFIG=/scripts/Finished/CONFIG

#download files
function download()
{

	#download an updated update.sh
	curl --tlsv1.3 -o $TEMPDIR/updates.sh 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Updates/updates.sh'
	
	## download an updated DB_updates.sh
	curl --tlsv1.3 -o $TEMPDIR/DB_Updates.sh 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Updates/DB_Updates.sh'
	
	## download an updated purge.sh
	curl --tlsv1.3 -o $TEMPDIR/purge.sh 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Updates/purge.sh'
	
	## download an updated configuration_changes.sh
	curl --tlsv1.3 -o $TEMPDIR/configuration_changes.sh 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/master/Updates/configuration_changes.sh'
}


#move
function move()
{

	## change permisions
	chmod 777 $TEMPDIR/updates.sh
	mv $TEMPDIR/updates.sh $FINISHED/updates.sh
		
	chmod 777 $TEMPDIR/DB_Updates.sh
	mv $TEMPDIR/DB_Updates.sh $FINISHED/DB_Updates.sh
	
	chmod 777 $TEMPDIR/purge.sh
	mv $TEMPDIR/purge.sh $FINISHED/purge.sh
	
	chmod 777 $TEMPDIR/configuration_changes.sh
	mv $TEMPDIR/configuration_changes.sh $FINISHED/configuration_changes.sh
}

download
move
