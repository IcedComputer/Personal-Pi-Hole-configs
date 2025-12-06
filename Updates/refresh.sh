## Created 25 July 2020
## Updated 2025-12-05
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
	
	## download an updated Research.sh
	curl --tlsv1.3 -o $TEMPDIR/Research.sh 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/refs/heads/master/Updates/Research.sh'
	
		## download an updated allow_update.sh
	curl --tlsv1.3 -o $TEMPDIR/allow_update.sh 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/refs/heads/master/Updates/allow_update.sh'
	
	## download an current updates_optimized.sh
	curl --tlsv1.3 -o $TEMPDIR/updates_optimized.sh 'https://raw.githubusercontent.com/IcedComputer/Personal-Pi-Hole-configs/refs/heads/master/Updates/Test%20-%20Optimized/updates_optimized.sh'

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
	
	chmod 777 $TEMPDIR/Research.sh
	mv $TEMPDIR/Research.sh $FINISHED/Research.sh
	
	chmod 777 $TEMPDIR/allow_update.sh
	mv $TEMPDIR/allow_update.sh $FINISHED/allow_update.sh
	
	chmod 777 $TEMPDIR/updates_optimized.sh
	mv $TEMPDIR/updates_optimized.sh $FINISHED/updates_optimized.sh
}

download
move
