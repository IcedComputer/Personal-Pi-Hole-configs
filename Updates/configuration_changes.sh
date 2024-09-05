## Last Updated 2024-09-05
## configuration_changes.sh
## This script is designed to keep the pihole updated and linked to any changes made
##



#!/bin/bash

#Vars
FINISHED=/scripts/Finished
TEMPDIR=/scripts/temp
PIDIR=/etc/pihole
CONFIG=/scripts/Finished/CONFIG


############ Temp Vars
version=$(<"$CONFIG/ver.conf")

bash -c 'echo -e "\033[1;33m This Script was last updated on 2024-09-05 \x1b[39m"'

	if [ $version = "yes" ]
		then
			sed -i -e 's/yes/5/g' $CONFIG/ver.conf
	fi