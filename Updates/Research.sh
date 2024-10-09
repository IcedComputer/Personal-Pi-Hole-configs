## Last Updated 2024-10-08
## Research.sh
## Use to find out which domains were sucessfully routed
##



#!/bin/bash


cat /var/log/pihole.log | grep -v blocked | grep -v CNAME | grep -v NODATA | grep -v HTTPS | grep -oP '(?<=reply\s)[^\s]+(?=\sis)' | sort | uniq -c | sort > /scripts/temp/research.temp
