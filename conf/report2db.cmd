#!/bin/bash

TARGETDB=http://loginreport:loginreport@localhost:5984/loginreport

while read LINE; do 
    echo $LINE | curl -s -d @- -H "Content-Type: application/json" $TARGETDB  > /dev/null
done
