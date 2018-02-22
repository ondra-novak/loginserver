#!/bin/bash

LOGFILE=`dirname $0`/../log/report.log

echo "{\"event\":\"service-started\"}" >> $LOGFILE
cat >> $LOGFILE
echo "{\"event\":\"service-died\"}" >> $LOGFILE
 