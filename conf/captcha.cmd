#!/bin/sh
# google recaptcha secret code
SECRET=aaabbbbccc
(read line;echo "&secret=$SECRET&response=$line") | curl -d @- -s https://www.google.com/recaptcha/api/siteverify | grep "\"success\": true" > /dev/null
 