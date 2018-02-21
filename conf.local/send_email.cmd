#!/bin/sh
#
# an example of sending request to an external server.
#
curl --user "bitkomise:1#tajne#heslo" -d @- -H "Content-Type: application/json" "https://send.novacisko.cz/send"

#just store request to a file - just for example
#cat >> ../run/send_mail_request

