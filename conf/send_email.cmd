#!/bin/sh
#
# an example of sending request to an external server.
#
#curl --user user:secret -d @- -H "Content-Type: application/json" "https://example.com/send"

#just store request to a file - just for example
cat >> ../run/send_mail_request

