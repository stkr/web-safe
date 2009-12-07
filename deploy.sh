#! /bin/bash

# Where to copy the files to.
# No traling slash!
DEPLOY_PATH='/smb/fileserver.ardning.homenet/srv/www/pwsafe'

cp -u "external/gibberish-aes/src/gibberish-aes.js" "${DEPLOY_PATH}/gibberish-aes.js"
