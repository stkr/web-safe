#! /bin/bash

# Where to copy the files to.
# No traling slash!
DEPLOY_PATH='/smb/fileserver.ardning.homenet/srv/www/pwsafe'

mkdir "${DEPLOY_PATH}/javascript";
chmod 0755 "${DEPLOY_PATH}/javascript";
cp -u "external/gibberish-aes/src/gibberish-aes.js" "${DEPLOY_PATH}/javascript/gibberish-aes.js"
cp -u "external/rsa/jsbn.js" "${DEPLOY_PATH}/javascript/jsbn.js"
cp -u "external/rsa/prng4.js" "${DEPLOY_PATH}/javascript/prng4.js"
cp -u "external/rsa/rng.js" "${DEPLOY_PATH}/javascript/rng.js"
cp -u "external/rsa/rsa.js" "${DEPLOY_PATH}/javascript/rsa.js"
cp -u "external/rsa/base64.js" "${DEPLOY_PATH}/javascript/base64.js"
cp -u "external/encoding/encoding.js" "${DEPLOY_PATH}/javascript/encoding.js"
cp -u "external/Pwsafe.pm" "${DEPLOY_PATH}/Pwsafe.pm"
cp -u "pwsafe.js" "${DEPLOY_PATH}/javascript/pwsafe.js"
chmod 0644 "${DEPLOY_PATH}/javascript/*";

cp -u "pwsafe.css" "${DEPLOY_PATH}/pwsafe.css"
cp -u "pwsafe.cgi" "${DEPLOY_PATH}/pwsafe.cgi"
cp -u "index.htm" "${DEPLOY_PATH}/index.htm"
cp -u "headline.htm" "${DEPLOY_PATH}/headline.htm"
chmod 0644 "${DEPLOY_PATH}/*";
