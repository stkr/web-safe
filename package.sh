#! /bin/bash

# Where to copy the files to.
# No traling slash!
TEMP_PATH='pwsafe'

mkdir -p "${TEMP_PATH}"
cp -u "pwsafe.css" "${TEMP_PATH}/pwsafe.css"
cp -u "pwsafe.cgi" "${TEMP_PATH}/pwsafe.cgi"
cp -u "index.htm" "${TEMP_PATH}/index.htm"
cp -u "headline.htm" "${TEMP_PATH}/headline.htm"
chmod 0644 "${TEMP_PATH}"/*;

mkdir -p "${TEMP_PATH}/javascript";
chmod 0755 "${TEMP_PATH}/javascript";
cp -u "external/gibberish-aes/src/gibberish-aes.js" "${TEMP_PATH}/javascript/gibberish-aes.js"
cp -u "external/rsa/jsbn.js" "${TEMP_PATH}/javascript/jsbn.js"
cp -u "external/rsa/prng4.js" "${TEMP_PATH}/javascript/prng4.js"
cp -u "external/rsa/rng.js" "${TEMP_PATH}/javascript/rng.js"
cp -u "external/rsa/rsa.js" "${TEMP_PATH}/javascript/rsa.js"
cp -u "external/rsa/base64.js" "${TEMP_PATH}/javascript/base64.js"
cp -u "external/encoding/encoding.js" "${TEMP_PATH}/javascript/encoding.js"
cp -u "external/Pwsafe.pm" "${TEMP_PATH}/Pwsafe.pm"
cp -u "pwsafe.js" "${TEMP_PATH}/javascript/pwsafe.js"
chmod 0644 "${TEMP_PATH}"/javascript/*;

tar cfz "pwsafe.tgz" "${TEMP_PATH}"
rm -r "${TEMP_PATH}"
