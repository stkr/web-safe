#! /bin/bash

# Where to copy the temporary files to.
# This is also the name of the root folder in the tgz file.
# No trailing slash allowed.
TEMP_PATH='web-safe'

mkdir -p "${TEMP_PATH}"
chmod 0755 "${TEMP_PATH}";

mkdir -p "${TEMP_PATH}"/cgi-bin
chmod 0755 "${TEMP_PATH}"/cgi-bin

mkdir -p "${TEMP_PATH}"/cgi-bin/web-safe
chmod 0755 "${TEMP_PATH}"/cgi-bin/web-safe
cp -u pwsafe.cgi "${TEMP_PATH}"/cgi-bin/web-safe/pwsafe.cgi
chmod 0755 "${TEMP_PATH}"/cgi-bin/web-safe/pwsafe.cgi
cp -u external/Pwsafe.pm "${TEMP_PATH}"/cgi-bin/web-safe/Pwsafe.pm
chmod 0644 "${TEMP_PATH}"/cgi-bin/web-safe/Pwsafe.pm

mkdir -p "${TEMP_PATH}"/web-safe
chmod 0755 "${TEMP_PATH}"/web-safe
cp -u pwsafe.css "${TEMP_PATH}"/web-safe/pwsafe.css
cp -u index.htm "${TEMP_PATH}"/web-safe/index.htm
cp -u headline.htm "${TEMP_PATH}"/web-safe/headline.htm
chmod 0644 "${TEMP_PATH}"/web-safe/*

mkdir -p "${TEMP_PATH}"/web-safe/javascript
chmod 0755 "${TEMP_PATH}"/web-safe/javascript
cp -u external/gibberish-aes/src/gibberish-aes.js "${TEMP_PATH}"/web-safe/javascript/gibberish-aes.js
cp -u external/rsa/jsbn.js "${TEMP_PATH}"/web-safe/javascript/jsbn.js
cp -u external/rsa/prng4.js "${TEMP_PATH}"/web-safe/javascript/prng4.js
cp -u external/rsa/rng.js "${TEMP_PATH}"/web-safe/javascript/rng.js
cp -u external/rsa/rsa.js "${TEMP_PATH}"/web-safe/javascript/rsa.js
cp -u external/rsa/base64.js "${TEMP_PATH}"/web-safe/javascript/base64.js
cp -u external/encoding/encoding.js "${TEMP_PATH}"/web-safe/javascript/encoding.js
cp -u pwsafe.js "${TEMP_PATH}"/web-safe/javascript/pwsafe.js
chmod 0644 "${TEMP_PATH}"/web-safe/javascript/*

mkdir -p "${TEMP_PATH}"/documentation
chmod 0755 "${TEMP_PATH}"/documentation
cp -u documentation/* "${TEMP_PATH}"/documentation
chmod 0644 "${TEMP_PATH}"/documentation/*

tar cfz web-safe.tgz "${TEMP_PATH}"
rm -r "${TEMP_PATH}"
