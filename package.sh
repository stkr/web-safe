#! /bin/bash

tar --transform 's,^,/web-safe/,' -c -f web-safe.tgz -z \
	COPYING \
	README.markdown \
	cgi-bin \
	web-safe/index.htm \
	web-safe/.htaccess \
	web-safe/css/pwsafe.css \
	web-safe/js/gibberish-aes/src/gibberish-aes.min.js \
	web-safe/js/rsa/jsbn.js \
	web-safe/js/rsa/prng4.js \
	web-safe/js/rsa/rng.js \
	web-safe/js/rsa/base64.js \
	web-safe/js/encoding/encoding.js \
	web-safe/js/jquery/jquery-1.4.1.min.js \
	web-safe/js/pwsafe.js
