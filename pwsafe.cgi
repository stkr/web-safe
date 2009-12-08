#! /usr/bin/perl

use strict;
use CGI;
use CGI::Carp 'fatalsToBrowser';
# Avoid DoS attacks:
$CGI::POST_MAX=1024 * 100;  # max 100K posts
$CGI::DISABLE_UPLOADS = 1;  # no uploads

my $base_uri='/pwsafe';
my $key_dir='/srv/www/pwsafe/data/';
my $query = new CGI;

use MIME::Base64;
my $client_id = 1;
my $key = '';
# system("openssl genrsa -f4 1024 > $key_dir$client_id.pem");

# open(OPENSSL, 'openssl genrsa 1024 |') || die "Unable to open openssl: $!\n";
# while (<OPENSSL>) { $key .= $_; }
# close(OPENSSL);

# A hexadecimal string containing the public exponent.
my $public_exponent = '10001';
# A hexadecimal string containing the modulus (publically known).
# my $modulus = `openssl rsa -noout -modulus < \"$key_dir$client_id.pem\"`;
my $modulus = 'C4600647BFA5697D5734471004A2324955ADC7EE7608694E993BB9BE446248A2EC147178FD8C5FC0635E264151272C47BB32AE005477459F42FD3BAFE3B5E0FA30799F070E83291CCFE3E3DED0CAD92C7F4AAF150233EEE2EBE3AADFD6762C3D68EE8200DFF3C04A065CF2F40671AA747C06F2D33AB2099610627AB8E3C3D49D';
$modulus =~ s/Modulus=//;

# open(OPENSSL, "openssl rsa -pubout < $id.pem |") || die "Unable to open openssl: $!\n";
# while (<OPENSSL>) { $pubkey .= $_; }
# close(OPENSSL);
my $debug;
if ($query->param()) {
  my $encryption_key = $query->param('encryption_key');
  # Openssl requires each line to have exactly 64 characters :(.
  $encryption_key =~ s/\n//g;
  $encryption_key = join("\n", unpack('(A64)*', $encryption_key ));

  $debug .= "encryption_key: $encryption_key\n";
#  open(OPENSSL, " | openssl base64 -d > \"${key_dir}decrypted.txt\"") || die "Unable to open openssl: $!\n";
#  open(OPENSSL, " -| openssl base64 -d | openssl rsautl -decrypt -inkey \"$key_dir$client_id.pem\" > \"${key_dir}decrypted.txt\"") || die "Unable to open openssl: $!\n";
#  print(OPENSSL "$encryption_key");
  my $encryption_key_dec = ` echo \"$encryption_key\" | openssl base64 -d | openssl rsautl -decrypt -inkey \"$key_dir$client_id.pem\" `;
  $debug .= "encryption_key_dec: $encryption_key_dec\n";
}

# Generate the page contents and save them to $page.
my $page = '';
# The ResponseForm contains only data from the server to the client.
$page .= $query->start_form(-name=>'ResponseForm',
                            -onSubmit=>'return false');
$page .= $query->textfield(-name=>'modulus',
                        -default=>$modulus);
$page .= $query->textfield(-name=>'public_exponent',
                        -default=>$public_exponent);
$page .= $query->endform;

$page .= $query->start_form(-method=>'POST',
                            -name=>'RequestForm',
                            -onSubmit=>'EvRequestFormOnSubmit()');
$page .= $query->textfield(-name=>'encryption_key',
                        -default=>'');

$page .= $query->button(-name=>'encrypt',
                        -value=>'encrypt',
                        -onclick=>'EncryptRequest()');

$page .= $query->endform;

#
#$page .= '<form id="test2">
#<input type="hidden" id="modulus" value="' . $modulus . '" />
#<input type="hidden" id="public_exponent" value="' . $public_exponent . '" />
#       <input type="hidden" id="client_id" value="' . $client_id . '" />
#       <input type="button" value="copy" onClick="EncryptRequest(); return true;">
#       <input type="button" value="gen random" onClick="GenerateRandomStr(2); return true;">
#       <input type="submit" value="submit" /></form>';
#
#$page .= 'This is the alternative text!';

# Finally base64 encode the page so it can be safely inserted into
# the javascript section.
my $page64 = encode_base64($page);
$page64 =~  s:\n:' + \"\\n\" + \n  ':g;


# Write the page contents to the client.

# Send a HTTP header.
print $query->header(-type => 'text/html',
                     -charset=>'UTF-8',
                     -expires=>'-3d',
                     -'Cache-Control'=>'no-store,no-cache,must-revalidate,private',
                     -Pragma=>'no-cache');

# Send the HTML header. The page contents are sent encrypted
# within a script block of the header.
print $query->start_html(-dtd=>1,
                         -title=>'Online Password Safe',
                         -author=>'skrug@gmx.at',
#                         -head=>[meta({-http_equiv=>'Content-Type', -content=>'text/html'}),
                         -script=>
                           [
                             { -type=>'text/javascript',
                               -src=>$base_uri . '/javascript/gibberish-aes.js' },

                             { -type=>'text/javascript',
                               -src=>$base_uri . '/javascript/jsbn.js' },

                             { -type=>'text/javascript',
                               -src=>$base_uri . '/javascript/prng4.js' },

                             { -type=>'text/javascript',
                               -src=>$base_uri . '/javascript/rng.js' },

                             { -type=>'text/javascript',
                               -src=>$base_uri . '/javascript/rsa.js' },

                             { -type=>'text/javascript',
                               -src=>$base_uri . '/javascript/base64.js' },

                             { -type=>'text/javascript',
                               -src=>$base_uri . '/javascript/encoding.js' },

                             { -type=>'text/javascript',
                               -src=>$base_uri . '/javascript/pwsafe.js' },

                             { -type=>'text/javascript',
                               -code=>"var page64 = '$page64'" }
                           ],
#                         -meta=>{'keywords'=>'password safe encryption',
#                                 'copyright'=>'copyright 2009 Stefan Krug'},
                         -style=>{'src'=>$base_uri . 'pwsafe.css'},
                         -lang=>'',
                         -onload=>'EvPwsafeBodyLoad()',
                         -onkeypress=>'EvPwsafeBodyKeyPress()');

# TODO: clear everything on close!


print '<div id="pwsafe_gui_content"></div>';
print $page;
print $debug;
print localtime();

print $query->end_html();
