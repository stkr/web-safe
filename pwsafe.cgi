#! /usr/bin/perl

use strict;
use warnings;
use CGI;
use CGI::Carp 'fatalsToBrowser';
# Avoid DoS attacks:
$CGI::POST_MAX=1024 * 100;  # max 100K posts
$CGI::DISABLE_UPLOADS = 1;  # no uploads

use File::Basename;

# Using the Crypt::Pwsafe module found in CPAN for decrypting the
# database. Requires the modules Crypt::Twofish and ecb end cbc encryption
# modules. In ubuntu 9.10 the required packages are
# libcrypt-twofish-perl, libcrypt-ecb-perl and libcrypt-cbc-perl.
#
# Notes on the usage of the Pwsafe module:
#   - The clumsy method of accessing entries with username@title prevents
#     the usage of the @ character in the username or title.
#
# Modifications to the Pwsafe module:
#   - Removed keyboard handling code. This is a webservice and uses no
#     keyboard at all.
#   - Return the title and user fields within the password hash.
use Pwsafe;

my $base_uri='/pwsafe';
my $key_dir='/srv/www/pwsafe/data/';
my $safe_dir='/srv/www/pwsafe/safes/';
my $cgi = new CGI;

use MIME::Base64;
my $client_id = 1;
my $key = '';
# system("openssl genrsa -f4 1024 > $key_dir$client_id.pem");
my $debug;

# Used (by client) for AES encryption of the request.
my $encryption_key = '';

# Used (by server) for AES encryption of the response. The value is chosen
# by the client and is different for each request. It is contained in
# the request.
my $request_key = '';

# The master passwor used for opening the passwor safe.
my $master_password = '';

# The action which is about to be performed by the script.
my $action = '';

# If the page contains sensitive data, this flag should be set to 1.
# When assembling the page, it is checked and if no request key was set,
# it is refused to send data.
my $encryption_needed = 0;

# Contains the contents of the generated html page.
# The first few characters contain a commonly known string which is
# used to check whether decryption was successful by javascript.
my $page = "<!-- pwsafe-web page start -->\n";

# open(OPENSSL, 'openssl genrsa 1024 |') || die "Unable to open openssl: $!\n";
# while (<OPENSSL>) { $key .= $_; }
# close(OPENSSL);

# A hexadecimal string containing the public exponent.
my $public_exponent = '10001';
# A hexadecimal string containing the modulus (publically known).
# my $modulus = `openssl rsa -noout -modulus < \"$key_dir$client_id.pem\"`;
my $modulus = 'C4600647BFA5697D5734471004A2324955ADC7EE7608694E993BB9BE446248A2EC147178FD8C5FC0635E264151272C47BB32AE005477459F42FD3BAFE3B5E0FA30799F070E83291CCFE3E3DED0CAD92C7F4AAF150233EEE2EBE3AADFD6762C3D68EE8200DFF3C04A065CF2F40671AA747C06F2D33AB2099610627AB8E3C3D49D';
$modulus =~ s/Modulus=//;


# Reformat a base64 encoded string so it matches a format which
# can be written to a javascript section in the html file.
# Params:
#   - A base64 encoded value with arbitrary newlines.
sub JavascriptBase64Format($)
{
  my $result = $_[0];
  $result =~ s/\n|\r//g;
#  $result = join("' + \"\\n\" + \n  '", unpack('(A64)*', $result ))."' + \"\\n\" + \n  '";
  return $result;
}


# Reformat a base64 encoded string so it matches the format expected
# by openssl.
# Openssl REQUIRES each line to have exactly 64 characters.
# Openssl REQUIRES a newline character at the end of the file.
# Params:
#   - A base64 encoded value with arbitrary newlines.
sub OpensslBase64Format($)
{
  my $result = $_[0];
  $result =~ s/\n|\r//g;
  $result = join("\n", unpack('(A64)*', $result ))."\n";
  return $result;
}


# Decrypt a base64 encoded string using openssl.
# Params:
#   - A base64 encoded rsa encrypted string.
sub OpensslRsaDecrypt($)
{
  my $msg = OpensslBase64Format($_[0]);
  my $result = ` echo \"$msg\" | openssl base64 -d | openssl rsautl -decrypt -inkey \"$key_dir$client_id.pem\" `;
}


# Call openssl enc for aes encryption or decryption.
# Params:
#   - A string which is en/decrypted. This is passed as is to openssl.
#     So be sure to have formatted it correctly.
#   - The en/decryption key (binary).
#   - 'E' 'e' or 'D' 'd' for selecting encryption or decryption.
sub OpensslAesCall($$$)
{
  my $msg = $_[0];
  my $key = $_[1];
  my $direction = lc($_[2]);
  if (! $direction =~ /e|d/) { die "OpensslAesCall invoked with illegal direction."; }

  # Create two pipes to feed data to the openssl process and make them
  # flush on every print.
  pipe(OPENSSL_KEY_READ, OPENSSL_KEY_WRITE);
  select(OPENSSL_KEY_WRITE); $| = 1; select(STDOUT);
  pipe(OPENSSL_MSG_READ, OPENSSL_MSG_WRITE);
  select(OPENSSL_MSG_WRITE); $| = 1; select(STDOUT);

  # Create key supplying child:
  # fork returns 0 for the parent process and the pid of the child for
  # the child process
  my $key_pid = fork();
  if($key_pid) { } # Parent
  elsif($key_pid == 0) { print OPENSSL_KEY_WRITE $key; exit; } # Child
  else { die "Fork did not work\n"; }

  # Create data supplying child:
  my $msg_pid = fork();
  if($msg_pid) { } # Parent
  elsif($msg_pid == 0) { print OPENSSL_MSG_WRITE $msg; exit; } # Child
  else { die "Fork did not work\n"; }

# Finally start the openssl executable in the main process:
	close OPENSSL_KEY_WRITE;
	close OPENSSL_MSG_WRITE;
	my $fd_pass = fileno(OPENSSL_KEY_READ);
	my $fd_in = fileno(OPENSSL_MSG_READ);
  my $result;
  if ($direction eq 'e') {
    $result = `openssl enc -e -aes-256-cbc -a -pass file:/proc/$$/fd/$fd_pass -in /proc/$$/fd/$fd_in `;
  }
  elsif ($direction eq 'd') {
    $result = `openssl enc -d -aes-256-cbc -a -pass file:/proc/$$/fd/$fd_pass -in /proc/$$/fd/$fd_in `;
  }
  close OPENSSL_KEY_READ;
  close OPENSSL_MSG_READ;

# Wait for the children to complete.
	waitpid($key_pid,0);
	waitpid($msg_pid,0);
  return $result;
}


# Encrypt a string using openssl aes-256-cbc encryption and base64 encoding.
# Params:
#   - The string to encrypt.
#   - The encryption key (binary).
sub OpensslAesEncrypt($$)
{
  OpensslAesCall($_[0], $_[1], 'e');
}


# Decrypt a base64 encoded aes-256-cbc encrypted string using openssl.
# Params:
#   - A base64 encoded encrypted string.
#   - The decryption key (binary).
sub OpensslAesDecrypt($$)
{
  OpensslAesCall(OpensslBase64Format($_[0]), $_[1], 'd');
}

sub OpenPwsafe($$)
{
  my $file = shift;
  my $key = shift;
  my $pwsafe = Crypt::Pwsafe->new($file, $key);
  return $pwsafe;
}


# Generate a password file list and return the html code.
sub PasswordFileList()
{
  my $result;
  my @list;

  opendir(DIR, $safe_dir);
  my @files = readdir(DIR);
  closedir(DIR);
  foreach (@files) {
    if (($_ ne '.') && ($_ ne '..')) {
      my ($filename, $directories, $suffix) = fileparse($_);
      push(@list, $cgi->li($cgi->a({href=>"javascript: OpenFile('$filename')"}, $filename)));
    }
  }

  if (length(@list > 0)) {
    $result .= $cgi->ul(@list);
  }
  return $result;
}

sub GroupSort
{
	# lc($a->{'group'}) cmp lc($b->{'group'});
	my @a = split /\./, $a->{'group'};
	my @b = split /\./, $b->{'group'};

	# Some corner cases:
	# A has no elements and b has no elements -> Same group, compare title.
	if (((scalar @a) == 0) and ((scalar @b) == 0)) { return $a->{'title'} cmp $b->{'title'}; }
	# A has no elements.
	elsif ((scalar @a) == 0) { return 1; }
	# B has no elements.
	elsif ((scalar @b) == 0) { return -1;	}

	my $n = 0;
	while(1) {
		if ($a[$n] eq $b[$n]) {
			$n++;
			# Both are the same group.
			if (($n == scalar @a) and ($n == scalar @b)) { return 0; }
			# A is finnished, but not b. So b is a subgroup of a.
			elsif ($n == scalar @a) { return 1; }
			# B is finnished, but not a. So a is a subgroup of b.
			elsif ($n == scalar @b) { return -1; }
			# None of them is finished. Continue with the next element.
		}
		else { return $a[$n] cmp $b[$n]
		}
	}
}

## Traverse the pwsafe object and extract all pass passwod objects.
# Params:
#   - A hash reference to a node in the pwsafe tree.
#   - A array reference which the password hashes are copied to.
sub RecursiveList
{
  while (my ($key, $value) = each %{$_[0]}) {
    # Only if we have a hash, we need to check it.
    # It it is not, it is already an attribute of a password.
    if (ref($value) eq 'HASH') {
      # If the has contains a 'UUID' key, it is a password. Otherwise, it is a group.
      if (defined $value->{'UUID'}) {
        # If the password has a title, add it to the list.
        if ($value ->{'title'} ne '') {
          # Ensure that every password hash has a group entry.
          if (! defined $value->{'group'}) { $value->{'group'} = '' }
          push(@{$_[1]}, $value);
        }
      }
      else {
        RecursiveList($value, $_[1]);
      }
    }
  }
}

# Create the html code for a group header.
# Params:
#   - group_id: A string used as id for the group. Must be unique within
#     the html document. A suggestrion is the group name including all
#     supergroups (so it is unique).
#   - group_name: A string displayed as group name in the UI.
sub HtmlGroupHeader
{
  my ($group_id, $group_name) = @_;
  return sprintf('<li><a id="%s_link" href="javascript:HideGroup(\'%s\')">%s</a><ul id="%s">', $group_id, $group_id, $group_name, $group_id);
}

# Create the html code for the end of a group. Must match the code
# of HtmlGroupHeader.
sub HtmlGroupFooter
{
  return '</ul></li>';
}

# Create the html code for a password entry in the list.
# Params:
#   - title: The displayed title of the password.
sub HtmlPasswordList
{
  sprintf('<li>%s</li>', $_[0]);
}

# Change the current group in the html sourcecode.
# This closes the opened containers for subgroups and
# opens required containers for the new group.
# Params:
#   - old_group: A string naming the old group.
#   - new_group: A string naming the new group.
sub HtmlChangeGroup
{
  my $last_group = $_[0];
  my @last_group = split(/\./, $last_group);
  my @new_group = split(/\./, $_[1]);
  my $result = '';
  my $i = 0;
  while ( (defined @last_group[$i]) && (defined @new_group[$i]) &&
          (@last_group[$i] eq @new_group[$i])) { $i++; }
  # So $i now is the index of the first distinct group entry.
  # Close every deeper level of the old group.
  my $close_levels = scalar(@last_group) - $i;
  while ($close_levels > 0) {
    $result .= HtmlGroupFooter();
    $close_levels--;
  }
  # And open a div for every deeper new group level.
  my $open_level = $i;
  my $group_id = $last_group;
  while ($open_level < scalar(@new_group)) {
    if ($group_id ne '') { $group_id .= '.'; }
    $group_id .= @new_group[$open_level];
    $result .= HtmlGroupHeader($group_id, @new_group[$open_level]);
    $open_level++;
  }
  return $result;
}

sub PasswordList($$)
{
  my ($filename, $key) = @_;
  $key = 'test'; # <-- TODO: this must be removed!
  my $result;
  my $pwsafe = Crypt::Pwsafe->new($filename, $key);
  my @passwords = ();
  RecursiveList(\%{$pwsafe}, \@passwords);
  # So at this point we have an array containing all passwords.
  # Sort the passwords by groupname:
  @passwords = sort GroupSort @passwords;
  # Create a group from the filename which contains top-level passwords.
  $result .= HtmlGroupHeader('root', $filename);
  # Print the group and password hierarchy.
  my $last_group = '';
  foreach (@passwords) {
    if ($_->{'group'} ne $last_group) {
      $result .= HtmlChangeGroup($last_group, $_->{'group'});
      $last_group = $_->{'group'};
    }
    $result .= HtmlPasswordList($_->{'title'});
  }
  # Close all groups.
  $result .= HtmlChangeGroup($last_group, '');
  # Close the group used for the file.
  $result .= HtmlGroupFooter();
  return $result;
}

# Handle the input parameters.
if ($cgi->param()) {
  $encryption_key = OpensslRsaDecrypt($cgi->param('encryption_key'));
  $request_key = OpensslAesDecrypt($cgi->param('request_key'), $encryption_key);
  $master_password = OpensslAesDecrypt($cgi->param('action'), $encryption_key);
  $action = OpensslAesDecrypt($cgi->param('action'), $encryption_key);
  if ($action eq 'view_file') {
    my $filename = $safe_dir . OpensslAesDecrypt($cgi->param('filename'), $encryption_key);
    $page .= '<ul>'.PasswordList($filename, $master_password).'</ul>';
  }
  elsif ($action eq 'view_password') {
  }
  else {
    $page .= PasswordFileList();
  }
#  $debug .= "encryption_key: $encryption_key<br />\n";
#  $debug .= "request_key: $request_key<br />\n";
}
else {
  $page .= PasswordFileList();
}

# The ResponseForm contains only data from the server to the client.
$page .= $cgi->start_form(-name=>'ResponseForm',
                          -onSubmit=>'return false');
$page .= $cgi->hidden(-name=>'modulus',
                      -default=>$modulus);
$page .= $cgi->hidden(-name=>'public_exponent',
                      -default=>$public_exponent);
$page .= $cgi->endform;

$page .= $cgi->start_form(-method=>'POST',
                          -name=>'RequestForm',
                          -onSubmit=>'EvRequestFormOnSubmit()');
$page .= $cgi->hidden(-name=>'encryption_key',
                      -default=>'');
$page .= $cgi->hidden(-name=>'request_key',
                      -default=>'');
$page .= $cgi->hidden(-name=>'master_password',
                      -default=>'');
$page .= $cgi->hidden(-name=>'action',
                      -default=>'');
$page .= $cgi->hidden(-name=>'filename',
                      -default=>'');
$page .= $cgi->endform;

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

# Finally encrypt and base64 encode the page so it can be safely
# inserted into the javascript section.
my $page64 = '';
if ($request_key eq '') {
  if ($encryption_needed) {
    # TODO: here, a link to the start page should be given to
    # restart the process.
    $page = 'No encryption key was specified for this request.';
  }
  $page64 = encode_base64($page);
}
else {
  $page64 = OpensslAesEncrypt($page, $request_key);
}
$page64 = JavascriptBase64Format($page64);



# Write the page contents to the client.

# Send a HTTP header.
print $cgi->header(-type => 'text/html',
                     -charset=>'UTF-8',
                     -expires=>'-3d',
                     -'Cache-Control'=>'no-store,no-cache,must-revalidate,private',
                     -Pragma=>'no-cache');

# Send the HTML header. The page contents are sent encrypted
# within a script block of the header.
print $cgi->start_html(-dtd=>1,
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
                         -style=>{'src'=>$base_uri . '/pwsafe.css'},
                         -lang=>'',
                         -onload=>'EvPwsafeBodyLoad()',
                         -onkeypress=>'EvPwsafeBodyKeyPress()');

# TODO: clear everything on close!

print '<div id="pwsafe-web-content">&nbsp;</div>';
print '<div id="pwsafe-web-debug">&nbsp;</div>';

# print $page;
print $debug;
# print localtime();

print $cgi->end_html();
