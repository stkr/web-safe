#! /usr/bin/perl

# web-safe - A browser based online password safe solution.
# Copyright (C) 2010  Stefan Krug
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Written by Stefan Krug <st@skobeloff.eu>.

use strict;
use warnings;

#
# Configuration:
# -----------------------
#
# This is the location which can be used to access the html files of the
# application. It is recommended to use a server-relative-url
# (starting with a slash) here.
my $base_uri='/web-safe';
# This is the absolute path of the folder where the temporary private key
# files are stored. It must be writeable by the user which executes the
# cgi script.
my $key_dir='/srv/www/web-safe/data/';
# This is the absolute path of the folder where the safe files can be
# found. The safe files must be readable by the user which executes the
# cgi script.
my $safe_dir='/srv/www/web-safe/safes/';
#
# End of Configuration
# -------------------------

use File::Basename;
use CGI;
use CGI::Carp 'fatalsToBrowser';
# Avoid DoS attacks:
$CGI::POST_MAX = 1024 * 100;  # max 100K posts
$CGI::DISABLE_UPLOADS = 1;  # no uploads
use MIME::Base64;
use JSON;

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

# A global cgi object for handling the document processing.
my $cgi = new CGI;

# Used for printing debug output to the document.
my $debug = '';

# Contains the response which is sent to the client.
my $response = {};

# An identification number for the current session.
# This has to be transmitted for every request except the
# initial handshake
my $session_id = '';

# Used for AES encryption of the traffic.
my $session_key = '';


# Sanity check the configuration:
$base_uri =~ s/\/$//;
$key_dir =~ s/\/$//;
$safe_dir =~ s/\/$//;


# Delete old keyfiles.
sub CleanupKeyFiles
{
  opendir(my $dh, $key_dir) || die "can't opendir $key_dir: $!";
  my @files = readdir($dh);
  my @remove = ();
  closedir $dh;
  my $now = time();
  foreach (@files) {
    my $filename = "$key_dir/$_";
    open(FH, $filename);
    while(<FH>) {
      if ($_ =~ /^\s*created:\s*([0-9]*)/) {
        if($1 + 10800 < $now) { push(@remove, $filename); }
        last;
      }
    }
    close FH;
  }
  foreach (@remove) { unlink($_); }
}

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
# by openssl. This does also strip everything that is no valid
# character of the base64 alphabet.
# Openssl REQUIRES each line to have exactly 64 characters.
# Openssl REQUIRES a newline character at the end of the file.
# Params:
#   - A base64 encoded value with arbitrary newlines.
sub OpensslBase64Format($)
{
  my $result = $_[0];
  $result =~ s/[^a-zA-Z0-9+\/=]//g;
  $result = join("\n", unpack('(A64)*', $result ))."\n";
  return $result;
}


# Decrypt a base64 encoded string using openssl.
# Params:
#   - A base64 encoded rsa encrypted string.
sub OpensslRsaDecrypt($)
{
  my $msg = $_[0];
  if (-e "$key_dir/$session_id") {
    # Openssl is rather picky about its input format.
    $msg = OpensslBase64Format($msg);
    return ` echo \"$msg\" | openssl base64 -d | openssl rsautl -decrypt -inkey \"$key_dir/$session_id\" `;
  }
  return '';
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


# Generate a new session id. This creates a new public key for
# the session and stores it in a file. Also the session creation
# timestamp is stored in that file. Old session files are deleted.
sub CreateSession
{
  CleanupKeyFiles();
  opendir(DIR, $key_dir);
  my @files = readdir(DIR);
  closedir(DIR);
  $session_id = 0;
  # While a file with $session_id exists, create a new one.
  while ( (scalar grep {$session_id eq $_} @files) > 0) { $session_id++; }
  my $filename = "$key_dir/$session_id";
  system("echo \"\" > \"$filename\" && chmod 600 \"$filename\"");
  system("openssl genrsa -f4 1024 >> \"$filename\"");
  system("echo \"created: ".time()."\" >> \"$filename\"");
}


# Get the session key for the current sesion_id.
sub GetSessionKey
{
  my $filename = "$key_dir/$session_id";
  if (-e "$filename") {
    my $session_key = '';
    open FH, " < $filename";
    while(<FH>) {
      if ($_ =~ /^\s*session_key:\s*([a-zA-Z0-9]*)/) {
        $session_key = $1;
        last;
      }
    }
    close FH;
    if ($session_key eq '') {
      $response->{'errnr'} = 1002;
      $response->{'errmsg'} = "GetSessionKey: No session key found for session id $session_id.";
    }
    return $session_key;
  }
  $response->{'errnr'} = 1001;
  $response->{'errmsg'} = "Invalid session id ($session_id). Maybe it has expired.";
  return '';
}


# Return a reference to an array containing all
# found safe files (without the path).
sub GetFiles
{
  opendir(DIR, $safe_dir);
  my @result = grep { ! /^.{1,2}$/ } readdir(DIR);
  closedir(DIR);
  return \@result;
}


# Return an array reference to all passwords found in the
# safe file.
# Params:
#   - $safe: The filename of the safe (without path).
#   - $key: The master password to open the safe with.
sub GetPasswordList
{
  my ($safe, $key) = @_;
  my @result = ();
  my $filename = "$safe_dir/$safe";
  @result = @{Crypt::Pwsafe->new($filename, $key)};
  return \@result;
}


# Return a reference to a hash containing all details for
# a password.
# Params:
#   - $id: An identification for the password for which details
#          are returned.
#   - $passwords: An reference to an array containing all passwords.
sub GetPasswordDetails
{
  my ($id, $passwords) = @_;
  my %result = ();
  foreach (@$passwords) {
    if ((defined $_->{'UUID'}) and ($_->{'UUID'} eq $id)) {
      %result = %$_;
    }
  }
  return \%result;
}


# Filter the passwords list so that it does only
# contain id, title, group and username.
# Params:
#   - $passwords: An reference to an array containing all passwords.
sub FilterDetails
{
  my ($passwords) = @_;
  my @result = ();
  foreach (@$passwords) {
    my $password = {};
    if (defined $_->{'UUID'}) { $password->{'uuid'} = $_->{'UUID'}; }
    if (defined $_->{'Title'}) { $password->{'title'} = $_->{'Title'}; }
    if (defined $_->{'Group'}) { $password->{'group'} = $_->{'Group'}; }
    if (defined $_->{'user'}) { $password->{'user'} = $_->{'user'}; }
    push(@result, $password);
  }
  return \@result;
}


# Append data to the data hash of the response.
# Param
#   - a reference to a hash which is merged with the data
#     hash of the response.
sub AppendToResponseData
{
  if (defined $response->{'data'}) {
    %{$response->{'data'}} = (%{$response->{'data'}}, %{$_[0]});
  }
  else {
    $response->{'data'} = $_[0];
  }
}


# Json encode the response. The data is encrypted (unless encryption
# is disabled for this request) and base64 encoded so it can be
# safely included in a json string.
sub EncodeResponse
{
  if (! defined ($response->{'disable-encryption'})) {
    if ($session_key ne '') {
      $response->{'encrypted'} = 1;
      if (defined $response->{'data'}) {
        $response->{'data'} = JavascriptBase64Format(OpensslAesEncrypt(encode_json($response->{'data'}), $session_key));
      }
    }
    else {
      # If any function has set an errormessage already, use that one.
      # Otherwise, create a new one.
      if (! defined $response->{'errmsg'}) {
        $response->{'errnr'} = 1002;
        $response->{'errmsg'} = "No session key found for session id $session_id.";
      }
      delete $response->{'data'};
    }
  }
  else { delete $response->{'disable-encryption'}; }
  return encode_json($response);
}


# Handle client authentication.
sub InitSession
{
  CreateSession();
  SendServerAuth();
}


# Send server authentication data.
sub SendServerAuth
{
  my $filename = "$key_dir/$session_id";
  my $modulus = `openssl rsa -noout -modulus < \"$filename\"`;
  $modulus =~ s/Modulus=//; $modulus =~ s/\n|\r//g;
  $response = { 'disable-encryption' => 1,
                'type' => 'server_auth',
                'modulus_server' => $modulus,
                'public_exponent_server' => '10001',
                'session_id' => $session_id };
}


# Handle client sending session key.
sub SetSessionKey
{
  my ($session_key_encrypted) = @_;
  my $filename = "$key_dir/$session_id";
  $session_key = OpensslRsaDecrypt($session_key_encrypted);
  # This is user input. So we must sanitize it.
  $session_key =~ s/[^0-9a-zA-Z]//g;
  if (length($session_key) < 64) { $session_key = '' };
  open FH, " >> $filename";
  print FH 'session_key: '.$session_key."\n";
  close FH;
  SendFileList();
}

# Add a file list to the response.
sub SendFileList
{
  # Read the available safe files.
  my $files = GetFiles();
  AppendToResponseData( { 'action' => 'SendFileList',
                          'files' => $files });
}

# Add a password list to the response.
# Params:
#   - $safe: The filename of the safe (without path).
#   - $key: The master password to open the safe with.
sub SendPasswordList
{
  my ($safe, $key) = @_;
  # Read the available safe files.
  my $passwords = GetPasswordList($safe, $key);
  # Filter the passwords list before transmission.
  # It should only contain id, title, group and username.
  $passwords = FilterDetails($passwords);
  AppendToResponseData ({ 'action' => 'SendPasswordList',
                          'safe_active' => $safe,
                          'passwords' => $passwords });
}

# Add the password details for a password to the response.
# Params:
#   - $safe: The filename of the safe (without path).
#   - $password: The uuid of the password to add.
#   - $key: The master password to open the safe with.
sub SendPasswordDetails
{
  my ($safe, $password, $key) = @_;
  # Read the available safe files.
  my $passwords = GetPasswordList($safe, $key);
  my $password_details = {};
  foreach (@$passwords) {
    if ((defined $_->{'UUID'}) and ($_->{'UUID'} eq $password)) {
      $password_details->{'uuid'} = $_->{'UUID'};
      if (defined $_->{'User'}) { $password_details->{'user'} = $_->{'User'}; }
      if (defined $_->{'Title'}) { $password_details->{'title'} = $_->{'Title'}; }
      if (defined $_->{'Password'}) { $password_details->{'password'} = $_->{'Password'}; }
      if (defined $_->{'Group'}) { $password_details->{'group'} = $_->{'Group'}; }
      if (defined $_->{'URL'}) { $password_details->{'url'} = $_->{'URL'}; }
      if (defined $_->{'Notes'}) { $password_details->{'notes'} = $_->{'Notes'}; }
      if (defined $_->{'ATime'}) { $password_details->{'atime'} = $_->{'ATime'}; }
      if (defined $_->{'RecordMTime'}) { $password_details->{'mtime'} = $_->{'RecordMTime'}; }
      if (defined $_->{'PWMTime'}) { $password_details->{'pwmtime'} = $_->{'PWMTime'}; }
      if (defined $_->{'PWHistory'}) { $password_details->{'history'} = $_->{'PWHistory'}; }
      last;
    }
  }
  AppendToResponseData ({ 'action' => 'SendPasswordDetails',
                          'safe_active' => $safe,
                          'password_active' => $password,
                          'password_details' => $password_details});
}


# Check if a specified filename matches a safe.
sub ValidSafe
{
  my $filename = shift;
  opendir(DIR, $safe_dir);
  my @result = grep { ! /^$filename$/ } readdir(DIR);
  closedir(DIR);
  if (not (scalar @result)) {
    $response->{'errnr'} = 2001;
    $response->{'errmsg'} = 'Invalid safe file.';
  }
  return (scalar @result);
}

# Handle the input parameters.
# Attention: this is user input and has to be checked for sane values!!!
# Execute methods based on the action parameter.
if ((! $cgi->param()) or
      (! defined $cgi->param('action')) or
      ($cgi->param('action') eq 'InitSession')) {
  InitSession();
}
else {
  if ($cgi->param()) {
    $response->{'type'} = 'session_traffic';
    # Check for a session id.
    if (defined $cgi->param('session_id')) {
      $session_id = $cgi->param('session_id');
      $session_id =~ s/[^0-9]//g; # Sanity check the session id.
    }
    else { $session_id = ''; }

    # If we have a valid session id and an action parameter, we
    # can continue execution.
    if (($session_id =~ /^[0-9]+$/)) {
      my $action = $cgi->param('action');
      if ($action eq 'SetSessionKey') {
        my $session_key_encrypted = $cgi->param('session_key');
        SetSessionKey($session_key_encrypted);
      }
      else {
        $session_key = GetSessionKey();
        $action = OpensslAesDecrypt($cgi->param('action'), $session_key);
        if ($action eq 'SendFileList') {
          SendFileList();
        }
        elsif ($action eq 'SendPasswordList') {
          my $master_password = OpensslAesDecrypt($cgi->param('master_password'), $session_key);
          my $safe_active = OpensslAesDecrypt($cgi->param('safe_active'), $session_key);
          if (ValidSafe($safe_active)) { SendPasswordList($safe_active, $master_password); }
          $response->{'master_password'} = $master_password;
        }
        elsif ($action eq 'SendPasswordDetails') {
          my $master_password = OpensslAesDecrypt($cgi->param('master_password'), $session_key);
          my $safe_active = OpensslAesDecrypt($cgi->param('safe_active'), $session_key);
          my $password_active = OpensslAesDecrypt($cgi->param('password_active'), $session_key);
          SendPasswordDetails($safe_active, $password_active, $master_password);
        }
      $response->{'action'} = $action;
      }
    }
    else {
      $response->{'errnr'} = 1001;
      $response->{'errmsg'} = "Invalid session id.";
    }
  }
}


# Send a HTTP header.
print $cgi->header(-type => 'application/json',
                     -charset=>'UTF-8',
                     -expires=>'-3d',
                     -'Cache-Control'=>'no-store,no-cache,must-revalidate,private',
                     -Pragma=>'no-cache');
# We should always have a response.
print EncodeResponse($response);
