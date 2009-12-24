
function GetMasterPassword()
{
  return top.headline.master_password;
}

function GetRequestKey()
{
  return top.headline.request_key;
}

function SetRequestKey(request_key)
{
  top.headline.request_key = request_key;
}

function GetModulus()
{
  return document.ResponseForm.modulus.value;
}

function GetPublicExponent()
{
  return document.ResponseForm.public_exponent.value;
}

function GetAction()
{
  return document.RequestForm.action.value;
}

function SetAction(action)
{
  document.RequestForm.action.value = action;
}

function GetFilename()
{
  return document.RequestForm.filename.value;
}

function SetFilename(filename)
{
  document.RequestForm.filename.value = filename;
}


function GetPassword()
{
  return document.RequestForm.password.value;
}

function SetPassword(password)
{
  document.RequestForm.password.value = password;
}


function SetContent(page)
{
  document.getElementById('pwsafe-web-content').innerHTML = page;
}

function ResetError()
{
  var error_obj = top.headline.document.getElementById('pwsafe-web-error');
  if (error_obj) {
    error_obj.innerHTML = '&nbsp;';
    // TODO: reset style.
  }
}

function SetError(error)
{
  var error_obj = top.headline.document.getElementById('pwsafe-web-error');
  if (error_obj) {
    error_obj.innerHTML = error;
    // TODO: set style (red, flashing, etc.).
    window.setTimeout('ResetError()', 3000);
  }
  else {
    alert(error);
  }
}


/* function ByteArrayToHexStr(&array)
{
  var str = '';
  for (var n = 0; n < array.length; ++n) {
    if (array[n] < 0x10) { str += '0' + array[n].toString(16); }
    else { str += array[n].toString(16); }
  }
  return str;
}
*/

/** Return a binary string containing the bytes of the array. */
/*
function ByteArrayToStr(&array)
{
  var str = '';
  for (var n = 0; n < array.length; ++n) {
    str += chr(array[n]);
  }
  return str;
}
*/

/** Decrypt the base64 encoded encrypted page using the request key.
 * If no request key is set, it is just base64 decoded. */
function GetDecryptedPage()
{
  var request_key = GetRequestKey();
  var page;
  if (request_key.length == 32) {
    page = GibberishAES.dec(page64, request_key);
    // Note: GibberishAES.dec expects base64 encoded data.
  }
  else {
    page = decodeBase64(page64);
  }
  // Look for the known start string to check if
  // decryption was successful.
  if (page.substr(0,30) != '<!-- pwsafe-web page start -->') {
    SetError('GetDecryptedPage: Error decrypting the page.');
    return '';
  }
  return page;
}

/** Return a byte array containing byte_count random bytes.
    Attention: there might be are null bytes and newline
    characters in the array! */
function GenerateRandom(byte_count)
{
  var rng = new SecureRandom();
  var bytes = new Array();
  bytes.length = byte_count;
  rng.nextBytes(bytes);
  return bytes;
}

/** Return a random binary string with byte_count bytes. */
function GenerateRandomStr(byte_count, is_key)
{
  var rng = new SecureRandom();
  var str = '';
  var bytes = new Array(); bytes.length = 1;
  for (var i = 0; i < byte_count; ++i){
    rng.nextBytes(bytes);

    // do not allow 0 and 10 (newline) to be part of the random number if
    // generating a key.
    // those are not treated correctly when passed to openssl on te server
    // side.
    if ((is_key == true) || (is_key == null)) {
      while ((bytes[0] == 0) | (bytes[0] == 10)) {
        rng.nextBytes(bytes);
      }
    }

    // ntos converts a number to its binary representation. Found in encoding.js.
    str += String.fromCharCode(bytes[0]);
  }
  return str;
}

/** Encrypt with the RSA public key and store in the RequestForm. */
function EncryptAndStoreRSA(name, value)
{
  // initialize the rsa object.
  rsa = new RSAKey();
  rsa.setPublic(GetModulus(), GetPublicExponent());
  var encrypted = rsa.encrypt(value);
  if(encrypted) {
    document.RequestForm[name].value = hex2b64(encrypted);
  }
}

/** Encrypt with AES and store in the RequestForm.
 *  The key needs to have a length of 32 chars (265 bit) and
 *  is expected to be a binary string. */
function EncryptAndStoreAES(name, value, key)
{
  // Sanitiy check the key, so nothing unencrypted gets sent.
  if (key.length != 32) {
    alert('Error: EncryptAndStoreAES: key.length != 32.');
    return;
  }
  var encrypted = GibberishAES.enc(value, key);
  // Note: GibberishAES.enc does return base64 encoded data already.
  if(encrypted) {
    document.RequestForm[name].value = encrypted;
  }
}

/*
Always trasmit:
  - request key
  - encryption key
  - master password
  - action (what do i want?)
Depending on the action:
  - overview (contains a list of safe files)
  - display file (display all entries of the file):
    - filename
  - display password (display details for a specific password entry)
    - filename
    - password uuid

Available actions (as named in code):
  - view_overview
  - view_file
  - view_password

Everything is transmitted in (hidden) input boxes of a form. The form
is then submitted.
For transmission always the following encapsulation is used:
  transmit(base64encode((ecrypt(msg))))
*/
function EncryptAndSubmit()
{
  var request_key = GetRequestKey();
  if (request_key.length != 32) {
    // TODO: Create a new request key.
    request_key = GenerateRandomStr(32);
//    request_key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF';
    SetRequestKey(request_key);
  }
  var encryption_key = GenerateRandomStr(32);
//  encryption_key = '12345678901234567890123456789012';

  // so we can encrypt everything now.
  EncryptAndStoreRSA('encryption_key', encryption_key);
  EncryptAndStoreAES('request_key', request_key, encryption_key);
  var action = GetAction();
  switch (action) {
    case 'view_file':
      EncryptAndStoreAES('master_password', GetMasterPassword(), encryption_key);
      EncryptAndStoreAES('filename', GetFilename(), encryption_key);
      break;
    case 'view_password':
      EncryptAndStoreAES('master_password', GetMasterPassword(), encryption_key);
      EncryptAndStoreAES('filename', GetFilename(), encryption_key);
      EncryptAndStoreAES('password', GetPassword(), encryption_key);
      break;
    default:
      break;
  }
  EncryptAndStoreAES('action', action, encryption_key);

  document.RequestForm.submit();
  return true;
}

/** Send the request for opening a file. */
function OpenFile(filename) {
  SetFilename(filename);
  SetAction('view_file');
  EncryptAndSubmit();
}

/** Send the request for opening a password. */
function OpenPassword(filename, password) {
  SetFilename(filename);
  SetPassword(password);
  SetAction('view_password');
  EncryptAndSubmit();
}

/** UI: Display a password group with all its entries. */
function ShowGroup(id)
{
  var obj = document.getElementById(id);
  obj.style.visibility = 'inherit';
  obj.style.height = 'auto';
  var link = document.getElementById(id+'_link');
  link.href = "javascript:HideGroup('" + id + "')";
}

/** UI: Hide a password group with all its entries. */
function HideGroup(id)
{
  var obj = document.getElementById(id);
  obj.style.visibility = 'hidden';
  obj.style.height = 0;
  var link = document.getElementById(id + '_link');
  link.href = "javascript:ShowGroup('" + id + "')";
}

/** Display the password in plaintext on the screen. */
function ShowPassword()
{
  var password = document.getElementById('hidden_password_field').value;
  document.getElementById('plaintext_password_field').innerHTML = password;
  var link = document.getElementById('toggle_password_visibility_link');
  link.href = "javascript:HidePassword()";
  link.innerHTML = 'hide';
}

/** Do not display the password in plaintext on the screen. */
function HidePassword()
{
  document.getElementById('plaintext_password_field').innerHTML = '[hidden]';
  var link = document.getElementById('toggle_password_visibility_link');
  link.href = "javascript:ShowPassword()";
  link.innerHTML = 'show';
}

function EvPwsafeBodyLoad()
{
  // Write the page to the document.
  SetContent(GetDecryptedPage());

  // Seed the random number generator.
  rng_seed_time();
}

function EvPwsafeBodyKeyPress()
{
  // Seed the random number generator.
  rng_seed_time();
  return true;
}

function EvRequestFormOnSubmit()
{
  return true;
}
