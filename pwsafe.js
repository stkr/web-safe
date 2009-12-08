
function GetMasterPassword()
{
  return top.headline.document.ResponseForm.master_password.value;
}

function GetRequestKey()
{
  return top.headline.document.ResponseForm.request_key.value;
}

function SetRequestKey(request_key)
{
  top.headline.document.ResponseForm.request_key.value = request_key;
}

function GetModulus()
{
  return document.ResponseForm.modulus.value;
}

function GetPublicExponent()
{
  return document.ResponseForm.public_exponent.value;
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

/** Return a byte array containing byte_count random bytes. */
function GenerateRandom(byte_count)
{
  var rng = new SecureRandom();
  var bytes = new Array();
  bytes.length = byte_count;
  rng.nextBytes(bytes);
  return bytes;
}

/** Return a random binary string with byte_count bytes. */
function GenerateRandomStr(byte_count)
{
  var rng = new SecureRandom();
  var str = '';
  var bytes = new Array(); bytes.length = 1;
  for (var i = 0; i < byte_count; ++i){
    rng.nextBytes(bytes);
    str += String.fromCharCode(bytes[0]);
  }
  alert(str);
  return str;
}

/** Encrypt with the RSA public key and store in the form */
function EncryptAndStoreRSA(name, value)
{
  var encrypted = window.rsa.encrypt(value);
  if(encrypted) {
    document.RequestForm[name].value = hex2b64(encrypted);
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
    - groupname
    - password title (probably better: uuid (?))

Available actions (as named in code):
  - view_overview
  - view_file
  - view_password

Everything is transmitted in (hidden) input boxes of a form. The form
is then submitted.
For transmission always the following encapsulation is used:
  transmit(base64encode((ecrypt(msg))))
*/
function EncryptRequest()
{
  var request_key = GetRequestKey();
  if (request_key.length != 32) {
    // TODO: Create a new request key.
    request_key = GenerateRandomStr(32);
    request_key = '12345678901234567890123456789012';
    SetRequestKey(request_key);
  }
  var encryption_key = GenerateRandomStr(32);
  encryption_key = '12345678901234567890123456789012';

  // so we can encrypt everything now.
  EncryptAndStoreRSA('encryption_key', encryption_key);
//  EncryptAndStoreAES('encryption_key', encryption_key);
// TODO: to be continued.
  document.RequestForm.submit();
  return true;
}

function EvPwsafeBodyLoad()
{
  // Write the page contents from the base64 encoded encrypted string passed
  // by the server
  // document.getElementById('pwsafe_gui_content').innerHTML = decodeBase64(page64);

  // Seed the random number generator.
  rng_seed_time();

  // initialize the rsa object.
  window.rsa = new RSAKey();
  window.rsa.setPublic(GetModulus(), GetPublicExponent());
  return true;
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
