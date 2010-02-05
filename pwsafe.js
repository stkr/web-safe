/** The url to use for ajax calls. */
var ajax_url = "/cgi-bin/web-safe/pwsafe.cgi";


/**
 * Handle the session establishment and provides low level functions for
 * the encryption and decryption of messages.
 */
var AjaxEncryptor = (function()
{
  /** An identification for the current session. */
  var _session_id = '';
  /** A key used for AES encryption of the session data. */
  var _session_key = '';
  /** RSA encryption (session key exchange) - modulus of the
   *  key of the server. */
  var _modulus_server = '';
  /** RSA encryption (session key exchange) - public exponent of the
   *  key of the server. */
  var _public_exponent_server = '';
  /** RSA encryption (session key exchange) - modulus of the
   *  key of the client. */

  /** The protocol state for initial session key exchange. The values
   *  have the following meanings:
   *    0: Initial state, no data exchange took place.
   *    1: The client has initiated a new session.
   *    2: The server has responded. The client now knows the
   *       public key of the server and the session id.
   *    3: The client has sent the client-chosen session key.
   *       From this point, all messages are encrypted using AES
   *       and the session key. */
  var _auth_protocol_state = 0;

  /** A function taking an error number and an error message (string)
   *  as parameter which is called whenever an error occurs. */
  var _error_handler = function(nr, msg) { alert(msg + ((nr > 0) ? ('(' + nr + ')') : (''))); };

  /** A function taking a response object as parameter which is called
   *  whenever a response was successfully received. */
   var _response_handler = 0;

  /** Return the session id. */
  var GetSessionId = function () { return _session_id; };

  /** Set an error handler. */
  var SetErrorHandler = function(handler) { _error_handler = handler; };
  /** Set a response handler. */
  var SetResponseHandler = function(handler) { _response_handler = handler; };

  /** Raise an error. */
  var RaiseError = function(nr, msg)
  {
    if (_error_handler) { _error_handler(nr, msg); }
  };

  /** Return a random string. */
  function GenerateRandomStr(length)
  {
    var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz'.split('');
    if (! length) { length = Math.floor(Math.random() * chars.length); }
    var str = '';
    for (var i = 0; i < length; i++) {
        str += chars[Math.floor(Math.random() * chars.length)];
    }
    return str;
  }

  /** Encrypt (with AES and the session key) and base64 encode a message. */
  var AESEncrypt = function (msg)
  {
    // Check the protocol state.
    if (_auth_protocol_state != 3) {
      RaiseError(0, 'AESEncrypt: _auth_protocol_state != 3 ('+_auth_protocol_state+')');
      return '';
    }
    // Check the session key.
    if (_session_key.length < 64) {
      RaiseError(0, 'AESEncrypt: _session_key.length < 64 ('+_session_key.length+')');
      return '';
    }
    // Note: GibberishAES.enc does return base64 encoded data already.
    return GibberishAES.enc(msg, _session_key);
  };

  /** Base64 decode and decrypt (with AES and the session key) a message. */
  var AESDecrypt = function (msg)
  {
    // Check the protocol state.
    if (_auth_protocol_state != 3) {
      RaiseError(0, 'AESDecrypt: _auth_protocol_state != 3 ('+_auth_protocol_state+')');
      return '';
    }
    // Check the session key.
    if (_session_key.length < 64) {
      RaiseError(0, 'AESDecrypt: _session_key.length < 64 ('+_session_key.length+')');
      return '';
    }
    // Note: GibberishAES.enc does return base64 encoded data already.
    return GibberishAES.dec(msg, _session_key);
  };

  var RSAEncrypt = function(msg)
  {
    var rsa = new RSAKey();
    rsa.setPublic(_modulus_server, _public_exponent_server);
    var encrypted = rsa.encrypt(msg);
    if(encrypted) {
      return hex2b64(encrypted);
    }
    return '';
  };


  /** Plaintext interpretation of the response for debugging. */
  var DebugResponse = function(response)
  {
    $('#web-safe-debug').append('<br /><br />' + response);
    response = $.parseJSON(response);
    HandleResponse(response);
  }

  /** Handle the response of an ajax request. */
  var HandleResponse = function (response)
  {
    switch (response.type) {
      case 'server_auth':
        HandleServerAuth(response);
        break;
      case 'session_traffic':
        HandleSessionTraffic(response);
        break;
      default:
        // something went terribly wrong.
        RaiseError(0, 'HandleResponse: unknown response type (' + response.type + ')');
        break;
    }
  }

  /** Handle session traffic. This decrypts data if
   *  necessary and returns the decrypted response for
   *  further processing. */
  var HandleSessionTraffic = function (response)
  {
    if (_response_handler) {
      // decrypt if necessary
      if((response.encrypted) && (response.data)) {
        response.data = $.parseJSON(AESDecrypt(response.data));
      }
      _response_handler(response);
    }
  }

  /** Send generic traffic. */
  var SendRequest = function(request_data)
  {
    // Use jQuery for the ajax request.
    $.getJSON(ajax_url, request_data, HandleResponse);
    // $.ajax({url: ajax_url, data: request_data, dataType: "text", success: DebugResponse});
  }

  /** Send session traffic. The data is sent encrypted. */
  var SendEncrypted = function (data)
  {
    if ((_session_id) && (_session_id != '')) {
      var data_transmission = { 'session_id': _session_id };
      for (var key in data) {
        data_transmission[key] = AESEncrypt(data[key]);
      }
      SendRequest(data_transmission);
    }
    else {
      RaiseError(0, 'SendEncrypted: Cannot send encrypted data without session id.');
    }
  }

  /** Request a public key and a session id from the server. */
  var InitSession = function ()
  {
    SendRequest();
    _auth_protocol_state = 1;
  };

  /** Store public key of the server and session information. */
  var HandleServerAuth = function (response)
  {
    _modulus_server = response.modulus_server;
    _public_exponent_server = response.public_exponent_server;
    _session_id = response.session_id;
    _auth_protocol_state = 2;
    SendClientSessionKey();
  };

  /** Send the client-chosen part of the session key. */
  var SendClientSessionKey = function ()
  {
    _session_key = GenerateRandomStr(64);
    var data = {'action': 'SetSessionKey',
                'session_id': _session_id,
                'session_key': RSAEncrypt(_session_key)};
    _auth_protocol_state = 3;
    SendRequest(data);
  };


  /** Reset the authentitcation protocol state and
   *  restart authentication. */
  var ResetSession = function ()
  {
    _modulus_server = '';
    _public_exponent_server = '';
    _session_id = '';
    _auth_protocol_state = 0;
  };

  // Export some public functions:
  return {
      'GetSessionId': GetSessionId,
      'SetResponseHandler': SetResponseHandler,
      'SetErrorHandler': SetErrorHandler,
      'InitSession': InitSession,
      'ResetSession': ResetSession,
      'SendRequest': SendRequest,
      'SendEncrypted': SendEncrypted
  };

})();


/**
 * Contains event handlers and GUI generation code.
 */
var WebSafeGUI = (function()
{
  /** The master password used for opening the safe. */
  var _master_password = '';

  /** A handler for the ajax responses. */
  var HandleResponse = function (response)
  {
    if (response.errmsg) {
      HandleError(0, response.errmsg);
    }
    else if (response.data) {
      if (response.data.files) {
        GenFileList(response.data.files);
      }
      if ((response.data.safe_active) && (response.data.passwords)) {
        GenPasswordList(response.data.safe_active, response.data.passwords);
      }
      if ((response.data.safe_active) && (response.data.password_active) && (response.data.password_details)) {
        GenPasswordDetails(response.data.safe_active, response.data.password_active, response.data.password_details);
      }
    }
    else {
      // Something went terribly wrong.
      HandleError(0, 'HandleResponse: Neither data nor errormessage received.');
    }
  };

  /** A handler for the ajax responses. */
  var HandleError = function (nr, msg)
  {
    msg = msg + ((nr > 0) ? ('(' + nr + ')') : (''));
    $('#web-safe-error').html(msg).show();
    window.setTimeout(function() {$('#web-safe-error').fadeOut('slow'); }, 3000);
  };

  /** Send an encrypted ajax request. */
  var SendRequest = function(data)
  {
    AjaxEncryptor.SendEncrypted(data);
  };

  /** When using file and groupnames as id values, they might contain
   *  '.' and ':' which are special characters for css selectors. Therefore,
   *  those chars need to be escaped. */
  var ToId = function id(id) { return '#' + id.replace(/(:|\.)/g,'\\$1'); };

  /** Output an ISO timestamp from a usinx timestamp. */
  var ISOFmtDate = function(date) {
    var pad = function (amount, width) {
      var padding = "";
      while (padding.length < width - 1 && amount < Math.pow(10, width - padding.length - 1))
        padding += "0";
      return padding + amount.toString();
    }
  date = date ? new Date(date) : new Date();
  var offset = date.getTimezoneOffset();
  return pad(date.getFullYear(), 4)
      + "-" + pad(date.getMonth() + 1, 2)
      + "-" + pad(date.getDate(), 2)
      + "T" + pad(date.getHours(), 2)
      + ":" + pad(date.getMinutes(), 2)
      + ":" + pad(date.getSeconds(), 2)
      + "." + pad(date.getMilliseconds(), 3)
      + (offset > 0 ? "-" : "+")
      + pad(Math.floor(Math.abs(offset) / 60), 2)
      + ":" + pad(Math.abs(offset) % 60, 2);
  }

  /** Convert newlines to <br>.
   *  Found on http://wiki.github.com/kvz/phpjs/
   *     example 1: nl2br('Kevin\nvan\nZonneveld');
   *     returns 1: 'Kevin<br />\nvan<br />\nZonneveld'
   *     example 2: nl2br("\nOne\nTwo\n\nThree\n", false);
   *     returns 2: '<br>\nOne<br>\nTwo<br>\n<br>\nThree<br>\n'
   *     example 3: nl2br("\nOne\nTwo\n\nThree\n", true);
   *     returns 3: '<br />\nOne<br />\nTwo<br />\n<br />\nThree<br />\n' */
  var Nl2Br = function (str, is_xhtml) {
      var breakTag = (is_xhtml || typeof is_xhtml === 'undefined') ? '<br />' : '<br>';
      return (str + '').replace(/([^>\r\n]?)(\r\n|\n\r|\r|\n)/g, '$1'+ breakTag +'$2');
  }

  /** Split a groupname to its subgroups. */
  var SplitGroupname = function(groupname)
  {
    var parts = groupname.split('.');
    var unescaped = [];
    var prefix = '';
    $.each(parts,
      function(index, part) {
        if (part.substring(part.length - 1, part.length) == "\\") {
          prefix += part + '.';
        }
        else {
          unescaped.push(prefix + part);
          prefix = '';
        }
      });
    return unescaped;
  }

  var Init = function()
  {
    AjaxEncryptor.SetResponseHandler(HandleResponse);
    AjaxEncryptor.SetErrorHandler(HandleError);
    AjaxEncryptor.InitSession();
    $('#web-safe-content').empty()
        .append($('<div></div>').attr('id', 'web-safe-list'))
        .append($('<div></div>').attr('id', 'web-safe-error'))
        .append($('<div></div>').attr('id', 'web-safe-details'))
        .append($('<div></div>').attr('id', 'web-safe-debug'));
    $('#web-safe-error').hide();
    Resize();
    $(window).resize(Resize);
  }

  var Resize = function()
  {
    var margin = 25; // a safety margin for scrollbars and browser differences.
    var obj = $('#web-safe-error');
    var spacing_error = parseInt(obj.css('margin-left')) +
          parseInt(obj.css('margin-right')) +
          parseInt(obj.css('padding-right')) +
          parseInt(obj.css('padding-right'));
    $('#web-safe-list').height($(document).height() - margin - $('#web-safe-header').height());
    $('#web-safe-list').width(($(document).width() - margin) * 0.30);
    $('#web-safe-error').width(($(document).width() - spacing_error - margin) * 0.70);
    $('#web-safe-details').width(($(document).width() - margin) * 0.70);
    $('#web-safe-debug').width(($(document).width() - margin) * 0.70);
  }

  var QueryMasterPassword = function ()
  {
    _master_password = '';
    $('#web-safe-master_password-query')
        .html(
          '<form action="headline.htm" onsubmit="WebSafeGUI.SubmitMasterPassword(); return false;">' +
            '<div><input type="password" id="web-safe-master_password-field" name="master_password" size="40" />&nbsp;&nbsp;' +
            '<input type="button" value="unlock" onclick="WebSafeGUI.SubmitMasterPassword()" /><\/div>' +
          '<\/form>');
    $('#web-safe-master_password-field').focus();
  }

  var SubmitMasterPassword = function ()
  {
    _master_password = $('#web-safe-master_password-field').val();
    $('#web-safe-master_password-query')
        .html('<a href="javascript:WebSafeGUI.QueryMasterPassword();">change master password<\/a>');
  }


  /** Generate the list item for a file in the file list. */
  var GenFile = function (file) {
    return $('<li></li>')
      .attr('id', 'file-' + file)
      .addClass('file')
      .append(
        $('<a></a>')
          .attr('id', 'lnk-' + file)
          .attr({"href": "javascript:WebSafeGUI.OpenFile('" + file + "');"})
          .html(file)
      );
  }

  /** Generate the file list. This deletes all other controls
   *  except the file list. */
  var GenFileList = function (files) {
    var list = $('<ul></ul>');
    $.each(files, function(nr, file) { list.append(GenFile(file)); });
    $('#web-safe-list').empty().append(list);
  }


  var GenGroup = function (group_full, group_title)
  {
    group_title = group_title.replace(/\\\./g, '.');
    return $('<li></li>')
      .addClass('group')
      .append($('<a></a>')
        .attr('id', 'lnk-' + group_full)
        .attr({"href": "javascript:WebSafeGUI.OpenGroup('" + group_full + "');"})
          .html(group_title)
      )
      .append($('<ul></ul>')
        .attr('id', group_full)
        .hide()
      );
  }

  /** Generate the password list for a file. */
  var GenPasswordList = function (safe_active, passwords) {

    var root_group = $(ToId('file-' + safe_active))
      .empty()
      .append(
        $('<a></a>')
          .attr('id', 'lnk-' + safe_active)
          .attr({"href": "javascript:WebSafeGUI.CloseGroup('" + safe_active + "');"})
          .html(safe_active)
      )
      .append($('<ul></ul>')
        .attr('id', safe_active)
      );

    var SortByGroup = function (a, b) {
      a = a.group;
      b = b.group;
      return a == b ? 0 : (a < b ? -1 : 1)
    }

    var SortByTitle = function (a, b) {
      a = a.title;
      b = b.title;
      return a == b ? 0 : (a < b ? -1 : 1)
    }

    // Sort by groupname and generate group hierarchy.
    passwords.sort(SortByGroup);
    var groups = {};
    $.each(passwords,
      function(index, password) {
        var groupname = password.group;
        if (groupname == '') return;
        if (! groups[groupname]) {
          var parts = SplitGroupname(groupname);
          var parent_group = root_group;
          var current_group = '';
          $.each(parts,
            function(index, part) {
              if (current_group != '') { current_group += '.'; }
              current_group += part;
              if (! groups[current_group]) {
                groups[current_group] = GenGroup(current_group, part);
                parent_group.find('ul:first').append(groups[current_group]);
              }
              parent_group = groups[current_group];
            });
        }
      });

    // Sort by title and fill in passwords.
    passwords.sort(SortByTitle);
    $.each(passwords,
      function(index, password) {
        var groupname = password.group;
        var obj = $('<li></li>')
          .addClass('password')
          .append(
            $('<a></a>')
              .attr('id', 'lnk-' + password.uuid)
              .attr('href', "javascript:WebSafeGUI.OpenPassword('" + safe_active + "', '" + password.uuid + "')")
              .html(password.title)
          );

        if (groupname == '') { root_group.find('ul:first').append(obj); }
        else { $(ToId(password.group)).append(obj) }
      });
  }

  var GenPasswordDetails = function(safe_active, password_active, password_details)
  {

    var headline = $('<h3>' + password_details.title + '</h3>');
    var table = $('<table summary="Password details."></table>');
    if (password_details.user) {
      table
        .append($('<tr></tr>')
          .append('<td>User:</td>')
          .append('<td>' + password_details.user + '</td>')
        );
    }
    if (password_details.password) {
      table
        .append($('<tr></tr>')
          .append('<td>Password:</td>')
          .append($('<td></td>')
            .attr('id', 'web-safe-password-field')
//            .data('password', password_details.password)
            .click(function() { $('#web-safe-password-field').unbind('click').html(password_details.password); })
            .html('[hidden]')
          )
        );
    }
    if (password_details.url) {
      table
        .append($('<tr></tr>')
          .append('<td>Url:</td>')
          .append('<td>' + password_details.url + '</td>')
        );
    }
    if (password_details.notes) {
      table
        .append($('<tr></tr>')
          .append('<td>Notes:</td>')
          .append('<td>' + Nl2Br(password_details.notes) + '</td>')
        );
    }
    if (password_details.atime) {
      table
        .append($('<tr></tr>')
          .append('<td>Added:</td>')
          .append('<td>' + ISOFmtDate(password_details.atime) + '</td>')
        );
    }
    if (password_details.mtime) {
      table
        .append($('<tr></tr>')
          .append('<td>Modified:</td>')
          .append('<td>' + ISOFmtDate(password_details.mtime) + '</td>')
        );
    }
    if (password_details.pwmtime) {
      table
        .append($('<tr></tr>')
          .append('<td>Last pw change:</td>')
          .append('<td>' + ISOFmtDate(password_details.pwmtime) + '</td>')
        );
    }
    if (password_details.history) {
      table
        .append($('<tr></tr>')
          .append('<td>History:</td>')
          .append('<td>' + password_details.history + '</td>')
        );
    }

    $('#web-safe-details').empty().append(headline).append(table);
  }


  /** Send the request for opening a file. */
  var OpenFile = function (safe_active) {
    if (_master_password == '') {
      HandleError(0, 'OpenFile: No master password was entered.');
    }
    else {
      SendRequest({ 'action': 'SendPasswordList',
                    'master_password': _master_password,
                    'safe_active': safe_active});
    }
  }

  /** Open a group */
  var OpenGroup = function (groupname) {
    $(ToId(groupname)).show();
    $(ToId('lnk-' + groupname)).attr('href', "javascript:WebSafeGUI.CloseGroup('" + groupname + "');");
  }

  /** Close a group */
  var CloseGroup = function (groupname) {
    $(ToId(groupname)).hide();
    $(ToId('lnk-' + groupname)).attr('href', "javascript:WebSafeGUI.OpenGroup('" + groupname + "');");
  }



  /** Send the request for opening a password. */
  var OpenPassword = function (safe_active, password_active) {
    if (_master_password == '') {
      HandleError(0, 'OpenFile: No master password was entered.');
    }
    else {
      SendRequest({ 'action': 'SendPasswordDetails',
                    'master_password': _master_password,
                    'safe_active': safe_active,
                    'password_active': password_active });
    }
  }

  return {
    'Init': Init,
    'QueryMasterPassword': QueryMasterPassword,
    'SubmitMasterPassword': SubmitMasterPassword,
    'OpenFile': OpenFile,
    'OpenGroup': OpenGroup,
    'CloseGroup': CloseGroup,
    'OpenPassword': OpenPassword
  };

})();
