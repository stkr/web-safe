/**
 * web-safe - A browser based online password safe solution.
 * Copyright (C) 2010  Stefan Krug
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Written by Stefan Krug <st@skobeloff.eu>.
 */

/**
 * Configuration:
 * -----------------------
 */

/** The url to use for ajax calls. */
var ajax_url = "/cgi-bin/web-safe/pwsafe.cgi";

/**
 * End of Configuration
 * -------------------------
 */


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

  /** When trying to automatically establish a session, this counter
   *  is increased to limit the retries. */
  var _init_session_counter = 0;

  /** A function taking an error number and an error message (string)
   *  as parameter which is called whenever an error occurs. */
  var _error_handler = function(nr, msg, warning) {
    alert(msg);
  };

  /** A function taking a response object as parameter which is called
   *  whenever a response was successfully received. */
  var _response_handler = 0;

  /** A function which is called whenever a session is established. */
  var _session_established_handler = 0;

  /** Return the session id. */
  var GetSessionId = function () { return _session_id; };

  /** Set an error handler. */
  var SetErrorHandler = function(handler) { _error_handler = handler; };
  /** Set a response handler. */
  var SetResponseHandler = function(handler) { _response_handler = handler; };
  /** Set a session established handler. */
  var SetSessionEstablishedHandler = function(handler) { _session_established_handler = handler; };

  /** Raise an error. */
  var RaiseError = function(nr, msg)
  {
    // For session related errors, try to establish
    // a new session. This means, the user has to execute
    // the action again.
    if ((nr > 1000) && (nr < 2000)) {
      if (_error_handler) { _error_handler(nr, msg, 1); }
      InitSession();
    }
    // Other errors are not resolvable here and must be
    // delegated.
    else {
      if (_error_handler) { _error_handler(nr, msg); }
    }
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
      RaiseError(3001, 'AESEncrypt: _auth_protocol_state != 3 ('+_auth_protocol_state+')');
      return '';
    }
    // Check the session key.
    if (_session_key.length < 64) {
      RaiseError(1002, 'AESEncrypt: _session_key.length < 64 ('+_session_key.length+')');
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
      RaiseError(3002, 'AESDecrypt: _auth_protocol_state != 3 ('+_auth_protocol_state+')');
      return '';
    }
    // Check the session key.
    if (_session_key.length < 64) {
      RaiseError(1002, 'AESDecrypt: _session_key.length < 64 ('+_session_key.length+')');
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
    if (response.errmsg) {
      var nr = 0;
      if (response.errnr) { nr = response.errnr; }
      RaiseError(nr, response.errmsg);
    }
    else {
      switch (response.type) {
        case 'server_auth':
          HandleServerAuth(response);
          break;
        case 'session_traffic':
          // reset session init counter when receiving session data.
          _init_session_counter = 0;
          HandleSessionTraffic(response);
          break;
        default:
          // something went terribly wrong.
          RaiseError(3003, 'HandleResponse: unknown response type (' + response.type + ')');
          break;
      }
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
      RaiseError(1001, 'SendEncrypted: Cannot send encrypted data without session id.');
    }
  }

  /** Request a public key and a session id from the server. */
  var InitSession = function ()
  {
    // Just retry to init a session three times.
    if (_init_session_counter < 3) {
      SendRequest();
      _auth_protocol_state = 1;
      _init_session_counter++;
    }
    else {
      RaiseError(3004, 'InitSession: Retried too often without success.');
    }
  };

  /** Store public key of the server and session information. */
  var HandleServerAuth = function (response)
  {
    if (response.key_verification) {
      if (AESDecrypt(response.key_verification) == 'key_verification') {
        if (_session_established_handler) { _session_established_handler(); }
      }
      else {
        RaiseError(1002, 'Invalid session key.');
      }
    }
    else {
      _modulus_server = response.modulus_server;
      _public_exponent_server = response.public_exponent_server;
      _session_id = response.session_id;
      _auth_protocol_state = 2;
      SendClientSessionKey();
    }
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
    _init_session_counter = 0;
  };

  // Export some public functions:
  return {
      'GetSessionId': GetSessionId,
      'SetResponseHandler': SetResponseHandler,
      'SetSessionEstablishedHandler': SetSessionEstablishedHandler,
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

  /** A flag indicating whether a session was established
   *  before. */
  var _session_established = 0;

  /** The id of the currently open file. */
  var _current_file_id = '';
  /** The id of the currently open group. */
  var _current_group_id = '';

  /** A handler for the ajax responses. */
  var HandleResponse = function (response)
  {
    if (response.errmsg) {
      HandleError(response.errnr, response.errmsg);
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
      HandleError(3003, 'HandleResponse: Neither data nor errormessage received.');
    }
  };

  /** A handler for the ajax responses. */
  var HandleError = function (nr, msg, warning)
  {
    msg = msg;
    var obj = $('#web-safe-error');
    obj.html(msg).show();
    if (warning) {
      obj.removeClass('error').addClass('warning');
      window.setTimeout(function() { obj.fadeOut('slow'); }, 3000);
    }
    else {
      obj.removeClass('warning').addClass('error');
      window.setTimeout(function() { obj.fadeOut('slow'); }, 10000);
    }
  };

  /** If no session has been established before, request a file list. */
  var HandleSessionEstablished = function ()
  {
    if (! _session_established) {
      SendRequest({ 'action': 'SendFileList' });
      _session_established = 1;
    }
  };

  /** Send an encrypted ajax request. */
  var SendRequest = function(data)
  {
    AjaxEncryptor.SendEncrypted(data);
  };

  /** Convert a unix timestampt to a formatted timestamp. */
  var FmtDate = function(date) {
    var pad = function (amount, width) {
      var padding = "";
      while (padding.length < width - 1 && amount < Math.pow(10, width - padding.length - 1))
        padding += "0";
      return padding + amount.toString();
    }
  date = date ? new Date(date * 1000) : new Date();
  var offset = date.getTimezoneOffset();
  return pad(date.getFullYear(), 4)
      + "-" + pad(date.getMonth() + 1, 2)
      + "-" + pad(date.getDate(), 2)
      + " " + pad(date.getHours(), 2)
      + ":" + pad(date.getMinutes(), 2)
      + ":" + pad(date.getSeconds(), 2);
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

  var Htmlentities = function (str) {
    return $('<div/>').text(str).html();
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
    AjaxEncryptor.SetSessionEstablishedHandler(HandleSessionEstablished);
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
    var margin = 20; // a safety margin for scrollbars and browser differences.
    var obj = $('#web-safe-error');
    var spacing_error = parseInt(obj.css('margin-left')) +
          parseInt(obj.css('margin-right')) +
          parseInt(obj.css('padding-right')) +
          parseInt(obj.css('padding-right'));
    $('#web-safe-list').height($(window).height() - margin - $('#web-safe-header').height());
    $('#web-safe-list').width(($(window).width() - margin) * 0.30);
    $('#web-safe-error').width(($(window).width() - spacing_error - margin) * 0.70);
    $('#web-safe-details').width(($(window).width() - margin) * 0.70);
    $('#web-safe-debug').width(($(window).width() - margin) * 0.70);
  }

  var QueryMasterPassword = function ()
  {
    _master_password = '';
    if (top != self) {
      HandleError(2003, "For security reasons, this application needs to have its own window. " +
          "<a href=\"#\" target=\"_blank\">Open in new window.</a>");
    }
    else {
      $('#web-safe-master_password-query')
          .html(
            '<form action="headline.htm" onsubmit="WebSafeGUI.SubmitMasterPassword(); return false;">' +
              '<div>master password:&nbsp;&nbsp;<input type="password" id="web-safe-master_password-field" name="master_password" size="20" />&nbsp;&nbsp;' +
              '<input type="button" value="unlock" onclick="WebSafeGUI.SubmitMasterPassword()" /><\/div>' +
            '<\/form>');
      $('#web-safe-master_password-field').focus();
    }
  }

  var SubmitMasterPassword = function ()
  {
    _master_password = $('#web-safe-master_password-field').val();
    $('#web-safe-master_password-query')
        .html('<a href="javascript:WebSafeGUI.QueryMasterPassword();">change master password<\/a>');
  }

  var ShowField = function (field) {
    field
      .empty()
      .text(field.data('plaintext'));
    field
      .append('&nbsp;&nbsp;')
      .append($('<a href="#"></a>')
        .click( function() { HideField(field); } )
        .text('hide')
      );
    Resize();
   }

  var HideField = function (field) {
    field
      .empty()
      .text('[hidden]');
    field
      .append('&nbsp;&nbsp;')
      .append($('<a href="#"></a>')
        .click( function() { ShowField(field); } )
        .text('show')
      );
    Resize();
  }

  var GenHiddenField = function (data) {
    var field = $('<span></span>')
    field.data('plaintext', data)
    HideField(field);
    return field;
  }



  /** Generate the list item for a file in the file list. */
  var GenFile = function (id, file) {
    return $('<li></li>')
      .addClass('file')
      .append(
        $('<a></a>')
          .attr('id', 'file-' + id)
          .data('name', file)
          .attr({"href":
              "javascript:WebSafeGUI.OpenFile('" + id + "');"})
          .text(file)
      );
  }

  /** Generate the file list. This deletes all other controls
   *  except the file list. */
  var GenFileList = function (files) {
    var id = 0;
    var list = $('<ul></ul>');
    $.each(files, function(nr, file) {
      list.append(GenFile(id, file));
      id++;
    });
    $('#web-safe-list').empty().append(list);
  }


  var GenGroup = function (id, group_full, group_title)
  {
    group_title = group_title.replace(/\\\./g, '.');
    group_title = group_title.replace(/\\\\/g, "\\");
    return $('<li></li>')
      .addClass('group')
      .append($('<a></a>')
        .attr('id', 'group-' + id)
        .data('name', group_full)
        .attr({"href": "javascript:WebSafeGUI.OpenGroup('" + id + "');"})
          .text(group_title)
      )
  }

  /** Generate the password list for a file.
   *  This is executed when receiving the password list
   *  from the server. */
  var GenPasswordList = function (safe_active, passwords) {

    var root_group = $('#file-' + _current_file_id).parent();
    root_group.find('a:first').attr({"href": "javascript:WebSafeGUI.CloseFile('" + _current_file_id + "');"});

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

    var AppendToGroup = function(group, hide, obj) {
      var list = group.find('ul:first');
      // if no parent list was found, we append it.
      if (list.length == 0) {
        list = $('<ul></ul>');
        if (hide) { list.hide(); }
        group.append(list);
      }
      if (obj) { list.append(obj); }
    }

    // Sort by groupname and generate group hierarchy.
    passwords.sort(SortByGroup);
    var groups = {};
    var group_id = 0;
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
                AppendToGroup(parent_group, 1);
                var list = parent_group.find('ul:first');
                groups[current_group] = GenGroup(group_id, current_group, part);
                list.append(groups[current_group]);
                group_id++;
              }
              parent_group = groups[current_group];
            });
        }
      });
    root_group.find('ul:first').show();

    // Sort by title and fill in passwords.
    passwords.sort(SortByTitle);
    $.each(passwords,
      function(index, password) {
        var groupname = password.group;
        var obj = $('<li></li>')
          .addClass('password')
          .append(
            $('<a></a>')
              .attr('id', 'password-' + password.uuid)
              .attr('href', "javascript:WebSafeGUI.OpenPassword('" + safe_active + "', '" + password.uuid + "')")
              .text(password.title)
          );

        if (groupname == '') { AppendToGroup(root_group, 0, obj); }
        else { AppendToGroup(groups[password.group], 1, obj); }
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
          .append($('<td></td>')
            .text(password_details.user)
          )
        );
    }
    if (password_details.password) {
      table
        .append($('<tr></tr>')
          .append('<td>Password:</td>')
          .append($('<td></td>')
            .append(GenHiddenField(Htmlentities(password_details.password)))
          )
        );
    }
    if (password_details.url) {
      table
        .append($('<tr></tr>')
          .append('<td>Url:</td>')
          .append($('<td></td>')
            .text(password_details.url)
          )
        );
    }
    if (password_details.notes) {
      table
        .append($('<tr></tr>')
          .append('<td>Notes:</td>')
          .append($('<td></td>')
            .html(Nl2Br(Htmlentities(password_details.notes))
            )
          )
        );
    }
    if (password_details.atime) {
      table
        .append($('<tr></tr>')
          .append('<td>Added:</td>')
          .append('<td>' + FmtDate(password_details.atime) + '</td>')
        );
    }
    if (password_details.mtime) {
      table
        .append($('<tr></tr>')
          .append('<td>Modified:</td>')
          .append('<td>' + FmtDate(password_details.mtime) + '</td>')
        );
    }
    if (password_details.pwmtime) {
      table
        .append($('<tr></tr>')
          .append('<td>Last pw change:</td>')
          .append('<td>' + FmtDate(password_details.pwmtime) + '</td>')
        );
    }
    if (password_details.history) {
      table
        .append($('<tr></tr>')
          .append('<td>History:</td>')
          .append($('<td></td>')
            .text(password_details.history)
          )
        );
    }

    $('#web-safe-details').empty().append(headline).append(table);
    Resize();
  }


  /** Send the request for opening a file. */
  var OpenFile = function (id) {
    if (_master_password == '') {
      HandleError(2002, 'OpenFile: No master password was entered.');
    }
    else {
      CloseFile(_current_file_id);
      var safe_active = $('#file-' + id).data('name');
      SendRequest({ 'action': 'SendPasswordList',
                    'master_password': _master_password,
                    'safe_active': safe_active});
      _current_file_id = id;
    }
  }

  var CloseFile = function (id) {
    var file = $('#file-' + _current_file_id).parent();
    file.find('ul:first').remove();
    file.find('a:first').attr({"href": "javascript:WebSafeGUI.OpenFile('" + id + "');"});
    _current_file_id = '';
  }


  /** Open a group */
  var OpenGroup = function (id) {
    $('#group-' + id)
      .attr('href', "javascript:WebSafeGUI.CloseGroup('" + id + "')")
      .nextAll('ul').show();
    _current_group_id = id;
  }

  /** Close a group */
  var CloseGroup = function (id) {
    $('#group-' + id)
      .attr('href', "javascript:WebSafeGUI.OpenGroup('" + id + "')")
      .nextAll('ul').hide();
    _current_group_id = '';
  }

  /** Send the request for opening a password. */
  var OpenPassword = function (safe_active, password_active) {
    if (_master_password == '') {
      HandleError(2002, 'OpenPassword: No master password was entered.');
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
    'CloseFile': CloseFile,
    'OpenGroup': OpenGroup,
    'CloseGroup': CloseGroup,
    'OpenPassword': OpenPassword
  };

})();
