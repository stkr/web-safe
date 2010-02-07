﻿
 Web-Safe
============

A browser based online password safe solution.

 Purpose
-----------

The purpose of the application is to have access to a password database from
foreign hosts via an Internet connection without needing any additional
software except the web browser. The password database is stored in
an encrypted form on a web server and can be unlocked remotely by providing a
master password. If a correct master password is given, the user has access
to all passwords stored in the safe file.


 Installation
----------------

The application consists of two parts. The cgi part which is executed by the
web server and the html and javascript part which is displayed and executed by
the web browser.

### Cgi Part Installation

The cgi part of the application consists of the *pwsafe.cgi* file and the
*Pwsafe.pm* perl module. They can be found in the *cgi-bin/web-safe/*
folder of the distribution package. The easiest method of installation is to
copy the whole contents including the subdirectory of the *cgi-bin* folder
of the distribution to the *cgi-bin* folder of the webserver. A typical
locations for the directory is */usr/lib/cgi-bin/*. The *pwsafe.cgi*
file has to be executable.

### Html and Javascript Part Installation

The other parts of the application are html, css and javascript files which
are not executed but delivered directly by the web server. Thus, they must be
accessible by the web server. Probably it is a good idea to place them
somewhere within the document root of the web server.

### Configuration

When all files have been moved to their locations, a little bit of
configuration is needed. The necessary configuration values with a more
detailed description can be found directly in the respective files.
Following files need to be edited:

 - *cgi-bin/web-safe/pwsafe.cgi*
 - *web-safe/javascript/pwsafe.js*


 Security Considerations
---------------------------

This section deals with considerations on the security of the system. It
explains why encryption is needed for data transmission and how this
encryption is realized.


### Encryption Concept

For the sake of security, the traffic from server to client as well as from
client to server is encrypted. The encryption is done between web server and
browser using ssl (https). This is a well understood technique to prohibit
man in the middle attacks. For this application, however, the level of
security has to be extended, because the browser can not be trusted. The
browser may cache pages and requests. The request must contain the master
password (at least once when unlocking the safe) and the response must
contain passwords which are stored in the safe (as they must be presented
on screen to the user). So if no precautions are made, the plaintext values
for passwords might get saved by the browser.

To prevent leakage of password by browser caches, a first idea is to send
http header fields which indicate to the browser, that the page should not be
cached. However, as quick Internet researches show, not all browsers respect
this method.

Therefore, the scope of encryption is extended further to the user. The
web server sends the page contents in an encrypted form and the request from
the user is also encrypted. The encryption and decryption on the client side
is handled by Javascript. This approach does never expose plaintext data and
does not allow the browser to save plaintext copies of the pages and
requests to the hard disk of the host computer.


### Realization of End-To-End Encryption

A session key is exchanged using Rsa. All further traffic is encrypted with
Aes in block chaining mode with the exchanged session key.

The client requests from the server a Rsa public key. The public key is
transmitted unencrypted from the server to the client.
The client generates a session key. Using the public key from the server,
the session key is encrypted and sent to the server.
The server can decrypt the message and extract the session key using its
private key. Afterwards, both parties know the session key. All following
requests and responses are encrypted with the session key.

The encrypted data must be considered binary data and is base64 encoded
before transmission.


### Possible weaknesses

On a foreign host, the environment can not be trusted. There is always the
threat of key loggers or other evil applications (e.g., reading the values
typed into password fields) being installed. This is a general problem which
is hard to solve for every secure application and especially for a browser
based application, it can not be solved. For now, the only solution is to
avoid execution on untrusted hosts.

Also related to the untrusted environment problem is a possible manipulation
of the application on the host. The browser might be manipulated in a way
that makes it save the Javascript application memory to the hard disk or
allows a manipulation of the application.

As example, the "greasemonkey" extension to the Firefox browser allows the
injection of Javascript code into the environment of an arbitrary
application. Therefore, it is recommended to temporarily disable such
extensions while using the password safe application.

It is no good practice to let one party choose the session key alone, because
a badly chosen key might circumvent or weaken encryption. However, as the key
is generated within the client application, to use a bad key, the application
itself would need to be manipulated. If an attacker is able to manipulate the
application, he is as well able to directly read the memory of the
application and, therefore, can read the password directly from the
application memory instead of having the application encrypt it with a weak
key. So if the (more evil) weakness of an attacker being able to manipulate
the application is solved, this also solves the bad key problem.

As summary, all weaknesses presented above are related to an untrusted
environment problem, which can not be sufficiently solved within the context
of the application.


#### Thoughts on Safe Hosts

A host can be considered safe when it is known that no hostile technology is
used which targets on stealing passwords. Hostile technology includes
keyloggers and memory dumping utilities. If there is a chance, such
technologies are used on a host, you are advised not to use the
password safe application on this host.

However, if the host is just used by many parties, this does not necessarily
mean the host is unsafe. Often such hosts restrict the user's ability to
install applications and if the restrictions are enforced correctly, the
hosts are probably safe.
However, hostile programs launched by your predecessor might still be
running, so it is recommended to log off and log back on to stop those
applications. Examples for such hosts are university or library computers.

Regarding browser caches, you might clear them after the usage of the
password safe application, however, no data should be saved to caches in
plaintext anyway, so this generally is not needed.


#### Webserver Security

The passwords get never saved to disk in plaintext on the web server.
However, for Rsa encryption of the communication, the private key for a
session needs to be stored. Also the session key needs to be saved between
two requests. This information is stored in the file system of the web
server. Both keys are stored in plaintext in a single key file. So you
should ensure that no other system user except the user executing the cgi
script can read this file.
If a user knows the session key and has an encrypted request, he can
decrypt the request which probably contains the master password.
This results in all password of the safe being corrupted. One person
which can always access the key files and might also trace the web server
requests is the web server operator (e.g., system root user).
However, this issue is again not controllable by the
application. The server operator has full control over the documents
presented to you and might as well forge you application and present an
entirely different application (which might just log your master password)
to you without you even noticing. So *trust in the server operator is
necessary* (think twice about deploying this application on rented
web space).


 Known Limitations and Bugs
------------------------------


 Error Codes
---------------

The following errors are related to the session establishment and might
get resolved automatically by creation of a new session.

 - 1001: Invalid session id.
 - 1002: Invalid session key.


The following errors should never happen and are not automatically
recoverable:

 - 2001: Invalid safe.
 - 2002: No master password.
 - 2003: The application does not work in a frameset (security).
 - 3001: Client encrypting in unsuited protocol state.
 - 3002: Client decrypting in unsuited protocol state.
 - 3003: Received unknown response type from server.
 - 3004: Retried too often to initialize a session.

 Todo List
-------------

- Restrict the amount of requests to prohibit DoS attacks.

- Gracefully handle "Bad safe combination".

- Warning for timeouts and unsuccessful clicks.

- Support html entities in all fields!.