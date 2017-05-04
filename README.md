# PV204 - PROJECT Qt-SESAM

### Team members
 - Michal Hajas 
 - Andrej Staruch 
 - Andrea Turiaková 

 
### About
The goal of this project was to implement extension of Qt-SESAM application which allow user authenticate with security token - JavaCard. Card and application are communicating through secure channel to prevent multiple kind of attacks. Communication between them is secured by AES-128 with keys generated randomly for each seddion and using Diffie-Hellman for key exchange.

### How to build
Extension of application is using functions defined in **winscard.h** header file  for communication with card. In Linux winscard.h is provided by **pcsc-lite** package and in Windows by **Winscard.lib** included in Windows SDK.

#### Linux
Link to original guide:
https://github.com/ola-ct/Qt-SESAM/wiki/Build-for-Linux
Following this guide all should work properly, if not please check if you are not missing pcsc-lite package or try uncheck shadow build in QT Creator. If problems persist do not hesitate to write to us. 

#### Windows
With Qt Creator open the .pro file, press F5 to compile and run in debug mode.
If you have problems with Winscard.lib try to copy this lib to project folder and add addres to this lib into .pro file.

### For reviewers - Where to look for our changes
- **Qt-SESAM/java_card**  - extended application code
- **java_card_application** - Javacard Applet
- **docs** - presentation, project design


###### Below is the original description of Qt-SESAM application.


# Qt-SESAM

**SESAM — Super Easy & Secure Authentication Management**

Qt-SESAM is a user-friendly application that enables you to generate strong passwords. You can use them for all the services you're using, e.g. websites, accounts, or apps.

The passwords are generated in realtime from service name, user name, a randomly shuffled salt and the master password. For services which don't allow passwords to be changed (e.g. credit cards) Qt-SESAM can also store fixed passwords.

Qt-SESAM has a unique feature which lets you choose the complexity (vertically) and length (horizontally) of the password in a colored widget:

![EasySelectorWidget](https://raw.githubusercontent.com/ola-ct/Qt-SESAM/master/doc/qt-sesam-screenshot.png)

You can share Qt-SESAM's settings across your computers via a [dedicated synchronisation server](https://github.com/ola-ct/ctSESAM-server) and a file located on a cloud drive like [OwnCloud](https://owncloud.org/), [Google Drive](https://www.google.com/drive/), [Microsoft OneDrive](https://onedrive.live.com/about/) or [Dropbox](https://www.dropbox.com/).

This is secure because all of your settings are [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)-encrypted with a 256 bit long [key](https://en.wikipedia.org/wiki/Key_(cryptography)) and a 128 bit long [IV](https://en.wikipedia.org/wiki/Initialization_vector) derived from your master password with [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2).

Qt-SESAM supports Windows, Linux and Mac OS X. An [Android app](https://github.com/pinae/ctSESAM-android) compatible to Qt-SESAM is underway.

## Download

 * [Source code](https://github.com/ola-ct/Qt-SESAM)
 * [Binaries for Windows and OS X](https://github.com/ola-ct/Qt-SESAM/releases)

## Important infos

 * [How Qt-SESAM works](http://ola-ct.github.io/Qt-SESAM/)
 * [FAQ in German](https://github.com/ola-ct/Qt-SESAM/wiki/FAQ-%5Bde%5D)
 * [Build instructions for Linux](https://github.com/ola-ct/Qt-SESAM/wiki/Build-for-Linux)
 * [Build instructions for Windows](https://github.com/ola-ct/Qt-SESAM/wiki/Build-for-Windows)
 * [How to contribute to Qt-SESAM](https://github.com/ola-ct/Qt-SESAM/wiki/Contribute) 
 

