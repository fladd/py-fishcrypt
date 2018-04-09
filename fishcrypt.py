#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# FiSH/Mircryption clone for XChat/HexChat in 100% Python
#
# Requirements: PyCrypto, and Python 2 (>=2.5)
#
# Copyright 2011 Nam T. Nguyen ( http://www.vithon.org/forum/Thread/show/54 )
# Released under the BSD license
#
# rewritten by trubo/segfault for irc.prooops.eu #py-fishcrypt trubo00@gmail.com
#
# fixes by fladd <fladd@fladd.de>
#
# irccrypt module is copyright 2009 Bjorn Edstrom ( http://www.bjrn.se/ircsrp )
# with modification from Nam T. Nguyen and trubo
#
# Changelog:
#   * 5.31
#      + Minor bugfix when sending messages
#
#   * 5.30
#      + Decrypt own messages (for https://github.com/TingPing/plugins/blob/master/HexChat/mymsg.py)
#
#   * 5.20
#      + Added authentification hash for DH key exchange
#
#   * 5.10
#      + Plugin will now load correctly on Windows
#      + Fixed bug that crashed the plugin in some cases

#   * 5.00
#      + Fixed compatibility for networks with identify-msg (e.g. freenode) in key exchange (fladd)
#      + Added FiSHLiM unload (fladd)
#      + Changed /ME+ to be compatibile with FiSHLiM (fladd)
#
#   * 4.21
#      + Fixed Empty Action /me

#   * 4.20
#      + Added support for Stealth mode >> no KeyExchange possible [/SET FISHSTEALTH True/False] 

#   * 4.19
#      + Added support for mIRC CBC KeyExchange, https://github.com/flakes/mirc_fish_10/ 

#   * 4.18
#      + Buffix Topic use key from channel not context

#   * 4.17
#      + CBC Default

#   * 4.16
#      + Bugfix Topic
#      + config plaintextmarker in keyprotection
#      + config parameter DEFAULTPROTECT and DEFAULTCBC

#   * 4.15
#      + Destroy object

#   * 4.14
#      + Stable

#   * 4.13
#      + new NickTrace
#      + wildcard /KEY search
#      + msg send to other target are marked with "Message Send"
#      + Tab Completion for udpate command
#      + using strxor from the pyCrypto packages if available
#      + some performance enhancements
#      + Pseudo Threading for Windows

#   * 4.12
#      + Beta Support

#   * 4.11
#      + BugFix /UPDATE

#   * 4.10
#      + BugFix /FISHSETUP

#   * 4.09
#      + BugFix again /FISHSETUP /UPDATE

#   * 4.08
#      + BugFix settings are not saved

#   * 4.07
#      + new Update function

#   * 4.06
#      + Small BugFixes

#   * 4.05
#      + BugFix Windows has no full xchatdir now using scriptpath for fish3.pickle

#   * 4.04
#      + BugFix notices

#   * 4.03
#      + BugFix /FISHSETUP

#   * 4.02
#      + noproxy oprions for /FISHSETUP

#   * 4.01
#      + BugFix pyBlowfish

#   * 4.00
#      + Windows Support with pyBlowfish.py and irccrypt now included

#   * 3.31
#      + BugFix unpack large messages

#   * 3.30
#      + Added chksum for irccrypt with __module_name__ tags http://pastebin.com/vTrWyBKv

#   * 3.29
#      + BugFix Update and Threaded Update

#   * 3.28
#      + /SET [fishcrypt]

#   * 3.27
#      + BugFix /ME+ in Query

#   * 3.26
#      + Updates over Proxy

#   * 3.25
#      + crypted /ME+ 

#   * 3.24
#      + BugFix topic 332

#   * 3.23
#      + BugFix notice send

#   * 3.22
#      + BugFix

#   * 3.21
#      + BugFix

#   * 3.20
#      + partly show incomplete messages

#   * 3.19
#      + /FISHUPDATE update switch

#   * 3.18
#      + AUTO CBC Mode only in querys

#   * 3.17
#      + Highlight Bugfix

#   * 3.16
#      + Highlight

#   * 3.15
#      + Bugfixes

#   * 3.13
#      + split lines if longer then 334 Chars 
#
#   * 3.12
#      + add PROTECTKEY to block dh1080 keyexchange on known Keys ( thx ^V^ )
#
#   * 3.11
#      + add Keystorage encryption
#to
#   * 3.10
#      + Fix Path for Windows and provide download URL for pycrypto
#
#   * 3.09
#      + Bugfixes
#
#   * 3.08:
#      + some docu added
#
#   * 3.07:
#      + fixed notice in channel not send to user 
#
#   * 3.06:
#	   + support for /msg /msg+ /notice /notice+ (trubo)
#
#   * 3.04:
#	   + new lock design (by target) (trubo)
#
#   * 3.01:
#	   + change switches to be compatible with fish.secure.la/xchat/FiSH-XChat.txt (trubo)
#
#	* 3.0:
#	   + rewritten to class XChatCrypt (trubo)
#
#   * 2.0:
#      + Suport network mask in /key command
#      + Alias key_exchange to keyx
#      + Support plaintext marker '+p '
#      + Support encrypted key store
#
#   * 1.0:
#      + Initial release
#
###


__module_name__ = 'fishcrypt'
__module_version__ = '5.31'
__module_description__ = 'fish encryption in pure python'

ISBETA = ""

UPDATEURL = 'https://raw.githubusercontent.com/fladd/py-fishcrypt/master/fishcrypt.py'
BETAUPDATEURL = 'https://raw.githubusercontent.com/fladd/py-fishcrypt/master/fishcrypt.py'
PYBLOWFISHURL = "https://raw.githubusercontent.com/fladd/py-fishcrypt/master/pyBlowfish.py"
SOCKSIPYURL = 'http://socksipy-branch.googlecode.com/svn/trunk/socks.py'

ONMODES = ["Y","y","j","J","1","yes","on","ON","Yes","True","true"]
YESNO = lambda x: (x==0 and "N") or "Y"

import sys
import os
import re
import base64
import hashlib
import struct
import time

from math import log

try:
    import xchat
except ImportError:
    sys.exit("should be run from xchat plugin with python enabled")

try:
    import cPickle as pickle
except ImportError:
    import pickle

## check for Windows
import platform
sep = "/"
isWindows = (platform.system() == "Windows")
if isWindows:
    sep = "\\"

## append current path
if isWindows:
    # Try XChat
    scriptname = os.getenv('APPDATA')+"\\XChat\\addons\\fishcrypt.py"
    if not os.path.exists(scriptname):
        # Try HexChat
        scriptname = os.getenv('APPDATA')+"\\HexChat\\addons\\fishcrypt.py"
        if not os.path.exists(scriptname):
            # Try portable install
            scriptname = sys.path[0]+"\\addons\\fishcrypt.py"
else:
    import inspect
    scriptname = inspect.currentframe().f_code.co_filename
script = "".join(scriptname.split(sep)[-1:])
path = sep.join(scriptname.split(sep)[:-1])
sys.path.insert(1,path)
SCRIPTCHKSUM = hashlib.sha1(open(scriptname,'rb').read()).hexdigest()
REQUIRESETUP = False

try:
    import Crypto.Cipher.Blowfish as cBlowfish
except ImportError:
    try:
        import pyBlowfish as cBlowfish
        pyBlowfishlocation = "%s.py" % str(cBlowfish)[str(cBlowfish).find("from '")+6:str(cBlowfish).find(".py")]
        chksum = hashlib.sha1(open(pyBlowfishlocation,'rb').read()).hexdigest()
        validVersion = {'35c1b6cd5af14add86dc0cf3f0309a185c308dcd':0.4,'877ae9de309685c975a6d120760c1ff9b4c55719':0.5, '57117e7c9c7649bf490589b7ae06a140e82664c6':0.5}.get(chksum,-1)
        if validVersion == -1:
            print "\0034** Loaded pyBlowfish.py with checksum: %s is untrusted" % (chksum)
        else:
            if validVersion < 0.5:
                print "\0034** Loaded pyBlowfish.py (%.1f) with checksum: %s is too old" % (validVersion,chksum)
                REQUIRESETUP = True
            else:
                print "\0033** Loaded pyBlowfish.py Version %.1f with checksum: %s" % (validVersion,chksum)

    except ImportError:
        import platform
        print "\002\0034No Blowfish implementation"
        if not isWindows:
            print "This module requires PyCrypto / The Python Cryptographic Toolkit."
            print "Get it from http://www.dlitz.net/software/pycrypto/. or"
        else:
            path = path.replace(sep,sep*2)
        print "Download Python only Blowfish at %s" % PYBLOWFISHURL
        print "or type \002/FISHSETUP\002 for automatic install of that"

        REQUIRESETUP = True

try:
    xchat.command("UNLOAD FiSHLiM")
except:
    pass

try:
    from Crypto.Util.strxor import strxor as xorstring
except ImportError:
    ## use slower python only xor
    def xorstring(a, b): # Slow.
        """xor string a and b, both of length blocksize."""
        xored = []
        for i in xrange(8):
            xored.append( chr(ord(a[i]) ^ ord(b[i])) )
        return "".join(xored)

if not isWindows:
    from threading import Thread
else:
    class Thread:
        def __init__(self,target=None,args=[],kwargs={},name='Thread*'):
            self.__target = target
            self.__args = args
            self.__kwargs = kwargs
            self.__name = name
            self.__hook = None
        def start(self):
            print "-Starting Pseudo Thread"
            self.__hook = xchat.hook_timer(1,self.__thread,(self.__target,self.__args,self.__kwargs))
        def __thread(self,userdata):
            try:
                _thread,args,kwargs = userdata
                _thread(*args,**kwargs)
            finally:
                xchat.unhook(self.__hook)
                self.__hook = None
                return False

import socket
REALSOCKET = socket.socket

def makedict(**kwargs):
    return kwargs

COLOR = makedict(white="\0030", black="\0031", blue="\0032", red="\0034",
    dred="\0035", purple="\0036", dyellow="\0037", yellow="\0038", bgreen="\0039",
    dgreen="\00310", green="\00311", bpurple="\00313", dgrey="\00314",
    lgrey="\00315", close="\003")


class SecretKey(object):
    def __init__(self, dh, key=None,protectmode=False,cbcmode=False):
        self.dh = dh
        self.key = key
        self.cbc_mode = cbcmode
        self.protect_mode = protectmode
        self.active = True
        self.cipher = 0
        self.keyname = (None,None)
    def __str__(self):
        return "%s@%s" % self.keyname

def proxyload(_thread,_useproxy,doExtra):
    socket.socket = REALSOCKET
    if xchat.get_prefs('net_proxy_type') > 0 and _useproxy:
        try:
            import socks
        except ImportError:
            print "\0034python-socksipy not installed"
            print "sudo apt-get install python-socksipy"
            print "or install %s" % SOCKSIPYURL
            print "or just use the noproxy option with /FISHUPDATE and /FISHSETUP"
            return xchat.EAT_ALL

        proxytype = [0,-1,socks.PROXY_TYPE_SOCKS4,socks.PROXY_TYPE_SOCKS5,socks.PROXY_TYPE_HTTP,-1][xchat.get_prefs('net_proxy_type')]
        nameproxytype = ['','Socks4a','Socks5','HTTP','']
        if proxytype < 0:
            print "\0034Proxytype not suported for updates"
            return xchat.EAT_ALL
        proxyuser = xchat.get_prefs('net_proxy_user')
        proxypass = xchat.get_prefs('net_proxy_pass')
        if len(proxyuser) < 1 or len(proxypass) < 1:
            proyxuser = proxypass = None
        socks.setdefaultproxy(proxytype,xchat.get_prefs('net_proxy_host'),xchat.get_prefs('net_proxy_port'),rdns=True,username=proxyuser,password=proxypass)
        print "\00310using xchat proxy settings \0037Type: %s Host: %s Port: %s" % (nameproxytype[proxytype],xchat.get_prefs('net_proxy_host'),xchat.get_prefs('net_proxy_port'))
        
        ## Replace default socket
        socket.socket = socks.socksocket
                    
    import urllib2
    _thread(urllib2,doExtra)

def destroyObject(userdata):
    global loadObj
    del loadObj
    return False

class XChatCrypt:
    def __init__(self):
        print "%sFishcrypt Version %s %s\003" % (COLOR['blue'],__module_version__,ISBETA)
        print "SHA1 checksum: %r" % SCRIPTCHKSUM
        self.active = True
        self.__KeyMap = {}
        self.__TargetMap = {}
        self.__lockMAP = {}
        self.config = {
            'PLAINTEXTMARKER' : '+p',
            'DEFAULTCBC' : True,
            'DEFAULTPROTECT' : False,
            'FISHUPDATETIMEOUT' : 30,
            'MAXMESSAGELENGTH' : 300,
            'USEPROXYUPDATE' : True,
            'FISHBETAVERSION': True,
            'FISHDEVELOPDEBUG': False,
            'AUTOBACKUP': True,
            'FISHSTEALTH': False,
        }
        self.status = {
            'CHKPW': None,
            'DBPASSWD' : None,
            'CRYPTDB' : False,
            'LOADED' : True
        }
        self.__update_thread = None
        self._updatedSource = None
        self.__hooks = []
        self.__hooks.append(xchat.hook_command('SETKEY', self.set_key, help='set a new key for a nick or channel /SETKEY <nick>/#chan [new_key]'))
        self.__hooks.append(xchat.hook_command('KEYX', self.key_exchange, help='exchange a new pub key, /KEYX <nick>'))
        self.__hooks.append(xchat.hook_command('KEYXC', self.key_exchange_commit, help='exchange a new commited pub key, /KEYXC <nick>'))
        #self.__hooks.append(xchat.hook_command('AUTH', self.set_auth, help='set or show whether authentication is used for key exchanges, /AUTH <0|1>'))
        self.__hooks.append(xchat.hook_command('KEY', self.show_key, help='list key of a nick or channel or all (*), /KEY [nick/#chan/*]' ))
        self.__hooks.append(xchat.hook_command('DELKEY', self.del_key, help='remove key, /DELKEY <nick>/#chan/*'))
        self.__hooks.append(xchat.hook_command('CBCMODE', self.set_cbc, help='set or show cbc mode for (current) channel/nick , /CBCMODE [<nick>] <0|1>'))
        self.__hooks.append(xchat.hook_command('PROTECTKEY', self.set_protect, help='sets or shows key protection mode for (current) nick, /PROTECTKEY [<nick>] <0|1>'))
        self.__hooks.append(xchat.hook_command('ENCRYPT', self.set_act, help='set or show encryption on for (current) channel/nick , /ENCRYPT [<nick>] <0|1>'))
        
        self.__hooks.append(xchat.hook_command('PRNCRYPT', self.prn_crypt, help='print msg encrpyted localy , /PRNCRYPT <msg>'))
        self.__hooks.append(xchat.hook_command('PRNDECRYPT', self.prn_decrypt, help='print msg decrpyted localy , /PRNDECRYPT <msg>'))

        self.__hooks.append(xchat.hook_command('UPDATE', self.update, help='Update this Script'))
        self.__hooks.append(xchat.hook_command('FISHUPDATE', self.fishupdate, help='Update this Script'))

        ## check for password sets
        self.__hooks.append(xchat.hook_command('SET',self.settings))
        self.__hooks.append(xchat.hook_command('DBPASS',self.set_dbpass))
        self.__hooks.append(xchat.hook_command('DBLOAD',self.set_dbload))

        self.__hooks.append(xchat.hook_command('HELP',self.get_help))

        self.__hooks.append(xchat.hook_command('', self.outMessage))
        self.__hooks.append(xchat.hook_command('ME+', self.outMessageCmd))
        self.__hooks.append(xchat.hook_command('MSG', self.outMessageCmd))
        self.__hooks.append(xchat.hook_command('MSG+', self.outMessageForce))
        self.__hooks.append(xchat.hook_command('NOTICE', self.outMessageCmd))
        self.__hooks.append(xchat.hook_command('NOTICE+', self.outMessageForce))

        self.__hooks.append(xchat.hook_server('notice', self.on_notice,priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_server('332', self.server_332_topic,priority=xchat.PRI_HIGHEST))

        self.__hooks.append(xchat.hook_print('Key Press',self.tabComplete))

        self.__hooks.append(xchat.hook_print('Notice Send',self.on_notice_send, 'Notice',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Change Nick', self.nick_trace))
        self.__hooks.append(xchat.hook_print('Channel Action', self.inMessage, 'Channel Action',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Private Action to Dialog', self.inMessage, 'Private Action to Dialog',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Private Action ', self.inMessage, 'Private Action',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Channel Message', self.inMessage, 'Channel Message',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Private Message to Dialog', self.inMessage, 'Private Message to Dialog',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Private Message', self.inMessage, 'Private Message',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_print('Your Message', self.inMessage, 'Your Message',priority=xchat.PRI_HIGHEST))
        self.__hooks.append(xchat.hook_unload(self.__destroy))
        self.loadDB()

    def __destroy(self,userdata):
        for hook in self.__hooks:
            xchat.unhook(hook)
        destroyObject(None)

    def __del__(self):
        print "\00311fishcrypt.py successful unloaded"

    def get_help(self,word, word_eol, userdata):
        if len(word) < 2:
            print "\n\0033 For fishcrypt.py help type /HELP FISHCRYPT"
            return xchat.EAT_NONE
        if word[1].upper() == "FISHCRYPT":
            print ""
            print "\002\0032 ****  fishcrypt.py Version: %s %s ****" % (__module_version__,ISBETA)
            if self.config['FISHBETAVERSION']:
                print "\0036Beta download %s" % (BETAUPDATEURL)
            
            print "\0036 %s" % UPDATEURL
            print "\n"
            print " \002\00314***************** Fishcrypt Help ********************"
            print " -----------------------------------------------------"
            print "/MSG+ \00314send crypted msg regardless of /ENCRYPT setting"
            print "/NOTICE+ \00314send crypted notice regardless of /ENCRYPT setting"
            print "/ME+ \00314send crypted CTCP ACTION"
            print "/SETKEY \00314set a new key for a nick or channel"
            print "/KEYX \00314exchange pubkey for dialog"
            print "/KEYXC \00314exchange commited pubkey for dialog"
            print "/KEY \00314show Keys"
            print "/DELKEY \00314delete Keys"
            print "/CBCMODE \00314enable/disable CBC Mode for this Key"
            print "/ENCRYPT \00314enable/disable encryption for this Key"
            print "/PROTECTKEY \00314enable/disable protection for keyx key exchange"
            print "/DBPASS \00314set/change the passphrase for the Key Storage"
            print "/DBLOAD \00314loads the Key Storage"
            print "/PRNDECRYPT \00314decrypts messages localy"
            print "/PRNCRYPT \00314encrypts messages localy"
            print "/FISHUPDATE \00314check online for new Version and update"
            print "/SET [fishcrypt] \00314show/set fishcrypt settings"
            return xchat.EAT_ALL

    def tabComplete(self,word, word_eol, userdata):
        if word[0] not in ["65289","65056"]:
            return xchat.EAT_NONE
        input = xchat.get_info('inputbox')
        if input.upper().startswith("/UPDATE FISHCRYPT I"):
            newinput = "/UPDATE FISHCRYPT INSTALL"
        elif input.upper().startswith("/UPDATE FISHCRYPT D"):
            newinput = "/UPDATE FISHCRYPT DIFF"
        elif input.upper().startswith("/UPDATE FISHCRYPT C"):
            newinput = "/UPDATE FISHCRYPT CHANGES"
        elif input.upper().startswith("/UPDATE FISHCRYPT L"):
            newinput = "/UPDATE FISHCRYPT LOAD"
        elif input.upper() == "/UPDATE FISHCRYPT ":
            print "LOAD INSTALL DIFF CHANGES"
            return xchat.EAT_NONE
        elif input.upper().startswith("/UPDATE F"):
            newinput = "/UPDATE FISHCRYPT "
        elif input.upper().startswith("/HELP F"):
            newinput = "/HELP FISHCRYPT "
        elif input.upper().startswith("/SET F"):
            newinput = "/SET FISHCRYPT "
        else:
            return xchat.EAT_NONE
        xchat.command("SETTEXT %s" % newinput)
        xchat.command("SETCURSOR %d" % len(newinput))
        return xchat.EAT_PLUGIN


    def fishupdate(self,word, word_eol, userdata):
        return self.update(["UPDATE","FISHCRYPT","INSTALL"],None,None)

    def update(self,word, word_eol, userdata):
        useproxy = self.config['USEPROXYUPDATE']
        if len(word) <3:
            print "\00313Fishcrypt.py Updater"
            print "\00313/UPDATE FISHCRYPT [LOAD,CHANGES,DIFF,INSTALL]"
            return xchat.EAT_XCHAT
        if word[1].upper() != "FISHCRYPT":
            return xchat.EAT_NONE
        if self.__update_thread:
            print "\0034Update Thread already running"
            return xchat.EAT_ALL
        _doExtra = None
        if word[2].lower() == "diff":
            if self._updatedSource:
                self._updateDiff(xchat.get_context())
            else:
                _doExtra = self._updateDiff
        if word[2].lower() == "changes":
            if self._updatedSource:
                self._updateChanges(xchat.get_context())
            else:
                _doExtra = self._updateChanges
        if word[2].lower() == "install":
            if self._updatedSource:
                self._updateInstall(xchat.get_context())
            else:
                _doExtra = self._updateInstall
        if word[2].lower() == "load" or _doExtra:
            proxyload(self._update,useproxy,_doExtra)
        
        return xchat.EAT_ALL
        
    def _update(self,urllib2,doExtra):
        self.__update_thread = Thread(target=self.__update,kwargs={'urllib2':urllib2,'context':xchat.get_context(),'doExtra':doExtra},name='fishcrypt_update')
        self.__update_thread.start()

    def _updateInstall(self,context):
        try:
            try:
                __fd = open(scriptname,"wb")
                __fd.write(self._updatedSource)
            finally:
                __fd.close()
            context.prnt( "\00310UPDATE Complete \r\nplease reload the script (/py reload %s)" % (script,) )
        except:
            context.prnt( "\002\0034UPDATE FAILED" )
            raise

    def _updateDiff(self,context):
        currentscript = open(scriptname,"rb").read()
        import difflib
        for line in difflib.unified_diff(currentscript.splitlines(1),self._updatedSource.splitlines(1)):
            context.prnt( line)

    def _updateChanges(self,context):
        currentscript = open(scriptname,"rb").read()
        import difflib
        for line in difflib.ndiff(currentscript[currentscript.find("# Changelog:"):currentscript.find("__module_name__")].splitlines(1),self._updatedSource[self._updatedSource.find("# Changelog:"):self._updatedSource.find("__module_name__")].splitlines(1)):
            if len(line) > 2:
                if line[0] in ["+","-"]:
                    context.prnt( line[2:])

    def __update(self,urllib2,context,doExtra):
        url = UPDATEURL
        if self.config['FISHBETAVERSION']:
            url = BETAUPDATEURL
        context.prnt("\0038.....checking for updates at %r... please wait ...." % url)
        try:
            try:
                __updatescript = urllib2.urlopen(url,timeout=self.config['FISHUPDATETIMEOUT']).read()
                __updateversion = re.search("__module_version__ = '([0-9]+\.[0-9]+)'",__updatescript)
                if __updateversion:
                    if float(__module_version__) < float(__updateversion.group(1)) or ISBETA != "":
                        updatechksum = hashlib.sha1(__updatescript).hexdigest()
                        if SCRIPTCHKSUM <> updatechksum:
                            self._updatedSource = __updatescript
                            context.prnt( "\00310Download Version %s with checksum %r complete" % (__updateversion.group(1),updatechksum))
                        else:
                            context.prnt( "\00310No new version available - checksums match")
                    else:
                        context.prnt( "\0032%sVersion %s is up to date (found Version %s)" % (__module_name__,__module_version__,__updateversion.group(1)) )
                else:
                    context.prnt( "\0034NO VALID PLUGIN FOUND AT %s" % (url,) )
            except urllib2.URLError,err:
                context.prnt( "\002\0034LOAD FAILED" )
                context.prnt( "%r" % (err,) )

            except:
                context.prnt( "\002\0034LOAD FAILED" )
                context.prnt("%r" % (sys.exc_info(),))
        finally:
            self.__update_thread = None
            context.prnt( "\00310Update Thread finished" )
        if doExtra and self._updatedSource:
            doExtra(context)


    ## Load key storage
    def loadDB(self):
        data = db = None
        try:
            try:
                hnd = open(os.path.join(path,'fish3.pickle'),'rb')
                data = hnd.read()
                ## set DB loaded to False as we have a file we don't want to create a new
                self.status['LOADED'] = False
            except:
                return
        finally:
            try:
                hnd.close()
            except:
                pass
        if data:
            try:
                db = pickle.loads(data)
                print "%sUnencrypted Key Storage loaded" % (COLOR['bpurple'],)
            except pickle.UnpicklingError:
                ## ignore if file is invalid
                if data.startswith("+OK *"):
                    self.status['CRYPTDB'] = True
                    if self.status['DBPASSWD']:
                        try:
                            algo = BlowfishCBC(self.status['DBPASSWD'])
                            decrypted = mircryption_cbc_unpack(data,algo)
                            db = pickle.loads(decrypted)
                            print "%sEncrypted Key Storage loaded" % (COLOR['green'],)
                        except pickle.UnpicklingError:
                            self.status['DBPASSWD'] = None
                            print "%sKey Storage can't be loaded with this password" % (COLOR['dred'],)
                            print "use /DBLOAD to load it later"
                    else:
                        xchat.command('GETSTR ""  "SET fishcrypt_passload" "Enter your Key Storage Password"')
                pass
        if type(db) == dict:
            self.status['LOADED'] = True
            ## save temp keymap
            oldKeyMap = self.__KeyMap
            oldTargetMap = self.__TargetMap
            ## fill dict with the loaded Keymap
            self.__KeyMap = db.get("KeyMap",{})
            self.__TargetMap = db.get("TargetMap",{})
            self.__KeyMap.update(oldKeyMap)
            self.__TargetMap.update(oldTargetMap)
            for key in self.__KeyMap.keys():
                self.__KeyMap[key].keyname = key
                if not hasattr(self.__KeyMap[key],'protect_mode'):
                    self.__KeyMap[key].protect_mode = False
            self.cleanUpTargetMap()

            ## only import valid config values
            for key in self.config.keys():
                try:
                    self.config[key] = db["Config"][key]
                except KeyError:
                    pass
            if self.config['FISHDEVELOPDEBUG']:
                self.__hooks.append(xchat.hook_command('FISHEVAL',self.__evaldebug))

    def cleanUpTargetMap(self):
        ## DB Cleanup
        for network in self.__TargetMap.values():
            for target,value in network.items():
                if type(value[1]) <> SecretKey or value[0] < time.time() - 60*60*24*7 or value[1] not in self.__KeyMap.values():
                    del network[target]
                    print "Expired: %r %r" % (target,value)


    ## save keys to storage
    def saveDB(self):
        self.cleanUpTargetMap()
        if not self.status['LOADED']:
            print "Key Storage not loaded, no save. use /DBLOAD to load it"
            return
        try:
            data = pickle.dumps({
                'KeyMap': self.__KeyMap,
                'TargetMap': self.__TargetMap,
                'Config': self.config,
                'Version': __module_version__ 
            })
            hnd = open(os.path.join(path,'fish3.pickle'),'wb')
            if self.status['DBPASSWD']:
                algo = BlowfishCBC(self.status['DBPASSWD'])
                encrypted = mircryption_cbc_pack(data,algo)
                data = encrypted
                self.status['CRYPTDB'] = True
            else:
                self.status['CRYPTDB'] = False
            hnd.write(data)
        finally:
            hnd.close()

    def __evaldebug(self,word, word_eol, userdata):
        eval(compile(word_eol[1],'develeval','exec'))
        return xchat.EAT_ALL

    def set_dbload(self,word, word_eol, userdata):
        self.loadDB()
        return xchat.EAT_ALL

    def set_dbpass(self,word, word_eol, userdata):
        xchat.command('GETSTR "" "SET fishcrypt_passpre" "New Password"')
        return xchat.EAT_ALL

    ## set keydb passwd
    def settings(self,word, word_eol, userdata):
        fishonly = False
        if len(word) == 2:
            if word[1].upper() == "FISHCRYPT":
                fishonly = True
        if len(word) < 2 or fishonly:
            ## not for us 
            #print "fishcrypt_pass%s%s%s: \003%r" % (COLOR['blue'],"."*16,COLOR['green'],self.status['DBPASSWD'])
            for key in self.config:
                keyname = "%s%s" % (key,"."*20)
                print "\00312%.29s: %s" % (keyname,str(self.config[key]))
            if fishonly:
                return xchat.EAT_ALL
            return xchat.EAT_NONE


        if word[1] == "fishcrypt_passpre":
            if len(word) == 2:
                self.status['CHKPW'] = ""
            else:
                self.status['CHKPW'] = word_eol[2]
            xchat.command('GETSTR ""  "SET fishcrypt_pass" "Repeat the Password"')
            return xchat.EAT_ALL

        if word[1] == "fishcrypt_pass":
            if len(word) == 2:
                if self.status['CHKPW'] <> "" and self.status['CHKPW'] <> None:
                    print "Passwords don't match"
                    self.status['CHKPW'] = None
                    return xchat.EAT_ALL
                self.status['DBPASSWD'] = None
                print "%sPassword removed and Key Storage decrypted" % (COLOR['dred'],)
                print "%sWarning Keys are plaintext" % (COLOR['dred'],)
            else:
                if self.status['CHKPW'] <> None and self.status['CHKPW'] <> word_eol[2]:
                    print "Passwords don't match"
                    self.status['CHKPW'] = None
                    return xchat.EAT_ALL
                if len(word_eol[2]) < 8 or len(word_eol[2]) > 56:
                    print "Passwords must be between 8 and 56 chars"
                    self.status['CHKPW'] = None
                    return xchat.EAT_ALL
                self.status['DBPASSWD'] = word_eol[2]
                ## don't show the pw on console if set per GETSTR
                if self.status['CHKPW'] == None:
                    print "%sPassword for Key Storage encryption set to %r" % (COLOR['dred'],self.status['DBPASSWD'])
                else:
                    print "%sKey Storage encrypted" % (COLOR['dred'])
            self.status['CHKPW'] = None
            self.saveDB()
            return xchat.EAT_ALL

        if word[1] == "fishcrypt_passload":
            if len(word) > 2:
                if len(word_eol[2]) < 8 or len(word_eol[2]) > 56:
                    print "Password not between 8 and 56 chars"
                else:
                    self.status['DBPASSWD'] = word_eol[2]
                    self.loadDB()
            else:
                print "Key Storage Not loaded"
                self.status['DBPASSWD'] = None
            return xchat.EAT_ALL

        key = word[1].upper()
        if key in self.config.keys():
            if len(word) <3:
                keyname = "%s%s" % (key,"."*20)
                print "\00312%.29s: %s" % (keyname,str(self.config[key]))
            else:
                try:
                    if type(self.config[key]) == bool:
                        self.config[key] = bool(word[2] in ONMODES)
                    else:
                        self.config[key] = type(self.config[key])(word_eol[2])
                    print "\0035Set %r to %r" % (key,word_eol[2])
                    self.saveDB()
                except ValueError:
                    print "\0034Invalid Config Value %r for %s" % (word_eol[2],key)
            return xchat.EAT_ALL

        return xchat.EAT_NONE

    ## incoming notice received
    def on_notice(self,word, word_eol, userdata):
        ## check if this is not allready processed
        if self.__chk_proc():
            return xchat.EAT_NONE

        ## check if DH Key Exchange
        if word[3].startswith(":") and word[3].endswith('DH1080_FINISH'):
            return self.dh1080_finish(word, word_eol, userdata)
        elif word[3].startswith(":") and word[3].endswith('DH1080_INIT'):
            return self.dh1080_init(word, word_eol, userdata)
        elif word[3].startswith(":") and word[3].endswith('DH1080_COMMIT'):
            return self.dh1080_commit(word, word_eol, userdata)

        ## check for encrypted Notice
        elif word[3].startswith(':') and (word[3].endswith(':+OK') or word[3].startswith(':mcps')):
            
            ## rewrite data to pass to default inMessage function
            ## change full ident to nick only
            nick = self.get_nick(word[0])
            target = word[2]
            speaker = nick
            ## strip :: from message
            if word[3].endswith("+OK"):
                idx = len(word[3]) - len("+OK")
            elif word[3].endswith("mcps"):
                idx = len(word[3]) - len("mcps")
            message = word_eol[3][idx:]
            if target.startswith("#"):
                id = self.get_id()
                speaker = "## %s" % speaker
            else:
                id = self.get_id(nick=nick)
            #print "DEBUG(crypt): key: %r word: %r" % (id,word,)
            key = self.find_key(id)
            ## if no key found exit
            if not key:
                return xchat.EAT_NONE
            
            ## decrypt the message
            try:
                sndmessage = self.decrypt(key,message)
            except:
                sndmessage = None
            isCBC=0
            if message.startswith("+OK *"):
                isCBC=1
            failcol = ""

            ## if decryption was possible check for invalid chars
            if sndmessage:
                try:
                    message = sndmessage.decode("UTF8").encode("UTF8")
                    ## mark nick for encrypted msgg
                    speaker = "%s %s" % ("°"*(1+isCBC),speaker)
                except UnicodeError:
                    try:
                        message = unicode(sndmessage,encoding='iso8859-1',errors='ignore').encode('UTF8')
                        ## mark nick for encrypted msgg
                        speaker = "%s %s" % ("°"*(1+isCBC),speaker)
                    except:
                        raise
                    ## send the message to local xchat
                    #self.emit_print(userdata,speaker,message)
                    #return xchat.EAT_XCHAT
                except:
                    ## mark nick with a question mark
                    speaker = "?%s" % (speaker)
                    failcol = "\003"
            else:
                failcol = "\003"
            ## mark the message with \003, it failed to be processed and there for the \003+OK  will no longer be excepted as encrypted so it wont loop
            self.emit_print(userdata,speaker,"%s%s" % (failcol,message))
            return xchat.EAT_XCHAT
#            return self.inMessage([nick,msg], ["%s %s" % (nick,msg),msg], userdata)

        ## ignore everything else
        else:
            #print "DEBUG: %r %r %r" % (word, word_eol, userdata)
            return xchat.EAT_NONE

    ## local notice send messages
    def on_notice_send(self,word, word_eol, userdata):
        ## get current nick
        target = xchat.get_context().get_info('nick')
        #print "DEBUG_notice_send: %r - %r - %r %r" % (word,word_eol,userdata,nick)
        
        ## check if this is not allready processed
        if self.__chk_proc(target=target):
            return xchat.EAT_NONE
        
        ## get the speakers nick only from full ident
        speaker = self.get_nick(word[0])
        
        ## strip first : from notice
        message = word_eol[1][1:]
        if message.startswith('+OK ') or message.startswith('mcps '):
            ## get the key id from the speaker
            id = self.get_id(nick=speaker)
            key = self.find_key(id)
            
            ## if no key available for the speaker exit
            if not key:
                return xchat.EAT_NONE
            
            ## decrypt the message
            sndmessage = self.decrypt(key,message)
            isCBC = 0
            if message.startswith("+OK *"):
                isCBC = 1
                if not target.startswith("#"):
                    ## if we receive a messge with CBC enabled we asume the partner can also except it so activate it
                    key.cbc_mode = True

            ## if decryption was possible check for invalid chars

            if sndmessage:
                try:
                    message = sndmessage.decode("UTF8").encode("UTF8")
                    ## mark nick for encrypted msgg
                    speaker = "%s %s" % ("°"*(1+isCBC),speaker)
                except:
                    ## mark nick with a question mark
                    speaker = "?%s" % (speaker)
                    ## send original message because invalid chars
                    message = message

            ## send the message back to incoming notice but with locked target status so it will not be processed again
            self.emit_print("Notice Send",speaker,message,target=target)
            return xchat.EAT_XCHAT
        return xchat.EAT_NONE
    
    ## incoming messages
    def inMessage(self,word, word_eol, userdata):
        ## if message is allready processed ignore
        if self.__chk_proc() or len(word_eol) < 2:
            return xchat.EAT_PLUGIN
        speaker = word[0]
        message = word_eol[1]
        #print "DEBUG(INMsg): %r - %r - %r" % (word,word_eol,userdata)
        # if there is mode char, remove it from the message
        if len(word_eol) >= 3:
            #message = message[ : -(len(word_eol[2]) + 1)]
            message = message[:-2]

        ## check if message is crypted
        if message.startswith('+OK ') or message.startswith('mcps '):
            target = None
            if userdata == "Private Message":
                target = speaker
            id = self.get_id(nick=target)
            target,network = id
            key = self.find_key(id)
            
            ## if no key found exit
            if not key:
                return xchat.EAT_NONE
            
            ## decrypt the message
            try:
                sndmessage = self.decrypt(key,message)
            except:
                sndmessage = None
            isCBC=0
            if message.startswith("+OK *"):
                isCBC=1
                if not target.startswith("#"):
                    ## if we receive a messge with CBC enabled we asume the partner can also except it so activate it
                    key.cbc_mode = True

            failcol = ""

            ## if decryption was possible check for invalid chars
            action = False
            if sndmessage:
                if sndmessage.startswith("\001ACTION"):
                    sndmessage = sndmessage.lstrip("\001ACTION")
                    action = True
                try:
                    message = sndmessage.decode("UTF8").encode("UTF8")
                    ## mark nick for encrypted msgg
                    speaker = "%s %s" % ("°"*(1+isCBC),speaker)
                except UnicodeError:
                    try:
                        message = unicode(sndmessage,encoding='iso8859-1',errors='ignore').encode('UTF8')
                        ## mark nick for encrypted msgg
                        speaker = "%s %s" % ("°"*(1+isCBC),speaker)
                    except:
                        raise
                    ## send the message to local xchat
                    #self.emit_print(userdata,speaker,message)
                    #return xchat.EAT_XCHAT
                except:
                    ## mark nick with a question mark
                    speaker = "?%s" % (speaker)
                    failcol = "\003"
            else:
                failcol = "\003"
            ## mark the message with \003, it failed to be processed and there for the \003+OK  will no longer be excepted as encrypted so it wont loop
            if action:
                self.emit_print('Channel Action',  speaker, message.strip())
            else:
                self.emit_print(userdata,speaker,"%s%s" % (failcol,message))
            return xchat.EAT_ALL

        return xchat.EAT_NONE

    def decrypt(self,key,msg):
        ## check for CBC
        if 3 <= msg.find(' *') <= 4:
            decrypt_clz = BlowfishCBC
            decrypt_func = mircryption_cbc_unpack
        else:
            decrypt_clz = Blowfish
            decrypt_func = blowcrypt_unpack
        try:
            b = decrypt_clz(key.key)
            #if msg[-2:-1] == " ":
            #	msg = msg[:-2]
            ret = decrypt_func(msg, b)
        except MalformedError:
            try:
                cut = (len(msg) -4)%12
                if cut > 0:
                    msg = msg[:cut *-1]
                    ret = "%s%s" % ( decrypt_func(msg, b), " \0038<<incomplete>>" * (cut>0))
                else:
                    #print "Error Malformed %r" % len(msg)
                    ret = None
            except MalformedError:
                #print "Error2 Malformed %r" % len(msg)
                ret = None
        except:
            print "Decrypt ERROR"
            ret = None
        return ret


    ## mark outgoing message being  prefixed with a command like /notice /msg ...
    def outMessageCmd(self,word, word_eol, userdata):
        return self.outMessage(word, word_eol, userdata,command=True)

    ## mark outgoing message being prefixed with a command that enforces encryption like /notice+ /msg+
    def outMessageForce(self,word, word_eol, userdata):
        return self.outMessage(word, word_eol, userdata, force=True,command=True)

    ## the outgoing messages will be proccesed herre
    def outMessage(self,word, word_eol, userdata,force=False,command=False):
        ## check if allready processed
        if self.__chk_proc():
            return xchat.EAT_NONE
        
        ## get the id
        id = self.get_id()
        target,network = id
        ## check if message is prefixed wit a command like /msg /notice
        action = False
        if command:
            
            if len(word) < (word[0].upper().startswith("ME") and 2 or 3):
                print "Usage: %s <nick/channel> <message>, sends a %s.%s are a type of message that should be auto reacted to" % (word[0],word[0],word[0])
                return xchat.EAT_ALL
            ## notice and notice+
            if word[0].upper().startswith("NOTICE"):
                command = "NOTICE"
            else:
                command = "PRIVMSG"
            if word[0].upper().startswith("ME"):
                action = True
                message = word_eol[1]
            else:
                ## the target is first parameter after the command, not the current channel
                target = word[1]
                ## change id
                id = (target,network)
                ## remove command and target from message
                message = word_eol[2]
        else:
            command = "PRIVMSG"
            if len(word_eol) < 1:
                return xchat.EAT_NONE
            else:
                message = word_eol[0]
        sendmsg = ''
        ## try to get a key for the target id
        key = self.find_key(id)
        
        ## my own nick
        nick = xchat.get_context().get_info('nick')

        #print "DEBUG(outMsg1)(%r) %r : %r %r" % (id,xchat.get_context().get_info('network'),word,nick)

        ## if we don't have a key exit
        if not key:
            return xchat.EAT_NONE
        
        ## if the key object is there but the key deleted or marked not active...and force is not set by command like /msg+ or /notice+
        if key.key == None or (key.active == False and not force):
            return xchat.EAT_NONE
        
        ## if the message is marked with the plaintextmarker (default +p) don't encrypt
        if message.startswith(self.config['PLAINTEXTMARKER']):
            ## remove the plaintextmarker from the message
            sendmessages = [message[len(self.config['PLAINTEXTMARKER'])+1:]]
            messages = sendmessages
        else:
            ## encrypt message
            maxlen = self.config['MAXMESSAGELENGTH']
            cutmsg = message
            if action:
                cutmsg = "\001ACTION %s\001" % cutmsg
            messages = []
            sendmessages = []
            while len(cutmsg) >0:
                sendmessages.append(self.encrypt(key,cutmsg[:maxlen]))
                messages.append(cutmsg[:maxlen])
                cutmsg = cutmsg[maxlen:]
            ## mark the nick with ° for encrypted messages
            nick = "%s %s" % ("°"*(1+key.cbc_mode),nick)

        #print "DEBUG(outMsg2): %r %r %r %r" % (command,message,nick,target)
        for sendmsg in sendmessages:
            ## lock the target
            self.__lock_proc(True)
            ## send the command (PRIVMSG / NOTICE)
            xchat.command('%s %s :%s' % (command,target, sendmsg))
            ## release the lock
            self.__lock_proc(False)
        
        for message in messages:
            ## if it is no notice it must be send plaintext to xchat for you
            if command == "PRIVMSG":
                if action:
                    self.emit_print('Channel Action',  nick, message.lstrip("\001ACTION\001").strip())
                else:
                    targetTab= xchat.find_context(channel=target)
                    if not targetTab and targetTab != xchat.get_context():
                        self.emit_print('Message Send',  "%s %s" % ("°"*(1+key.cbc_mode),target), message)
                    else:
                        self.emit_print('Your Message',  nick, message,toContext=targetTab)
        return xchat.EAT_ALL
        
    def encrypt(self,key, msg):
        if key.cbc_mode:
            encrypt_clz = BlowfishCBC
            encrypt_func = mircryption_cbc_pack
        else:
            encrypt_clz = Blowfish
            encrypt_func = blowcrypt_pack
        b = encrypt_clz(key.key)
        return encrypt_func(msg, b)

    ## send message to local xchat and lock it
    def emit_print(self,userdata,speaker,message,target=None,toContext=None):
        if not toContext:
            toContext = xchat.get_context()
        if userdata == None:
            ## if userdata is none its possible Notice
            userdata = "Notice"
        if not target:
            ## if no special target for the lock is set, make it the speaker
            target = speaker
        ## lock the processing of that message
        self.__lock_proc(True,target=target)
        ## check for Highlight
        for hl in [xchat.get_info('nick')] + xchat.get_prefs("irc_extra_hilight").split(","):
            if len(hl) >0 and message.find(hl) > -1:
                if userdata == "Channel Message":
                    userdata = "Channel Msg Hilight"
                xchat.command("GUI COLOR 3")
        ## send the message
        toContext.emit_print(userdata,speaker, message.replace('\0',''))
        ## release the lock
        self.__lock_proc(False,target=target)

    ## set or release the lock on the processing to avoid loops
    def __lock_proc(self,state,target=None):
        ctx = xchat.get_context()
        if not target:
            ## if no target set, the current channel is the target
            target = ctx.get_info('channel')
        ## the lock is NETWORK-TARGET
        id = "%s-%s" % (ctx.get_info('network'),target)
        self.__lockMAP[id] = state

    ## check if that message is allready processed to avoid loops
    def __chk_proc(self,target=None):
        ctx = xchat.get_context()
        if not target:
            ## if no target set, the current channel is the target
            target = ctx.get_info('channel')
        id = "%s-%s" % (ctx.get_info('network'),target)
        return self.__lockMAP.get(id,False)

    # get an id from channel name and networkname
    def get_id(self,nick=None):
        ctx = xchat.get_context()
        if nick:
            target = nick
        else:
            target = str(ctx.get_info('channel'))
        ##return the id
        return (target, str(ctx.get_info('network')).lower())

    def find_key(self,id,create=None):
        key = self.__KeyMap.get(id,None)
        target, network = id
        networkmap = self.__TargetMap.get(network,None)
        if not networkmap:
            networkmap = {}
            self.__TargetMap[network] = networkmap
        if not key:
            lastaxx,key = networkmap.get(target,(-1,None))
        else:
            for _target,_key in filter(lambda x: x[1] == key,networkmap.items()):
                if _target != target:
                    del networkmap[_target]
        if not key and create:
            key = create
        if key:
            self.__TargetMap[network][target] = (int(time.time()),key)
        return key

    ## return the nick only
    def get_nick(self,full):
        if full[0] == ':':
            full = full[1:]
        try:
            ret = full[:full.index('!')]
        except ValueError:
            ret  = full
        return ret

    ## print encrypted localy
    def prn_crypt(self,word, word_eol, userdata):
        id = self.get_id()
        target, network = id
        key = self.find_key(id)
        if len(word_eol) < 2:
            print "usage: /PRNCRYPT <msg to encrypt>"
        else:    
            if key:
                print "%s%s" % (COLOR['blue'],self.encrypt(key,word_eol[1]))
            else:
                print "%sNo known Key found for %s" % (COLOR['red'],target,)
        return xchat.EAT_ALL

    ## print decrypted localy
    def prn_decrypt(self,word, word_eol, userdata):
        id = self.get_id()
        target, network = id
        key = self.find_key(id)
        if len(word_eol) < 2:
            print "usage: /PRNDECRYPT <msg to decrypt>"
        else:    
            if key:
                print "%s%s" % (COLOR['blue'],self.decrypt(key,word_eol[1]))
            else:
                print "%sNo known Key found for %s" % (COLOR['red'],target,)
        return xchat.EAT_ALL


    ## manual set a key for a nick or channel
    def set_key(self,word, word_eol, userdata):
        id = self.get_id()
        target, network = id
        
        ## if more than 2 parameter the nick/channel target is set to para 1 and the key is para 2
        if len(word) > 2:
            target = word[1]
            if target.find("@") > 0:
                target,network = target.split("@",1)
            newkey = word[2]
            id = (target,network)
        ## else the current channel/nick is taken as target and the key is para 1
        else:
            newkey = word[1]
        if len(newkey) < 8 or len(newkey) > 56:
            print "Key must be between 8 and 56 chars"
            return xchat.EAT_ALL
        ## get the Keyobject if available or get a new one
        key = self.find_key(id,create=SecretKey(None,protectmode=self.config['DEFAULTPROTECT'],cbcmode=self.config['DEFAULTCBC']))
        ## set the key 
        key.key = newkey
        key.keyname = id
        ## put it in the key dict
        self.__KeyMap[id] = key

        print "Key for %s on Network %s set to %r" % ( target,network,newkey)
        ## save the key storage
        self.saveDB()
        return xchat.EAT_ALL

    ## delete a key or all
    def del_key(self,word, word_eol, userdata):
        ## don't accept no parameter
        if len(word) <2:
            print "Error: /DELKEY nick|channel|* (* deletes all keys)"
            return xchat.EAT_ALL
        target = word_eol[1]
        ## if target name is * delete all
        if target == "*":
            self.__KeyMap = {}
        else:
            if target.find("@") > 0:
                target,network = target.split("@",1)
                id = target,network
            else:            
                id = self.get_id(nick=target)
                target,network = id
            ## try to delete the key
            try:
                del self.__KeyMap[id]
                print "Key for %s on %s deleted" % (target,network)
            except KeyError:
                print "Key %r not found" % (id,)
        ## save the keystorage
        self.saveDB()
        return xchat.EAT_ALL

    ## show either key for current chan/nick or all
    def show_key(self,word, word_eol, userdata):
        ## if no parameter show key for current chan/nick
        if len(word) <2:
            id = self.get_id()
        else:
            target = word_eol[1]
            network = ""
            if target.find("@") > 0:
                target,network = target.split("@",1)
                if network.find("*") > -1:
                    network = network[:-1]
            ## if para 1 is * show all keys and there states
            if target.find("*") > -1:
                print " -------- nick/chan ------- -------- network ------- -ON- -CBC- -PROTECT- -------------------- Key --------------------"
                for id,keys in self.__KeyMap.items():
                    if id[0].startswith(target[:-1]) and id[1].startswith(network):
                        print "  %-26.26s %-22.22s  %2.2s   %3.3s   %5.5s      %s" % (id[0],id[1],YESNO(keys.active),YESNO(keys.cbc_mode),YESNO(keys.protect_mode),keys.key)

                return xchat.EAT_ALL
            ## else get the id for the target
            id = self.get_id(nick=target)
        
        ## get the Key
        key = self.find_key(id)
        if key:
            ## show Key for the specified chan/nick
            print "[ %s ] Key: %s - Active: %s - CBC: %s - PROTECT: %s" % (key,key.key,YESNO(key.active),YESNO(key.cbc_mode),YESNO(key.protect_mode))
        else:
            print "No Key found"
        return xchat.EAT_ALL

    ## start commited key exchange
    def key_exchange_commit(self, word, word_eol, userdata):
        id = self.get_id()
        target,network = id
        if len(word) >1:
            target = word[1]
            id = (target,network)

        ## fixme chan notice - what should happen when keyx is send to channel trillian seems to accept it and send me a key --
        if target.startswith("#"):
            print "Channel Exchange not implemented"
            return xchat.EAT_ALL

        ## create DH 
        dh = DH1080Ctx()

        self.__KeyMap[id] = self.find_key(id,create=SecretKey(dh,protectmode=self.config['DEFAULTPROTECT'],cbcmode=self.config['DEFAULTCBC']))
        self.__KeyMap[id].keyname = id
        self.__KeyMap[id].dh = dh

        ## lock the target
        self.__lock_proc(True)
        ## send hash of public key with notice to target
        self.__KeyMap[id].commit = hashlib.sha256(dh.public).hexdigest()
        xchat.command('NOTICE %s DH1080_COMMIT %s' % (target, self.__KeyMap[id].commit))
        ## release the lock
        self.__lock_proc(False)


    ## Answer to authenticated KeyExchange
    def dh1080_commit(self, word, word_eol, userdata):
        id = self.get_id(nick=self.get_nick(word[0]))
        target,network = id
        message = word_eol[3].lstrip(":+")
        key = self.find_key(id,create=SecretKey(None,protectmode=self.config['DEFAULTPROTECT'],cbcmode=self.config['DEFAULTCBC']))
        ## Protection against a new key if "/PROTECTKEY" is on for nick
        if key.protect_mode:
            print "%sKEYPROTECTION: %s on %s" % (COLOR['red'],target,network)
            xchat.command("notice %s %s KEYPROTECTION:%s %s" % (target,self.config['PLAINTEXTMARKER'],COLOR['red'],target))
            return xchat.EAT_ALL

        ## Stealth Check
        if self.config['FISHSTEALTH']:
            print "%sSTEALTHMODE: %s tried a commited keyexchange on %s" % (COLOR['green'],target,network)
            return xchat.EAT_ALL

        key.keyname = id
        key.commit = message

        print "DH1080 Commit: %s on %s" % (target,network)
        xchat.command('KEYX %s' % target)
        return xchat.EAT_ALL


    ## start the DH1080 Key Exchange
    def key_exchange(self,word, word_eol, userdata):
        id = self.get_id()
        target,network = id
        if len(word) >1:
            target = word[1]
            id = (target,network)

        ## fixme chan notice - what should happen when keyx is send to channel trillian seems to accept it and send me a key --
        if target.startswith("#"):
            print "Channel Exchange not implemented"
            return xchat.EAT_ALL

        if not hasattr(self.__KeyMap[id], "commit"):
            ## create DH 
            dh = DH1080Ctx()

            self.__KeyMap[id] = self.find_key(id,create=SecretKey(dh,protectmode=self.config['DEFAULTPROTECT'],cbcmode=self.config['DEFAULTCBC']))
            self.__KeyMap[id].keyname = id
            self.__KeyMap[id].dh = dh

        ## lock the target
        self.__lock_proc(True)
        ## send key with notice to target
        xchat.command('NOTICE %s %s' % (target, dh1080_pack(dh)))
        ## release the lock
        self.__lock_proc(False)

        ## save the key storage
        self.saveDB()
        return xchat.EAT_ALL


    ## Answer to KeyExchange
    def dh1080_init(self,word, word_eol, userdata):
        id = self.get_id(nick=self.get_nick(word[0]))
        target,network = id
        message = word_eol[3].lstrip(":+")
        key = self.find_key(id,create=SecretKey(None,protectmode=self.config['DEFAULTPROTECT'],cbcmode=self.config['DEFAULTCBC']))
        ## Protection against a new key if "/PROTECTKEY" is on for nick
        if key.protect_mode:
            print "%sKEYPROTECTION: %s on %s" % (COLOR['red'],target,network)
            xchat.command("notice %s %s KEYPROTECTION:%s %s" % (target,self.config['PLAINTEXTMARKER'],COLOR['red'],target))
            return xchat.EAT_ALL

        ## Stealth Check
        if self.config['FISHSTEALTH']:
            print "%sSTEALTHMODE: %s tried a keyexchange on %s" % (COLOR['green'],target,network)
            return xchat.EAT_ALL

        mirc_mode = False
        try:
            if word[5] == "CBC":
                print "mIRC CBC KeyExchange detected."
                message = "%s %s" % (word[3].lstrip(":+"),word[4])
                mirc_mode = True
        except IndexError:
            pass

        dh = DH1080Ctx()
        dh1080_unpack(message, dh)
        key.key = dh1080_secret(dh)
        key.keyname = id

        ## lock the target
        self.__lock_proc(True)
        ## send key with notice to target
        if mirc_mode:
            xchat.command('NOTICE %s %s CBC' % (target, dh1080_pack(dh)))
        else:
            xchat.command('NOTICE %s %s' % (target, dh1080_pack(dh)))
            
        ## release the lock
        self.__lock_proc(False)
        self.__KeyMap[id] = key
        print "DH1080 Init: %s on %s" % (target,network)
        #print "Key set to %r" % (key.key,)
        received_public = bytes2int(dh1080_b64decode(message.split(' ', 1)[1]))
        fingerprint = hmac.new(key.key, str(key.dh.public) + str(received_public), digestmode=hashlib.sha256)
        auth = fingerprint.hexdigest()
        if hasattr(key, "commit"):
            print "Key set (Authenticate: %s" %auth[:4]
        else:
            print "Key set (Authenticate: %s" %auth

        fingerprint = hashlib.sha256(str(dh.public +
                bytes2int(dh1080_b64decode(message.split(' ', 1)[1]))))
        print "Key set (Authentication: %s)" %fingerprint.hexdigest()[:32]
        ## save key storage
        self.saveDB()
        return xchat.EAT_ALL

    ## Answer from targets init
    def dh1080_finish(self,word, word_eol, userdata):
        id = self.get_id(nick=self.get_nick(word[0]))
        message = word_eol[3].lstrip(":+")
        target,network = id
        ## fixme if not explicit send to the Target the received key is discarded - chan exchange 
        if id not in self.__KeyMap:
            print "Invalid DH1080 Received from %s on %s" % (target,network)
            return xchat.EAT_NONE
        key = self.__KeyMap[id]
        received_public = bytes2int(dh1080_b64decode(message.split(' ', 1)[1]))
        if hasattr(key, "commit") & hashlib.sha256().hexdigest(received_public) != key.commit:
            print "Unverified DH1080 Received from %s on %s" % (target,network)
            return xchat.EAT_NONE
        dh1080_unpack(message, key.dh)
        key.key = dh1080_secret(key.dh)
        key.keyname = id
        print "DH1080 Finish: %s on %s" % (target,network)
        #print "Key set to %r" % (key.key,)
        fingerprint = hmac.new(key.key, str(key.dh.public) + str(received_public), digestmode=hashlib.sha256)
        auth = fingerprint.hexdigest()
        if hasattr(key, "commit"):
            print "Key set (Authenticate: %s" %auth[:4]
        else:
            print "Key set (Authenticate: %s" %auth
        ## save key storage
        self.saveDB()
        return xchat.EAT_ALL

    ## set cbc mode or show the status
    def set_cbc(self,word, word_eol, userdata):
        ## check for parameter
        if len(word) >2:
            # if both specified first is target second is mode on/off
            target = word[1]
            mode = word[2]
        else:
            ## if no target defined target is current chan/nick
            target = None
            if len(word) >1:
                ## if one parameter set mode to it else show only
                mode = word[1]

        id = self.get_id(nick=target)
        target,network = id
        ## check if there is a key
        key = self.find_key(id)
        if not key:
            print "No Key found for %r" % (target,)
        else:
            ## if no parameter show only status
            if len(word) == 1:
                print "CBC Mode is %s" % ((key.cbc_mode and "on" or "off"),)
            else:
                ## set cbc mode to on/off
                key.cbc_mode = bool(mode in ONMODES)
                print "set CBC Mode for %s to %s" % (target,(key.cbc_mode == True and "on") or "off")
                ## save key storage
                self.saveDB()
        return xchat.EAT_ALL

    ## set key protection mode or show the status
    def set_protect(self,word, word_eol, userdata):
        ## check for parameter
        if len(word) >2:
            # if both specified first is target second is mode on/off
            target = word[1]
            mode = word[2]
        else:
            ## if no target defined target is current nick, channel is not allowed/possible yet
            target = None
            if len(word) >1:
                ## if one parameter set mode to it else show only
                mode = word[1]

        id = self.get_id(nick=target)
        target,network = id
        if "#" in target:
            print "We don't make channel protection. Sorry!"
            return xchat.EAT_ALL
        
        key = self.find_key(id)
        ## check if there is a key
        if not key:
            print "No Key found for %r" % (target,)
        else:
            ## if no parameter show only status
            if len(word) == 1:
                print "KEY Protection is %s" % ((key.protect_mode and "on" or "off"),)
            else:
                ## set KEY Protection mode to on/off
                key.protect_mode = bool(mode in ONMODES)
                print "set KEY Protection for %s to %s" % (target,(key.protect_mode == True and "on") or "off")
                ## save key storage
                self.saveDB()
        return xchat.EAT_ALL


    ## activate/deactivate encryption for chan/nick
    def set_act(self,word, word_eol, userdata):
        ## if two parameter first is target second is mode on/off
        if len(word) >2:
            target = word[1]
            mode = word[2]
        else:
            ## target is current chan/nick 
            target = None
            if len(word) >1:
                ## if one parameter set mode to on/off
                mode = word[1]

        id = self.get_id(nick=target)
        target,network = id
        key = self.find_key(id)
        ## key not found
        if not key:
            print "No Key found for %r" % (target,)
        else:
            if len(word) == 1:
                ## show only
                print "Encryption is %s" % ((key.active and "on" or "off"),)
            else:
                ## set mode to on/off 
                key.active = bool(mode in ONMODES)
                print "set Encryption for %s to %s" % (target,(key.active == True and "on") or "off")
                ## save key storage
                self.saveDB()
        return xchat.EAT_ALL

    ## handle topic server message
    def server_332_topic(self,word, word_eol, userdata):
        ## check if allready processing
        if self.__chk_proc():
            return xchat.EAT_NONE
        server, cmd, nick, channel, topic = word[0], word[1], word[2], word[3], word_eol[4]
        
        if word[4].endswith("+OK"):
            idx = len(word[4]) - len("+OK")
            topic = word_eol[4][idx:]
        elif word[4].endswith("mcps"):
            idx = len(word[4]) - len("mcps")
            topic = word_eol[4][idx:]

        ## check if topic is crypted
        if not topic.startswith('+OK ') and not topic.startswith('mcps '):
            return xchat.EAT_NONE
        id = self.get_id(nick=channel)
        ## look for a key
        key = self.find_key(id,create=SecretKey(None))
        ## if no key exit
        if not key.key:
            return xchat.EAT_NONE
        ## decrypt
        topic = self.decrypt(key, topic)
        ##todo utf8 check for illegal chars
        if not topic:
            return xchat.EAT_NONE
        ## lock the target
        self.__lock_proc(True)
        ## send the message to xchat
        xchat.command('RECV %s %s %s %s :%s' % (server, cmd, nick, channel, topic.replace("\x00","")))
        ## release the lock
        self.__lock_proc(False)
        return xchat.EAT_ALL

    ## trace nick changes
    def nick_trace(self,word, word_eol, userdata):
        old, new = word[0], word[1]
        ## create id's for old and new nick
        oldid,newid = (self.get_id(nick=old),self.get_id(nick=new))
        target, network = newid
        networkmap = self.__TargetMap.get(network,None)
        if not networkmap:
            networkmap = {}
            self.__TargetMap[network] = networkmap
        key = self.__KeyMap.get(oldid,None)
        if not key:
            lastaxx,key = networkmap.get(old,(-1,None))
        if key:
            ## make the new nick the entry the old
            networkmap[new] = (int(time.time()),key)
            try:
                del networkmap[old]
            except KeyError:
                pass
            ## save key storage
            self.saveDB()
        return xchat.EAT_NONE

## Preliminaries.

class MalformedError(Exception):
    pass


def sha256(s):
    """sha256"""
    return hashlib.sha256(s).digest()


def int2bytes(n):
    """Integer to variable length big endian."""
    if n == 0:
        return '\x00'
    b = []
    while n:
        b.insert(0,chr(n % 256))
        n /= 256
    return "".join(b)


def bytes2int(b):
    """Variable length big endian to integer."""
    n = 0
    for p in b:
        n *= 256
        n += ord(p)
    return n

def padto(msg, length):
    """Pads 'msg' with zeroes until it's length is divisible by 'length'.
    If the length of msg is already a multiple of 'length', does nothing."""
    L = len(msg)
    if L % length:
        msg = "%s%s" % (msg,'\x00' * (length - L % length))
    assert len(msg) % length == 0
    return msg

def cbc_encrypt(func, data, blocksize):
    """The CBC mode. The randomy generated IV is prefixed to the ciphertext.
    'func' is a function that encrypts data in ECB mode. 'data' is the
    plaintext. 'blocksize' is the block size of the cipher."""
    assert len(data) % blocksize == 0
    
    IV = os.urandom(blocksize)
    assert len(IV) == blocksize
    
    ciphertext = IV
    for block_index in xrange(len(data) / blocksize):
        xored = xorstring(data[:blocksize], IV)
        enc = func(xored)
        
        ciphertext += enc
        IV = enc
        data = data[blocksize:]

    assert len(ciphertext) % blocksize == 0
    return ciphertext


def cbc_decrypt(func, data, blocksize):
    """See cbc_encrypt."""
    assert len(data) % blocksize == 0
    
    IV = data[0:blocksize]
    data = data[blocksize:]

    plaintext = ''
    for block_index in xrange(len(data) / blocksize):
        temp = func(data[0:blocksize])
        temp2 = xorstring(temp, IV)
        plaintext += temp2
        IV = data[0:blocksize]
        data = data[blocksize:]
    
    assert len(plaintext) % blocksize == 0
    return plaintext


class Blowfish:
    def __init__(self, key=None):
        if key:
            self.blowfish = cBlowfish.new(key)

    def decrypt(self, data):
        return self.blowfish.decrypt(data)
    
    def encrypt(self, data):
        return self.blowfish.encrypt(data)


class BlowfishCBC:
    
    def __init__(self, key=None):
        if key:
            self.blowfish = cBlowfish.new(key)

    def decrypt(self, data):
        return cbc_decrypt(self.blowfish.decrypt, data, 8)
    
    def encrypt(self, data):
        return cbc_encrypt(self.blowfish.encrypt, data, 8)

## blowcrypt, Fish etc.
# XXX: Unstable.
def blowcrypt_b64encode(s):
    """A non-standard base64-encode."""
    B64 = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    res = []
    while s:
        left, right = struct.unpack('>LL', s[:8])
        for i in xrange(6):
            res.append( B64[right & 0x3f] )
            right >>= 6
        for i in xrange(6):
            res.append( B64[left & 0x3f] )
            left >>= 6
        s = s[8:]
    return "".join(res)

def blowcrypt_b64decode(s):
    """A non-standard base64-decode."""
    B64 = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    res = []
    while s:
        left, right = 0, 0
        for i, p in enumerate(s[0:6]):
            right |= B64.index(p) << (i * 6)
        for i, p in enumerate(s[6:12]):
            left |= B64.index(p) << (i * 6)
        res.append( struct.pack('>LL', left, right) )
        s = s[12:]
    return "".join(res)

def blowcrypt_pack(msg, cipher):
    """."""
    return '+OK %s' % (blowcrypt_b64encode(cipher.encrypt(padto(msg, 8))))

def blowcrypt_unpack(msg, cipher):
    """."""
    if not (msg.startswith('+OK ') or msg.startswith('mcps ')):
        raise ValueError
    _, rest = msg.split(' ', 1)
    if (len(rest) % 12):
        raise MalformedError

    try:
        raw = blowcrypt_b64decode(rest)
    except TypeError:
        raise MalformedError
    if not raw:
        raise MalformedError

    try:
        plain = cipher.decrypt(raw)
    except ValueError:
        raise MalformedError
    
    return plain.strip('\x00')

## Mircryption-CBC
def mircryption_cbc_pack(msg, cipher):
    """."""
    padded = padto(msg, 8)
    return '+OK *%s' % (base64.b64encode(cipher.encrypt(padded)))


def mircryption_cbc_unpack(msg, cipher):
    """."""
    if not (msg.startswith('+OK *') or msg.startswith('mcps *')):
        raise ValueError

    try:
        _, coded = msg.split('*', 1)
        raw = base64.b64decode(coded)
    except TypeError:
        raise MalformedError
    if not raw:
        raise MalformedError

    try:
        padded = cipher.decrypt(raw)
    except ValueError:
        raise MalformedError
    if not padded:
        raise MalformedError

    return padded.strip('\x00')

## DH1080
g_dh1080 = 2
p_dh1080 = int('FBE1022E23D213E8ACFA9AE8B9DFAD'
               'A3EA6B7AC7A7B7E95AB5EB2DF85892'
               '1FEADE95E6AC7BE7DE6ADBAB8A783E'
               '7AF7A7FA6A2B7BEB1E72EAE2B72F9F'
               'A2BFB2A2EFBEFAC868BADB3E828FA8'
               'BADFADA3E4CC1BE7E8AFE85E9698A7'
               '83EB68FA07A77AB6AD7BEB618ACF9C'
               'A2897EB28A6189EFA07AB99A8A7FA9'
               'AE299EFA7BA66DEAFEFBEFBF0B7D8B', 16)
q_dh1080 = (p_dh1080 - 1) / 2 

def dh1080_b64encode(s):
    """A non-standard base64-encode."""
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    d = [0]*len(s)*2

    L = len(s) * 8
    m = 0x80
    i, j, k, t = 0, 0, 0, 0
    while i < L:
        if ord(s[i >> 3]) & m:
            t |= 1
        j += 1
        m >>= 1
        if not m:
            m = 0x80
        if not j % 6:
            d[k] = b64[t]
            t &= 0
            k += 1
        t <<= 1
        t %= 0x100
        #
        i += 1
    m = 5 - j % 6
    t <<= m
    t %= 0x100
    if m:
        d[k] = b64[t]
        k += 1
    d[k] = 0
    res = []
    for q in d:
        if q == 0:
            break
        res.append(q)
    return "".join(res)

def dh1080_b64decode(s):
    """A non-standard base64-encode."""
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    buf = [0]*256
    for i in range(64):
        buf[ord(b64[i])] = i

    L = len(s)
    if L < 2:
        raise ValueError
    for i in reversed(range(L-1)):
        if buf[ord(s[i])] == 0:
            L -= 1
        else:
            break
    if L < 2:
        raise ValueError

    d = [0]*L
    i, k = 0, 0
    while True:
        i += 1
        if k + 1 < L:
            d[i-1] = buf[ord(s[k])] << 2
            d[i-1] %= 0x100
        else:
            break
        k += 1
        if k < L:
            d[i-1] |= buf[ord(s[k])] >> 4
        else:
            break
        i += 1
        if k + 1 < L:
            d[i-1] = buf[ord(s[k])] << 4
            d[i-1] %= 0x100
        else:
            break
        k += 1
        if k < L:
            d[i-1] |= buf[ord(s[k])] >> 2
        else:
            break
        i += 1
        if k + 1 < L:
            d[i-1] = buf[ord(s[k])] << 6
            d[i-1] %= 0x100
        else:
            break
        k += 1
        if k < L:
            d[i-1] |= buf[ord(s[k])] % 0x100
        else:
            break
        k += 1
    return ''.join(map(chr, d[0:i-1]))


def dh_validate_public(public, q, p):
    """See RFC 2631 section 2.1.5."""
    return 1 == pow(public, q, p)


class DH1080Ctx:
    """DH1080 context."""
    def __init__(self):
        self.public = 0
        self.private = 0
        self.secret = 0
        self.state = 0
        
        bits = 1080
        while True:
            self.private = bytes2int(os.urandom(bits/8))
            self.public = pow(g_dh1080, self.private, p_dh1080)
            if 2 <= self.public <= p_dh1080 - 1 and \
               dh_validate_public(self.public, q_dh1080, p_dh1080) == 1:
                break

def dh1080_pack(ctx):
    """."""
    if ctx.state == 0:
        ctx.state = 1
        cmd = "DH1080_INIT"
    else:
        cmd = "DH1080_FINISH"
    return "%s %s" % (cmd,dh1080_b64encode(int2bytes(ctx.public)))

def dh1080_unpack(msg, ctx):
    """."""
    if not "DH1080_" in msg:
        raise ValueError

    invalidmsg = "Key does not validate per RFC 2631. This check is not performed by any DH1080 implementation, so we use the key anyway. See RFC 2785 for more details."

    if ctx.state == 0:
        if not "DH1080_INIT " in msg:
            raise MalformedError
        ctx.state = 1
        try:
            cmd, public_raw = msg.split(' ', 1)
            public = bytes2int(dh1080_b64decode(public_raw))

            if not 1 < public < p_dh1080:
                raise MalformedError
            
            if not dh_validate_public(public, q_dh1080, p_dh1080):
                print invalidmsg
                pass
                
            ctx.secret = pow(public, ctx.private, p_dh1080)
        except:
            raise MalformedError

    elif ctx.state == 1:
        if not "DH1080_FINISH " in msg:
            raise MalformedError
        ctx.state = 1
        try:
            cmd, public_raw = msg.split(' ', 1)
            public = bytes2int(dh1080_b64decode(public_raw))

            if not 1 < public < p_dh1080:
                raise MalformedError

            if not dh_validate_public(public, q_dh1080, p_dh1080):
                print invalidmsg
                pass
            
            ctx.secret = pow(public, ctx.private, p_dh1080)
        except:
            raise MalformedError

    return True
        

def dh1080_secret(ctx):
    """."""
    if ctx.secret == 0:
        raise ValueError
    return dh1080_b64encode(sha256(int2bytes(ctx.secret)))

if REQUIRESETUP:
    __install_thread = None
    def _install_pyBlowfish(urllib2,doExtra):
        global __install_thread
        if __install_thread:
            print "Install is allready running"
            return
        __install_thread = Thread(target=__install_pyBlowfish,kwargs={'urllib2':urllib2,'context':xchat.get_context()})
        __install_thread.start()
    def __install_pyBlowfish(urllib2,context):
        global __install_thread
        context.prnt("\0038.....checking for pyBlowfish.py at %r... please wait ...." % PYBLOWFISHURL)
        try:
            __script = urllib2.urlopen(PYBLOWFISHURL,timeout=40).read()
            try:
                __fd = open("%s%spyBlowfish.py" % (path,sep),"wb")
                __fd.write(__script)
                print "\002\0033Please type /py reload %s" % script
            finally:
                __fd.close()
        except urllib2.URLError,err:
            print err

        except:
            context.prnt( "\002\0034INSTALL FAILED" )
            raise
        __install_thread = None

    def fishsetup(word, word_eol, userdata):
        useproxy = True
        if len(word) >1:
            if word[1].lower() == "noproxy":
                useproxy = False
        proxyload(_install_pyBlowfish,useproxy,None)
        return xchat.EAT_ALL
    xchat.hook_command('FISHSETUP', fishsetup)
else:    
    loadObj = XChatCrypt()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

