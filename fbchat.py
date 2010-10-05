#!/usr/bin/env python
# jloomis@gmail.com - crappy modified facebook chat example with oauth 2.0
# chat.facebook.com doesn't accept ssl connections, hence no access token
# authentication. To get around that, we parse a session key out of the
# access token, and use an old facebook REST API method - auth.promoteSession -
# to associate a secret with it.

# original facebook chat example from: http://developers.facebook.com/docs/chat
# here is their blurb:
# This is a demonstration script for Facebook Chat
# using the X-FACEBOOK-PLATFORM SASL mechanism.
# It requires pyfacebook and pyxmpp to be installed.
# This client only works for desktop applications (configured in the
# developer app)
#

# 3 methods copied from pyfacebook for clarity's sake, so here's their blurb:
#
# pyfacebook - Python bindings for the Facebook API
#
# Copyright (c) 2008, Samuel Cormier-Iijima
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the author nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Python bindings for the Facebook API (pyfacebook - http://code.google.com/p/pyfacebook)


import sys
import os
import facebook
import json
import urllib
import urllib2
import cgi

APP_KEY = None
APP_SECRET = None
APP_ID = None

redirect_uri = 'http://www.facebook.com/connect/login_success.html'
login_url = 'https://graph.facebook.com/oauth/authorize?'

def get_facebook_client():
    client = facebook.Facebook(APP_KEY, APP_SECRET)
    try:
        # Try to read cached credentials from the cookies file.
        # If authorization fails, you should delete this file and start over.
        handle = open('cookies.txt', 'r')
        client.uid, client.access_token, client.session_key, client.secret = [ line.strip() for line in handle ]
        handle.close()
    except IOError:
        code = getCode()
        client.access_token = getAccessToken(code)
        client.session_key = getSessionKey(client.access_token, code)
        client.secret = getSessionSecret(client.access_token)
        client.uid = getUid(client.access_token)
        handle = open('cookies.txt', 'w')
        print >> handle, client.uid
        print >> handle, client.access_token
        print >> handle, client.session_key
        print >> handle, client.secret
        handle.close()

    return client


def getCode():
    params = {}
    params['display'] = 'popup'
    params['client_id'] = APP_ID
    params['scope'] = 'xmpp_login'
    params['redirect_uri'] = redirect_uri
    auth_url = login_url+urllib.urlencode(params)
    print 'Log in to the app in your browser, copy the part after code= in the url bar, paste here & press enter.'
    import webbrowser
    webbrowser.open(auth_url)
    code = raw_input()
    return str(code)

def getAccessToken(code):
    access_token = None
    params = {}
    params['client_id'] = APP_ID
    params['redirect_uri'] = redirect_uri
    params['client_secret'] = APP_SECRET
    params['code'] = code
    try:
        response = cgi.parse_qs(urllib2.urlopen(
            "https://graph.facebook.com/oauth/access_token?" +
            urllib.urlencode(params)).read())
        #response is {'access_token': ['userAcesstoken123']}
        access_token = response["access_token"][-1]
        return access_token
    except Exception, e:
        print str(e)

def getUid(access_token):
    profile = json.load(urllib2.urlopen(
                "https://graph.facebook.com/me?" +
                urllib.urlencode(dict(access_token=access_token))))
    uid = profile['id']
    return uid

# currently access_token is of form appId | blah-uid | foo, where blah-uid is sessionKey.
# If fb changes format, try to get it from code, which is in form: blah-uid %7C bah.
def getSessionKey(token, code=None):
    parts = urllib2.unquote(token).split('|')
    if len(parts) < 3:
        if code is not None:
            return urllib2.unquote(code).split('|')[0]
        else:
            return 'ParseSessionKeyFailed'
    else:
        return parts[1]

# get a session secret associated with the access token (and it's underlying session key)
def getSessionSecret(access_token):
    try:
        return json.load(urllib2.urlopen(
                'https://api.facebook.com/method/auth.promoteSession?' +
                urllib.urlencode(dict(access_token=access_token, format='JSON')))).encode("UTF-8")
    except Exception, e:
        return 'FetchSecretFailed'


# build_post_args, hash_args, and add_session_args are ripped from
# pyfacebook library to make it clear what this example is actually doing
def build_post_args(method, args, secret):
    for arg in args.items():
        if type(arg[1]) == list:
            args[arg[0]] = ','.join(str(a) for a in arg[1])
        elif type(arg[1]) == unicode:
            args[arg[0]] = arg[1].encode("UTF-8")
        elif type(arg[1]) == bool:
            args[arg[0]] = str(arg[1]).lower()

    args['method'] = method
    args['api_key'] = APP_KEY
    args['v'] = '1.0'
    args['sig'] = hash_args(args, secret)
    return args

def hash_args(args, secret):
    """Hashes arguments by joining key=value pairs, appending a secret, and then taking the MD5 hex digest."""
    import hashlib
    #Before hashing arrange kv pairs in alphabetical order by key, in form a=1b=7c=foo
    tohash = ''.join(['%s=%s' % (isinstance(x, unicode) and x.encode("utf-8") or x, isinstance(args[x], unicode) and args[x].encode("utf-8") or args[x]) for x in sorted(args.keys())])
    print 'to hash: ', tohash, ' secret: ', secret
    hasher = hashlib.md5(tohash + secret)
    return hasher.hexdigest()

def add_session_args(args, session):
    """Adds 'session_key' and 'call_id' to args, which are used for API calls that need sessions."""
    import time
    if args is None:
        args = {}

    args['call_id'] = str(int(time.time() * 1000))
    args['session_key'] = session
    return args

from pyxmpp.sasl.core import ClientAuthenticator
from pyxmpp.sasl.core import Response, Failure, Success

class XFacebookPlatformClientAuthenticator(ClientAuthenticator):
    def __init__(self, password_manager, fb_client=None):
        ClientAuthenticator.__init__(self, password_manager)
        if fb_client is None:
            global global_fb_client
            fb_client = global_fb_client
        self._fb_client = fb_client

    def start(self, ignored_username, ignored_authzid):
        return Response()

    def challenge(self, challenge):
        in_params = dict([part.split('=') for part in challenge.split('&')])
        out_params = {'nonce': in_params['nonce']}
        out_params = add_session_args(out_params, self._fb_client.session_key)
        out_params = build_post_args(in_params['method'], out_params, self._fb_client.secret)
        return Response(urllib.urlencode(out_params))

    def finish(self,data):
        return Success(None)


from pyxmpp.all import JID, Presence, Message
from pyxmpp.client import Client

class FacebookChatClient(Client):
    def __init__(self, to_uid, message, **kwargs):
        Client.__init__(self, **kwargs)
        self.to_uid = to_uid
        self.message = message
        self.sent = False

    def session_started(self):
        self.get_stream().set_message_handler('chat', self.got_message)
        self.get_stream().send(Presence())

    def idle(self):
        print 'Idle...'
        Client.idle(self)
        if self.session_established and not self.sent:
            self.sent = True
            target = JID('-' + self.to_uid, self.jid.domain)
            self.get_stream().send(Message(to_jid=target, body=unicode(self.message)))

    def got_message(self, stanza):
        print stanza.get_from().node, stanza.get_body()



if __name__ == '__main__':
    # Uncomment these lines to get more verbose logging.
    import logging
    logger = logging.getLogger()
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

    # Sneak our authenticator into the map.
    import pyxmpp.sasl
    pyxmpp.sasl.all_mechanisms_dict['X-FACEBOOK-PLATFORM'] = \
    (XFacebookPlatformClientAuthenticator, None)

    try:
        handle = open('appData.txt', 'r')
        APP_ID, APP_KEY, APP_SECRET = [ line.strip() for line in handle ]
        handle.close()
    except IOError:
        print "Paste facebook app id here (no quotes), and press enter: "
        APP_ID = str(raw_input())
        print "Paste facebook app key here (no quotes), and press enter: "
        APP_KEY = str(raw_input())
        print "Paste facebook app secret here (no quotes), and press enter: "
        APP_SECRET = str(raw_input())
        handle = open('appData.txt', 'w')
        print >> handle, APP_ID
        print >> handle, APP_KEY
        print >> handle, APP_SECRET
        handle.close()

    print 'Preparing Facebook client...'
    global_fb_client = get_facebook_client()

    try:
        my_uid = str(global_fb_client.uid)
        to_uid = sys.argv[1]
        message = unicode(sys.argv[2])
        my_jid = '-' + my_uid + '@chat.facebook.com/TestClient'
    except IndexError:
        sys.exit('usage: %s {to_uid} {message}' % sys.argv[0])

    print 'Creating stream...'
    xmpp_client = FacebookChatClient(
            to_uid = to_uid,
            message = message,
            jid = JID(my_jid),
            password = u'ignored',
            auth_methods = ['sasl:X-FACEBOOK-PLATFORM'],
            #server = 'localhost'
            )

    print 'Connecting...'
    xmpp_client.connect()

    print 'Processing...'
    try:
        xmpp_client.loop(1)
    finally:
        xmpp_client.disconnect()