#!/usr/bin/env python
# XMPP client utils for testing bot


from twisted.internet import reactor, defer
from twisted.internet.task import LoopingCall
from twisted.words.protocols.jabber import xmlstream, sasl, sasl_mechanisms, jid, client
from twisted.words.protocols.jabber.client import CheckVersionInitializer, BindInitializer,\
    SessionInitializer
from twisted.words.xish import domish

from wokkel import xmppim

from zope.interface import implements

import gpgme

try:
    from io import BytesIO
except ImportError:
    from StringIO import StringIO as BytesIO

try:
    from OpenSSL import crypto
    from twisted.internet import ssl
except ImportError:
    ssl = None
if ssl and not ssl.supported:
    ssl = None

import base64

from kontalk.xmppserver import util, xmlstream2


def user_token(userid, fp):
    '''Generates a user token.'''

    '''
    token is made up of the hashed phone number (the user id)
    plus the resource (in one big string, 40+8 characters),
    and the fingerprint of the server he registered to
    '''
    string = '%s|%s' % (userid, fp)
    plain = BytesIO(str(string))
    cipher = BytesIO()
    ctx = gpgme.Context()
    ctx.armor = False

    # signing key
    ctx.signers = [ctx.get_key(fp)]

    ctx.sign(plain, cipher, gpgme.SIG_MODE_NORMAL)
    cipher.seek(0, 0)
    token = cipher.read()
    return base64.b64encode(token)


class KontalkExternalMechanism(object):
    """Implements the external SASL authentication mechanism."""
    implements(sasl_mechanisms.ISASLMechanism)

    name = 'EXTERNAL'

    def __init__(self, data='='):
        self.data = data

    def getInitialResponse(self):
        return self.data


class KontalkTokenMechanism(object):
    """Implements the Kontalk token SASL authentication mechanism."""
    implements(sasl_mechanisms.ISASLMechanism)

    name = 'KONTALK-TOKEN'

    def __init__(self, token=None):
        self.token = token

    def getInitialResponse(self):
        return self.token.encode('utf-8')

class KontalkSASLInitiatingInitializer(xmlstream.BaseFeatureInitiatingInitializer):
    """Stream initializer that performs SASL authentication (only Kontalk)."""

    feature = (sasl.NS_XMPP_SASL, 'mechanisms')
    _deferred = None

    def setMechanism(self):
        """
        Select and setup authentication mechanism.
        """

        self.mechanism = None

        token = self.xmlstream.authenticator.token

        mechanisms = sasl.get_mechanisms(self.xmlstream)
        if token is not None and 'KONTALK-TOKEN' in mechanisms:
            self.mechanism = KontalkTokenMechanism(token)
        elif 'EXTERNAL' in mechanisms:
            self.mechanism = KontalkExternalMechanism()

        if not self.mechanism:
            raise sasl.SASLNoAcceptableMechanism()

    def start(self):
        """
        Start SASL authentication exchange.
        """

        self.setMechanism()
        self._deferred = defer.Deferred()
        self.xmlstream.addOnetimeObserver('/success', self.onSuccess)
        self.xmlstream.addOnetimeObserver('/failure', self.onFailure)
        self.xmlstream.addOnetimeObserver('/challenge', self.onChallenge)
        self.sendAuth(self.mechanism.getInitialResponse())
        return self._deferred

    def sendAuth(self, data=None):
        """
        Initiate authentication protocol exchange.

        If an initial client response is given in C{data}, it will be
        sent along.

        @param data: initial client response.
        @type data: L{str} or L{None}.
        """

        auth = domish.Element((sasl.NS_XMPP_SASL, 'auth'))
        auth['mechanism'] = self.mechanism.name
        if data is not None:
            # token is already base64
            auth.addContent(data)
        self.xmlstream.send(auth)

    def onChallenge(self, challenge):
        challenge_str = str(challenge)
        response = self.mechanism.getResponse(base64.b64decode(challenge_str))
        packet = domish.Element((sasl.NS_XMPP_SASL, 'response'))
        packet.addContent(base64.b64encode(response))
        self.xmlstream.send(packet)

    def onSuccess(self, success):
        self.xmlstream.removeObserver('/failure', self.onFailure)
        self.xmlstream.reset()
        self.xmlstream.sendHeader()
        self._deferred.callback(xmlstream.Reset)

    def onFailure(self, failure):
        self.xmlstream.removeObserver('/success', self.onSuccess)
        try:
            condition = failure.firstChildElement().name
        except AttributeError:
            condition = None
        self._deferred.errback(sasl.SASLAuthError(condition))


class TLSInitiatingInitializer(xmlstream.BaseFeatureInitiatingInitializer):
    """
    TLS stream initializer for the initiating entity.

    It is strongly required to include this initializer in the list of
    initializers for an XMPP stream. By default it will try to negotiate TLS.
    An XMPP server may indicate that TLS is required. If TLS is not desired,
    set the C{wanted} attribute to False instead of removing it from the list
    of initializers, so a proper exception L{TLSRequired} can be raised.

    @cvar wanted: indicates if TLS negotiation is wanted.
    @type wanted: C{bool}
    """

    feature = (xmlstream.NS_XMPP_TLS, 'starttls')
    wanted = True
    _deferred = None

    def onProceed(self, obj):
        """
        Proceed with TLS negotiation and reset the XML stream.
        """

        self.xmlstream.removeObserver('/failure', self.onFailure)
        cert = self.xmlstream.authenticator.certificate
        key = self.xmlstream.authenticator.privkey
        print "using certificate data: %s" % (cert.get_subject(), )
        ctx = ssl.CertificateOptions(privateKey=key, certificate=cert)
        self.xmlstream.transport.startTLS(ctx)
        self.xmlstream.reset()
        self.xmlstream.sendHeader()
        self._deferred.callback(xmlstream.Reset)


    def onFailure(self, obj):
        self.xmlstream.removeObserver('/proceed', self.onProceed)
        self._deferred.errback(xmlstream.TLSFailed())


    def start(self):
        """
        Start TLS negotiation.

        This checks if the receiving entity requires TLS, the SSL library is
        available and uses the C{required} and C{wanted} instance variables to
        determine what to do in the various different cases.

        For example, if the SSL library is not available, and wanted and
        required by the user, it raises an exception. However if it is not
        required by both parties, initialization silently succeeds, moving
        on to the next step.
        """
        if self.wanted:
            if ssl is None:
                if self.required:
                    return defer.fail(xmlstream.TLSNotSupported())
                else:
                    return defer.succeed(None)
            else:
                pass
        elif self.xmlstream.features[self.feature].required:
            return defer.fail(xmlstream.TLSRequired())
        else:
            return defer.succeed(None)

        self._deferred = defer.Deferred()
        self.xmlstream.addOnetimeObserver("/proceed", self.onProceed)
        self.xmlstream.addOnetimeObserver("/failure", self.onFailure)
        self.xmlstream.send(domish.Element((xmlstream.NS_XMPP_TLS, "starttls")))
        return self._deferred


class KontalkXMPPAuthenticator(xmlstream.ConnectAuthenticator):
    namespace = 'jabber:client'

    def __init__(self, network, token, fingerprint, sasl_external=False, certfile=None, keyfile=None):
        xmlstream.ConnectAuthenticator.__init__(self, network)
        if fingerprint:
            self.fingerprint = fingerprint
        else:
            self.token = token

        self.sasl_external = sasl_external

        if certfile:
            cert = open(certfile, 'rb')
            cert_buf = cert.read()
            cert.close()
        else:
            cert_buf = None

        if keyfile:
            cert = open(keyfile, 'rb')
            key_buf = cert.read()
            cert.close()
        else:
            key_buf = None

        if key_buf and cert_buf:
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key_buf)
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_buf)
        else:
            pkey = cert = None

        self.certificate = cert
        self.privkey = pkey
        # this is for making twisted bits not complaining
        self.jid = jid.JID('anon@example.com')


    def associateWithStream(self, xs):
        """
        Register with the XML stream.

        Populates stream's list of initializers, along with their
        requiredness. This list is used by
        L{ConnectAuthenticator.initializeStream} to perform the initalization
        steps.
        """
        xmlstream.ConnectAuthenticator.associateWithStream(self, xs)

        xs.initializers = [CheckVersionInitializer(xs)]
        if self.token or self.sasl_external:
            inits = [
                (TLSInitiatingInitializer, False),
                (KontalkSASLInitiatingInitializer, True),
                (BindInitializer, True),
                (SessionInitializer, False),
            ]

            for initClass, required in inits:
                init = initClass(xs)
                init.required = required
                xs.initializers.append(init)
        else:
            self.xmlstream.dispatch(self.xmlstream, xmlstream.STREAM_AUTHD_EVENT)


class Client(object):
    logTrafficOut = True
    logTrafficIn = True

    def __init__(self, config, handler):
        self.config = config
        if config['identity'] and not config['sasl_external']:
            self.token = user_token(config['identity'], config['fingerprint'])
        else:
            self.token = None
        try:
            self.fingerprint = config['key']
        except:
            self.fingerprint = None
        self.network = config['network']
        self.logTrafficIn = config['debug']
        self.logTrafficOut = config['debug']
        self.handler = handler
        self.handler.client = self

        a = KontalkXMPPAuthenticator(config['network'], self.token, self.fingerprint,
            config['sasl_external'], config['ssl_cert'], config['ssl_key'])
        f = xmlstream.XmlStreamFactory(a)
        f.addBootstrap(xmlstream.STREAM_CONNECTED_EVENT, self.connected)
        f.addBootstrap(xmlstream.STREAM_END_EVENT, self.disconnected)
        f.addBootstrap(xmlstream.STREAM_AUTHD_EVENT, self.authenticated)
        f.addBootstrap(xmlstream.INIT_FAILED_EVENT, self.init_failed)
        reactor.connectTCP(config['connect'][0], config['connect'][1], f)

    def send(self, stanza):
        self.xmlstream.send(stanza)

    def connected(self, xs):
        print 'Connected.'

        self.xmlstream = xs

        if self.logTrafficIn:
            def logDataIn(buf):
                print "RECV: %s" % unicode(buf, 'utf-8').encode('utf-8')
            xs.rawDataInFn = logDataIn

        if self.logTrafficOut:
            def logDataOut(buf):
                print "SEND: %s" % unicode(buf, 'utf-8').encode('utf-8')
            xs.rawDataOutFn = logDataOut


    def disconnected(self, xs):
        print 'Disconnected.'

        reactor.stop()


    def authenticated(self, xs):
        self.handler.authenticated()

        xs.addObserver("/iq[@type='get']/ping[@xmlns='%s']" % xmlstream2.NS_XMPP_PING, self.pong, xs=xs)

        xs.addObserver('/message', self.handler.message)
        xs.addObserver('/presence', self.handler.presence)
        xs.addObserver('/iq', self.handler.iq)

        # TODO if logged_in (was: if self.xmlstream.authenticator.token):
        pcfg = self.config['presence']
        p = domish.Element((None, 'presence'))
        if pcfg['type'] != 'available':
            p['type'] = pcfg['type']
        p.addElement((None, 'status'), content=pcfg['status'])
        p.addElement((None, 'priority'), content=pcfg['priority'])
        p.addElement((None, 'show'), content=pcfg['show'])
        xs.send(p)

        self.handler.ready()

        """
        ver = client.IQ(xs, 'get')
        ver.addElement((xmlstream2.NS_IQ_VERSION, 'query'))
        ver.send(self.network)

        info = client.IQ(xs, 'get')
        info.addElement((xmlstream2.NS_DISCO_INFO, 'query'))
        info.send(self.network)

        items = client.IQ(xs, 'get')
        q = items.addElement((xmlstream2.NS_DISCO_ITEMS, 'query'))
        q['node'] = xmlstream2.NS_PROTO_COMMANDS
        items.send(self.network)

        items = client.IQ(xs, 'get')
        q = items.addElement((xmlstream2.NS_DISCO_ITEMS, 'query'))
        q['node'] = xmlstream2.NS_MESSAGE_UPLOAD
        items.send(self.network)
        """

        def testProbe():
            if self.peer is not None:
                userid, resource = util.split_userid(self.peer)
                presence = xmppim.Presence(jid.JID(tuple=(userid, self.network, resource)), 'probe')
                presence['id'] = util.rand_str(8)
                xs.send(presence)

        def testMassProbe():
            global count, num
            num = 400
            count = 0
            def _presence(stanza):
                global count, num
                count += 1
                if count >= 400:
                    print 'received all presence'
            xs.addObserver('/presence', _presence)

            for n in range(num):
                userid = util.rand_str(util.USERID_LENGTH, util.CHARSBOX_HEX_LOWERCASE)
                presence = xmppim.Presence(jid.JID(tuple=(userid, self.network, None)), 'probe')
                xs.send(presence)

        def testRoster():
            global count, num
            num = 400
            count = 0
            def _presence(stanza):
                global count, num
                count += 1
                if count >= 400:
                    print 'received all presence'
            xs.addObserver('/presence', _presence)

            _jid = jid.JID(tuple=(None, self.network, None))
            r = domish.Element((None, 'iq'))
            r.addUniqueId()
            r['type'] = 'get'
            q = r.addElement((xmppim.NS_ROSTER, 'query'))
            for n in range(num):
                _jid.user = util.rand_str(util.USERID_LENGTH, util.CHARSBOX_HEX_LOWERCASE)
                item = q.addElement((None, 'item'))
                item['jid'] = _jid.userhost()
            xs.send(r)

            if self.peer is not None:
                _jid = util.userid_to_jid(self.peer, self.network)
                r = domish.Element((None, 'iq'))
                r['type'] = 'get'
                r['id'] = util.rand_str(8)
                q = r.addElement((xmppim.NS_ROSTER, 'query'))
                item = q.addElement((None, 'item'))
                item['jid'] = _jid.userhost()
                xs.send(r)

        def testSubscribe():
            # subscription request
            self.index = 0
            if self.peer is not None:
                userid, resource = util.split_userid(self.peer)
                presence = xmppim.Presence(jid.JID(tuple=(userid, self.network, None)), 'subscribe')
                presence['id'] = util.rand_str(8)
                xs.send(presence)
            else:
                def pres():
                    self.index += 1
                    presence = xmppim.AvailablePresence(statuses={None: 'status message (%d)' % (self.index, )})
                    xs.send(presence)

                LoopingCall(pres).start(2, False)

        def testMsgLoop():
            global counter
            counter = 0
            def _loop():
                global counter
                counter += 1
                jid = xs.authenticator.jid
                message = domish.Element((None, 'message'))
                message['id'] = 'kontalk' + util.rand_str(8, util.CHARSBOX_AZN_LOWERCASE)
                message['type'] = 'chat'
                if self.peer:
                    message['to'] = util.userid_to_jid(self.peer, self.network).full()
                else:
                    message['to'] = jid.userhost()
                message.addElement((None, 'body'), content=('%d' % counter))
                message.addElement(('urn:xmpp:server-receipts', 'request'))
                xs.send(message)
            LoopingCall(_loop).start(1)

        def testRegisterRequest():
            reg = client.IQ(xs, 'get')
            reg.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
            reg.send(self.network)

        def testRegister():
            reg = client.IQ(xs, 'set')
            query = reg.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
            form = query.addElement(('jabber:x:data', 'x'))
            form['type'] = 'submit'

            hidden = form.addElement((None, 'field'))
            hidden['type'] = 'hidden'
            hidden['var'] = 'FORM_TYPE'
            hidden.addElement((None, 'value'), content=xmlstream2.NS_IQ_REGISTER)

            phone = form.addElement((None, 'field'))
            phone['type'] = 'text-single'
            phone['label'] = 'Phone number'
            phone['var'] = 'phone'
            phone.addElement((None, 'value'), content='+39123456')

            reg.send(self.network)

        def testValidate():
            reg = client.IQ(xs, 'set')
            query = reg.addElement((xmlstream2.NS_IQ_REGISTER, 'query'))
            form = query.addElement(('jabber:x:data', 'x'))
            form['type'] = 'submit'

            hidden = form.addElement((None, 'field'))
            hidden['type'] = 'hidden'
            hidden['var'] = 'FORM_TYPE'
            hidden.addElement((None, 'value'), content='http://kontalk.org/protocol/register#code')

            code = form.addElement((None, 'field'))
            code['type'] = 'text-single'
            code['label'] = 'Validation code'
            code['var'] = 'code'
            code.addElement((None, 'value'), content='686129')

            reg.send(self.network)

        def testCommand():
            cmd = client.IQ(xs, 'set')
            ch = cmd.addElement((xmlstream2.NS_PROTO_COMMANDS, 'command'))
            ch['node'] = 'serverlist'
            ch['action'] = 'execute'
            cmd.send(self.network)

        def testUpload():
            cmd = client.IQ(xs, 'set')
            ch = cmd.addElement((xmlstream2.NS_MESSAGE_UPLOAD, 'upload'))
            ch['node'] = 'kontalkbox'
            media = ch.addElement((None, 'media'))
            media['type'] = 'image/png'
            cmd.send(self.network)

        #reactor.callLater(2, testProbe)
        #reactor.callLater(1, testProbe)
        #reactor.callLater(1, testSubscribe)
        #reactor.callLater(1, testMessage)
        #reactor.callLater(1, testMsgLoop)
        #reactor.callLater(1, testRoster)
        #reactor.callLater(1, testRegisterRequest)
        #reactor.callLater(1, testRegister)
        #reactor.callLater(1, testValidate)
        #reactor.callLater(1, testCommand)
        #reactor.callLater(1, testUpload)
        #reactor.callLater(30, xs.sendFooter)

    def pong(self, stanza, xs):
        r = xmlstream.toResponse(stanza, 'result')
        xs.send(r)

    def init_failed(self, failure):
        print "Initialization failed."
        print failure

        self.xmlstream.sendFooter()
