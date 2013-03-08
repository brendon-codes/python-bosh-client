"""
Bosh Client Helpers
"""

import sys
import os
import httplib
import urllib
import uuid
import random
import base64
from urlparse import urlparse
import logging
from xml.dom import minidom

from django.conf import settings

logger = logging.getLogger('bosh_client')


TLS_XMLNS = 'urn:ietf:params:xml:ns:xmpp-tls'
SASL_XMLNS = 'urn:ietf:params:xml:ns:xmpp-sasl'
BIND_XMLNS = 'urn:ietf:params:xml:ns:xmpp-bind'
SESSION_XMLNS = 'urn:ietf:params:xml:ns:xmpp-session'
XMPP_XMLNS = 'urn:xmpp:xbosh'


class JID:
    """
    JID Class

    @note This was taken from SleekXMPP
    @see sleekxmpp.basexmpp.set_jid
    """

    fulljid = None
    resource = None
    jid = None
    user = None
    host = None

    def __init__(self, jid):
        """
        Rip a JID apart and claim it as our own.

        @author BrendonCrawford
        @author NathanFritz
        @param jid String
        @constructor
        """
        self.fulljid = jid
        self.resource = self.getjidresource(jid)
        self.jid = self.getjidbare(jid)
        self.user = jid.split('@', 1)[0]
        self.host = jid.split('@', 1)[-1].split('/', 1)[0]

    def getjidresource(self, fulljid):
        """
        Jid Resource

        @author BrendonCrawford
        @author NathanFritz
        @param fulljid String
        @return List
        """
        if '/' in fulljid:
            return fulljid.split('/', 1)[-1]
        else:
            return ''

    def getjidbare(self, fulljid):
        """
        Bare Jid

        @author BrendonCrawford
        @author NathanFritz
        @param fulljid String
        @return List
        """
        return fulljid.split('/', 1)[0]


class BOSHClient:
    """
    BOSHClient Class

    @see punjab.httpb_client
    """

    rid = None
    jid = None
    jabberid = None
    password = None
    authid = None
    sid = None
    logged_in = False
    headers = None
    bosh_service = None

    def __init__(self, jabberid, password, bosh_service, hold='1', wait='60'):
        """
        @constructor
        @author BrendonCrawford
        @author JackMoffit
        @param jabberid
        @param password
        @param bosh_service
        """
        logger.debug("Initialized BOSHClient")
        self.rid = random.randint(0, 10000000)
        self.jabberid = JID(jabberid)
        self.password = password
        self.authid = None
        self.sid = None
        self.logged_in = False
        self.headers = {
            "Content-type": "text/xml",
            "Accept": "text/xml"
        }
        self.bosh_service = urlparse(bosh_service)
        self.logged_in = self.startSessionAndAuth(hold, wait)
        logger.debug("BOSH Logged In: %s", self.logged_in)

    def buildElement(self, name, child=None, attrs=None):
        """
        Builds xml element

        @author BrendonCrawford
        @param name
        @param child
        @param attrs
        @return minidom.Element
        """
        if attrs is None:
            attrs = {}
        e = minidom.Element(name)
        for attr_k, attr_v in attrs.items():
            e.setAttribute(attr_k, attr_v)
        if child is not None:
            e.appendChild(child)
        return e

    def buildText(self, data):
        """
        Builds xml text element

        @author BrendonCrawford
        @param data
        @return minidom.Text
        """
        t = minidom.Text()
        t.data = data
        return t

    def buildBody(self, child=None, attrs=None):
        """
        Build a BOSH body.

        @author BrendonCrawford
        @author JackMoffit
        @param child
        @param attrs
        @return minidom.Element
        """
        if attrs is None:
            attrs = {}
        self.rid += 1
        body = {}
        body['xmlns'] = 'http://jabber.org/protocol/httpbind'
        body['content'] = 'text/xml; charset=utf-8'
        body['rid'] = str(self.rid)
        body['xml:lang'] = 'en'
        if self.sid != None:
            body['sid'] = str(self.sid)
        for attr_k, attr_v in attrs.items():
            body[attr_k] = attr_v
        elm = self.buildElement('body', child=child, attrs=body)
        return elm

    def sendBody(self, body):
        """
        Send the body.

        @author BrendonCrawford
        @author JackMoffit
        @param body
        @return Tuple(minidom.Element, String)
        """
        # start new session
        out = body.toxml()
        #print "######"
        #print out
        conn = httplib.HTTPConnection(self.bosh_service.netloc)
        conn.request("POST", self.bosh_service.path, out, self.headers)
        response = conn.getresponse()
        data = ''
        if response.status == 200:
            data = response.read()
        conn.close()
        #print "------"
        #print data
        doc = minidom.parseString(data)
        return (doc.documentElement, data)

    def buildAuthStringPlain(self):
        """
        Builds auth string

        @author BrendonCrawford
        @author JackMoffit
        @return String
        """
        auth_str = ""
        auth_str += "\000"
        auth_str += self.jabberid.user.encode('UTF-8')
        auth_str += "\000"
        try:
            auth_str += self.password.encode('UTF-8').strip()
        except UnicodeDecodeError:
            auth_str += self.password.decode('latin1').encode('UTF-8').strip()
        enc_str = base64.b64encode(auth_str)
        return enc_str

    def uniqueId(self):
        """
        Returns a Unique ID

        @author BrendonCrawford
        @return String
        """
        ret = uuid.uuid4().hex
        return ret

    def startSessionAndAuth(self, hold='1', wait='2'):
        """
        Starts session and authenticates

        @author BrendonCrawford
        @author JackMoffit
        @param hold
        @param wait
        @return Bool
        """
        # Create a session
        # create body
        body = {}
        body['hold'] = hold
        body['to'] = self.jabberid.host
        body['wait'] = wait
        body['window'] = '5'
        body['ver'] = '1.6'
        body['xmpp:version'] = '1.0'
        body['xmlns:xmpp'] = XMPP_XMLNS
        body_elm = self.buildBody(attrs=body)
        retb, _data = self.sendBody(body_elm)
        if retb.hasAttribute('authid') and retb.hasAttribute('sid'):
            self.authid = retb.getAttribute('authid')
            self.sid = retb.getAttribute('sid')
            auth = {}
            auth['xmlns'] = SASL_XMLNS
            auth['mechanism'] = 'PLAIN'
            if auth['mechanism'] == 'PLAIN':
                auth_str = self.buildAuthStringPlain()
                auth_text_elm = self.buildText(auth_str)
                auth_elm = self.buildElement('auth', child=auth_text_elm,
                                             attrs=auth)
                body_auth = self.buildBody(child=auth_elm)
                retb, _data = self.sendBody(body_auth)
                sucs = retb.getElementsByTagName('success')
                if len(sucs) > 0:
                    body_binder = {}
                    body_binder['xmpp:restart'] = 'true'
                    body_binder['xmlns:xmpp'] = XMPP_XMLNS
                    body_binder_elm = self.buildBody(attrs=body_binder)
                    retb, _data = self.sendBody(body_binder_elm)
                    bind_elms = retb.getElementsByTagName('bind')
                    ## Bind element was found
                    if len(bind_elms) > 0:
                        bind = {}
                        bind['xmlns'] = BIND_XMLNS
                        bind_elm = self.buildElement('bind', attrs=bind)
                        if self.jabberid.resource:
                            resource_text = \
                                self.buildText(self.jabberid.resource)
                            resource = self.buildElement('resource',
                                                         child=resource_text)
                            bind_elm.appendChild(resource)
                        iq = {}
                        iq['xmlns'] = 'jabber:client'
                        iq['type'] = 'set'
                        iq['id'] = self.uniqueId()
                        iq_elm = self.buildElement('iq', bind_elm, iq)
                        iq_body = self.buildBody(child=iq_elm)
                        retb, _data = self.sendBody(iq_body)
                        jids = retb.getElementsByTagName('jid')
                        ## Jid was found
                        if len(jids) > 0:
                            self.jid = jids[0].childNodes[0].nodeValue
                            # send session
                            iq = {}
                            iq['xmlns'] = 'jabber:client'
                            iq['type'] = 'set'
                            iq['id'] = self.uniqueId()
                            session = {}
                            session['xmlns'] = SESSION_XMLNS
                            sess_elm = \
                                self.buildElement('session', attrs=session)
                            sess_iq_elm = \
                                self.buildElement('iq', sess_elm, attrs=iq)
                            sess_body_elm = \
                                self.buildBody(sess_iq_elm)
                            retb, _data = self.sendBody(sess_body_elm)
                            sess_res = retb.getElementsByTagName('session')
                            ## Session returned ok
                            if len(sess_res) > 0:
                                self.rid += 1
                                return True
        return False


if __name__ == '__main__':
    USERNAME = sys.argv[1]
    PASSWORD = sys.argv[2]
    SERVICE = sys.argv[3]
    c = BOSHClient(USERNAME, PASSWORD, SERVICE)
    print
    print "Logged In: %s" % c.logged_in
    print "SID: %s" % c.sid
    print "JID: %s" % c.jid
    print "RID: %s" % c.rid
    print
