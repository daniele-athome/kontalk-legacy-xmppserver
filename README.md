> The Kontalk XMPP server is being replaced by Tigase with extensions. Please see our new repositories:
> * https://github.com/kontalk/tigase-server
> * https://github.com/kontalk/tigase-extension
> * https://github.com/kontalk/tigase-utils
> 
> Documentation will follow soon.

Kontalk XMPP server
===================

[![Build Status](https://travis-ci.org/kontalk/xmppserver.svg?branch=master)](https://travis-ci.org/kontalk/xmppserver)

The official XMPP-based Kontalk server based on Twisted Words and Wokkel.

## Overview ##
Kontalk XMPP server will be a fully compatible XMPP server integrated with the
Jabber federation, it's also a big clustered system where every user will be
under the network domain (e.g. kontalk.net).

## Components ##
* Router: stanza router
* C2S: accept client connections/network JID lookup
* SM: manage client connections (part of C2S)
* Net: inter-server communication with Kontalk servers in the same network
* S2S: inter-server communication with other servers

## Router ##
Router will be a standard XMPP router. Router will also be capable of receving
routing requests via inter-component protocol, for example from S2S.

## C2S ##
C2S will listen on XMPP client ports (5222, etc.) and accept client
connections. Obviously only Kontalk users will be allowed and special
extensions to the protocol will be added to fit the Kontalk protocol needs,
using existing XEPs if possible.
A built-in resolver will lookup network JIDs (user@kontalk.net) in order to
discover users and deliver messages to them.
C2S component should bind to the host route (e.g. beta.kontalk.net)

## SM ##
Session manager handles sessions opened by C2S with clients. Features:
* message exchange between users
* message and file storage
SM is actually part of C2S as a plugin.
SM can send stanzas for some JID/domain to the router, then:
1. a local route is found - stanza is bounced back to C2S, which will
   internally route it to the assigned SM instance
2. a remote route is found - stanza is sent to S2S, which will forward it to
   the server that hosts the JID the stanza is for
3. a route is not found - stanza is refused and bounced back, SM will act
   accordingly (e.g. store the message for future send, discard it, etc.)

## Net ##
Net will listen on a special s2s port and accept connections from Kontalk
servers.
Net component should bind to every host name in the Kontalk network, but the
local server name (e.g. beta.kontalk.net).

## S2S ##
S2S will listen on XMPP s2s ports and accept connections from non-Kontalk
servers.
S2S component should bind to the default route, because all unknown routes (e.g.
jabber.org, gmail.com, ...) are handled by interserver communication.
