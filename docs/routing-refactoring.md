Refactoring routing
===================

Current routing rule uses two custom stanza attributes:
 * `origin`
 * `destination`

The actuals `from` and `to` attributes are replaced "at the right time" with
`origin` and `destination` so the stanza will be delivered to the correct
component.
However, this rule can lead to confusion, bad code mainteinance and difficulties
in debugging and tracking stanza errors.


Direct component addressing
---------------------------
In order to simplify delivery and stop using `origin` and `destination` to route
stanzas to the correct component, a prefix will be added to the component JID.
The prefix will always be known because it's hard-coded:

 * `resolver.prime.kontalk.net`
 * `c2s.prime.kontalk.net`

Components will register with the component name (e.g. `resolver`). The *router*
will add the server host name automatically (e.g. `resolver.prime.kontalk.net`).
Components will also bind to their specific route (like in the old way, e.g.
`prime.kontalk.net` for *c2s* and `kontalk.net` for *resolvers*).

"Internal" JIDs (e.g. `kontalk.net`) can only be used internally to a server.
To deliver a stanza to an external component, servers must add the host name to the
component name (those JIDs will be bound by the *net* component whenever they
are online. See [smart *net* component](#smart-net-component) section).


Envelope stanzas
------------------
There might be cases when a stanza must be delivered to a certain component,
without touching the stanza itself. Therefore, the stanza should be wrapped inside
an "envelope":

```xml
<stanza from='c2s.beta.kontalk.net' to='resolver.prime.kontalk.net'>
  <presence from='user@prime.kontalk.net/resource'/>
</stanza>
```

Since this is a top-level stanza, the namespace is implicit &mdash; the stream
namespace is used.

A wrapped stanza is delivered as-is to the intended recipient: the destination
component must unwrap it before processing it. Also, any reply should be sent
to the *from* address indicated in the envelope.


Smart *net* component
---------------------
The *net* component now binds to all servers routes. This is wrong because if
a server is not accounted for, router should bounce stanzas directed to it.  
Therefore, *net* will register with its internal JID (i.e. `net`).
It will then bind to remote components routes whenever it receives presence from
them, and unbind whenever those components disappear.
