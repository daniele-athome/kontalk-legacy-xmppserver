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

Components will register with the component name (e.g. `resolver`). Router will
add the server host name automatically (e.g. `resolver.prime.kontalk.net`).
Components will also bind to their specific route (like in the old way, e.g.
`prime.kontalk.net` for c2s and `kontalk.net` for resolvers).

"Internal" JIDs (e.g. `kontalk.net`) can only be used internally to a server.
To deliver a stanza to an external component, servers must add the host name to the
component name (those JIDs will be bound by the `net` component whenever they
are online. See [*smart `net` component*](#smart-net-component) section).


Envelop forwarding
------------------
TODO


Smart `net` component
---------------------
TODO
