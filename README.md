# pfw-rules

pfw-C policies for the [pfw](https://github.com/yeet-src/pfw-core) firewall,
pulled and applied with the `pfw` command.

```sh
pfw remote add rules git@github.com:yeet-src/pfw-rules.git
pfw pull                      # fetch, and see what changed
pfw ls                        # every policy, numbered, with whether it compiles
pfw apply rules:http/crawlers.pfc
```

The firewall runs one policy at a time, so each `.pfc` here is a whole
program: what it does not decide, it must pass.

## Policies

| policy | what it does |
|---|---|
| [`baseline/pass.pfc`](baseline/pass.pfc) | passes everything: the firewall attached and counting, deciding nothing |
| [`http/crawlers.pfc`](http/crawlers.pfc) | resets AI crawlers on a web port by user-agent (`port`, default 80) |
| [`php/php2shell.pfc`](php/php2shell.pfc) | resets the multipart request shapes php2shell uses, CVE-2026-109618 and CVE-2026-109619 (`port`, default 80) |
| [`java/roller-xmlrpc.pfc`](java/roller-xmlrpc.pfc) | resets requests for Apache Roller's XML-RPC endpoint, CVE-2026-129448 (`port`, default 8080) |
| [`java/axis1-soap.pfc`](java/axis1-soap.pfc) | resets requests for Confluence's Remote API (SOAP and XML-RPC), CVE-2026-90436 (`port`, default 8090) |
| [`java/log4shell.pfc`](java/log4shell.pfc) | resets requests carrying a Log4j lookup, `${jndi:` and the nested forms that hide it, CVE-2021-44228 (`port`, default 8080) |

The virtual patches read plaintext HTTP, so they belong on the hop behind the
TLS terminator. Each one narrows what reaches the vulnerable code until the
software is upgraded; none of them is the fix.

## Writing one

A policy is `pattern` declarations and one `filter` block that ends every
path in a verdict: `pass`, `drop`, `rst`, `ban` or `count`. A named verdict
(`rst("crawler", 60)`) is a rule, and `pfw status` and `pfw metrics`
count packets by it. The language is documented in
[pfw-core](https://github.com/yeet-src/pfw-core/blob/master/docs/lang.md).

Open it with a block of `@key value` comments. `pfw ls` prints them under
the policy, so they are how someone choosing a policy learns what it is for:

```c
// @description Resets connections that carry a JNDI lookup string.
// @patches Apache Log4j 2.0-beta9 to 2.14.1
// @cve CVE-2021-44228, CVE-2021-45046
// @severity critical
// @tags http, rce
```

| key | what it says |
|---|---|
| `description` | one line: what it blocks and what it leaves alone |
| `patches` | the software and versions it shields, when it is a virtual patch |
| `cve` | the CVEs it addresses, comma-separated |
| `severity` | `critical`, `high`, `medium` or `low` |
| `tags` | words to find it by, comma-separated |
| `knob NAME` | what one of its knobs is for |

A **knob** is a value the policy reads and the operator may set, so one
policy serves hosts that differ: `knob("port") ?? 80` is port 80 until someone
runs `pfw knob set port 8080`. Give every knob a default and a `@knob`
line. Values are kept per policy, so two policies may both call theirs `port`.

Only `description` is expected of every policy. The block ends at the first
line that is not a comment; ordinary comments may follow the keys.

Put a policy under the directory for the protocol or concern it guards.

`pfw ls` compiles every policy in the repo against the running firewall,
and `pfw apply` refuses one that does not compile, so check there before
pushing.

## Testing one

A policy that compiles has not been shown to do anything. Two scripts do
that, both against a [pfw-core](https://github.com/yeet-src/pfw-core) checkout:

```sh
PFW_CORE=../pfw-core node test/run.mjs       # anywhere: the reference interpreter
PFW_CORE=../pfw-core node test/kernel.mjs    # Linux, root, yeetd: the real XDP program
```

`test/run.mjs` gives each policy the requests it must reset and the ones it
must leave alone, and runs every captured request in `test/fixtures/` through
every policy. `test/kernel.mjs` loads each policy into the kernel and drives it
over loopback TCP: tokens split across segments, a signature kilobytes into a
connection, a 300 kB upload that must arrive whole. It attaches to loopback,
so give it a network namespace of its own.

The two disagree in one place worth knowing: the interpreter's match mask
remembers a whole connection, the kernel's only the current reassembly
window. A policy that needs two tokens which may lie more than a window apart
keeps them in a `flow.r0` bit each, as `java/roller-xmlrpc.pfc` does.

Take the cases from the software, not from the advisory. Tomcat serves
`/a;x=y/b`, `/a//b`, `/a/./b` and `/a/%62` as `/a/b`; PHP reads a multipart
field name quoted, single-quoted or bare; Log4j resolves `${jndi${::-:}ldap…}`
with no `jndi:` in it. Each of those was found by asking the real thing, and
each broke a first draft that matched the string in the write-up.
