# Writing a policy

A policy is `pattern` and `regex` declarations and one `filter` block that
ends every path in a verdict: `pass`, `drop`, `rst`, `ban` or `count`. A named
verdict (`rst("crawler", 60)`) is a rule, and `pfw status` and `pfw metrics`
count packets by it. The language is documented in
[pfw-core](https://github.com/yeet-src/pfw-core/blob/master/docs/lang.md).

The firewall runs one policy at a time, so each `.pfc` is a whole program:
what it does not decide, it must pass.

## Where it goes

| directory | what belongs there |
|---|---|
| `baseline/` | policies that decide nothing about content |
| `http/` | rules about HTTP itself, whatever serves it |
| `tls/` | rules about the TLS handshake, the part a filter can read |
| `runtimes/` | a language runtime, library or server every app on it shares: PHP, the JVM, Log4j, Tomcat |
| `cms/` | content management systems and their plugins |
| `ai/` | model servers, proxies and labelling tools |
| `apps/` | any other single product: its endpoint, its bug |

Add its cases at the same path under `test/cases/`, and a row to the README.

## The opening comments

Open with a block of `@key value` comments. `pfw ls` prints them under the
policy, so they are how someone choosing a policy learns what it is for:

```c
// @description Resets connections that carry a JNDI lookup string.
// @patches Apache Log4j 2.0-beta9 to 2.14.1
// @cve CVE-2021-44228, CVE-2021-45046
// @severity critical
// @tags http, rce
// @knob port  The port to guard.
```

| key | what it says |
|---|---|
| `description` | one line: what it blocks and what it leaves alone |
| `patches` | the software and versions it shields, when it is a virtual patch |
| `cve` | the CVEs it addresses, comma-separated |
| `severity` | `critical`, `high`, `medium` or `low` |
| `tags` | words to find it by, comma-separated |
| `knob NAME` | what one of its knobs is for |

Only `description` is required; the tests fail a policy without it. The block
ends at the first line that is not a comment. After the keys, say in ordinary
comments what each rule matches, what it was checked against, what it costs
ordinary traffic and what it does not cover.

A **knob** is a value the policy reads and the operator may set, so one policy
serves hosts that differ: `knob("port") ?? 80` is port 80 until someone runs
`pfw knob set port 8080`. Give every knob a default and a `@knob` line. Values
are kept per policy, so two policies may both call theirs `port`.

## What the first drafts here got wrong

Each of these was found by testing, not by reading.

**Match what the server accepts, not what the advisory printed.** Tomcat
serves `/a;x=y/b`, `/a//b`, `/a/./b` and `/a/%62` as `/a/b`. FastAPI matches
only the exact path, but decodes `%2f` first. PHP reads a multipart field name
quoted, single-quoted or bare. Log4j resolves `${jndi${::-:}ldap…}`, which has
no `jndi:` in it. A literal copied from a write-up is stepped around by the
first person who tries. Run the real software and ask it.

**Never a bare `reassemble;`.** Without a port it follows every TCP connection
on the interface, and a connection first seen half-way is reset. Applying
such a policy cut every connection already open on the host, on any port,
`pfw`'s own control connection included (so `pfw apply` reported a failure it
had not had), and on loopback the resets fed themselves into a storm. Write
`reassemble 80;`, the same number as the `port` knob's default, and say in
the comments that the knob alone does not move reassembly.

**A segment larger than the window is only partly read.** The window is 2,048
bytes in pfw-core as released, and of a single segment longer than that only
the first 2,048 bytes are inspected. On a network card segments are about
1,500 bytes; on loopback, with its 64 kB MTU and segmentation offload, one
`write` is one segment. No policy can fix this from inside; the README says
what an operator must set on `lo`, and the end-to-end test carries a case
marked `gap` that will say when pfw-core has closed it.

**The match mask is one window.** In the kernel, `scan` reports what is in the
current reassembly window, not what the connection has carried. Two tokens
that a client can put kilobytes apart (two headers, two path segments) each
set a bit in `flow.r0`; see `apps/roller-xmlrpc.pfc`.

**A match that can be stretched can be split.** When the window moves it keeps
its last 256 bytes. A regex such as `route[^ ]*bad` is not seen if a client
pads the middle past 256 bytes and times the move. Either the tokens are
remembered separately, or the policy says in its comments that the gap exists.

**Counted repeats are expensive.** `prefix[^ ]{200}` is exponential when the
prefix can occur inside the run, and does not compile. An unbounded `*` is
cheap. `test/run.mjs` fails a policy whose automaton is larger than one the
kernel has been seen to load.

**Bodies are noise.** A pattern short enough to occur by chance will, in an
upload: `log4shell_default` trips on random bytes about once in 16 MB. Tie a
rule to the request line where the bug allows it (an upper-case method, a
target that starts with `/`), and measure the rest.

**`after()` is for literals.** It returns 0 for a `regex`, so a regex match
has no position to compare with `end`. To ask "does the data end here", read
the last bytes directly: `u8(end - 1)`.

**`ban` bans an address.** Behind a proxy or a NAT that address is everyone.
The policies here reset the connection and leave the source alone.
