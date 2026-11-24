# pfw-rules

pfw-C policies for the [pfw](https://github.com/yeet-src/pfw-core) firewall,
pulled and applied with `pfwctl`.

```sh
pfwctl remote add rules git@github.com:yeet-src/pfw-rules.git
pfwctl pull                      # fetch, and see what changed
pfwctl ls                        # every policy, numbered, with whether it compiles
pfwctl load rules:http/crawlers.pfc
pfwctl apply
```

The firewall runs one policy at a time, so each `.pfc` here is a whole
program: what it does not decide, it must pass.

## Policies

| policy | what it does |
|---|---|
| [`baseline/pass.pfc`](baseline/pass.pfc) | passes everything: the firewall attached and counting, deciding nothing |
| [`http/crawlers.pfc`](http/crawlers.pfc) | resets AI crawlers on port 80 by user-agent |

## Writing one

A policy is `pattern` declarations and one `filter` block that ends every
path in a verdict: `pass`, `drop`, `rst`, `ban` or `count`. A named verdict
(`rst("crawler", 60)`) is a rule, and `pfwctl status` and `pfwctl metrics`
count packets by it. The language is documented in
[pfw-core](https://github.com/yeet-src/pfw-core/blob/master/docs/lang.md).

Open it with a block of `@key value` comments. `pfwctl ls` prints them under
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

Only `description` is expected of every policy. The block ends at the first
line that is not a comment; ordinary comments may follow the keys.

Put a policy under the directory for the protocol or concern it guards.

`pfwctl ls` compiles every policy in the repo against the running firewall,
and `pfwctl load` refuses one that does not compile, so check there before
pushing.
