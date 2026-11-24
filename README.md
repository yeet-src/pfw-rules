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

Put a policy under the directory for the protocol or concern it guards, and
open it with a comment saying what it blocks and what it leaves alone.

`pfwctl ls` compiles every policy in the repo against the running firewall,
and `pfwctl load` refuses one that does not compile, so check there before
pushing.
