# Testing a policy

A policy that compiles has not been shown to do anything. Three tests show
it, and CI runs all of them on every push and pull request.

```sh
PFW_CORE=../pfw/.deps/pfw-core node test/run.mjs [policy ...]                 # anywhere
PFW_CORE=../pfw/.deps/pfw-core sh test/kernel-ns.sh [policy ...]              # Linux
PFW=/usr/local/bin/pfw sh test/in-namespace.sh node test/e2e.mjs [policy ...] # Linux, pfw installed
```

`PFW_CORE` is a pfw-core checkout. The one to test against is the one pfw
ships: build [pfw](https://github.com/yeet-src/pfw) with `make` and use its
`.deps/pfw-core`, which is what CI does. A newer pfw-core may accept a policy
that the released firewall will refuse: its regex automaton may hold 32,768
states where the released one holds 1,024.

## The interpreter: `test/run.mjs`

Runs each policy in pfw-core's reference interpreter, which executes the same
bytecode as the kernel over exactly the bytes it is handed. It checks that

- every `.pfc` compiles, without warnings, and opens with `@description`;
- every policy has a cases file, and the cases pass;
- every captured request in `test/fixtures/*.http` passes every policy, whole
  and cut into 1460-byte segments.

A policy `apps/name.pfc` has its cases in `test/cases/apps/name.mjs`:

```js
/* Which real server these spellings were checked against. */
export const port = 8080;

export default function ({ f, run, stream, get, post }) {
  const web = { dport: port };
  run(f, "the request it exists for", post("/bad/path", "", "x"), "rst(rule_name)", web);
  run(f, "an ordinary page", get("/"), "pass", web);
  stream(f, "split across segments", ["POST /bad", "/path HTTP/1.1\r\n\r\n"], "rst(rule_name)", web);
}
```

`run` gives the policy one buffer; `stream` gives it segments in order with
the connection's state carried between them. Keep segments no larger than a
real one (1460 bytes): the interpreter does not reassemble.

The fixtures are what real clients sent to a listener, byte for byte: curl,
python-requests, wget and node's `fetch`; an admin session on a real
WordPress, recorded through a proxy (`wordpress-*.http`); and the ClientHellos
of a dozen TLS stacks. Add to them when a policy touches a kind of request
they do not hold.

## The kernel: `test/kernel-ns.sh`

Loads each policy into the real XDP program and drives it over loopback TCP:
tokens split across segments, a signature kilobytes into a connection, a
300 kB upload that must arrive whole. This is the test for what only the
kernel has: reassembly, the window sliding, per-connection registers.

It runs in a network namespace of its own (`test/in-namespace.sh`), with its
own loopback, its own bpffs and its own yeetd, and removes all of it
afterwards. A firewall already up on the host, or another test run, is not
touched. Each policy is tested on its own default port, since that is the
port its `reassemble` follows. It needs Linux, sudo, yeet and yeetd, node 24
or newer, and a pfw-core with `bin/vm.bpf.o` built.

`test/kernel.mjs` is the test itself; run it directly only where loopback is
yours to attach to.

## End to end: `test/e2e.mjs`

The test an operator would recognise. It brings the firewall up with
`pfw up`, and for each policy runs `pfw apply -f`, checks `pfw status`, and
sends the requests in the cases file's `e2e` export at a server listening on
the policy's own port:

```js
export const e2e = ({ url, fixture }) => [
  { name: "the request it exists for", curl: ["-d", "x", `${url}/bad/path`], want: "cut" },
  { name: "an ordinary page", curl: [`${url}/`], want: "served" },
  { name: "bytes curl cannot send", raw: fixture("clienthello-openssl-tls10.bin"), want: "cut" },
  { name: "with a knob set", knobs: { strict: 1 }, curl: [`${url}/x`], want: "cut" },
];
```

`curl` gives a request as a real client would; `raw` is for what curl cannot
say, and `udp` sends one datagram. It also checks that applying the policy did not cost `pfw` its own
control connection, and that `pfw knob set port` moves the policy.

It changes the firewall it is pointed at, so on a machine you care about run
it through `test/in-namespace.sh`. It also runs a copy of the built service
whose state file is moved into a scratch directory: the service saves its
policy in `/var/lib/pfw/state.js`, which no network namespace hides, and
without that the test would write over the saved state of the host's own
firewall.

It needs a yeet login. yeet serves a login page in place of every route of a
host that is not logged in, the firewall's control route among them, and
logging in takes a route to yeet's servers that a namespace does not have. So:

- in CI it runs on the runner's own loopback, logged in with the
  `YEET_API_KEY` repository secret, and is skipped where there is none;
- in a namespace it works with a daemon that does not ask for a login, such as
  a development build of yeetd.

## Where the cases come from

From the software. For each policy here a real server was run and asked what
it accepts, and those answers are the cases:

| asked | what it showed |
|---|---|
| Tomcat 9.0 | which path spellings reach the same servlet |
| PHP 8.3 under Apache 2.4 | which multipart spellings are parsed, and how deep names nest |
| Log4j 2.14.1 | which strings make the logger open a connection (`test/fixtures/log4j-2.14.1-lookups.json`) |
| FastAPI on uvicorn | how paths are routed, queries decoded and header lines parsed |
| Apache 2.4 with mod_php | which path spellings execute a PHP file |
| nginx 1.27, httpd 2.4.71 | how cleartext HTTP/2 is started |
| `unserialize()` in PHP 8.3 | which strings become an object, and through which transports |
| Struts 2.3.28 on Jetty | which spellings of the `method:` prefix are read, and from where |
| Plex Media Server 1.43.5 | which spellings of the `protocol` parameter a timeline subscription reads |
| ProFTPD 1.3.8 with mod_copy | which spellings of `SITE CPFR` it recognises, and the Telnet bytes it strips |
| OpenJDK 17's Base64 decoders | that the Java4Shell shape is never valid Base64 |
| Linux's NFS client and nfsd | what a mount's CREATE_SESSION asks for, and how nfsd frames a call: fragments, the tag's limit, long credentials |
| openssl 3.6, curl, python, node | the ClientHellos they send (`test/fixtures/clienthello-*.bin`) |

Four of these are asked again on every push, by the scripts in `test/real/`.
In the `real-servers` job Struts 2.3.28, ProFTPD and Plex Media Server are
started in containers and each is asked which spellings it reads, with
requests that do no harm (a method the action does not have, a protocol the
server refuses, a command that wants a login first). In the `nfs` job the
runner's own kernel serves an export and mounts it, as NFSv4.1 and as 4.2,
through a relay that keeps what the client sent: the session it asks for has
to stay above the floor `apps/nfsd-session-cache.pfc` sets, or the policy
would cut every mount. When a server or a client starts behaving differently,
its job fails.

```sh
docker run -d -p 8080:8080 vulhub/struts2:2.3.28 && node test/real/struts.mjs 8080
sudo node test/real/nfs.mjs 2049   # Linux, with nfsd exporting an fsid=0 directory to 127.0.0.1, `insecure`
```

None of this is a run of an exploit against a vulnerable build. It shows that
a policy resets the request shapes the software accepts and the advisory
describes; it does not show that no other shape reaches the bug.
