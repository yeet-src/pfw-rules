# pfw-rules

Policies for the [pfw](https://github.com/yeet-src/pfw) firewall: virtual
patches for remote-code-execution bugs that are being exploited now, and a
few rules about HTTP itself. Each one is a pfw-C program that runs at XDP,
before a packet reaches the server.

```sh
pfw remote add rules git@github.com:yeet-src/pfw-rules.git
pfw pull                      # fetch, and see what changed
pfw ls                        # every policy, with what it is for
pfw apply rules:runtimes/php2shell.pfc
pfw knob set port 8080        # each policy guards one port; this is how to say which
```

## Which one do I need

Start from what the host runs. The firewall enforces one policy at a time, so
pick the one for the thing you cannot upgrade yet.

| the host runs | policy |
|---|---|
| PHP, any application | `runtimes/php2shell.pfc` |
| WordPress or Drupal | `cms/installers.pfc`; for plugins that unserialize input, `cms/php-object-injection.pfc` |
| Node.js | `runtimes/node2shell.pfc` |
| Java, any application | `runtimes/java4shell.pfc`; with an old Log4j, `runtimes/log4shell.pfc`; on Tomcat, `runtimes/tomcat-strict-path.pfc` |
| Confluence Data Center | `apps/confluence-remote-api.pfc` |
| Grafana before 13.3.2, 13.2.7, 13.1.11, 13.0.14 or 12.4.16 | `apps/grafana-secrets.pfc` |
| Apache Roller | `apps/roller-xmlrpc.pfc` |
| Struts 2 with Dynamic Method Invocation on | `runtimes/struts-method-prefix.pfc` |
| Plex Media Server | `apps/plex-timeline-protocol.pfc` |
| ONLYOFFICE Document Server | `apps/onlyoffice-encrypted-upload.pfc` |
| AhsayCBS | `apps/ahsaycbs-update-receivers.pfc` |
| ProFTPD with mod_copy | `ftp/proftpd-mod-copy.pfc` |
| Nextcloud with the built-in Collabora server | `apps/nextcloud-builtin-code.pfc` |
| a legacy ASP.NET site using Idunno.AntiCsrf | `runtimes/aspnet-anticsrf.pfc` |
| nginx or Apache httpd with HTTP/2 or HTTP/3 on | `http/h2c.pfc`, `http/quic.pfc` |
| LiteLLM, GPUStack or MONAI Label | the policy of that name under `ai/` |
| any TLS listener | `tls/legacy-clients.pfc` |
| none of these, or not sure yet | `baseline/pass.pfc`: attached and counting, blocking nothing |

Then, in order:

```sh
pfw ls                          # find it, and its number
pfw shadow                      # dry run: count what it would block, block nothing
pfw apply NUMBER
pfw knob set port 8080          # if the service is not on the policy's default port
pfw status                      # "would block N": look at it under real traffic
pfw unshadow                    # enforce
```

## The rules

Every policy resets the connection that carries what it names and passes
everything else (the one about UDP drops instead). None of them bans a source
address.

### Applications

One product, one endpoint, one bug.

| policy | shields | what it resets | port |
|---|---|---|---|
| [`apps/confluence-remote-api.pfc`](apps/confluence-remote-api.pfc) | Confluence Data Center 1.x–9.x with the Remote API on. CVE-2026-90436, Apache Axis 1.x. In CISA KEV. | Requests for the SOAP API (`soap-axis1`) and the XML-RPC API (`/rpc/xmlrpc`). | 8090 |
| [`apps/roller-xmlrpc.pfc`](apps/roller-xmlrpc.pfc) | Apache Roller 4.0.0–6.1.4. CVE-2026-129448. In CISA KEV. | Requests for `/roller-services/xmlrpc`. | 8080 |
| [`apps/nextcloud-builtin-code.pfc`](apps/nextcloud-builtin-code.pfc) | Nextcloud's built-in Collabora server (richdocumentscode) before 26.4.303. CVE-2026-110447. In CISA KEV. | Requests for the app's `proxy.php`. | 80 |
| [`apps/plex-timeline-protocol.pfc`](apps/plex-timeline-protocol.pfc) | Plex Media Server before 1.43.3.10861. CVE-2026-96652, the first step of the Plex2Shell chain. In CISA KEV. | Requests whose `protocol` parameter holds more than a bare word: a colon, a slash, a percent sign. | 32400 |
| [`apps/onlyoffice-encrypted-upload.pfc`](apps/onlyoffice-encrypted-upload.pfc) | ONLYOFFICE Document Server 5.1.5–5.6.2. CVE-2021-3199. In CISA KEV. | Uploads that begin `ENCRYPTED;` and then name anything but a file extension; with `strict` set, compressed and chunked request bodies as well. | 80 |
| [`apps/ahsaycbs-update-receivers.pfc`](apps/ahsaycbs-update-receivers.pfc) | AhsayCBS up to 9.15.2.69 and 10.3.4.44. CVE-2026-105134. In CISA KEV. | Requests that name `UpdateReceivers`, the replication endpoint the exploit chain ends in. | 80 |
| [`apps/grafana-secrets.pfc`](apps/grafana-secrets.pfc) | Grafana before 13.3.2, 13.2.7, 13.1.11, 13.0.14, 12.4.16. CVE-2026-107561, CVE-2026-88960; Grafana has not said which ID is which fix, so both are covered. | Any request carrying a `login_error` cookie, which `/login` decrypted and displayed; tests of a saved contact point, which could carry its stored secrets elsewhere. | 3000 |

### AI tooling

| policy | shields | what it resets | port |
|---|---|---|---|
| [`ai/monai-label.pfc`](ai/monai-label.pfc) | MONAI Label 0.8.5 and earlier. CVE-2026-133968. In CISA KEV. | `/datastore/` requests whose query holds `..`, a slash, a backslash or an encoded dot. | 8000 |
| [`ai/litellm-guardrails.pfc`](ai/litellm-guardrails.pfc) | LiteLLM 1.81.8 up to 1.83.10. CVE-2026-40217. In CISA KEV. | `POST /guardrails/test_custom_code`. | 4000 |
| [`ai/gpustack-real-ip.pfc`](ai/gpustack-real-ip.pfc) | GPUStack before 2.2.0. CVE-2026-102895. In CISA KEV. | Requests that bring their own `X-GPUStack-Real-IP` header, which GPUStack trusts to mean "from localhost". | 80 |

### Content management

| policy | shields | what it resets | port |
|---|---|---|---|
| [`cms/installers.pfc`](cms/installers.pfc) | Drupal before 10.6.22, 11.3.22, 11.4.13 (CVE-2026-132165) and WordPress before 7.1.4 (CVE-2026-119977). Both in CISA KEV. | Requests for `install.php`, and for anything under `/wp-content/upgrade/`. | 80 |
| [`cms/php-object-injection.pfc`](cms/php-object-injection.pfc) | WordPress plugins and other PHP code that unserializes request data: Simple Shopping Cart (CVE-2026-131782), APCu Manager (CVE-2026-131754), and the class of bug. | A serialized PHP object (`O:n:"` or `C:n:"`), raw, percent-encoded or base64. | 80 |

### Runtimes

A language runtime, library or server that every application on it shares.

| policy | shields | what it resets | port |
|---|---|---|---|
| [`runtimes/php2shell.pfc`](runtimes/php2shell.pfc) | PHP before 8.2.35, 8.3.36, 8.4.27, 8.5.12. CVE-2026-109618, CVE-2026-109619. In CISA KEV. | The `PHP_SESSION_UPLOAD_PROGRESS` field; multipart with `Transfer-Encoding`; field names nested eight deep; optionally all multipart. | 80 |
| [`runtimes/node2shell.pfc`](runtimes/node2shell.pfc) | Node.js before 22.23.4, 24.22.1, 26.12.1. CVE-2026-111497, the bundled Brotli decoder. In CISA KEV. | Requests whose body is Brotli-compressed: a `Content-Encoding` header whose whole value is `br`. | 3000 |
| [`runtimes/java4shell.pfc`](runtimes/java4shell.pfc) | OpenJDK 17.0.6+, 21, 25, 27 on x86-64 with AVX-512 VBMI. CVE-2026-114938. | Base64 of the one shape that reaches the decoder bug: a 1–3 character tail ending in `=` after whole 64-character blocks. No encoder produces it. | 8080 |
| [`runtimes/aspnet-anticsrf.pfc`](runtimes/aspnet-anticsrf.pfc) | Idunno.AntiCsrf 0.9.1, an abandoned ASP.NET library. CVE-2026-131914. Exploited; there will be no fix. | A `__CSRFTOKEN` form field holding anything but the serialized string the module itself writes. | 80 |
| [`runtimes/struts-method-prefix.pfc`](runtimes/struts-method-prefix.pfc) | Struts 2.3.20–2.3.28 with Dynamic Method Invocation on. CVE-2016-3081 (S2-032). In CISA KEV. | A `method:` parameter or multipart field followed by anything that is not a method name. | 8080 |
| [`runtimes/log4shell.pfc`](runtimes/log4shell.pfc) | Log4j 2.0-beta9–2.14.1. CVE-2021-44228, CVE-2021-45046. | `${jndi`, `${` with a built-in lookup name, and `${name:-value}`, raw, percent-encoded or as JSON `\u` escapes. | 8080 |
| [`runtimes/tomcat-strict-path.pfc`](runtimes/tomcat-strict-path.pfc) | Any application on Tomcat. Hardening, no single CVE. | Paths Tomcat rewrites before routing: `;parameters`, `//`, `/./`, `/../`, percent-encoded letters. | 8080 |

### HTTP

| policy | shields | what it resets | port |
|---|---|---|---|
| [`http/h2c.pfc`](http/h2c.pfc) | nginx 1.9.5–1.31.8 and Apache httpd 2.4.55–2.4.70 with HTTP/2. CVE-2026-123007, CVE-2026-123633, CVE-2026-119618. | Cleartext HTTP/2: the client preface and the `Upgrade: h2c` handshake. | 80 |
| [`http/quic.pfc`](http/quic.pfc) | nginx 1.25.0–1.31.8 with HTTP/3 enabled. CVE-2026-121810. | QUIC handshakes over UDP, so HTTP/3 never starts and clients use TCP. It drops; UDP has no reset. | 443/udp |
| [`http/crawlers.pfc`](http/crawlers.pfc) | A site that does not want to be crawled for training. | Requests from GPTBot, ClaudeBot and Bytespider, by user-agent. | 80 |

### FTP

| policy | shields | what it resets | port |
|---|---|---|---|
| [`ftp/proftpd-mod-copy.pfc`](ftp/proftpd-mod-copy.pfc) | ProFTPD 1.3.5 with mod_copy. CVE-2015-3306. In CISA KEV. | Control connections that send `SITE CPFR` or `SITE CPTO`, in any case, with Telnet control bytes between the letters or without. | 21 |

### TLS

| policy | shields | what it resets | port |
|---|---|---|---|
| [`tls/legacy-clients.pfc`](tls/legacy-clients.pfc) | Any TLS listener. Hardening: the protocol versions RFC 8996 deprecates. | Handshakes from clients offering at most SSLv3, TLS 1.0 or 1.1; with `suites` set, also those offering a NULL, RC4 or EXPORT suite. | 443 |

### Baseline

| policy | what it does |
|---|---|
| [`baseline/pass.pfc`](baseline/pass.pfc) | Passes everything: the firewall attached and counting, deciding nothing. The one to fall back to. |

The port is each policy's default; `pfw knob set port N` changes it, with one
caveat. A policy that reads a stream follows connections only on its default
port, so on another port a signature split across two packets is missed: for
that, change the number on its `reassemble` line as well. The other knobs,
and what each rule is called in `pfw status`, are in the comments at the top
of the policy, which `pfw ls` prints.

## Before applying one

**They are stopgaps.** A virtual patch narrows what reaches the vulnerable
code until the software is upgraded. Each policy says in its comments which
request shapes it does not cover. Upgrade anyway.

**Plaintext HTTP/1 only.** A policy reads the bytes on the wire, so it belongs
on the hop behind the TLS terminator. It sees nothing on a TLS port, over
HTTP/2, on a FastCGI socket or on an AJP port. Two are exceptions:
`tls/legacy-clients.pfc` reads the one part of TLS that is in the clear, the
handshake, and `ftp/proftpd-mod-copy.pfc` reads an FTP control connection,
until the client turns TLS on with `AUTH TLS`.

**Applying one resets the connections it guards.** Connections already open
on the policy's port are reset when it is applied, because a stream first seen
half-way cannot be judged. Connections on other ports are not touched.

**One at a time.** The firewall runs a single policy. A host that needs two
of these cannot have both yet.

**Each has a cost, and it is written down.** The endpoint blocks stop the
legitimate use of that endpoint: blog clients that post to Roller over
XML-RPC, Confluence SOAP integrations, the guardrail tester in LiteLLM's admin
UI, document editing through Nextcloud's built-in Collabora, changes to an
AhsayCBS replication, file copies over FTP with mod_copy, the "Test"
button on a saved Grafana contact point. `log4shell`
resets `${HOME:-/root}` in a posted shell script. `h2c` breaks
a port that is meant to carry cleartext HTTP/2, gRPC above all. Read the
policy's comments for its own list, and for the knob that relaxes it.

## How far each has been tested

CI runs three tests on every push, against pfw as it is built that day:

- **the interpreter**: each policy's cases in pfw-core's reference interpreter;
- **the kernel**: each policy loaded into the real XDP program and driven over
  loopback TCP, with signatures split across segments and deep into streams;
- **end to end**: the firewall brought up with `pfw up`, each policy enforced
  with `pfw apply -f`, and real `curl` requests sent at a real server. The
  ones a policy names must be cut off, an ordinary one must be served, and
  `pfw knob set port` must move it.

The cases come from running the real software and recording what it accepts:

| policy | checked against |
|---|---|
| `confluence-remote-api`, `roller-xmlrpc`, `tomcat-strict-path` | Tomcat 9.0: which path spellings reach the same servlet. Confluence and Roller themselves were not run. |
| `installers`, `nextcloud-builtin-code` | Apache 2.4 with mod_php, which the official Drupal, WordPress and Nextcloud images run: which path spellings execute a PHP file. None of the three products was run, and nginx with PHP-FPM was not checked. The WordPress half follows CISA's and Wordfence's description; the vendor names no path. |
| `gpustack-real-ip` | uvicorn, the server GPUStack runs on: which spellings of a header line reach the application. GPUStack was not run. |
| `php2shell`, `php-object-injection` | PHP 8.3 under Apache 2.4: which multipart spellings its parser accepts, and which strings `unserialize()` builds an object from, by which transport. |
| every policy | A recorded admin session on a real WordPress 7.1.5 (login, settings, a post written and edited, an upload, a comment): 25 requests, none reset by any policy. |
| `node2shell` | Express 5 and Koa on Node 24: which `Content-Encoding` spellings reach the Brotli decoder. Only valid Brotli was sent, to a patched Node. |
| `log4shell` | Log4j 2.14.1: which of 25 lookup spellings made the logger connect out. All 17 that did are reset. |
| `java4shell` | The shape shirudo's `java-base64` guard refuses inside the JVM, and OpenJDK 17: its decoder refuses every form of it, and no encoder output of 1 to 5,000 bytes has it. Not run on an affected x86-64 JVM. |
| `aspnet-anticsrf` | Mandiant's description of how the module writes its token, and real .NET Framework on a Windows runner in CI (`test/dotnet/TokenLayout.cs`): what that token looks like, that no other type looks like it, and that what follows a string is not read. The module itself was not run. |
| `monai-label`, `litellm-guardrails` | FastAPI on uvicorn, the stack both run on: how paths are routed and queries decoded. Neither product was run. |
| `struts-method-prefix` | Struts 2.3.28 on Jetty, an affected build with Dynamic Method Invocation on: which spellings of the `method:` prefix it reads, from a query, a form body and a multipart field. Asked with ordinary method names; no exploit was sent. |
| `plex-timeline-protocol` | Plex Media Server 1.43.5, the fixed build, with a player registered: which spellings of the `protocol` parameter it reads, by the refusals in its log. No recorded session of a real Plex client was replayed. |
| `proftpd-mod-copy` | ProFTPD 1.3.8 with mod_copy: which spellings of the two commands it recognises, the Telnet control bytes it strips out of a command among them. 1.3.5 was not run. |
| `onlyoffice-encrypted-upload` | The source of ONLYOFFICE server 5.6.3.1 and of its fix: how the marker is compared and where the extension ends. No Document Server was run. |
| `ahsaycbs-update-receivers` | Nothing but the advisories, which name the path, and Tomcat 9.0 for its spellings. AhsayCBS is commercial and was not run. |
| `grafana-secrets` | Grafana 13.3.1 itself: which `Cookie` header spellings Go's `Request.Cookie` reads a named cookie from, and which spellings of the receiver test route reach its handler. Percent-encoding anywhere in the route does; `//`, `/./` and a trailing slash do not. |
| `h2c` | nginx 1.27 and httpd 2.4.71 with cleartext HTTP/2 enabled. |
| `quic` | The QUIC Initial packet a real curl sends with `--http3-only`. That a refused client falls back to TCP was not tested. |
| `legacy-clients` | The ClientHellos twelve real client stacks send: openssl 3.6, curl on macOS, Alpine and CentOS 7, BusyBox wget, Go, Java 17, node, python. Only macOS's curl offers a weak suite. |

No policy has been run against an exploit on a vulnerable build. What is
shown is that each resets the request shapes the software accepts and the
advisory describes.

## What is not covered yet

`node tools/kev.mjs` compares the `@cve` lines here with CISA's Known Exploited
Vulnerabilities catalogue and lists the recent entries no policy covers. An
entry is a candidate when the software can be run and its advisory names a
request, a path or a header; many name nothing.

## More

- [Writing a policy](docs/writing.md): the layout, the opening comments, and
  what the first drafts here got wrong.
- [Testing a policy](docs/testing.md): the two test scripts, the cases files,
  and where cases come from.
