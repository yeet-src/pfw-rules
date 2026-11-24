/* The hellos are captures: the first bytes each client sent to a listener
 * (test/fixtures/clienthello-*.bin). On this Mac: openssl 3.6, the system
 * curl (LibreSSL 3.3.6), python and node. In containers: Alpine's curl,
 * BusyBox wget, Go 1.23, Java 17, CentOS 7's curl (NSS) and Python 3.12. */
export const port = 443;

export default function ({ f, run, root, readFileSync, get }) {
  const tls = { dport: port };
  const hello = (n) => Uint8Array.from(readFileSync(new URL(`test/fixtures/clienthello-${n}.bin`, root)));
  const strict = { ...tls, knobs: { suites: 1 } };
  const CURRENT = ["openssl", "openssl-tls12", "openssl-tls13", "python", "node", "alpine-curl", "busybox-wget", "go", "java17", "centos7-curl", "python312"];
  for (const n of [...CURRENT, "curl"]) run(f, `${n} ClientHello`, hello(n), "pass", tls);
  run(f, "openssl -tls1", hello("openssl-tls10"), "rst(tls_legacy_version)", tls);
  run(f, "openssl -tls1_1", hello("openssl-tls11"), "rst(tls_legacy_version)", tls);
  run(f, "openssl offering NULL-SHA256, suites left alone", hello("openssl-null-suite"), "pass", tls);

  /* suites=1 */
  /* of the twelve stacks captured, eleven offer no weak suite at all */
  for (const n of CURRENT) run(f, `suites=1: ${n} ClientHello`, hello(n), "pass", strict);
  run(f, "suites=1: openssl offering NULL-SHA256", hello("openssl-null-suite"), "rst(tls_weak_suites)", strict);
  /* the twelfth, and the reason the rule is not on by default: RC4 is the 41st to 44th of its 49 suites */
  run(f, "suites=1: the curl that ships with macOS 15, which still lists RC4", hello("curl"), "rst(tls_weak_suites)", strict);

  /* edits to a real TLS 1.2 hello */
  const edit = (fn) => { const h = hello("openssl-tls12"); fn(h); return h; };
  run(f, "legacy_version SSLv3", edit((h) => { h[9] = 0x03; h[10] = 0x00; }), "rst(tls_sslv3)", tls);
  const suites = (h) => { const sid = h[43]; return { at: 44 + sid + 2, n: ((h[44 + sid] << 8) | h[45 + sid]) / 2 }; };
  run(f, "RC4-SHA as the first suite", edit((h) => { const s = suites(h); h[s.at] = 0x00; h[s.at + 1] = 0x05; }), "rst(tls_weak_suites)", strict);
  run(f, "an EXPORT suite as the last one", edit((h) => { const s = suites(h); h[s.at + 2 * (s.n - 1)] = 0x00; h[s.at + 2 * (s.n - 1) + 1] = 0x03; }), "rst(tls_weak_suites)", strict);
  /* 00 05 lying across two suites (xx00 05xx) is not RC4-SHA: alignment matters */
  run(f, "00 05 straddling two suites", edit((h) => { const s = suites(h); h[s.at + 1] = 0x00; h[s.at + 2] = 0x05; }), "pass", strict);

  run(f, "application data, not a handshake", Uint8Array.from([0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]), "pass", tls);
  run(f, "plain HTTP on the TLS port", get("/"), "pass", tls);
  run(f, "another port", hello("openssl-tls10"), "pass", { dport: 8443 });
  run(f, "port knob", hello("openssl-tls10"), "rst(tls_legacy_version)", { dport: 8443, knobs: { port: 8443 } });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ fixture }) => [
  { name: "the ClientHello openssl -tls1 sends", raw: fixture("clienthello-openssl-tls10.bin"), want: "cut" },
  { name: "the ClientHello openssl -tls1_1 sends", raw: fixture("clienthello-openssl-tls11.bin"), want: "cut" },
  { name: "the ClientHello openssl sends by default", raw: fixture("clienthello-openssl.bin"), want: "served" },
  { name: "the ClientHello python sends", raw: fixture("clienthello-python.bin"), want: "served" },
  { name: "suites=1: a hello offering NULL-SHA256", knobs: { suites: 1 }, raw: fixture("clienthello-openssl-null-suite.bin"), want: "cut" },
];
