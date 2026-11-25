/* LINUX holds captures: the CREATE_SESSION calls the kernel's own client
 * (Linux 6.10) sent to the kernel's own nfsd when asked to mount with
 * vers=4.1 and vers=4.2, record marker left off. test/real/nfs.mjs records
 * them again in CI. Every other call here is built by hand from RFC 5531 and
 * RFC 8881, around the same layout; how nfsd frames a call (fragments, the
 * tag's limit, long credentials) was asked of that nfsd. No affected kernel
 * was attacked. */
export const port = 2049;

const LINUX = {
  "4.1": "9e5c19200000000000000002000186a300000004000000010000000100000020000000000000000c35343465323039396439346400000000000000000000000000000000000000000000000000000001000000010000002bf768076b47faeb07000000010000000300000000001004140010038800001da000000008000000400000000000000000000010000000100000000000000000020000001000000000400000000000000100000001a1b45c7f0000000c353434653230393964393464000000000000000000000000",
  "4.2": "c8f4a0b00000000000000002000186a300000004000000010000000100000020000000000000000c35343465323039396439346400000000000000000000000000000000000000000000000000000002000000010000002bf768076b49faeb07000000010000000300000000001004140010038800001da000000008000000400000000000000000000010000000100000000000000000020000001000000000400000000000000100000001a1b45c7f0000000c353434653230393964393464000000000000000000000000",
};
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const cat = (...p) => Buffer.concat(p);
const opaque = (b) => cat(u32(b.length), b, Buffer.alloc((4 - (b.length % 4)) % 4));
/* one RPC record: the marker's top bit says "last fragment" */
const rec = (body, last = true) => cat(u32((last ? 0x80000000 : 0) | body.length), body);
const SYS = cat(u32(1), opaque(cat(u32(0), opaque(Buffer.from("client")), u32(0), u32(0), u32(0))));
const NONE = cat(u32(0), u32(0));
/* RPCSEC_GSS: version 1, data, sequence 7, a service, a context handle */
const gss = (service) => cat(u32(6), opaque(cat(u32(1), u32(0), u32(7), u32(service), opaque(Buffer.alloc(16, 0x11)))));
/* an NFSv4 COMPOUND call. `lead` is what krb5i puts before the arguments. */
const call = (ops, { cred = SYS, verf = NONE, tag = "", minor = 1, vers = 4, proc = 1, lead = Buffer.alloc(0) } = {}) =>
  cat(u32(0x1234abcd), u32(0), u32(2), u32(100003), u32(vers), u32(proc), cred, verf, lead, opaque(Buffer.from(tag, "latin1")), u32(minor), u32(ops.length), ...ops);
const chan = (cached) => cat(u32(0), u32(1049620), u32(1049480), u32(cached), u32(8), u32(64), u32(0));
/* CREATE_SESSION: client id, sequence, flags, the two channels, the callback program and its one security flavour */
const createSession = (cached) => cat(u32(43), Buffer.alloc(8, 0x5a), u32(1), u32(3), chan(cached), chan(0), u32(0x40000000), u32(1), u32(0));
const sequence = cat(u32(53), Buffer.alloc(16, 0x33), u32(1), u32(0), u32(0), u32(0));
const exchangeId = cat(u32(42), Buffer.alloc(8, 1), opaque(Buffer.from("Linux NFSv4.1 client")), u32(0x101), u32(0), u32(0));
const putrootfh = u32(24), getfh = u32(10);
const getattr = cat(u32(9), u32(2), u32(0x0010011a), u32(0x00b0a23a));
const write = (data) => cat(u32(38), Buffer.alloc(16), u32(0), u32(0), u32(0), opaque(data));
/* the same capture with another number where ca_maxresponsesize_cached is */
const linux = (v, cached) => { const b = Buffer.from(LINUX[v], "hex"); const at = b.indexOf(Buffer.from("0000002b", "hex"), 40) + 4 + 28; if (cached !== undefined) b.writeUInt32BE(cached, at); return b; };

export default function ({ f, run, stream, ok }) {
  const nfs = { dport: port };
  const hit = "rst(nfsd_session_cache)";
  ok(Buffer.from(LINUX["4.1"], "hex").readUInt32BE(Buffer.from(LINUX["4.1"], "hex").indexOf(Buffer.from("0000002b", "hex"), 40) + 32) === 7584, `${f}: the capture asks for 7584 bytes`);

  /* what the kernel's client sends */
  for (const v of ["4.1", "4.2"]) {
    run(f, `Linux's CREATE_SESSION, vers=${v}`, rec(linux(v)), "pass", nfs);
    run(f, `the same asking for 80 bytes, vers=${v}`, rec(linux(v, 80)), hit, nfs);
  }
  run(f, "the same asking for what nfsd grants at most, 2128", rec(linux("4.1", 2128)), hit, nfs);
  run(f, "the same asking for 2560", rec(linux("4.1", 2560)), "pass", nfs);

  /* the floor */
  for (const n of [0, 1, 79, 80, 81, 160, 255, 256, 512, 1023, 1024, 2128, 2559]) run(f, `a cache of ${n} bytes`, rec(call([createSession(n)])), hit, nfs);
  for (const n of [2560, 2561, 4096, 7584, 65536, 0xffffffff]) run(f, `a cache of ${n} bytes`, rec(call([createSession(n)])), "pass", nfs);
  run(f, "floor knob at 4096: Linux's own is let through", rec(linux("4.1")), "pass", { ...nfs, knobs: { floor: 4096 } });
  run(f, "floor knob at 4096: 4095 is not", rec(call([createSession(4095)])), hit, { ...nfs, knobs: { floor: 4096 } });
  run(f, "floor knob at 4096: nor after a SEQUENCE", rec(call([sequence, createSession(4095)])), hit, { ...nfs, knobs: { floor: 4096 } });
  run(f, "floor knob at 8192: Linux's own is refused", rec(linux("4.1")), hit, { ...nfs, knobs: { floor: 8192 } });
  run(f, "floor knob at 64: the line does not come down", rec(call([createSession(80)])), hit, { ...nfs, knobs: { floor: 64 } });
  run(f, "floor knob at 0: nor here", rec(call([createSession(0)])), hit, { ...nfs, knobs: { floor: 0 } });

  /* the header, in the shapes nfsd reads */
  run(f, "NFSv4.2", rec(call([createSession(80)], { minor: 2 })), hit, nfs);
  run(f, "AUTH_NONE", rec(call([createSession(80)], { cred: NONE })), hit, nfs);
  run(f, "a credential with sixteen groups", rec(call([createSession(80)], { cred: cat(u32(1), opaque(cat(u32(9), opaque(Buffer.from("a-rather-long-host-name.example.test")), u32(1000), u32(1000), u32(16), Buffer.alloc(64, 1)))) })), hit, nfs);
  run(f, "a credential of 400 bytes", rec(call([createSession(80)], { cred: cat(u32(1), opaque(Buffer.alloc(400))) })), hit, nfs);
  for (const n of [1, 2, 3, 4, 127, 128]) run(f, `a tag of ${n} bytes`, rec(call([createSession(80)], { tag: "t".repeat(n) })), hit, nfs);
  run(f, "a tag that looks like a call header", rec(call([createSession(80)], { tag: cat(u32(0), u32(2), u32(100003), u32(4), u32(1), u32(0), u32(0), u32(0), u32(0), u32(1), u32(1), u32(43)).toString("latin1") })), hit, nfs);
  run(f, "Kerberos without integrity", rec(call([createSession(80)], { cred: gss(1), verf: cat(u32(6), opaque(Buffer.alloc(28, 7))) })), hit, nfs);
  run(f, "Kerberos with integrity (krb5i)", rec(call([createSession(80)], { cred: gss(2), verf: cat(u32(6), opaque(Buffer.alloc(28, 7))), lead: cat(u32(200), u32(7)) })), hit, nfs);
  run(f, "krb5i asking for Linux's size", rec(call([createSession(7584)], { cred: gss(2), verf: cat(u32(6), opaque(Buffer.alloc(28, 7))), lead: cat(u32(200), u32(7)) })), "pass", nfs);
  run(f, "after a SEQUENCE", rec(call([sequence, createSession(80)])), hit, nfs);
  run(f, "after a SEQUENCE, asking for Linux's size", rec(call([sequence, createSession(7584)])), "pass", nfs);
  run(f, "with operations after it", rec(call([createSession(80), putrootfh, getfh])), hit, nfs);

  /* further into a COMPOUND, behind operations the policy does not parse */
  run(f, "third, behind a SEQUENCE and a PUTROOTFH", rec(call([sequence, putrootfh, createSession(80)])), hit, nfs);
  run(f, "sixth", rec(call([sequence, putrootfh, getfh, getattr, getattr, createSession(80)])), hit, nfs);
  run(f, "behind a WRITE of 3 kB", rec(call([sequence, putrootfh, write(Buffer.alloc(3000, 0x61)), createSession(80)])), hit, nfs);
  for (const n of [1, 2, 3, 5, 6, 7]) run(f, `behind ${n} odd bytes, off the four-byte grid`, cat(rec(call([sequence, putrootfh])), Buffer.alloc(n, 0x61), createSession(80)), hit, nfs);
  run(f, "sixth, asking for Linux's size", rec(call([sequence, putrootfh, getfh, getattr, getattr, createSession(7584)])), "pass", nfs);
  run(f, "in a credential of 400 bytes and a tag of 128: the header at its longest", rec(call([sequence, putrootfh, createSession(80)], { cred: cat(u32(1), opaque(Buffer.alloc(400))), tag: "t".repeat(128) })), hit, nfs);
  run(f, "with a client id of zero, which nfsd has never given out", rec(call([sequence, putrootfh, cat(u32(43), Buffer.alloc(8), createSession(80).subarray(12))])), "pass", nfs);
  run(f, "with a flag nfsd refuses", rec(call([sequence, putrootfh, cat(createSession(80).subarray(0, 16), u32(0x100), createSession(80).subarray(20))])), "pass", nfs);

  /* where in the stream */
  const small = rec(call([sequence, putrootfh, getfh, getattr]));
  run(f, "behind another call in the segment", cat(small, rec(call([createSession(80)]))), hit, nfs);
  run(f, "behind twenty other calls", cat(...Array(20).fill(small), rec(call([createSession(80)]))), hit, nfs);
  run(f, "behind thirty other calls, a window's worth", cat(...Array(30).fill(rec(call([sequence, putrootfh]))), rec(call([createSession(80)]))), hit, nfs);
  run(f, "between other calls", cat(small, rec(call([exchangeId])), rec(call([createSession(80)])), small, small), hit, nfs);
  run(f, "behind Linux's own", cat(rec(linux("4.1")), rec(call([createSession(80)]))), hit, nfs);
  run(f, "behind the end of a record that began earlier", cat(Buffer.alloc(700, 0x86), rec(call([createSession(80)]))), hit, nfs);
  run(f, "behind data that holds a call header", cat(rec(call([sequence, write(cat(Buffer.alloc(40), call([createSession(7584)]), Buffer.alloc(40)))])), rec(call([createSession(80)]))), hit, nfs);
  run(f, "behind an NFSv3 call and a NULL", cat(rec(call([], { vers: 3, proc: 1 })), rec(call([], { proc: 0 })), rec(call([createSession(80)]))), hit, nfs);
  run(f, "with its record marker out of sight", call([createSession(80)]).subarray(4), hit, nfs);
  run(f, "with nothing before its header at all", call([createSession(80)]).subarray(4), hit, nfs);
  /* every distance into the window, so the search for the first header is walked down each of its branches */
  for (let n = 0; n <= 3600; n += 37) run(f, `${n} bytes into a record that began earlier`, cat(Buffer.alloc(n, n % 3 ? 0x61 : 0), rec(call([createSession(80)]))), hit, nfs);
  run(f, "3 kB into a segment", cat(rec(call([sequence, write(Buffer.alloc(3000, 0x61))])), rec(call([createSession(80)]))), hit, nfs);

  /* framing nfsd reads and this cannot follow */
  const body = call([createSession(80)]);
  const cut = body.indexOf(Buffer.from("0000002b", "hex")) + 20;
  run(f, "sent as two fragments, the second beginning inside the operation", cat(rec(body.subarray(0, cut), false), rec(body.subarray(cut))), "rst(nfsd_fragmented)", nfs);
  run(f, "sent as two fragments, the operation whole in the second", cat(rec(body.subarray(0, 60), false), rec(body.subarray(60))), hit, nfs);
  run(f, "an ordinary call sent as two fragments", cat(rec(call([sequence, putrootfh]).subarray(0, 60), false), rec(call([sequence, putrootfh]).subarray(60))), "rst(nfsd_fragmented)", nfs);
  run(f, "fragments knob: let through, unread", cat(rec(call([sequence, putrootfh]).subarray(0, 60), false), rec(call([sequence, putrootfh]).subarray(60))), "pass", { ...nfs, knobs: { fragments: 1 } });
  run(f, "fragments knob: a whole call is still read", rec(body), hit, { ...nfs, knobs: { fragments: 1 } });
  run(f, "a credential of 404 bytes", rec(call([createSession(7584)], { cred: cat(u32(1), opaque(Buffer.alloc(404))) })), "rst(nfsd_long_auth)", nfs);
  run(f, "a verifier of 404 bytes", rec(call([createSession(7584)], { verf: cat(u32(0), opaque(Buffer.alloc(404))) })), "rst(nfsd_long_auth)", nfs);

  /* ordinary traffic */
  run(f, "EXCHANGE_ID", rec(call([exchangeId])), "pass", nfs);
  run(f, "a SEQUENCE and a lookup", small, "pass", nfs);
  /* the shape is refused wherever it is, in calls nfsd would itself refuse too */
  run(f, "the shape in an NFSv4.0 COMPOUND", rec(call([createSession(80)], { minor: 0 })), hit, nfs);
  run(f, "the shape in an NFSv3 call", rec(call([createSession(80)], { vers: 3 })), hit, nfs);
  run(f, "the shape under a tag nfsd refuses, 129 bytes", rec(call([createSession(80)], { tag: "t".repeat(129) })), hit, nfs);
  /* and the header reading alone, where the shape is not there to be seen */
  run(f, "floor knob at 4096, NFSv4.0: no sessions, nothing to judge", rec(call([createSession(4000)], { minor: 0 })), "pass", { ...nfs, knobs: { floor: 4096 } });
  run(f, "floor knob at 4096, an NFSv3 call", rec(call([createSession(4000)], { vers: 3 })), "pass", { ...nfs, knobs: { floor: 4096 } });
  run(f, "floor knob at 4096, a tag nfsd refuses", rec(call([createSession(4000)], { tag: "t".repeat(129) })), "pass", { ...nfs, knobs: { floor: 4096 } });
  run(f, "floor knob at 4096, krb5i", rec(call([createSession(4000)], { cred: gss(2), verf: cat(u32(6), opaque(Buffer.alloc(28, 7))), lead: cat(u32(200), u32(7)) })), hit, { ...nfs, knobs: { floor: 4096 } });
  run(f, "a WRITE of zeros with one 43 among them", rec(call([sequence, write(cat(Buffer.alloc(600), u32(43), Buffer.alloc(600)))])), "pass", nfs);
  run(f, "a WRITE of text about C++ and 1+1", rec(call([sequence, write(Buffer.from("int a = b+++c; // C++\n1+1=2\0\0\0+\n".repeat(60)))])), "pass", nfs);
  /* the known cost: big-endian integers that line up as the operation does */
  run(f, "a WRITE of a table of small big-endian numbers that lines up", rec(call([sequence, write(cat(...[43, 5, 9, 1, 2, 3, 500, 600, 7, 8].map(u32)))])), hit, nfs);
  run(f, "a WRITE of zeros and plus signs", rec(call([sequence, write(cat(Buffer.alloc(600), Buffer.alloc(600, 0x2b), Buffer.alloc(100)))])), "pass", nfs);
  run(f, "a WRITE of the number 43, over and over", rec(call([sequence, write(cat(...Array(300).fill(u32(43))))])), "pass", nfs);
  run(f, "a WRITE whose data is Linux's own CREATE_SESSION", rec(call([sequence, write(rec(linux("4.2")))])), "pass", nfs);
  run(f, "a reply, on its way back to a client", rec(cat(u32(0x1234abcd), u32(1), u32(0), u32(0), u32(0), u32(0), u32(0), u32(0), u32(1), u32(43), u32(0), Buffer.alloc(64))), "pass", { sport: port, dport: 51000 });
  run(f, "a cut-off header: nothing to judge yet", rec(call([createSession(80)])).subarray(0, 90), "pass", nfs);
  run(f, "cut off before the cache size", rec(call([createSession(80)])).subarray(0, 4 + call([createSession(80)]).indexOf(Buffer.from("0000002b", "hex")) + 30), "pass", nfs);
  run(f, "an empty segment", new Uint8Array(0), "pass", nfs);
  run(f, "the call over UDP", call([createSession(80)]), "pass", { ...nfs, proto: 17 });
  run(f, "the call to another port", rec(call([createSession(80)])), "pass", { dport: 111 });
  run(f, "port knob: nfsd on 20049", rec(call([createSession(80)])), hit, { dport: 20049, knobs: { port: 20049 } });
  run(f, "port knob: 2049 is then left alone", rec(call([createSession(80)])), "pass", { ...nfs, knobs: { port: 20049 } });

  /* a megabyte WRITE, as the client sends it: one record, 1460 bytes a segment */
  const big = rec(call([sequence, write(Buffer.from(Array.from({ length: 1 << 20 }, (_, i) => (i * 2654435761) >>> 24)))]));
  const segs = []; for (let i = 0; i < big.length; i += 1460) segs.push(big.subarray(i, i + 1460));
  stream(f, "a megabyte WRITE, segment by segment", segs, "pass", nfs);
}

/* The same builders, for test/kernel.mjs. */
export const wire = { rec, call, createSession, sequence, putrootfh, getfh, getattr, write, linux };

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = () => [
  { name: "a CREATE_SESSION asking for an 80-byte cache", raw: rec(linux("4.1", 80)), want: "cut" },
  { name: "the one Linux's client sends", raw: rec(linux("4.1")), want: "served" },
  { name: "Linux's own, with the floor knob raised past it", knobs: { floor: 8192 }, raw: rec(linux("4.1")), want: "cut" },
];
