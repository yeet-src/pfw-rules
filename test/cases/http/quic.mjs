/* The Initial is a capture: the first datagram curl 8 sent with --http3-only
 * (test/fixtures/quic-initial-curl.bin). */
export const port = 443;

export default function ({ f, run, root, readFileSync, get }) {
  const udp = { dport: port, proto: 17 };
  const initial = Uint8Array.from(readFileSync(new URL("test/fixtures/quic-initial-curl.bin", root)));
  const first = (b) => { const d = Uint8Array.from(initial); d[0] = b; return d; };
  run(f, "curl's QUIC Initial", initial, "drop(quic_handshake)", udp);
  run(f, "a 0-RTT packet (long header, type 1)", first(0xd3), "drop(quic_handshake)", udp);
  run(f, "a Handshake packet (long header, type 2)", first(0xe1), "drop(quic_handshake)", udp);
  run(f, "a Retry packet (long header, type 3)", first(0xf0), "drop(quic_handshake)", udp);
  run(f, "a short-header packet, which only follows a handshake", first(0x41), "pass", udp);
  run(f, "DTLS: a handshake record", Uint8Array.from([0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]), "pass", udp);
  run(f, "STUN: a binding request", Uint8Array.from([0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]), "pass", udp);
  run(f, "RTP: version 2, top bits 10", Uint8Array.from([0x80, 0x60, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 1]), "pass", udp);
  run(f, "an empty datagram", new Uint8Array(0), "pass", udp);
  run(f, "TCP on the same port, which is TLS", initial, "pass", { dport: port });
  run(f, "plain HTTP over TCP", get("/"), "pass", { dport: port });
  run(f, "another UDP port", initial, "pass", { dport: 8443, proto: 17 });
  run(f, "port knob", initial, "drop(quic_handshake)", { dport: 8443, proto: 17, knobs: { port: 8443 } });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ fixture }) => [
  { name: "the QUIC Initial curl --http3-only sends", udp: fixture("quic-initial-curl.bin"), want: "cut" },
  { name: "a datagram that is not QUIC (a STUN binding request)", udp: Buffer.from([0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]), want: "served" },
];
