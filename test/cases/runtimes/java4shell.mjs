/* The shape is the one shirudo's java-base64 guard (GuardCheck.java) refuses
 * inside the JVM; `candidate` below is that check, line for line. That no
 * valid Base64 has the shape, and that the JDK's own decoder refuses every
 * tail form as malformed, was checked on OpenJDK 17 (Temurin 17.0.21). */
export const port = 8080;

/* GuardCheck.check, for the standard or the URL-safe alphabet. */
function candidate(s, isURL) {
  const length = s.length;
  if (length < 65) return false;
  const remainder = length & 63;
  if (remainder < 1 || remainder > 3) return false;
  let padding = 0;
  while (padding < 3 && s[length - 1 - padding] === "=") padding++;
  if (padding < 1 || padding > 2 || padding > remainder) return false;
  const ok = isURL ? /^[A-Za-z0-9_-]*$/ : /^[A-Za-z0-9+/]*$/;
  return ok.test(s.slice(0, length - padding));
}

export default function ({ f, run, stream, ok, progs, bytes, get, post }) {
  const web = { dport: port };
  const basic = (v) => get("/", `Authorization: Basic ${v}\r\n`);
  const verdict = (data) => progs.get(f).exec(bytes(data), { flow: {}, source: {}, bucket: {}, now: 0n, ...web }).verdict;
  const A = (n, c = "A") => c.repeat(n);

  /* the five tails, after one block and after three */
  for (const blocks of [1, 3]) for (const tail of ["=", "A=", "==", "AA=", "A=="])
    run(f, `${blocks} block${blocks > 1 ? "s" : ""} + "${tail}" in Authorization: Basic`, basic(A(64 * blocks) + tail), "rst(java4shell_base64)", web);
  run(f, "the string shirudo's badDecoder sends", basic(A(64) + "A="), "rst(java4shell_base64)", web);
  run(f, "URL-safe alphabet", basic(A(60) + "-_-_" + "A="), "rst(java4shell_base64)", web);
  run(f, "in a cookie", get("/", `Cookie: session=${A(128)}=; theme=dark\r\n`), "rst(java4shell_base64)", web);
  run(f, "in a query parameter", get(`/sso?SAMLart=${A(64)}A=&RelayState=x`), "rst(java4shell_base64)", web);
  run(f, "in a JSON body", post("/api", "Content-Type: application/json\r\n", `{"token":"${A(64)}=="}`), "rst(java4shell_base64)", web);
  run(f, "padding percent-encoded", post("/login", "Content-Type: application/x-www-form-urlencoded\r\n", `csrf=${A(64)}A%3D&user=jo`), "rst(java4shell_base64)", web);
  run(f, "characters percent-encoded", post("/login", "Content-Type: application/x-www-form-urlencoded\r\n", `csrf=${A(30)}%2B%2F%41${A(31)}%3D%3D&user=jo`), "rst(java4shell_base64)", web);
  run(f, `"AA=" as the last bytes of a body`, post("/login", "Content-Type: application/x-www-form-urlencoded\r\n", `user=jo&csrf=${A(64)}AA=`), "rst(java4shell_base64)", web);
  run(f, `"A=" as the last bytes of a body`, post("/login", "Content-Type: application/x-www-form-urlencoded\r\n", `user=jo&csrf=${A(64)}A=`), "rst(java4shell_base64)", web);
  stream(f, "the token split across segments", [`GET / HTTP/1.1\r\nAuthorization: Basic ${A(40)}`, basic(A(64) + "A=")], "rst(java4shell_base64)", web);
  run(f, "another port", basic(A(64) + "A="), "pass", { dport: 80 });

  /* what encoders really produce, for every payload size up to 400 bytes */
  let quiet = true;
  for (let n = 1; n <= 400 && quiet; n++) {
    const raw = Buffer.alloc(n, (n * 37) & 0xff).map((b, i) => (b + i * 101) & 0xff);
    const std = Buffer.from(raw).toString("base64"), url = std.replace(/\+/g, "-").replace(/\//g, "_");
    for (const v of [std, std.replace(/=+$/, ""), url, url.replace(/=+$/, "")]) {
      if (candidate(v, false) || candidate(v, true)) { quiet = false; ok(false, `${f}: valid Base64 of ${n} bytes is never a candidate`); }
      if (verdict(basic(v)) !== "pass" || verdict(post("/x", "", `a=${encodeURIComponent(v)}`)) !== "pass" || verdict(post("/x", "", `{"t":"${v}"}`)) !== "pass") { quiet = false; ok(false, `${f}: valid Base64 of ${n} bytes passes`, v.slice(-12)); }
    }
  }
  ok(quiet, `${f}: every valid Base64 encoding of 1 to 400 bytes passes, padded or not, in a header, a form and JSON`);

  /* the rule and the guard agree, on strings near the boundary of the shape */
  let agree = true, checked = 0, x = 20261124;
  const rnd = (k) => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x % k; };
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (let i = 0; i < 4000 && agree; i++) {
    const len = [60, 64, 128, 192][rnd(4)] + rnd(8), pads = rnd(3);
    let s = ""; for (let j = 0; j < len - pads; j++) s += alpha[rnd(64)];
    s += "=".repeat(pads);
    const want = candidate(s, false), got = verdict(basic(s)) === "rst";
    checked++;
    if (want !== got) { agree = false; ok(false, `${f}: agrees with the guard`, `length ${s.length}, ${pads} padding: guard ${want}, policy ${got}`); }
  }
  ok(agree, `${f}: agrees with shirudo's guard on ${checked} strings around the shape`);

  /* near misses and ordinary traffic */
  run(f, "64 characters and no tail", basic(A(64)), "pass", web);
  run(f, "valid: 64 + AA==", basic(A(64) + "AA=="), "pass", web);
  run(f, "valid: 64 + AAA=", basic(A(64) + "AAA="), "pass", web);
  run(f, "too short: 63 + =", basic(A(63) + "="), "pass", web);
  run(f, "three padding characters, which the guard lets go too", basic(A(64) + "==="), "pass", web);
  run(f, "a 64-character name with an empty value, the known cost", get(`/?${A(64, "a")}=&x=1`), "rst(java4shell_base64)", web);
  run(f, "a JWT", get("/", `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${A(86)}.${A(43)}\r\n`), "pass", web);
  run(f, "PEM, 64 characters a line", post("/cert", "Content-Type: text/plain\r\n", `-----BEGIN CERTIFICATE-----\n${A(64)}\n${A(64)}\n${A(22)}==\n-----END CERTIFICATE-----\n`), "pass", web);
  run(f, "a 64-character hex name with a value", get(`/?${A(64, "a")}=1`), "pass", web);
  run(f, "a 64-character name with a value, as the last form field", post("/x", "", `${A(64, "a")}=yes`), "pass", web);
  run(f, "valid 64 + AA== as the last bytes of a body", post("/x", "", `token=${A(64)}AA==`), "pass", web);
  run(f, "valid 64 + AA== earlier, and a body that ends in ==", post("/x", "", `a=${A(64)}AA==&b=QQ==`), "pass", web);
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "Basic credentials of the bad shape", curl: ["-H", `Authorization: Basic ${"A".repeat(64)}A=`, `${url}/`], want: "cut" },
  { name: "the same shape as the last form field", curl: ["-d", `user=jo&csrf=${"A".repeat(64)}AA=`, `${url}/login`], want: "cut" },
  { name: "real Basic credentials", curl: ["-u", "a-user-with-a-long-name@example.test:and-a-long-passphrase-of-many-words-indeed", `${url}/`], want: "served" },
  { name: "a long valid token", curl: ["-H", `Authorization: Basic ${Buffer.alloc(200, 7).toString("base64")}`, `${url}/`], want: "served" },
];
