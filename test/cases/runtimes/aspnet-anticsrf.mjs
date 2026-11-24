/* The legitimate value is what Mandiant's advisory says the module writes,
 * ObjectStateFormatter.Serialize(guid), laid out by Microsoft's token numbers:
 * ff 01 05 24 and the 36 characters of the GUID. The module itself has not
 * been run. That the decoder skips whitespace and ignores what follows a
 * string was checked on Mono. */
export const port = 80;

export default function ({ f, run, stream, post, get, B, part }) {
  const web = { dport: port };
  const osf = (type, rest) => Buffer.concat([Buffer.from([0xff, 0x01, type]), Buffer.from(rest, "latin1")]).toString("base64");
  const legit = osf(0x05, "\x24" + "99f141b2-d899-4452-9ed8-e21d76ff6c1d");
  const ue = (s) => s.replace(/\//g, "%2F").replace(/\+/g, "%2B").replace(/=/g, "%3D");
  const form = (body) => post("/Default.aspx", "Content-Type: application/x-www-form-urlencoded\r\nCookie: __CSRFCOOKIE=99f141b2-d899-4452-9ed8-e21d76ff6c1d\r\n", body);
  const mp = (parts) => post("/Default.aspx", `Content-Type: multipart/form-data; boundary=${B}\r\n`, parts.join("") + `--${B}--\r\n`);

  run(f, "the token the module writes", form(`__VIEWSTATE=%2FwEPDwUK&__CSRFTOKEN=${ue(legit)}&name=jo`), "pass", web);
  run(f, "the same, slash left unencoded", form(`__CSRFTOKEN=${legit.replace(/=/g, "%3D")}&name=jo`), "pass", web);
  run(f, "the same, in a multipart form", mp([part(`name="__CSRFTOKEN"`, legit), part(`name="upload"; filename="a.txt"`, "hello", "text/plain")]), "pass", web);
  run(f, "the same, under the name RaiseException", form(`RaiseException=${ue(legit)}`), "pass", web);
  run(f, "a form with no token", form("__VIEWSTATE=%2FwEPDwUK&name=jo"), "pass", web);
  run(f, "a GET", get("/Default.aspx"), "pass", web);
  run(f, "two form posts on one keep-alive connection", form(`__CSRFTOKEN=${ue(legit)}&a=1`) + form(`__VIEWSTATE=x&__CSRFTOKEN=${ue(legit)}`), "pass", web);

  /* every other top-level type: none of these opens /wEF */
  for (const [what, type] of [["a binary-serialized object", 0x32], ["a pair", 0x0f], ["a triplet", 0x10], ["an array", 0x14], ["an array list", 0x16], ["a hashtable", 0x17], ["a type reference", 0x19], ["a formatted string", 0x28], ["a sparse array", 0x3c]])
    run(f, `token holding ${what}`, form(`__CSRFTOKEN=${ue(osf(type, "\x00\x01\x00\x00\x00\xff\xff\xff\xff"))}`), "rst(anticsrf_token)", web);
  const evil = osf(0x32, "\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00");
  run(f, "under the name RaiseException", form(`RaiseException=${ue(evil)}`), "rst(anticsrf_token)", web);
  run(f, "field name in another case", form(`__csrfToken=${ue(evil)}`), "rst(anticsrf_token)", web);
  run(f, "field name percent-encoded", form(`%5F%5FCSRF%54OKEN=${ue(evil)}`), "rst(anticsrf_token)", web);
  run(f, "every opening character percent-encoded", form(`__CSRFTOKEN=%2f%77%45%79${ue(evil.slice(4))}`), "rst(anticsrf_token)", web);
  run(f, "leading space, as +", form(`__CSRFTOKEN=+${ue(evil)}`), "rst(anticsrf_token)", web);
  run(f, "leading space, as %20", form(`__CSRFTOKEN=%20${ue(evil)}`), "rst(anticsrf_token)", web);
  run(f, "leading newline", form(`__CSRFTOKEN=%0A${ue(evil)}`), "rst(anticsrf_token)", web);
  run(f, "a space inside the opening", form(`__CSRFTOKEN=%2Fw+Ey${ue(evil.slice(4))}`), "rst(anticsrf_token)", web);
  run(f, "a legitimate opening hidden behind whitespace", form(`__CSRFTOKEN=+${ue(legit)}`), "rst(anticsrf_token)", web);
  run(f, "second field after a legitimate one", form(`__CSRFTOKEN=${ue(legit)}&__CSRFTOKEN=${ue(evil)}`), "rst(anticsrf_token)", web);
  run(f, "in a multipart part", mp([part(`name="__CSRFTOKEN"`, evil)]), "rst(anticsrf_token)", web);
  run(f, "multipart, name unquoted", mp([part(`name=__CSRFTOKEN`, evil)]), "rst(anticsrf_token)", web);
  run(f, "multipart, with a Content-Type on the part", mp([part(`name="__CSRFTOKEN"`, evil, "text/plain")]), "rst(anticsrf_token)", web);
  run(f, "multipart, under the name RaiseException", mp([part(`name="RaiseException"`, evil)]), "rst(anticsrf_token)", web);
  stream(f, "the field split across segments", [form("__CSRFTOK"), form(`__CSRFTOKEN=${ue(evil)}`)], "rst(anticsrf_token)", web);
  run(f, "second request on a keep-alive connection", form(`__CSRFTOKEN=${ue(legit)}`) + form(`__CSRFTOKEN=${ue(evil)}`), "rst(anticsrf_token)", web);
  run(f, "another port", form(`__CSRFTOKEN=${ue(evil)}`), "pass", { dport: 8080 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => {
  const osf = (type, rest) => Buffer.concat([Buffer.from([0xff, 0x01, type]), Buffer.from(rest, "latin1")]).toString("base64");
  const legit = osf(0x05, "\x24" + "99f141b2-d899-4452-9ed8-e21d76ff6c1d"), other = osf(0x32, "\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00");
  return [
    { name: "a token that is not a string", curl: ["--data-urlencode", `__CSRFTOKEN=${other}`, "-d", "name=jo", `${url}/Default.aspx`], want: "cut" },
    { name: "the same in a multipart form", curl: ["-F", `__CSRFTOKEN=${other}`, `${url}/Default.aspx`], want: "cut" },
    { name: "the token the module writes", curl: ["--data-urlencode", `__CSRFTOKEN=${legit}`, "-d", "name=jo", `${url}/Default.aspx`], want: "served" },
    { name: "the same in a multipart form", curl: ["-F", `__CSRFTOKEN=${legit}`, `${url}/Default.aspx`], want: "served" },
  ];
};
