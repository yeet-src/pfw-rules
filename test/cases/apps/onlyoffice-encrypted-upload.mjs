/* From the source of ONLYOFFICE server 5.6.3.1 and of its fix: the marker is
 * compared exactly at the first byte of the body, and the extension is what
 * lies before the next semicolon. No Document Server was run. */
export const port = 80;

export default function ({ f, run, stream, get, post, req }) {
  const web = { dport: port };
  const up = (body, headers = "", path = "/upload/Khirz6zTPdfd7/uid-1/1") => post(path, `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.x\r\nContent-Length: ${body.length}\r\n${headers}`, body);
  const png = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00";
  for (const ext of ["/../../../../../../../../../var/www/x", "/..", "../x", "..\\x", "png/../../x", "a.b", "%2e%2e%2fx", " png", "png\x00", "/etc/cron.d/x", "p\r\nng"])
    run(f, `ENCRYPTED;${JSON.stringify(ext).slice(1, -1)};`, up(`ENCRYPTED;${ext};#!/bin/sh\n`), "rst(onlyoffice_encrypted)", web);
  run(f, "the older route", up("ENCRYPTED;/../x;data", "", "/uploadold/Khirz6zTPdfd7/uid-1/1"), "rst(onlyoffice_encrypted)", web);
  run(f, "a chunked body that starts with the marker", post("/upload/k/u/1", "Transfer-Encoding: chunked\r\n", "1a\r\nENCRYPTED;/../../x;payload\r\n0\r\n\r\n"), "rst(onlyoffice_encrypted)", web);
  run(f, "second request on a keep-alive connection", get("/healthcheck") + up("ENCRYPTED;/../x;data"), "rst(onlyoffice_encrypted)", web);

  run(f, "an image upload", up(png), "pass", web);
  run(f, "an encrypted upload from the desktop editors", up("ENCRYPTED;png;" + "\x8f\x02\xa1/../".repeat(40)), "pass", web);
  run(f, "an encrypted upload, another extension", up("ENCRYPTED;jpeg;\x00\x01\x02"), "pass", web);
  run(f, "the editor's page", get("/web-apps/apps/api/documents/api.js"), "pass", web);
  run(f, "the marker in lower case, which the server does not take", up("encrypted;/../x;data"), "pass", web);
  run(f, "the marker not at the start of a line", up("xENCRYPTED;/../x;data"), "pass", web);
  /* the encodings the marker can hide in: reset only when asked */
  const gz = up("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03", "Content-Encoding: gzip\r\n");
  const chunked = post("/upload/k/u/1", "Transfer-Encoding: chunked\r\n", "3\r\nENC\r\n7\r\nRYPTED;\r\n0\r\n\r\n");
  run(f, "a gzip body", gz, "pass", web);
  run(f, "a chunked body", chunked, "pass", web);
  run(f, "strict=1: a gzip body", gz, "rst(onlyoffice_encoding)", { ...web, knobs: { strict: 1 } });
  run(f, "strict=1: a chunked body", chunked, "rst(onlyoffice_encoding)", { ...web, knobs: { strict: 1 } });
  run(f, "strict=1: Transfer-Encoding spelled another way", req("POST", "/upload/k/u/1", "TRANSFER-ENCODING :chunked\r\n", "0\r\n\r\n"), "rst(onlyoffice_encoding)", { ...web, knobs: { strict: 1 } });
  run(f, "strict=1: an image upload", up(png), "pass", { ...web, knobs: { strict: 1 } });
  run(f, "strict=1: a page, Accept-Encoding is not one of them", get("/web-apps/apps/api/documents/api.js", "Accept-Encoding: gzip, deflate, br\r\n"), "pass", { ...web, knobs: { strict: 1 } });
  run(f, "another port", up("ENCRYPTED;/../x;data"), "pass", { dport: 8080 });
  run(f, "port knob", up("ENCRYPTED;/../x;data"), "rst(onlyoffice_encrypted)", { dport: 8080, knobs: { port: 8080 } });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "an upload whose encrypted header names a path", curl: ["-H", "Content-Type: application/octet-stream", "--data-binary", "ENCRYPTED;/../../../tmp/x;data", `${url}/upload/k/u/1`], want: "cut" },
  { name: "an encrypted upload with an extension", curl: ["-H", "Content-Type: application/octet-stream", "--data-binary", "ENCRYPTED;png;data", `${url}/upload/k/u/1`], want: "served" },
  { name: "strict=1: a chunked upload", knobs: { strict: 1 }, curl: ["-H", "Transfer-Encoding: chunked", "--data-binary", "ENCRYPTED;png;data", `${url}/upload/k/u/1`], want: "cut" },
];
