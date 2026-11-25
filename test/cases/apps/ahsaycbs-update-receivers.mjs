/* The path spellings are ones Tomcat 9.0 served the same resource for (see
 * tomcatSpellings in the harness). AhsayCBS itself was not run, and that it
 * decodes a path the way Tomcat does is an assumption. */
export const port = 80;

export default function ({ f, run, stream, get, post, tomcatSpellings }) {
  const web = { dport: port };
  const json = "Content-Type: application/json\r\n";
  for (const t of tomcatSpellings("rps/api/json", "UpdateReceivers.do")) run(f, `POST ${t}`, post(t, json, "{}"), "rst(ahsay_update_receivers)", web);
  for (const t of ["/rps/api/json/updatereceivers.do", "/rps/api/json/UPDATERECEIVERS.DO", "/rps/api/json/%55pdate%52eceivers.do", "/rps/api/json/UpdateReceiver%73.do", "/rps/api/json/UpdateReceivers.do?random=1", "/rps/api/json/UpdateReceivers.do;jsessionid=1"])
    run(f, `POST ${t}`, post(t, json, "{}"), "rst(ahsay_update_receivers)", web);
  run(f, "GET", get("/rps/api/json/UpdateReceivers.do"), "rst(ahsay_update_receivers)", web);
  run(f, "second request on a keep-alive connection", get("/cbs/system/ShowLogon.do") + post("/rps/api/json/UpdateReceivers.do", json, "{}"), "rst(ahsay_update_receivers)", web);
  stream(f, "5 kB of path parameter before it", ["POST /rps;", ...Array(4).fill("a".repeat(1250)), "/api/json/UpdateReceivers.do HTTP/1.1\r\nHost: x\r\n\r\n"], "rst(ahsay_update_receivers)", web);

  run(f, "the console's logon page", get("/cbs/system/ShowLogon.do"), "pass", web);
  run(f, "a backup client's API call", post("/obs/api/json/GetUser.do", json, `{"SysUser":"system","LoginName":"jo"}`), "pass", web);
  run(f, "another replication endpoint", post("/rps/api/json/ListReceivers.do", json, "{}"), "pass", web);
  run(f, "a path that only starts like it", get("/rps/api/json/UpdateReceiver.do"), "pass", web);
  run(f, "another port", post("/rps/api/json/UpdateReceivers.do", json, "{}"), "pass", { dport: 8080 });
  run(f, "port knob", post("/rps/api/json/UpdateReceivers.do", json, "{}"), "rst(ahsay_update_receivers)", { dport: 8080, knobs: { port: 8080 } });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "POST /rps/api/json/UpdateReceivers.do", curl: ["-H", "Content-Type: application/json", "-d", "{}", `${url}/rps/api/json/UpdateReceivers.do`], want: "cut" },
  { name: "the same path, spelled another way", curl: ["-d", "{}", `${url}/rps;a=b//api/json/%55pdateReceiver%73.do`], want: "cut" },
  { name: "the console's logon page", curl: [`${url}/cbs/system/ShowLogon.do`], want: "served" },
];
