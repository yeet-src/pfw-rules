/* The path spellings are ones Tomcat 9.0, which Confluence runs on, served the
 * same resource for (see tomcatSpellings in the harness). */
export const port = 8090;

export default function ({ f, run, stream, ok, progs, bytes, show, root, readFileSync, req, get, post, part, multipart, B, tomcatSpellings }) {
  const web = { dport: port };
  const env = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body/></soapenv:Envelope>`;
  run(f, "the path seen exploited", post("/plugins/servlet/soap-axis1/confluenceservice-v2", `Content-Type: text/xml\r\nSOAPAction: ""\r\n`, env), "rst(axis1_soap)", web);
  for (const t of tomcatSpellings("soap-axis1", "confluenceservice-v2")) run(f, `POST /rpc${t.startsWith("http") ? " " + t : t}`, post(t.startsWith("http") ? t : "/rpc" + t, "Content-Type: text/xml\r\n", env), "rst(axis1_soap)", web);
  run(f, "soap-axis%31", get("/rpc/soap-axis%31/confluenceservice-v2?wsdl"), "rst(axis1_soap)", web);
  for (const t of tomcatSpellings("rpc", "xmlrpc")) run(f, `POST ${t}`, post(t, "Content-Type: text/xml\r\n", "<methodCall/>"), "rst(axis1_xmlrpc)", web);
  run(f, "xmlrpc=1 lets XML-RPC through", post("/rpc/xmlrpc", "Content-Type: text/xml\r\n", "<methodCall/>"), "pass", { ...web, knobs: { xmlrpc: 1 } });
  run(f, "xmlrpc=1 still resets SOAP", post("/rpc/soap-axis1/confluenceservice-v2", "", env), "rst(axis1_soap)", { ...web, knobs: { xmlrpc: 1 } });
  run(f, "dashboard", get("/dashboard.action"), "pass", web);
  run(f, "a page", get("/display/ENG/Runbook"), "pass", web);
  run(f, "REST API", get("/rest/api/content?spaceKey=ENG"), "pass", web);
  run(f, "another plugin servlet", get("/plugins/servlet/upm"), "pass", web);
  run(f, "a page whose title has rpc in it", get("/display/ENG/gRPC+and+JSON-RPC+notes"), "pass", web);
  run(f, "another port", post("/rpc/soap-axis1/confluenceservice-v2", "", env), "pass", { dport: 80 });
}
