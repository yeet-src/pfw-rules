/* Every spelling reset here is one Apache 2.4 with mod_php ran proxy.php for. */
export const port = 80;

export default function ({ f, run, stream, get, post }) {
  const web = { dport: port };
  for (const t of ["/apps/richdocumentscode/proxy.php", "/apps/richdocumentscode/proxy.php?status", "/apps/richdocumentscode/proxy.php?req=/hosting/capabilities", "/apps/richdocumentscode/proxy.php/x",
    "/apps/richdocumentscod%65/prox%79.php?req=x", "/apps/richdocumentscode//proxy.php", "/apps/richdocumentscode/./proxy.php", "/custom_apps/richdocumentscode/proxy.php", "/apps/richdocumentscode_arm64/proxy.php",
    "/nextcloud/apps/richdocumentscode/proxy%2ephp"])
    run(f, `GET ${t}`, get(t), "rst(nextcloud_code_proxy)", web);
  run(f, "POST to it", post("/apps/richdocumentscode/proxy.php?req=/cool/convert-to", "Content-Type: application/octet-stream\r\n", "x"), "rst(nextcloud_code_proxy)", web);
  stream(f, "the request line split across segments", ["GET /apps/richdocumentsc", "GET /apps/richdocumentscode/proxy.php?status HTTP/1.1\r\nHost: x\r\n\r\n"], "rst(nextcloud_code_proxy)", web);

  run(f, "the files app", get("/apps/files/"), "pass", web);
  run(f, "WebDAV", get("/remote.php/dav/files/jo/Documents/"), "pass", web);
  run(f, "the app's own page, not its proxy", get("/apps/richdocuments/index"), "pass", web);
  run(f, "the app's static files", get("/apps/richdocumentscode/img/app.svg"), "pass", web);
  run(f, "another app's proxy.php", get("/apps/other/proxy.php"), "pass", web);
  run(f, "the path named only in a query", get("/settings/apps?search=richdocumentscode/proxy.php"), "pass", web);
  run(f, "another port", get("/apps/richdocumentscode/proxy.php"), "pass", { dport: 8080 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "the built-in server's proxy.php", curl: [`${url}/apps/richdocumentscode/proxy.php?status`], want: "cut" },
  { name: "the same, percent-encoded", curl: [`${url}/apps/richdocumentscod%65/prox%79.php?req=x`], want: "cut" },
  { name: "the files app", curl: [`${url}/apps/files/`], want: "served" },
];
