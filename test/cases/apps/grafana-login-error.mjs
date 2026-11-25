/* The spellings are ones Grafana 13.3.1 read: handed a `login_error` cookie
 * it had set itself after a failed OAuth login, it decrypted it and showed
 * the message on the login page (test/real/grafana.mjs). The value below is
 * the shape of such a cookie, not a secret from anywhere. */
export const port = 3000;

export default function ({ f, run, stream, get, post }) {
  const web = { dport: port };
  const V = "23596d6331596d5a776347686d5a476b305a324d232a5957567a4c574e6d59672a3864644651654a790550c2ab568aa06cde3b44747c70994cb1e0b887409b1e76c35cd4d9e2aaec3519";
  /* each of these Grafana read */
  for (const [label, h] of [["Cookie: login_error=V", `Cookie: login_error=${V}\r\n`], ["a lower-case header name", `cookie: login_error=${V}\r\n`], ["an upper-case header name", `COOKIE: login_error=${V}\r\n`],
    ["no space after the colon", `Cookie:login_error=${V}\r\n`], ["a tab after the colon", `Cookie:\tlogin_error=${V}\r\n`], ["after another cookie", `Cookie: grafana_session=abc; login_error=${V}\r\n`],
    ["before another cookie", `Cookie: login_error=${V}; grafana_session=abc\r\n`], ["no space after the semicolon", `Cookie: a=b;login_error=${V}\r\n`], ["spaces before the name", `Cookie: a=b;   login_error=${V}\r\n`],
    ["a space before the =", `Cookie: login_error =${V}\r\n`], ["the value in double quotes", `Cookie: login_error="${V}"\r\n`], ["the value in upper-case hex", `Cookie: login_error=${V.toUpperCase()}\r\n`],
    ["the second of two Cookie headers", `Cookie: a=b\r\nCookie: login_error=${V}\r\n`], ["twice", `Cookie: login_error=${V}; login_error=00\r\n`]])
    run(f, label, get("/login", h), "rst(grafana_login_error)", web);
  run(f, "on any path, since the cookie is sent with every request", get("/api/health", `Cookie: login_error=${V}\r\n`), "rst(grafana_login_error)", web);
  run(f, "a cookie in the format the fix writes", get("/login", "Cookie: login_error=bf1cacc4c0dc0bc87d84543e10dad9477cc33e7f1fe4d5c58e671cc5680ca3b56f617574682e6c6f67696e2e6572726f72\r\n"), "rst(grafana_login_error)", web);
  run(f, "second request on a keep-alive connection", get("/login") + get("/login", `Cookie: login_error=${V}\r\n`), "rst(grafana_login_error)", web);
  stream(f, "after 5 kB of other cookies in earlier segments", ["GET /login HTTP/1.1\r\nHost: x\r\nCookie: a=", ...Array(4).fill("b".repeat(1250)), `; login_error=${V}\r\n\r\n`], "rst(grafana_login_error)", web);

  run(f, "the login page", get("/login"), "pass", web);
  run(f, "a session", get("/d/abc/overview?orgId=1", "Cookie: grafana_session=0123456789abcdef; grafana_session_expiry=1795000000\r\n"), "pass", web);
  run(f, "a login", post("/login", "Content-Type: application/json\r\n", `{"user":"admin","password":"hunter2"}`), "pass", web);
  run(f, "the start of an OAuth login", get("/login/generic_oauth", "Cookie: oauth_state=abc; redirect_to=%2Fd%2Fabc\r\n"), "pass", web);
  run(f, "a cookie whose name only ends the same way", get("/", "Cookie: my_login_error=1; oauth_login_error=ab\r\n"), "pass", web);
  run(f, "the cookie cleared, as a browser would never send it", get("/login", "Cookie: login_error=\r\n"), "pass", web);
  run(f, "a query that names it", get("/explore?left=%7B%22expr%22:%22login_error%3D1%22%7D&q=login_error=1"), "pass", web);
  run(f, "a dashboard that mentions it", post("/api/dashboards/db", "Content-Type: application/json\r\n", `{"dashboard":{"title":"auth","panels":[{"expr":"sum(rate(login_error_total[5m]))","legend":"login_error={{code}}"}]}}`), "pass", web);
  run(f, "another port", get("/login", `Cookie: login_error=${V}\r\n`), "pass", { dport: 80 });
  run(f, "port knob", get("/login", `Cookie: login_error=${V}\r\n`), "rst(grafana_login_error)", { dport: 80, knobs: { port: 80 } });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "the login page with a login_error cookie", curl: ["-b", "login_error=23596d6331596d5a776347686d5a476b305a324d232a59", `${url}/login`], want: "cut" },
  { name: "the same among other cookies, quoted", curl: ["-H", `Cookie: grafana_session=abc;login_error ="23596D6331596D5A"`, `${url}/api/health`], want: "cut" },
  { name: "the login page with a session cookie", curl: ["-b", "grafana_session=0123456789abcdef", `${url}/login`], want: "served" },
];
