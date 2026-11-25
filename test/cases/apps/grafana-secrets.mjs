/* Checked against Grafana 13.3.1 (Go 1.27 net/http). A cookie spelling reset
 * here is one Go read a named cookie from (our own grafana_session, through the
 * same Request.Cookie the login page uses for login_error); one passed is one
 * it did not. A route reset here reached the receiver test handler (400 for an
 * empty body, before any secret is touched); one passed got a 404. */
export const port = 3000;

export default function ({ f, run, stream, get, post }) {
  const web = { dport: port };
  const ct = "0123456789abcdef0123456789abcdef0123456789abcdef";
  const login = (lines) => get("/login", lines);

  for (const [how, lines] of [
    ["as written", `Cookie: login_error=${ct}\r\n`],
    ["no space after the colon", `Cookie:login_error=${ct}\r\n`],
    ["a tab after the colon", `Cookie:\tlogin_error=${ct}\r\n`],
    ["the header in lower case", `cookie: login_error=${ct}\r\n`],
    ["the header in upper case", `COOKIE: login_error=${ct}\r\n`],
    ["after another cookie", `Cookie: grafana_session=abc; login_error=${ct}\r\n`],
    ["after a bare semicolon", `Cookie: a=1;login_error=${ct}\r\n`],
    ["after a semicolon and a tab", `Cookie: a=1;\tlogin_error=${ct}\r\n`],
    ["after ' ; '", `Cookie: a=1 ; login_error=${ct}\r\n`],
    ["after ';;'", `Cookie: a=1;;login_error=${ct}\r\n`],
    ["in a second Cookie header", `Cookie: a=1\r\nCookie: login_error=${ct}\r\n`],
    ["folded onto the next line", `Cookie:\r\n login_error=${ct}\r\n`],
    ["a space before the '='", `Cookie: login_error =${ct}\r\n`],
    ["a tab before the '='", `Cookie: login_error\t=${ct}\r\n`],
    ["three spaces before the '='", `Cookie: login_error   =${ct}\r\n`],
    ["a quoted value", `Cookie: login_error="${ct}"\r\n`],
  ]) run(f, `login_error, ${how}`, login(lines), "rst(grafana_login_error)", web);
  run(f, "login_error, with bare line feeds", `GET /login HTTP/1.1\nHost: x\nCookie: login_error=${ct}\n\n`, "rst(grafana_login_error)", web);
  run(f, "login_error on another route", get("/api/user", `Cookie: login_error=${ct}\r\n`), "rst(grafana_login_error)", web);
  stream(f, "login_error after 6 kB of other headers, five segments on", ["GET /login HTTP/1.1\r\nHost: x\r\nX-Pad: ", ...Array(5).fill("a".repeat(1200)), `\r\nCookie: login_error=${ct}\r\n\r\n`], "rst(grafana_login_error)", web);
  stream(f, "login_error after 3 kB of other cookies, in segments", ["GET /login HTTP/1.1\r\nHost: x\r\nCookie: ", ...Array(3).fill("c=x; ".repeat(200)), `d=1; login_error=${ct}\r\n\r\n`], "rst(grafana_login_error)", web);
  stream(f, "the cookie name cut off, then the request again", ["GET /login HTTP/1.1\r\nHost: x\r\nCookie: a=1; login_er", `GET /login HTTP/1.1\r\nHost: x\r\nCookie: a=1; login_error=${ct}\r\n\r\n`], "rst(grafana_login_error)", web);

  run(f, "the login page", login(""), "pass", web);
  run(f, "a logged-in page", get("/d/abc/my-dashboard", "Cookie: grafana_session=0123abcd; grafana_session_expiry=1795565917\r\n"), "pass", web);
  run(f, "a cookie whose name ends in login_error", login("Cookie: my_login_error=1\r\n"), "pass", web);
  run(f, "LOGIN_ERROR, which Go does not read as login_error", login(`Cookie: LOGIN_ERROR=${ct}\r\n`), "pass", web);
  run(f, "after a comma, which Go does not split on", login(`Cookie: a=1,login_error=${ct}\r\n`), "pass", web);
  run(f, "a percent-encoded name, which Go does not decode", login(`Cookie: %6Cogin_error=${ct}\r\n`), "pass", web);
  run(f, "a dashboard that names the cookie in a panel", post("/api/dashboards/db", "Content-Type: application/json\r\n", `{"dashboard":{"title":"auth","panels":[{"type":"text","options":{"content":"OAuth failures set \\"login_error=...\\""}}]}}`), "pass", web);
  run(f, "login_error on another port", login(`Cookie: login_error=${ct}\r\n`), "pass", { dport: 80 });

  const uid = "ZW1wdHk";
  const base = (v = "v1beta1") => `/apis/notifications.alerting.grafana.app/${v}/namespaces/default/receivers`;
  const test = (target, v) => post(target ?? `${base(v)}/${uid}/test`, "Content-Type: application/json\r\n", "{}");
  const enc = (s) => [...s].map((c) => "%" + c.charCodeAt(0).toString(16).toUpperCase()).join("");
  for (const [how, target] of [
    ["as the UI sends it", `${base()}/${uid}/test`],
    ["on v0alpha1", `${base("v0alpha1")}/${uid}/test`],
    ["with a query string", `${base()}/${uid}/test?dryRun=All`],
    ["%74est", `${base()}/${uid}/%74est`],
    ["every letter of test encoded", `${base()}/${uid}/${enc("test")}`],
    ["the uid percent-encoded", `${base()}/${enc(uid)}/test`],
    ["a dot of the group as %2E", base().replace("notifications.alerting", "notifications%2Ealerting") + `/${uid}/test`],
    ["%2F for the slash before test", `${base()}/${uid}%2Ftest`],
    ["%2f in lower case", `${base()}/${uid}%2ftest`],
    ["receivers encoded", base().replace("receivers", enc("receivers")) + `/${uid}/test`],
    ["an absolute-form target", `http://grafana.example.test:3000${base()}/${uid}/test`],
    ["a one-character uid", `${base()}/a/test`],
  ]) run(f, `testing a saved contact point, ${how}`, test(target), "rst(grafana_receiver_test)", web);
  run(f, "testing a saved contact point over HTTP/1.0", `POST ${base()}/${uid}/test HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}`, "rst(grafana_receiver_test)", web);
  stream(f, "the route cut off, then the request again", [`POST ${base()}/${uid}/te`, test()], "rst(grafana_receiver_test)", web);
  run(f, "block_test=0 counts and lets it through", test(), "pass", { ...web, knobs: { block_test: 0 } });
  run(f, "block_test=0 still resets login_error", login(`Cookie: login_error=${ct}\r\n`), "rst(grafana_login_error)", { ...web, knobs: { block_test: 0 } });

  run(f, "testing a new contact point, '-'", test(`${base()}/-/test`), "pass", web);
  run(f, "testing a new contact point, '%2D'", test(`${base()}/%2D/test`), "pass", web);
  run(f, "listing contact points", get(base()), "pass", web);
  run(f, "reading one contact point", get(`${base()}/${uid}`), "pass", web);
  run(f, "saving a contact point", req("PUT", `${base()}/${uid}`, "Content-Type: application/json\r\n", `{"spec":{"title":"test"}}`), "pass", web);
  run(f, "a trailing slash, which Grafana does not route", test(`${base()}/${uid}/test/`), "pass", web);
  run(f, "TEST in upper case, which Grafana does not route", test(`${base()}/${uid}/TEST`), "pass", web);
  run(f, "a #fragment, which Go keeps in the path and Grafana does not route", test(`${base()}/${uid}/test#x`), "pass", web);
  run(f, "the legacy receivers test, another code path", test("/api/alertmanager/grafana/config/api/v1/receivers/test"), "pass", web);
  run(f, "the contact points page", get("/alerting/notifications"), "pass", web);
  run(f, "another port", test(), "pass", { dport: 80 });

  function req(method, target, headers = "", body = "") { return `${method} ${target} HTTP/1.1\r\nHost: example.test\r\nUser-Agent: Mozilla/5.0\r\n${headers}\r\n${body}`; }
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "the login page with a login_error cookie", curl: ["-b", "login_error=0123456789abcdef", `${url}/login`], want: "cut" },
  { name: "login_error with a space before the '='", curl: ["-H", "Cookie: a=1; login_error =0123456789abcdef", `${url}/login`], want: "cut" },
  { name: "testing a saved contact point", curl: ["-H", "Content-Type: application/json", "-d", "{}", `${url}/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/receivers/ZW1wdHk/test`], want: "cut" },
  { name: "the same, with %2F before test", curl: ["-H", "Content-Type: application/json", "-d", "{}", `${url}/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/receivers/ZW1wdHk%2Ftest`], want: "cut" },
  { name: "the login page", curl: [`${url}/login`], want: "served" },
  { name: "testing a new contact point", curl: ["-H", "Content-Type: application/json", "-d", "{}", `${url}/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/receivers/-/test`], want: "served" },
  { name: "block_test=0: testing a saved contact point", knobs: { block_test: 0 }, curl: ["-H", "Content-Type: application/json", "-d", "{}", `${url}/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/receivers/ZW1wdHk/test`], want: "served" },
];
