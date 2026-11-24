export const port = 80;

export default function ({ f, run, req, get }) {
  const web = { dport: port };
  const as = (ua) => req("GET", "/", "").replace("Mozilla/5.0", ua);
  for (const ua of ["Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", "ClaudeBot/1.0", "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)", "gptbot"])
    run(f, `User-Agent ${ua.slice(0, 40)}`, as(ua), "rst(crawler)", web);
  run(f, "a browser", get("/"), "pass", web);
  run(f, "curl", as("curl/8.7.1"), "pass", web);
  run(f, "another port", as("GPTBot/1.2"), "pass", { dport: 8080 });
  run(f, "port knob", as("GPTBot/1.2"), "rst(crawler)", { dport: 8080, knobs: { port: 8080 } });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "curl -A GPTBot", curl: ["-A", "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)", `${url}/`], want: "cut" },
  { name: "curl -A ClaudeBot", curl: ["-A", "ClaudeBot/1.0", `${url}/`], want: "cut" },
  { name: "a browser", curl: ["-A", "Mozilla/5.0 (X11; Linux x86_64) Firefox/133.0", `${url}/`], want: "served" },
];
