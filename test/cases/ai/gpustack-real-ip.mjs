/* Every spelling reset here is one uvicorn handed to the application as
 * X-GPUStack-Real-IP; the ones passed are ones it did not. */
export const port = 80;

export default function ({ f, run, stream, get, post }) {
  const web = { dport: port };
  const api = (lines) => get("/v2/users", lines);
  for (const [how, line] of [["as written", "X-GPUStack-Real-IP: 127.0.0.1\r\n"], ["lower case", "x-gpustack-real-ip: 127.0.0.1\r\n"], ["upper case", "X-GPUSTACK-REAL-IP: 127.0.0.1\r\n"], ["no space after the colon", "X-GPUStack-Real-IP:127.0.0.1\r\n"],
    ["a tab after the colon", "X-GPUStack-Real-IP:\t127.0.0.1\r\n"], ["value folded onto the next line", "X-GPUStack-Real-IP:\r\n 127.0.0.1\r\n"], ["given twice", "X-GPUStack-Real-IP: 203.0.113.9\r\nX-GPUStack-Real-IP: 127.0.0.1\r\n"],
    ["an IPv6 loopback", "X-GPUStack-Real-IP: ::1\r\n"]])
    run(f, `the header, ${how}`, api(line), "rst(gpustack_real_ip)", web);
  stream(f, "the header after 6 kB of others, five segments on", ["GET /v2/users HTTP/1.1\r\nHost: x\r\nX-Pad: ", ...Array(5).fill("a".repeat(1200)), "\r\nX-GPUStack-Real-IP: 127.0.0.1\r\n\r\n"], "rst(gpustack_real_ip)", web);
  run(f, "after a bare line feed", "GET /v2/users HTTP/1.1\r\nHost: x\nX-GPUStack-Real-IP: 127.0.0.1\n\r\n", "rst(gpustack_real_ip)", web);
  run(f, "on the code-execution route", post("/v2/inference-backends/from-yaml", "Content-Type: application/json\r\nX-GPUStack-Real-IP: 127.0.0.1\r\n", "{}"), "rst(gpustack_real_ip)", web);
  stream(f, "the header split across segments", ["GET /v2/users HTTP/1.1\r\nHost: x\r\nX-GPUStack-Re", "GET /v2/users HTTP/1.1\r\nHost: x\r\nX-GPUStack-Real-IP: 127.0.0.1\r\n\r\n"], "rst(gpustack_real_ip)", web);

  run(f, "a request with no such header", api("Authorization: Bearer gpustack_abc\r\n"), "pass", web);
  run(f, "the usual proxy headers", api("X-Real-IP: 203.0.113.9\r\nX-Forwarded-For: 203.0.113.9\r\n"), "pass", web);
  run(f, "underscores, which uvicorn does not take for the header", api("X_GPUStack_Real_IP: 127.0.0.1\r\n"), "pass", web);
  run(f, "a chat prompt that names the header", post("/v1/chat/completions", "Content-Type: application/json\r\n", `{"messages":[{"role":"user","content":"what does the X-GPUStack-Real-IP: header do?"}]}`), "pass", web);
  run(f, "the code-execution route with no header, which GPUStack then authenticates", post("/v2/inference-backends/from-yaml", "Content-Type: application/json\r\nAuthorization: Bearer gpustack_abc\r\n", "{}"), "pass", web);
  run(f, "another port", api("X-GPUStack-Real-IP: 127.0.0.1\r\n"), "pass", { dport: 8080 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "a request with X-GPUStack-Real-IP: 127.0.0.1", curl: ["-H", "X-GPUStack-Real-IP: 127.0.0.1", `${url}/v2/users`], want: "cut" },
  { name: "the same header in lower case on the code-execution route", curl: ["-H", "x-gpustack-real-ip: ::1", "-H", "Content-Type: application/json", "-d", "{}", `${url}/v2/inference-backends/from-yaml`], want: "cut" },
  { name: "an ordinary API call", curl: ["-H", "Authorization: Bearer gpustack_abc", "-H", "X-Forwarded-For: 203.0.113.9", `${url}/v2/users`], want: "served" },
];
