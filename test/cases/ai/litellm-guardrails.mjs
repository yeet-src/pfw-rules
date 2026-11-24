/* Paths are ones FastAPI 0.165 on uvicorn 0.54, the stack LiteLLM runs on,
 * routed to the handler. */
export const port = 4000;

export default function ({ f, run, stream, ok, progs, bytes, show, root, readFileSync, req, get, post, part, multipart, B, tomcatSpellings }) {
  const web = { dport: port };
  const body = `{"custom_code":"def apply_guardrail(inputs, request_data, input_type):\\n    return inputs","test_input":{}}`;
  /* each of these reached the handler */
  for (const p of ["/guardrails/test_custom_code", "/guardrails/test_custom_cod%65", "/guardrails%2ftest_custom_code", "/guardrails/test%5fcustom%5Fcode", "/%67uardrails/test_custom_code", "/guardrails/test_custom_code?x=1", "/litellm/guardrails/test_custom_code"])
    run(f, `POST ${p}`, post(p, "Content-Type: application/json\r\nAuthorization: Bearer sk-1234\r\n", body), "rst(litellm_guardrail_test)", web);
  run(f, "second request on a keep-alive connection", get("/health/liveliness") + post("/guardrails/test_custom_code", "", body), "rst(litellm_guardrail_test)", web);
  run(f, "a chat completion", post("/v1/chat/completions", "Content-Type: application/json\r\n", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`), "pass", web);
  run(f, "a prompt that quotes the path", post("/v1/chat/completions", "Content-Type: application/json\r\n", `{"messages":[{"role":"user","content":"what does /guardrails/test_custom_code do in LiteLLM?"}]}`), "pass", web);
  run(f, "listing guardrails", get("/guardrails/list"), "pass", web);
  run(f, "applying a guardrail", post("/guardrails/apply_guardrail", "Content-Type: application/json\r\n", "{}"), "pass", web);
  run(f, "GET on the path, which the route refuses", get("/guardrails/test_custom_code"), "pass", web);
  run(f, "another port", post("/guardrails/test_custom_code", "", body), "pass", { dport: 80 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "POST /guardrails/test_custom_code", curl: ["-H", "Content-Type: application/json", "-d", "{}", `${url}/guardrails/test_custom_code`], want: "cut" },
  { name: "the same path, percent-encoded", curl: ["-d", "{}", `${url}/guardrails%2ftest%5fcustom_cod%65`], want: "cut" },
  { name: "a chat completion that mentions the path", curl: ["-H", "Content-Type: application/json", "-d", '{"messages":[{"role":"user","content":"what is /guardrails/test_custom_code?"}]}', `${url}/v1/chat/completions`], want: "served" },
];
