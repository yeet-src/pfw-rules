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
  const chat = (text) => post("/v1/chat/completions", "Content-Type: application/json\r\n", JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: text }] }));
  run(f, "a prompt in lower-case prose", chat("how do I post /guardrails/test_custom_code to my proxy?"), "pass", web);
  run(f, "a prompt quoting the advisory", chat("The advisory says: block POST /guardrails/test_custom_code at your reverse proxy or API gateway."), "pass", web);
  run(f, "a prompt that pastes a whole request, line ends and all", chat("POST /guardrails/test_custom_code HTTP/1.1\r\nHost: litellm\r\n\r\n{}"), "pass", web);
  run(f, "the same text in a plain-text body, one line", post("/v1/completions", "Content-Type: text/plain\r\n", "Why does POST /guardrails/test_custom_code HTTP/1.1 return 403?"), "pass", web);
  run(f, "a query padded to push the end of the line away", `POST /guardrails/test_custom_code?x=${"a".repeat(300)}`, "rst(litellm_guardrail_test)", web);
  /* uvicorn (httptools) strips a #fragment before routing, so these reach the handler too. */
  run(f, "a fragment after the path", "POST /guardrails/test_custom_code#x HTTP/1.1\r\nHost: x\r\n\r\n", "rst(litellm_guardrail_test)", web);
  run(f, "a fragment then a query", "POST /guardrails/test_custom_code#x?a=1 HTTP/1.1\r\nHost: x\r\n\r\n", "rst(litellm_guardrail_test)", web);
  run(f, "a fragment padded to push the end of the line away", `POST /guardrails/test_custom_code#${"a".repeat(300)}`, "rst(litellm_guardrail_test)", web);
  run(f, "lower-case post, which the route refuses", "post /guardrails/test_custom_code HTTP/1.1\r\nHost: x\r\n\r\n", "pass", web);
  run(f, "another case of the path, which the route answers 404", post("/Guardrails/Test_Custom_Code", "", "{}"), "pass", web);
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
  { name: "a chat completion that quotes the advisory", curl: ["-H", "Content-Type: application/json", "-d", '{"messages":[{"role":"user","content":"The advisory says: block POST /guardrails/test_custom_code at your proxy. And: post /guardrails/test_custom_code"}]}', `${url}/v1/chat/completions`], want: "served" },
];
