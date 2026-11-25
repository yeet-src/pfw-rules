/* Checked against Next.js 16.0.6 with React 19.2.0. Every body reset here
 * carries a reference walk that the server's Flight decoder performed (a
 * "$1:a:a" in the same spelling hung the request; "$1:x:name" came back),
 * or a Transfer-Encoding Node accepted. No exploit was run: the gadgets
 * below are the public chain's shape with its command left out. */
export const port = 3000;

const ACTION = "400ca6c0cabefaa7ed1ab22d6be71d7c13ca370938";
const BD = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";
const u16 = (s) => Buffer.from(s, "utf16le").toString("latin1");
const parts = (fields) => fields.map(([name, value, type]) => `--${BD}\r\nContent-Disposition: form-data; name="${name}"\r\n${type ? `Content-Type: ${type}\r\n` : ""}\r\n${value}\r\n`).join("") + `--${BD}--\r\n`;

export default function ({ f, run, stream, req, get }) {
  const web = { dport: port };
  const action = (body, lines = `Next-Action: ${ACTION}\r\n`, type = `multipart/form-data; boundary=${BD}`) =>
    req("POST", "/", `${lines}Content-Type: ${type}\r\nContent-Length: ${body.length}\r\n`, body);
  const two = (zero, one = "{}") => action(parts([["0", zero], ["1", one]]));

  const chain = '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"","_formData":{"get":"$1:constructor:constructor"}}}';
  run(f, "the public chain's shape", action(parts([["0", chain], ["1", '"$@0"']]), "Next-Action: x\r\n"), "rst(react2shell_gadget)", web);
  for (const [how, zero] of [
    ["$1:constructor:constructor", '["$1:constructor:constructor"]'],
    ["$1:__proto__:then", '["$1:__proto__:then"]'],
    ["constructor at the end of the reference", '["$1:then:constructor"]'],
    ["__proto__ at the end of the reference", '["$1:__proto__"]'],
    ["one level down, closed by \\\"", '{"value":"{\\"x\\":\\"$1:constructor\\"}"}'],
  ]) run(f, `a reference to ${how}`, two(zero), "rst(react2shell_gadget)", web);
  run(f, "without Next-Action, in a $ACTION_REF_ form", action(parts([["$ACTION_REF_1", ""], ["$ACTION_1:0", `{"id":"${ACTION}","bound":"$@1"}`], ["$ACTION_1:1", '["$2:constructor:constructor"]'], ["$ACTION_1:2", "{}"]]), ""), "rst(react2shell_gadget)", web);
  run(f, "a text/plain body", action('[{}, "$0:0:constructor:constructor"]', `Next-Action: ${ACTION}\r\n`, "text/plain;charset=UTF-8"), "rst(react2shell_gadget)", web);
  run(f, "a body with no Content-Type", req("POST", "/any/route", `Next-Action: x\r\nContent-Length: 30\r\n`, '["$1:constructor:constructor"]'), "rst(react2shell_gadget)", web);
  run(f, "in a UTF-16LE part", two(u16('["$1:constructor:constructor"]'), "{}").replace('name="0"\r\n', 'name="0"\r\nContent-Type: text/plain; charset=utf-16le\r\n'), "rst(react2shell_gadget)", web);
  run(f, "__proto__ in a UCS-2 part", action(parts([["0", u16('["$1:__proto__:then"]'), 'text/plain; charset="UCS-2"'], ["1", "{}"]])), "rst(react2shell_gadget)", web);
  run(f, "on a second request on the connection", get("/") + two('["$1:constructor:constructor"]'), "rst(react2shell_gadget)", web);
  stream(f, "after 6 kB of padding, five segments on", [`POST / HTTP/1.1\r\nHost: x\r\nNext-Action: x\r\nContent-Type: multipart/form-data; boundary=${BD}\r\n\r\n--${BD}\r\nContent-Disposition: form-data; name="p"\r\n\r\n`, ...Array(5).fill("a".repeat(1200)), `\r\n` + parts([["0", '["$1:constructor:constructor"]'], ["1", "{}"]])], "rst(react2shell_gadget)", web);
  stream(f, "the reference cut off, then the request again", [two('["$1:constr'), two('["$1:constructor:constructor"]')], "rst(react2shell_gadget)", web);

  for (const [how, zero] of [
    ["c as \\u0063", '["$1:\\u0063onstructor:\\u0063onstructor"]'],
    ["_ as \\u005F", '["$1:\\u005F_proto__:then"]'],
    ["the colon as \\u003a", '["$1\\u003aconstructor\\u003aconstructor"]'],
    ["the quote as \\u0022", '["$1:a:b\\u0022]'],
    ["a backslash as \\u005c, two levels down", '{"value":"[\\"$1:\\u005cu0063onstructor\\"]"}'],
    ["u as \\u0075, two levels down", '{"value":"[\\"$1:\\\\\\u00750063onstructor\\"]"}'],
    ["a hex digit as \\u0036", '{"value":"[\\"$1:\\\\u00\\u00363onstructor\\"]"}'],
  ]) run(f, `an escape: ${how}`, two(zero), "rst(react2shell_escape)", web);
  run(f, "an escape in a UTF-16LE part", action(parts([["0", u16('["$1:\\u0063onstructor:\\u0063onstructor"]'), "text/plain;charset=utf16le"], ["1", "{}"]])), "rst(react2shell_escape)", web);

  const body = parts([["0", '["$1:a"]'], ["1", "{}"]]);
  const chunk = (b) => b.match(/[^]{1,7}/g).map((c) => `${c.length.toString(16)}\r\n${c}\r\n`).join("") + "0\r\n\r\n";
  for (const [how, line] of [["chunked", "Transfer-Encoding: chunked"], ["the header in lower case", "transfer-encoding: CHUNKED"], ["no space", "Transfer-Encoding:chunked"],
    ["a tab", "Transfer-Encoding:\tchunked"], ["after gzip", "Transfer-Encoding: gzip, chunked"]])
    run(f, `Transfer-Encoding, ${how}`, req("POST", "/", `Next-Action: x\r\nContent-Type: multipart/form-data; boundary=${BD}\r\n${line}\r\n`, chunk(body)), "rst(react2shell_chunked)", web);

  /* What Next's own client sends, and other traffic to the app. */
  run(f, "a server action as the client sends it", action('["hello",{"n":1,"s":"$$1"}]', `Next-Action: ${ACTION}\r\nNext-Router-State-Tree: %5B%22%22%5D\r\nAccept: text/x-component\r\n`, "text/plain;charset=UTF-8"), "pass", web);
  run(f, "a form action as the client sends it", action(parts([[`1_$ACTION_ID_${ACTION}`, ""], ["1_q", "hello"], ["0", '["$K1"]']])), "pass", web);
  run(f, "React's own encoding of an object with a constructor key, a date, a BigInt, a Map and a form", two('["He said \\"hi\\" <b>&</b> \\u0001",{"constructor":1,"__proto__x":2,"nested":{"s":"$$1:a"}},"$D1970-01-01T00:00:00.000Z","$n10","$Q1","$K2"]', '[["k","v"]]'), "pass", web);
  run(f, "references that stay on own properties", two('["$1","$@1","$Q1","$1:items:0:name","$K1"]', '{"items":[{"name":"x"}]}'), "pass", web);
  run(f, "JSON with < > & escaped for HTML", req("POST", "/api/notes", "Content-Type: application/json\r\nContent-Length: 72\r\n", '{"html":"\\u003cb\\u003ebold\\u003c/b\\u003e \\u0026 more","name":"Jos\\u00e9"}'), "pass", web);
  run(f, "escapes of control characters and an emoji", req("POST", "/api/log", "Content-Type: application/json\r\nContent-Length: 40\r\n", '{"m":"a\\u001fb\\u0000c","e":"\\ud83d\\ude00"}'), "pass", web);
  run(f, "prose and code that name constructor", two('["The constructor runs first. Foo.prototype.constructor === Foo; {constructor: x}; a: constructor; obj.__proto__"]'), "pass", web);
  run(f, "a UTF-16LE part without either", action(parts([["0", u16('["$1:name"]'), "text/plain; charset=utf-16le"], ["1", "{}"]])), "pass", web);
  run(f, "a body that names the header mid-line", req("POST", "/api/notes", "Content-Type: text/plain\r\nContent-Length: 44\r\n", "Uploads use a Transfer-Encoding: chunked body"), "pass", web);
  run(f, "a page", get("/dashboard", "Accept: text/html\r\n"), "pass", web);
  run(f, "a client navigation", get("/dashboard?_rsc=1x2y3", "RSC: 1\r\nNext-Router-State-Tree: %5B%22%22%5D\r\n"), "pass", web);
  run(f, "another port", two('["$1:constructor:constructor"]'), "pass", { dport: 8080 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
const form = (zero) => ["-H", "Next-Action: x", "-F", `0=${zero}`, "-F", "1={}"];
export const e2e = ({ url }) => [
  { name: "a reference to $1:constructor:constructor", curl: [...form('["$1:constructor:constructor"]'), `${url}/`], want: "cut" },
  { name: "the same with c as \\u0063", curl: [...form('["$1:\\u0063onstructor:\\u0063onstructor"]'), `${url}/`], want: "cut" },
  { name: "a chunked body", curl: ["-H", "Transfer-Encoding: chunked", ...form('["$1"]'), `${url}/`], want: "cut" },
  { name: "a server action as the client sends it", curl: ["-H", "Next-Action: x", "-H", "Content-Type: text/plain;charset=UTF-8", "--data-binary", '["hello",{"s":"$$1"}]', `${url}/`], want: "served" },
  { name: "a page", curl: [`${url}/`], want: "served" },
];
