/* What apps/grafana-login-error.pfc assumes about Grafana, asked of Grafana
 * itself: 13.3.1, the last release before the fix.
 *
 *   docker run -d -p 3000:3000 -e GF_AUTH_GENERIC_OAUTH_ENABLED=true \
 *     -e GF_AUTH_GENERIC_OAUTH_CLIENT_ID=x -e GF_AUTH_GENERIC_OAUTH_AUTH_URL=http://127.0.0.1:9/auth \
 *     -e GF_AUTH_GENERIC_OAUTH_TOKEN_URL=http://127.0.0.1:9/token grafana/grafana:13.3.1
 *   node test/real/grafana.mjs 3000
 *
 * Nothing here is an exploit, and no ciphertext is brought from anywhere. A
 * login through an OAuth provider that fails makes Grafana set a `login_error`
 * cookie of its own: its error message, encrypted with the instance's secrets
 * key. That cookie is handed back to the login page in one spelling after
 * another. When Grafana has read it, the page carries the decrypted message
 * ("loginError" in its boot data) and the reply clears the cookie; when it
 * has not, neither happens. Every spelling it reads is one the policy has to
 * match. The second argument, `fixed`, is for a release with the fix: it must
 * not read the old cookie at all. */
import { send, status, check, finish, until } from "./lib.mjs";
const port = Number(process.argv[2] ?? 3000), fixed = process.argv[3] === "fixed";
const req = (target, headers = "") => send(port, `GET ${target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n${headers}\r\n`);

if (!(await until(async () => status(await req("/api/health")) === 200, 180))) { console.error(`no Grafana answering on :${port}`); process.exit(2); }
const version = (await req("/api/health")).toString("latin1").match(/"version":\s*"([^"]+)"/)?.[1];
/* a failed OAuth login: Grafana redirects to /login and sets the cookie */
const issue = async () => (await req("/login/generic_oauth?error=access_denied&error_description=nope")).toString("latin1").match(/\r\nSet-Cookie: login_error=([0-9a-f]+);/i)?.[1];
const V = await issue();
console.log(`Grafana ${version}; its own login_error cookie is ${V?.length ?? 0} hex characters, beginning ${V?.slice(0, 8)}`);
if (!V) { console.error("Grafana set no login_error cookie: is generic OAuth enabled?"); process.exit(2); }
/* -> whether the login page showed the message the cookie holds */
const read = async (headers) => { const r = (await req("/login", headers)).toString("latin1"); return /"loginError":"[^"]+"/.test(r); };

if (fixed) {
  /* the old format begins with '#', the id of the key it was encrypted under */
  const old = "23596d6331596d5a776347686d5a476b305a324d232a5957567a4c574e6d59672a3864644651654a790550c2ab568aa06cde3b44747c70994cb1e0b887409b1e76c35cd4d9e2aaec3519";
  check("the fixed release reads the cookie it signed itself", await read(`Cookie: login_error=${V}\r\n`));
  check("and no longer reads one in the old, encrypted format", !(await read(`Cookie: login_error=${old}\r\n`)));
  check("nor its own with one character of the message changed", !(await read(`Cookie: login_error=${V.slice(0, -1)}${V.endsWith("0") ? "1" : "0"}\r\n`)));
  finish();
}

check("the cookie it set is encrypted, not signed: it begins with '#'", V.startsWith("23"));
check("the login page without the cookie shows no error", !(await read("")));
console.log("Grafana decrypts the cookie and shows what it held when it is sent as");
for (const [label, h] of [
  ["Cookie: login_error=V", `Cookie: login_error=${V}\r\n`],
  ["cookie: (lower case header)", `cookie: login_error=${V}\r\n`],
  ["COOKIE:", `COOKIE: login_error=${V}\r\n`],
  ["Cookie:login_error=V (no space)", `Cookie:login_error=${V}\r\n`],
  ["Cookie:<tab>login_error=V", `Cookie:\tlogin_error=${V}\r\n`],
  ["after another cookie", `Cookie: grafana_session=abc; login_error=${V}\r\n`],
  ["before another cookie", `Cookie: login_error=${V}; grafana_session=abc\r\n`],
  ["after another, no space after the semicolon", `Cookie: a=b;login_error=${V}\r\n`],
  ["spaces before the name", `Cookie: a=b;   login_error=${V}\r\n`],
  ["a space before the =", `Cookie: login_error =${V}\r\n`],
  ["the value in double quotes", `Cookie: login_error="${V}"\r\n`],
  ["the value in upper-case hex", `Cookie: login_error=${V.toUpperCase()}\r\n`],
  ["in the second of two Cookie headers", `Cookie: a=b\r\nCookie: login_error=${V}\r\n`],
  ["twice, the first one real", `Cookie: login_error=${V}; login_error=00\r\n`],
]) check(label, await read(h));

console.log("\nand does not read these");
for (const [label, h] of [
  ["Login_Error=V", `Cookie: Login_Error=${V}\r\n`],
  ["LOGIN_ERROR=V", `Cookie: LOGIN_ERROR=${V}\r\n`],
  ["login%5Ferror=V", `Cookie: login%5Ferror=${V}\r\n`],
  ["a space after the =", `Cookie: login_error= ${V}\r\n`],
  ["after a comma, not a semicolon", `Cookie: a=b, login_error=${V}\r\n`],
  ["twice, the first one empty", `Cookie: login_error=; login_error=${V}\r\n`],
  ["in a header that is not Cookie", `X-Cookie: login_error=${V}\r\n`],
  ["in the query", ``, `/login?login_error=${V}`],
]) check(label, !(h ? await read(h) : /"loginError":"[^"]+"/.test((await req(`/login?login_error=${V}`)).toString("latin1"))));
finish();
