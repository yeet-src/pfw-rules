/* End to end, as an operator would: bring the firewall up with `pfw up`,
 * enforce each policy with `pfw apply -f`, point it at a real server with
 * `pfw knob set port`, and send real requests. One the policy names must be
 * cut off; an ordinary one must be served.
 *
 *   PFW=/path/to/pfw/bin/pfw PFW_SOURCE=/path/to/pfw/dist sh test/in-namespace.sh node test/e2e.mjs [policy ...]
 *
 * It takes the firewall on this host's loopback, changes its policy and stops
 * it at the end, so run it through in-namespace.sh, where loopback and the
 * daemon are its own. PFW defaults to the `pfw` on PATH.
 *
 * Each policy's requests are the `e2e` export of its cases file: a curl
 * command where curl can say it, raw bytes where it cannot (a TLS hello).
 */
import net from "node:net";
import { execFile } from "node:child_process";
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync, mkdirSync, cpSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";

const root = new URL("../", import.meta.url);
const PFW = process.env.PFW || "pfw";
const only = process.argv.slice(2);
const home = process.env.SCRATCH_HOME || process.env.HOME;
mkdirSync(home, { recursive: true });
/* pfw keeps its settings under HOME: give it a scratch one. */
const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: `${home}/.config`, XDG_CACHE_HOME: `${home}/.cache`, NO_COLOR: "1" };

const sh = (cmd, args, opts = {}) => new Promise((res) => execFile(cmd, args, { env, timeout: 60000, encoding: "utf8", ...opts }, (err, stdout, stderr) => res({ ok: !err, code: err ? (err.killed ? `killed by ${err.signal}` : err.code) : 0, out: `${stdout}${stderr}` })));
const pfw = async (...args) => { const r = await sh(PFW, args); if (!r.ok) throw new Error(`pfw ${args.join(" ")} failed:\n${r.out}`); return r.out; };

let fail = 0, n = 0, shown = false;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${!cond && detail ? ": " + detail : ""}`); };

/* A server that answers anything with a page, once the client has gone quiet
 * for a moment: the whole request has to get past the firewall first. One per
 * port a policy guards by default, so each policy is tested as it ships. */
const answer = (s) => { let t; s.on("data", () => { clearTimeout(t); t = setTimeout(() => s.end("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n"), 150); }); s.on("error", () => {}); };
const servers = new Map();
async function serve(port) { if (!servers.has(port)) { const srv = net.createServer(answer); await new Promise((res, rej) => { srv.once("error", rej); srv.listen(port, "127.0.0.1", res); }); servers.set(port, srv); } return `http://127.0.0.1:${port}`; }
/* a second port, for showing that `pfw knob set port` moves a policy */
const OTHER = 18473;

/* served: an HTTP status came back. cut: the connection died first. */
async function curl(args) {
  const r = await sh("curl", ["-s", "-o", "/dev/null", "-m", "5", "-w", "%{http_code}", "--path-as-is", ...args]);
  return /^[1-5]\d\d$/.test(r.out.trim()) ? "served" : "cut";
}
function raw(port, bytes) {
  return new Promise((res) => { let got = false, done = false; const fin = (v) => { if (!done) { done = true; s.destroy(); res(v); } };
    const s = net.connect({ port, host: "127.0.0.1" }, () => s.write(Buffer.from(bytes)));
    s.on("data", () => { got = true; fin("served"); }); s.on("error", () => fin("cut")); s.on("close", () => fin(got ? "served" : "cut")); setTimeout(() => fin("cut"), 5000); });
}

const policies = [];
const SKIP = new Set(["test", "pfw", "pfw-core", "node_modules"]);
const walk = (dir) => { for (const f of readdirSync(new URL(dir || ".", root))) { if (f.startsWith(".") || SKIP.has(f)) continue; const p = dir + f; if (statSync(new URL(p, root)).isDirectory()) walk(p + "/"); else if (f.endsWith(".pfc")) policies.push(p); } };
walk("");

/* The service saves its policy for restarts in /var/lib/pfw/state.js, a path
 * no network namespace hides: started as it is built, this test would write
 * over the saved state of the host's own firewall. So it runs a copy of the
 * built service whose keeper is told to keep its state in the scratch
 * directory, and refuses to run at all if it cannot arrange that. */
const built = process.env.PFW_SOURCE || (await sh(PFW, ["config", "get", "source"])).out.trim();
if (!existsSync(`${built}/service.toml`)) { console.error(`no built pfw service at "${built}": set PFW_SOURCE to pfw's dist/ or share/pfw`); process.exit(2); }
const service = `${home}/pfw-service`, stateFile = `${home}/pfw-state.js`;
cpSync(built, service, { recursive: true, dereference: true });
const toml = readFileSync(`${service}/service.toml`, "utf8");
const KEEPER = 'args = ["--iface", "lo"]';
if (!toml.includes(KEEPER)) { console.error("pfw's service.toml no longer starts its keeper the way this test expects, so its state file cannot be moved: not running"); process.exit(2); }
writeFileSync(`${service}/service.toml`, toml.replace(KEEPER, `args = ["--iface", "lo", "--state-file", ${JSON.stringify(stateFile)}]`));
env.PFW_SOURCE = service;

/* yeet serves a login page in place of every route of a host that is not
 * logged in, the firewall's control route among them. Logging in takes a
 * route to yeet's servers, which a namespace made by in-namespace.sh does not
 * have: there the daemon has to be one that does not ask (a development
 * build), and on a host with a network YEET_API_KEY logs it in. */
const YEET = process.env.YEET || "yeet";
if (process.env.YEET_API_KEY && !(await sh(YEET, ["whoami", "--quiet"])).ok) {
  const r = await sh(YEET, ["login", "--key", process.env.YEET_API_KEY]);
  console.log(r.ok ? "logged this host's daemon in with the key in YEET_API_KEY" : `yeet login --key failed: ${r.out.trim().split("\n").slice(-2).join(" | ").replaceAll(process.env.YEET_API_KEY, "<key>")}`);
}

try {
  console.log(`${PFW} up, from a copy of ${built} that keeps its state in ${stateFile}`);
  await pfw("up");
  if (!/\S/.test(await pfw("status"))) {
    console.error("\nThe firewall is up but its control route answers with nothing: this host's daemon is not\nlogged in to yeet, which serves a login page in place of the service. Set YEET_API_KEY\n(in CI, as a repository secret) or run `yeet login` first.");
    process.exitCode = 3; throw new Error("not logged in to yeet");
  }
  await sh(PFW, ["clear"]);
  await sh(PFW, ["unshadow"]);
  check("with no policy, a request is served", (await curl([`${await serve(80)}/`])) === "served");
  await serve(OTHER);

  for (const f of policies.sort()) {
    if (only.length && !only.some((o) => f.includes(o))) continue;
    const rel = `test/cases/${f.replace(/\.pfc$/, ".mjs")}`;
    console.log(`\n${f}`);
    const mod = existsSync(new URL(rel, root)) ? await import(new URL(rel, root)) : {};
    check("has end-to-end requests", typeof mod.e2e === "function", `export e2e from ${rel}`);
    if (typeof mod.e2e !== "function") continue;

    const applied = await sh(PFW, ["apply", "-f", new URL(f, root).pathname]);
    check("pfw apply -f accepts it", applied.ok, `exit ${applied.code}: ${applied.out.trim().split("\n").slice(-6).join(" | ") || "(no output)"}`);
    if (!applied.ok && !shown) { shown = true; for (const args of [["--version"], ["status"], ["doctor"]]) console.log(`    pfw ${args.join(" ")}:\n${(await sh(PFW, args)).out.replace(/^/gm, "      ")}`); }
    if (/saved for restarts at/.test(applied.out) && !applied.out.includes(stateFile)) throw new Error(`the service is saving its state outside the scratch directory: ${applied.out.trim().split("\n").pop()}`);
    if (!applied.ok) continue;
    check("pfw status says it is enforcing", /enforcing/.test(await pfw("status")));
    /* applying a policy must not cost the connections that are already open */
    check("the control connection survived the apply", applied.ok && !/not reachable/.test(applied.out));
    await sleep(200);

    const port = mod.port ?? 80;
    const url = await serve(port);
    const fixture = (name) => readFileSync(new URL(`test/fixtures/${name}`, root));
    const cases = mod.e2e({ url, port, fixture });
    for (const c of cases) {
      for (const [k, v] of Object.entries(c.knobs ?? {})) await pfw("knob", "set", k, String(v));
      const got = c.curl ? await curl(c.curl) : await raw(port, c.raw);
      check(`${c.want === "cut" ? "cut off" : "served "}: ${c.name}`, got === c.want, `the request was ${got}`);
      for (const k of Object.keys(c.knobs ?? {})) await pfw("knob", "unset", k);
    }
    /* the port knob, as an operator would use it: the first request that is cut, on another port */
    const first = cases.find((c) => c.want === "cut" && !c.knobs);
    if (first && /@knob port\b/.test(readFileSync(new URL(f, root), "utf8"))) {
      const moved = mod.e2e({ url: `http://127.0.0.1:${OTHER}`, port: OTHER, fixture }).find((c) => c.name === first.name);
      const send = (c, p) => (c.curl ? curl(c.curl) : raw(p, c.raw));
      await pfw("knob", "set", "port", String(OTHER));
      check(`pfw knob set port ${OTHER}: cut off there`, (await send(moved, OTHER)) === "cut");
      check(`pfw knob set port ${OTHER}: port ${port} is left alone`, (await send(first, port)) === "served");
      await pfw("knob", "unset", "port");
    }
  }
} catch (e) {
  fail++; console.log(`FAIL ${e.message}`);
  console.log((await sh(PFW, ["status"])).out);
  console.log((await sh(PFW, ["doctor"])).out);
} finally {
  await sh(PFW, ["clear"]);
  await sh(PFW, ["down"]);
  for (const srv of servers.values()) srv.close();
}

console.log(`\n${n - fail}/${n} passed`);
process.exit(process.exitCode || (fail ? 1 : 0));
