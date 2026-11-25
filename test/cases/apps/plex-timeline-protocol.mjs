/* The spellings are ones Plex Media Server 1.43.5 read as the `protocol` of a
 * timeline subscription, with a player registered: it refuses a value that is
 * not a protocol and names it in its log. Harmless values were sent, such as
 * `a:b`; the URLs below are the shape the advisories describe and were not. */
export const port = 32400;

export default function ({ f, run, stream, get, post, req }) {
  const web = { dport: port };
  const common = "deviceClass=pc&protocolCapabilities=playback&protocolVersion=1";
  const sub = (proto, path = "/player/timeline/subscribe") => get(`${path}?${common}&${proto}&port=32500&commandID=1&X-Plex-Target-Client-Identifier=tv`, "X-Plex-Token: anything\r\nX-Plex-Client-Identifier: phone\r\n");
  /* each of these the server read as the protocol */
  for (const p of ["protocol=a:b", "protocol=a%3Ab", "protocol=a/b", "%70rotocol=a:b", "protoco%6C=a:b", "protocol=http&protocol=a:b",
    "protocol=http://127.0.0.1:32400/x", "protocol=http%3A%2F%2F127.0.0.1%3A32400%2Fx%23", "protocol=https://example.test/%23", "protocol=http:", "protocol=http%3a"])
    run(f, `subscribe with ${p}`, sub(p), "rst(plex_protocol)", web);
  run(f, "the same with a trailing slash on the path", sub("protocol=a:b", "/player/timeline/subscribe/"), "rst(plex_protocol)", web);
  run(f, "under /x/../player/", sub("protocol=a:b", "/x/../player/timeline/subscribe"), "rst(plex_protocol)", web);
  run(f, "the first parameter of the query", get("/player/timeline/subscribe?protocol=a:b&port=1"), "rst(plex_protocol)", web);
  run(f, "the first of two, the second bare", sub("protocol=a:b&protocol=http"), "rst(plex_protocol)", web);
  run(f, "at the start of a form body", post("/player/timeline/subscribe", "Content-Type: application/x-www-form-urlencoded\r\n", "protocol=a:b&port=1"), "rst(plex_protocol)", web);
  run(f, "POST, as one write-up has it", req("POST", `/player/timeline/subscribe?${common}&protocol=http://127.0.0.1:32400/x&port=1`), "rst(plex_protocol)", web);
  run(f, "second request on a keep-alive connection", get("/identity") + sub("protocol=a:b"), "rst(plex_protocol)", web);

  run(f, "subscribe over http", sub("protocol=http"), "pass", web);
  run(f, "subscribe over https", sub("protocol=https"), "pass", web);
  run(f, "protocol last in the query", get(`/player/timeline/subscribe?${common}&port=32500&protocol=http`), "pass", web);
  run(f, "unsubscribe", get(`/player/timeline/unsubscribe?${common}&X-Plex-Target-Client-Identifier=tv`), "pass", web);
  run(f, "a player's long poll", get(`/player/proxy/poll?${common}&wait=1&timeout=30`, "X-Plex-Client-Identifier: tv\r\nX-Plex-Provides: player\r\n"), "pass", web);
  run(f, "the transcoder, protocol=hls and a path that is a URL", get("/video/:/transcode/universal/start.m3u8?path=http%3A%2F%2F127.0.0.1%3A32400%2Flibrary%2Fmetadata%2F42&protocol=hls&directPlay=0&session=abc"), "pass", web);
  run(f, "the transcoder, protocol=dash", get("/video/:/transcode/universal/decision?path=%2Flibrary%2Fmetadata%2F42&protocol=dash&mediaIndex=0"), "pass", web);
  run(f, "protocol=*", get("/video/:/transcode/universal/decision?path=%2Flibrary%2Fmetadata%2F42&protocol=*&mediaIndex=0"), "pass", web);
  run(f, "a client profile that names a protocol", get("/library/sections", "X-Plex-Client-Profile-Extra: add-transcode-target(type=videoProfile&context=streaming&protocol=dash&container=mp4)\r\n"), "pass", web);
  run(f, "other parameters whose names contain the word", get(`/player/timeline/poll?protocolVersion=1&protocolCapabilities=timeline,playback&wait=1`), "pass", web);
  run(f, "the library", get("/library/metadata/42?includeExtras=1&X-Plex-Token=abc"), "pass", web);
  run(f, "another port", sub("protocol=a:b"), "pass", { dport: 80 });
  run(f, "port knob", sub("protocol=a:b"), "rst(plex_protocol)", { dport: 80, knobs: { port: 80 } });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "subscribe with a URL for a protocol", curl: ["-H", "X-Plex-Token: anything", `${url}/player/timeline/subscribe?protocolVersion=1&protocol=http://127.0.0.1:32400/x&port=32500&commandID=1`], want: "cut" },
  { name: "the same, name and value encoded", curl: [`${url}/player/timeline/subscribe?protocolVersion=1&%70rotocol=http%3A%2F%2F127.0.0.1%2Fx&port=32500`], want: "cut" },
  { name: "subscribe over http", curl: [`${url}/player/timeline/subscribe?protocolVersion=1&protocol=http&port=32500&commandID=1`], want: "served" },
  { name: "the transcoder, protocol=hls", curl: [`${url}/video/:/transcode/universal/start.m3u8?path=%2Flibrary%2Fmetadata%2F42&protocol=hls`], want: "served" },
];
