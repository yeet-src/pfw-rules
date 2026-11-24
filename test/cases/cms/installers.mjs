/* Every spelling reset here is one Apache 2.4 with mod_php ran the file for;
 * the ones passed are ones it answered 404 to. */
export const port = 80;

export default function ({ f, run, stream, req, get, post }) {
  const web = { dport: port };
  for (const t of ["/core/install.php", "/core/install.php?rewrite=ok&langcode=en", "//core//install.php", "/core/./install.php", "/core/x/../install.php", "/x/../core/install.php",
    "/core/%69nstall.php", "/core/install%2ephp", "/core/install%2Ephp", "/core/install.ph%70", "/core/%2e/install.php", "/core/install.php/", "/core/install.php/extra/path", "http://example.test/core/install.php",
    "/install.php", "/wp-admin/install.php", "/wp-admin/install.php?step=1", "/blog/wp-admin/install.php"])
    run(f, `GET ${t}`, get(t), "rst(cms_installer)", web);
  for (const m of ["POST", "HEAD", "FOO"]) run(f, `${m} /core/install.php`, req(m, "/core/install.php"), "rst(cms_installer)", web);
  for (const t of ["/wp-content/upgrade/wordpress-7.1.3-abc123/wordpress/wp-admin/install.php", "/wp-content/upgrade/wordpress-7.1.3-abc123/readme.html", "/wp-content/upgrade/", "/wp-content/upgrad%65/x/wordpress/wp-load.php",
    "/wp-content//upgrade/./x/readme.html".replace("//upgrade/./", "/upgrade/"), "/blog/wp-content/upgrade/x/wordpress/index.php"])
    run(f, `GET ${t}`, get(t), "rst(cms_upgrade_staging)", web);
  run(f, "second request on a keep-alive connection", get("/") + get("/core/install.php"), "rst(cms_installer)", web);
  stream(f, "the request line split across segments", ["GET /core/inst", "GET /core/install.php HTTP/1.1\r\nHost: x\r\n\r\n"], "rst(cms_installer)", web);

  run(f, "the front page", get("/"), "pass", web);
  run(f, "a Drupal node", get("/node/42"), "pass", web);
  run(f, "Drupal's update script, which is not the installer", get("/update.php"), "pass", web);
  run(f, "a WordPress post", get("/2026/11/hello-world/"), "pass", web);
  run(f, "the WordPress admin", post("/wp-admin/admin-ajax.php", "Content-Type: application/x-www-form-urlencoded\r\n", "action=heartbeat"), "pass", web);
  run(f, "the WordPress updater's own page", get("/wp-admin/update-core.php"), "pass", web);
  run(f, "an upload, which is not the upgrade directory", get("/wp-content/uploads/2026/11/photo.jpg"), "pass", web);
  run(f, "install.php in the query, not the path", get("/search?q=install.php&next=/wp-content/upgrade/"), "pass", web);
  run(f, "a page whose text mentions both", post("/node/add", "Content-Type: text/plain\r\n", "Delete core/install.php and empty /wp-content/upgrade/ after an upgrade."), "pass", web);
  run(f, "another file that only starts the same", get("/docs/install.php.html"), "pass", web);
  run(f, "another case, which Apache answers 404", get("/core/INSTALL.PHP"), "pass", web);
  run(f, "another port", get("/core/install.php"), "pass", { dport: 8080 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "Drupal's installer", curl: [`${url}/core/install.php?rewrite=ok&langcode=en`], want: "cut" },
  { name: "the same, with an encoded dot and a doubled slash", curl: [`${url}//core/install%2ephp`], want: "cut" },
  { name: "the installer staged by a WordPress upgrade", curl: [`${url}/wp-content/upgrade/wordpress-7.1.3-abc123/wordpress/wp-admin/install.php`], want: "cut" },
  { name: "a page", curl: [`${url}/node/42`], want: "served" },
  { name: "the WordPress admin", curl: ["-d", "action=heartbeat", `${url}/wp-admin/admin-ajax.php`], want: "served" },
];
