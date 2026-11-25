/* What ftp/proftpd-mod-copy.pfc assumes about ProFTPD, asked of ProFTPD with
 * mod_copy loaded.
 *
 *   node test/real/proftpd.mjs 21
 *
 * Nothing here is an exploit, and the server asked is a fixed one: it wants a
 * login before it will copy anything. That is the answer read here. A line
 * the server takes for SITE CPFR gets "530 Please login", and one it does not
 * gets "500 ... not understood". Every spelling it takes is one the policy
 * has to match. */
import { send, check, finish, until } from "./lib.mjs";
const port = Number(process.argv[2] ?? 21);
/* the reply to one command sent before any login, Telnet replies stripped */
const ask = async (line) => { const out = (await send(port, line + "QUIT\r\n", { wait: 4000 })).toString("latin1").replace(/\xff[\xfb-\xfe][^]/g, ""); return Number(out.split("\r\n").find((l) => /^\d{3}[ -]/.test(l) && !/^22[01]/.test(l))?.slice(0, 3) ?? 0); };
const show = (s) => s.replace(/[^\x20-\x7e]/g, (c) => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0"));
const IP = "\xff\xf4", DM = "\xff\xf2";

if (!(await until(async () => /^220/.test((await send(port, "QUIT\r\n", { wait: 3000 })).toString("latin1")), 180))) { console.error(`no FTP server answering on :${port}`); process.exit(2); }
check("mod_copy is loaded", /CPFR/.test((await send(port, "SITE HELP\r\nQUIT\r\n", { wait: 4000 })).toString("latin1")));
console.log("ProFTPD takes these for SITE CPFR");
for (const c of ["SITE CPFR /etc/hostname\r\n", "site cpfr /etc/hostname\r\n", "SiTe CpFr /etc/hostname\r\n", "SITE\tCPFR /etc/hostname\r\n", "SITE\x0bCPFR /etc/hostname\r\n", "SITE\x0cCPFR /etc/hostname\r\n", "SITE CPFR /etc/hostname\n",
  `SITE C${IP}PFR /etc/hostname\r\n`, `SITE C${DM}PFR /etc/hostname\r\n`, `SI${IP}TE CPFR /etc/hostname\r\n`, "SITE C\xff\xfb\x01PFR /etc/hostname\r\n", "SITE C\xff\xfc\x01PFR /etc/hostname\r\n", "SITE C\xff\xfd\x01PFR /etc/hostname\r\n", "SITE C\xff\xfe\x01PFR /etc/hostname\r\n",
  "SITE\xff\xfb\x01 CPFR /x\r\n", `SITE ${IP}${IP}${IP}CPFR /x\r\n`, `S${IP}I${IP}T${IP}E${IP} ${IP}C${IP}P${IP}F${IP}R /etc/hostname\r\n`, "SITE C\xff\xfbsPFR /x\r\n"])
  check(show(c), (await ask(c)) === 530);
check("SITE CPTO is known too (503: no CPFR came first)", (await ask("SITE CPTO /tmp/x\r\n")) === 503);

console.log("\nand does not take these");
for (const c of ["SITE_CPFR /x\r\n", "SITE  CPFR /x\r\n", "SITE\xa0CPFR /x\r\n", " SITE CPFR /x\r\n", "SITE CPFRX /x\r\n", "SITE C\xff\xf1PFR /x\r\n", "SITE C\xff\xf0PFR /x\r\n", "SITE C\xff\xffPFR /x\r\n", "SITE C\x00PFR /x\r\n"])
  check(show(c), (await ask(c)) === 500);
finish();
