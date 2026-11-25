/* The spellings are ones ProFTPD 1.3.8 with mod_copy recognised as the
 * command before a login: it answers those with "530 Please login" and
 * anything else with "500 ... not understood". 1.3.5 was not run. */
export const port = 21;

export default function ({ f, run, stream }) {
  const ftp = { dport: port };
  const IP = "\xff\xf4", DM = "\xff\xf2", WILL = "\xff\xfb\x01", WONT = "\xff\xfc\x01", DO = "\xff\xfd\x01", DONT = "\xff\xfe\x01";
  /* each of these the server took for SITE CPFR */
  for (const [label, c] of [["SITE CPFR", "SITE CPFR /etc/passwd"], ["lower case", "site cpfr /etc/passwd"], ["mixed case", "SiTe CpFr /etc/passwd"], ["a tab between", "SITE\tCPFR /etc/passwd"],
    ["a vertical tab between", "SITE\x0bCPFR /etc/passwd"], ["a form feed between", "SITE\x0cCPFR /etc/passwd"], ["a bare newline to end it", "SITE CPFR /etc/passwd\n"],
    ["IAC IP inside the second word", `SITE C${IP}PFR /etc/passwd`], ["IAC DM inside the second word", `SITE C${DM}PFR /etc/passwd`], ["IAC IP inside the first word", `SI${IP}TE CPFR /etc/passwd`],
    ["IAC WILL inside", `SITE C${WILL}PFR /etc/passwd`], ["IAC WONT inside", `SITE C${WONT}PFR /etc/passwd`], ["IAC DO inside", `SITE C${DO}PFR /etc/passwd`], ["IAC DONT inside", `SITE C${DONT}PFR /etc/passwd`],
    ["IAC WILL before the space", `SITE${WILL} CPFR /x`], ["three IAC IP after the space", `SITE ${IP}${IP}${IP}CPFR /x`], ["IAC IP between every two letters", `S${IP}I${IP}T${IP}E${IP} ${IP}C${IP}P${IP}F${IP}R /etc/passwd`],
    ["an option byte that is a letter", `SITE C\xff\xfbsPFR /x`]])
    run(f, label, c.endsWith("\n") ? c : c + "\r\n", "rst(proftpd_copy)", ftp);
  run(f, "SITE CPTO", "SITE CPTO /var/www/x.php\r\n", "rst(proftpd_copy)", ftp);
  run(f, "SITE CPTO with IAC IP inside", `SITE CP${"\xff\xf4"}TO /var/www/x.php\r\n`, "rst(proftpd_copy)", ftp);
  run(f, "after a login", "USER jo\r\nPASS secret\r\nPWD\r\nSITE CPFR /home/jo/a\r\n", "rst(proftpd_copy)", ftp);

  run(f, "an ordinary session", "USER anonymous\r\nPASS jo@example.test\r\nSYST\r\nFEAT\r\nPWD\r\nTYPE I\r\nPASV\r\nRETR pub/readme.txt\r\nQUIT\r\n", "pass", ftp);
  run(f, "an upload", "USER jo\r\nPASS secret\r\nCWD /srv/site\r\nEPSV\r\nSTOR cpto-notes.txt\r\nMDTM cpto-notes.txt\r\n", "pass", ftp);
  run(f, "other SITE commands", "SITE HELP\r\nSITE CHMOD 644 index.html\r\nSITE UTIME 20260101000000 a\r\nSITE COPY a b\r\n", "pass", ftp);
  run(f, "an abort, with the Telnet interrupt clients send before it", "RETR big.iso\r\n\xff\xf4\xff\xf2ABOR\r\n", "pass", ftp);
  run(f, "a file name in UTF-8", "STOR Site caf\xc3\xa9 \xe2\x80\x93 prix fix\xc3\xa9s.pdf\r\n", "pass", ftp);
  run(f, "the two words in different commands", "SITE HELP\r\nCWD cpfr\r\n", "pass", ftp);
  /* what the server did not take for the command */
  run(f, "SITE_CPFR", "SITE_CPFR /x\r\n", "pass", ftp);
  run(f, "another port", "SITE CPFR /etc/passwd\r\n", "pass", { dport: 2121 });
  run(f, "port knob", "SITE CPFR /etc/passwd\r\n", "rst(proftpd_copy)", { dport: 2121, knobs: { port: 2121 } });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = () => [
  { name: "SITE CPFR", raw: Buffer.from("SITE CPFR /etc/passwd\r\n", "latin1"), want: "cut" },
  { name: "SITE CPTO, a Telnet interrupt inside the word", raw: Buffer.from("SITE CP\xff\xf4TO /var/www/x.php\r\n", "latin1"), want: "cut" },
  { name: "an ordinary command", raw: Buffer.from("USER anonymous\r\n", "latin1"), want: "served" },
];
