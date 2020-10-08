# ionizer v0.0.3

<p align="left">
  <img src="https://badgen.net/github/release/loouislow81/ionizer">
  <img src="https://badgen.net/github/releases/loouislow81/ionizer">
  <img src="https://badgen.net/github/assets-dl/loouislow81/ionizer">
  <img src="https://badgen.net/github/branches/loouislow81/ionizer">
  <img src="https://badgen.net/github/forks/loouislow81/ionizer">
  <img src="https://badgen.net/github/stars/loouislow81/ionizer">
  <img src="https://badgen.net/github/watchers/loouislow81/ionizer">
  <img src="https://badgen.net/github/tag/loouislow81/ionizer">
  <img src="https://badgen.net/github/commits/loouislow81/ionizer">
  <img src="https://badgen.net/github/last-commit/loouislow81/ionizer">
  <img src="https://badgen.net/github/contributors/loouislow81/ionizer">
  <img src="https://badgen.net/github/license/loouislow81/ionizer">
</p>

System-wide ads filter with just `DNSMASQ` and `BASH` for Linux.

This is my daily use mini tool for all my Linux computers. Blocking ads works seamlessly amazing than installing web browser extensions and desktop apps.

<p align="left">
  <img src="assets/screenshot_01.png" width="49%" height="auto">
  <img src="assets/screenshot_02.png" width="49%" height="auto">
</p>


#### __usage

**(!!)** May required root permissions.

edit file `/etc/dnsmasq.conf` and add this line,

```bash
...
addn-hosts=/etc/ionizer/ipaddress.ions
...
```

install and update the blocklists, ionizer will install `dnsmasq` for you if not installed,

```bash
$ ionizer --install
$ ionizer --update
```

**Note:** you can add `ionizer --update` into `crontab` to automate the blocklist updates.

CLI options,

```bash
-h,--help ............... Display this information
-u,--update ............. Update blocklists
-l,--list ............... Show total blocklists
-i,--install ............ Install to system
```

Enjoy!

---

[MIT](https://github.com/loouislow81/ionizer/blob/master/LICENSE)
