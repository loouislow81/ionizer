# ionizer v0.0.4

> **⚠** Filter hosts data updated on (27 DEC 2020).

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

This is my daily use mini-tool for all my Linux computers. It blocks ads and works seamlessly better than installing web browser extensions and desktop apps. The filter data is hosted at Github by using a dedicated [generator](https://github.com/loouislow81/ionizer/tree/master/generator). The [client](https://github.com/loouislow81/ionizer/tree/master/client) is responsible for downloading and updating filter data.

<p align="left">
  <img src="assets/screenshot_01.png" width="49%" height="auto">
  <img src="assets/screenshot_02.png" width="49%" height="auto">
</p>


### _usage

install app and update the data,

> ionizer will install `dnsmasq` package for you, if not installed,

```bash
# install via download
$ wget https://github.com/loouislow81/ionizer/releases/download/untagged-5240e09eafb9428546b3/ionizer_0.0.4_linux_x86-64.app_image
$ sudo ionizer_0.0.4_linux_x86-64.app_image --install
# install via source
$ sudo ionizer --install
$ sudo ionizer --update
```

edit file `/etc/dnsmasq.conf` and add this line,

```bash
...
addn-hosts=/etc/ionizer/ipaddress.ions
...
```

> you can add `ionizer --update` into `crontab` to automate the blocklist updates.

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
