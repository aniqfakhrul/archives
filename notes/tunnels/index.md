---
title: Tunnels
date: 2024-3-16T09:30:10+08:00
tags:
  - tunnels
  - notes
---
>[!Under Development]
>These tools details are yet to be updated. So don't judge yet!

| Name                                                | Protocol  | HTTP | Socks | Stable | Details               |
| --------------------------------------------------- | --------- | :--: | :---: | :----: | --------------------- |
| [SSF](https://github.com/securesocketfunneling/ssf) |           |      |  🟢   |   🟡   | [SSF](#ssf)           |
| [chisel](https://github.com/jpillora/chisel)        | WebSocket |      |  🟢   |   🟢   | [chisel](#ssf)        |
| [wstunnel](https://github.com/erebe/wstunnel)       | WebSocket |      |  🟢   |   🔴   | [wstunnel](#wstunnel) |
| [frp](https://github.com/fatedier/frp)              |           |  🟢  |  🟢   |   🟢   | [frp](#frp)           |

## SSF

**Server**
```bash
ssfd --port 80
```

**Client**
```bash
ssf -F 1080 -p 80 <server-ip>
```

## chisel

**Server**
```bash
chisel server --reverse --port 80
```

**Client**
```bash
chisel client <server-ip>:80 R:socks [--fingerprint <fingerprint>]
```

## wstunnel

**Server**
```bash
wstunnel server wss://0.0.0.0:80
```

**Client**
```bash
wstunnel client -R socks5://127.0.0.1:1080 ws://<server-ip>:80
```

## frp

**Server**
```bash
frps -c frps.toml
```

```toml title="frps.toml"
# server listening port, default interface on 0.0.0.0
bindPort = 7000
```

**Client**
```bash
frpc -c frpc.toml
```

```toml title="frpc.toml"
serverAddr = "<server-ip>"
serverPort = 7000

[[proxies]]
name = "socks"
type = "tcp"
remotePort = 1080
[proxies.plugin]
type = "socks5"
```
