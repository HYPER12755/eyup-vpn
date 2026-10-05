# sshproxy wire protocol

How a client reaches the SSH server through the bridge. This is the part you
need when a connection fails between haproxy and `sshd`, or when writing a
client that is not one of the bundled menus.

`sshproxy` always answers `101` with the same banner, whether or not the client
speaks WebSocket:

```
HTTP/1.1 101 <font color="green">SCRIPT BY PUSAT BLITAR</b></font>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: <base64(sha1(key + GUID))>   # "foo" when no key was sent
```

`Sec-WebSocket-Accept` is only meaningful when the client sent
`Sec-WebSocket-Key`; a raw client can ignore it.

## Request headers

`sshproxy` reads exactly **one** request, stopping at the first blank line
(64 KiB max, 10 s deadline). Everything the client sends after that blank line
is treated as payload and forwarded to the target untouched.

This means the whole WebSocket upgrade must live in the **first** request.
Sending the handshake in request 1, a probe in request 2, and the real upgrade
in request 3 does not work:

```http
GET / HTTP/1.1
Host: example.com

X / HTTP/1.1
Host: [host]

GET / HTTP/1.1
Upgrade: websocket
Sec-WebSocket-Key: ...
```

Request 1 has no `Sec-WebSocket-Key`, so framing is disabled and the response
carries `Sec-WebSocket-Accept: foo`. Requests 2 and 3 are then forwarded to
the SSH server, which sees `X / HTTP/1.1` as its client banner and aborts. A
client that later sends a WebSocket frame also breaks, because the raw relay
copies it without unmasking.

A correct single request looks like this:

```http
GET / HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64 16 random bytes>
Sec-WebSocket-Version: 13
X-Real-Host: 127.0.0.1:109

```

| Header | Effect when present |
|---|---|
| `X-Real-Host` | Target as `host:port`. Omitted → `127.0.0.1:109`. Port omitted → `443`. |
| `X-Split` | Discards one incoming packet before relaying (see below). |
| `X-Pass` | Shared secret; only checked when the binary is built with a non-empty `pass`. |
| `Sec-WebSocket-Key` | Selects RFC 6455 framing for the rest of the stream. |
| `Host` | Ignored. `sshproxy` does not route on domain. |

Header names are matched **case-insensitively** (`x-real-host` and
`X-ReAl-HoSt` both work), and only against the name field of a line. A header
name mentioned inside another header's value is ignored, so
`Referer: http://x/X-Real-Host: 8.8.8.8:53` does **not** set a target.

## Host and domain

No domain is baked in, and none is required. `Host:` is read but unused —
haproxy routes purely on the request line (`GET`/`CONNECT` → sshproxy,
anything else → the SSH backend), so **any hostname reaches the bridge**.
`gnc.dnatech.io`, an IP literal, or `localhost` all behave identically.

The domain that appears in *generated client links* is a separate thing: it
comes from `appconfig.PublicHost()`, which resolves in this order —
`SSH_PUBLIC_HOST`, then `FAKE_HOST`, then `FAKE_HOST` in
`/etc/sshvpn/menu.conf`, then the built-in default `can.vps-mosto.site`. Set
`SSH_PUBLIC_HOST` to your own domain before running `vpnctl links` so the
links you hand out point where you want.

## Target validation

`sshproxy` refuses to become a general relay:

| Condition | Response |
|---|---|
| `X-Real-Host` absent | falls back to `127.0.0.1:109` |
| target is not loopback and no password is set | `403 Forbidden` |
| port unparsable, empty (`host:`), `0`, or `> 65535` | `400 BadTarget` |
| dial to target fails | connection closed, logged at WARN |

Loopback means `localhost`, an address that parses to loopback
(`127.0.0.0/8`, `::1`), or a bracketed IPv6 literal such as `[::1]:1443`. It is
a parsed-address comparison, not a string-prefix test, so
`localhost.attacker.example` and `127.0.0.1.evil` are **not** loopback.

If you genuinely need to relay to another host, build with a non-empty `pass`
(`const pass` in `cmd/sshproxy/main.go:27`). The check then becomes an exact
`X-Pass` match instead of the loopback rule.

## Framing selection

After the `101`, if `Sec-WebSocket-Key` was sent, `sshproxy` peeks at the next
byte for up to **2 s** and checks whether it is a WebSocket frame header
(`FIN` set + opcode in `0x0 0x1 0x2 0x8 0x9 0xA`). Otherwise it falls back to
raw TCP relay.

**Practical consequence:** a WebSocket client must send its first frame within
2 s of the handshake. Send the request head and the first data frame back to
back; a client that waits for the banner before speaking will be treated as a
raw client.

Once framed, the relay translates:

- client `0x1`/`0x2` (text/binary) → written to the target as-is
- client `0x9` (ping) → answered `0xA` (pong) with the same payload
- client `0xA` (pong) → ignored
- client `0x8` (close) → `0x8` sent back, both sides closed
- target bytes → client as binary frames

Incoming frames are masked (RFC 6455 requires it from clients); frames sent to
the client are **unmasked** (`writeFrame` never sets the mask bit). Payload
length is capped at 1 MiB per frame.

## X-Split

`X-Split` tells `sshproxy` the client sends its first data packet separately
from the request head. One packet (up to 16 KiB) is read and **discarded**
before relaying starts, bounded by a 2 s deadline so a client blocked on the
`101` cannot deadlock.

This is deliberate parity with the original `ws.py` script. Note the cost: if
your client's first packet carries real data, it is dropped.

## Flow and timeouts

```
client ──head──► sshproxy ──dial 10s──► target (dropbear/sshd)
       ◄──101───            ◄──banner─
       ◄═════ relay (two goroutines, first to EOF closes both) ═════►
```

| Setting | Value |
|---|---|
| Copy buffer | 16 KiB |
| Header read deadline | 10 s |
| Dial timeout | 10 s |
| Frame sniff timeout | 2 s |
| Raw relay idle timeout | 180 s (no traffic → both sides closed) |
| haproxy `timeout client`/`server` | 1 m |
| haproxy `timeout tunnel` | 1 h |

The **raw** relay reaps idle connections after 3 minutes (checked every 3 s).
The **WebSocket** relay has no idle timer of its own — it relies on haproxy's
`timeout tunnel 1h`. An SSH session that sits idle past haproxy's tunnel timeout
will drop; haproxy's `timeout client`/`server` of 1 m only applies to
inactivity *before* the tunnel is established.

## Verifying by hand

With a real `sshd` on `127.0.0.1:2222`:

```bash
# banner relayed through the proxy
printf 'GET / HTTP/1.1\r\nX-Real-Host: 127.0.0.1:2222\r\n\r\n' | nc 127.0.0.1 10015
```

Expected: the `101` banner followed by `SSH-2.0-OpenSSH_...`.

To drive a genuine `ssh(1)` session through the WebSocket path you need a
ProxyCommand that wraps the stream in WebSocket frames; `nc` alone cannot, since
the client must speak framed protocol after the `101`.