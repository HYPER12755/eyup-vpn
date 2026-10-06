#!/usr/bin/env python3
"""Marker-based Xray config editor used by xraymenu.

The legacy layout stores users as a pair of text lines after each inbound
marker, e.g. for VLESS:

    #vless                       <- insertion marker (one per inbound)
    #& baba 2026-11-01           <- user + expiry line
    },{"id": "<uuid>","email": "baba"

Xray ignores the `#`-prefixed lines, so the file stays valid config. The same
scheme is used by the compiled legacy tools and by the limit.* daemons, which
is why this script edits the text instead of rewriting the JSON.

Prefixes per protocol: vless `#&`, vmess `###`, trojan `#!`.
"""

import argparse
import base64
import datetime
import json
import os
import shutil
import subprocess
import sys
import uuid as uuidlib

CONFIG = os.environ.get("XRAY_CONFIG", "/etc/xray/config.json")
XRAY_BIN = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
DB_ROOT = os.environ.get("XRAY_DBDIR", "/etc")
DOMAIN = os.environ.get("XRAY_DOMAIN", "")

PROTOCOLS = {
    "vless": {
        "prefix": "#&",
        "markers": ("#vless", "#vlessgrpc"),
        "db": "vless/.vless.db",
        "db_prefix": "###",
    },
    "vmess": {
        "prefix": "###",
        "markers": ("#vmess", "#vmessgrpc"),
        "db": "vmess/.vmess.db",
        "db_prefix": "###",
    },
    "trojan": {
        "prefix": "#!",
        "markers": ("#trojanws", "#trojangrpc"),
        "db": "trojan/.trojan.db",
        "db_prefix": "#!",
    },
}


def read_lines(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().splitlines()


def write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def injection(proto, user, uid):
    if proto == "vless":
        return '},{"id": "%s","email": "%s"' % (uid, user)
    if proto == "vmess":
        return '},{"id": "%s","alterId": 0,"email": "%s"' % (uid, user)
    return '},{"password": "%s","email": "%s"' % (uid, user)


def user_line_matches(line, prefix, user):
    stripped = line.strip()
    return stripped == prefix + " " + user or stripped.startswith(prefix + " " + user + " ")


def collect_rows():
    """Returns (proto, user, expiry, uid) for every marker user in the config."""
    lines = read_lines(CONFIG)
    prefixes = [(proto, PROTOCOLS[proto]["prefix"] + " ") for proto in PROTOCOLS]
    rows = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        for proto, prefix in prefixes:
            if not stripped.startswith(prefix):
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            user = parts[1]
            expiry = parts[2] if len(parts) > 2 else ""
            uid = ""
            if index + 1 < len(lines):
                nxt = lines[index + 1]
                for key in ("id", "password"):
                    token = '"%s": "' % key
                    if token in nxt:
                        uid = nxt.split(token, 1)[1].split('"', 1)[0]
                        break
            row = (proto, user, expiry or "süresiz", uid)
            if row not in rows:
                rows.append(row)
    return rows


def remove_pairs(lines, prefix, user):
    out, removed, index = [], 0, 0
    while index < len(lines):
        if user_line_matches(lines[index], prefix, user):
            removed += 1
            index += 1
            if index < len(lines) and lines[index].lstrip().startswith("},{"):
                index += 1
            continue
        out.append(lines[index])
        index += 1
    return out, removed


def config_test():
    """Validate the config with the Xray binary ("run -test" only parses)."""
    try:
        result = subprocess.run(
            [XRAY_BIN, "run", "-c", CONFIG, "-test"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        return False, "xray bulunamadı: %s" % XRAY_BIN
    if result.returncode == 0:
        return True, ""
    return False, "\n".join(result.stderr.strip().splitlines()[-3:])


def write_validated(lines):
    """Backup, write, validate; restore the backup when validation fails."""
    backup = CONFIG + ".bak"
    shutil.copy2(CONFIG, backup)
    write_lines(CONFIG, lines)
    ok, err = config_test()
    if not ok:
        shutil.copy2(backup, CONFIG)
        print("HATA: config doğrulanamadı, değişiklik geri alındı.", file=sys.stderr)
        if err:
            print(err, file=sys.stderr)
        return False
    return True


def update_db(proto, user, expiry, uid):
    spec = PROTOCOLS[proto]
    path = os.path.join(DB_ROOT, spec["db"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = read_lines(path) if os.path.exists(path) else ["& plughin Account"]
    lines = [line for line in lines if not user_line_matches(line, spec["db_prefix"], user)]
    lines.append("%s %s %s %s 0 " % (spec["db_prefix"], user, expiry, uid))
    write_lines(path, lines)


def cmd_add(args):
    spec = PROTOCOLS[args.proto]
    uid = args.uuid or str(uuidlib.uuid4())
    expiry = ""
    if args.days > 0:
        expiry = (datetime.date.today() + datetime.timedelta(days=args.days)).isoformat()

    lines, _ = remove_pairs(read_lines(CONFIG), spec["prefix"], args.user)
    user_line = ("%s %s %s" % (spec["prefix"], args.user, expiry)).rstrip() + " "
    out = []
    marker_count = 0
    for line in lines:
        out.append(line)
        if line.strip() in spec["markers"]:
            marker_count += 1
            out.append(user_line)
            out.append(injection(args.proto, args.user, uid))

    if marker_count == 0:
        print("HATA: %s için marker bulunamadı (%s)." % (args.proto, ", ".join(spec["markers"])), file=sys.stderr)
        return 1

    if not write_validated(out):
        return 1
    update_db(args.proto, args.user, expiry, uid)

    print("USER=%s" % args.user)
    print("UUID=%s" % uid)
    print("EXPIRY=%s" % (expiry or "süresiz"))
    print("MARKERS=%d" % marker_count)
    return 0


def cmd_del(args):
    spec = PROTOCOLS[args.proto]
    lines, removed = remove_pairs(read_lines(CONFIG), spec["prefix"], args.user)
    if removed == 0:
        print("HATA: %s için '%s' bulunamadı." % (args.proto, args.user), file=sys.stderr)
        return 1
    if not write_validated(lines):
        return 1

    db = os.path.join(DB_ROOT, spec["db"])
    if os.path.exists(db):
        keep = [line for line in read_lines(db) if not user_line_matches(line, spec["db_prefix"], args.user)]
        write_lines(db, keep)

    print("Silindi: %s (%s, %d kayıt)" % (args.user, args.proto, removed))
    return 0


def cmd_list(args):
    rows = collect_rows()
    if args.tsv:
        for proto, user, expiry, uid in rows:
            print("%s\t%s\t%s\t%s" % (proto, user, expiry, uid))
        return 0

    if not rows:
        print("Kayıtlı Xray kullanıcısı yok.")
        return 0
    print("%-8s %-14s %-12s %s" % ("PROTO", "KULLANICI", "BİTİŞ", "UUID/ŞİFRE"))
    for proto, user, expiry, uid in rows:
        print("%-8s %-14s %-12s %s" % (proto, user, expiry, uid))
    return 0


def vmess_payload(user, uid, net, path):
    return base64.b64encode(json.dumps({
        "v": "2", "ps": user, "add": DOMAIN, "port": "443", "id": uid, "aid": "0",
        "scy": "auto", "net": net, "type": "none", "host": DOMAIN,
        "path": path, "tls": "tls", "sni": DOMAIN,
    }, separators=(",", ":")).encode()).decode()


def cmd_links(args):
    if not DOMAIN:
        print("HATA: domain bilinmiyor (XRAY_DOMAIN ya da /etc/xray/domain).", file=sys.stderr)
        return 1

    found = False
    for proto, user, _expiry, uid in collect_rows():
        if user != args.user:
            continue
        found = True
        if proto == "vless":
            print("VLESS  WS  : vless://%s@%s:443?encryption=none&security=tls&sni=%s&type=ws&host=%s&path=%%2Fvless#%s" % (uid, DOMAIN, DOMAIN, DOMAIN, user))
            print("VLESS  gRPC: vless://%s@%s:443?encryption=none&security=tls&sni=%s&type=grpc&serviceName=vless-grpc#%s" % (uid, DOMAIN, DOMAIN, user))
        elif proto == "vmess":
            print("VMess  WS  : vmess://%s" % vmess_payload(user, uid, "ws", "/vmess"))
            print("VMess  gRPC: vmess://%s" % vmess_payload(user, uid, "grpc", "vmess-grpc"))
        else:
            print("Trojan WS  : trojan://%s@%s:443?security=tls&sni=%s&type=ws&host=%s&path=%%2Ftrojan-ws#%s" % (uid, DOMAIN, DOMAIN, DOMAIN, user))
            print("Trojan gRPC: trojan://%s@%s:443?security=tls&sni=%s&type=grpc&serviceName=trojan-grpc#%s" % (uid, DOMAIN, DOMAIN, user))
    if not found:
        print("HATA: '%s' bulunamadı." % args.user, file=sys.stderr)
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add")
    add.add_argument("proto", choices=sorted(PROTOCOLS))
    add.add_argument("user")
    add.add_argument("--days", type=int, default=30)
    add.add_argument("--uuid", default="")
    add.set_defaults(func=cmd_add)

    delete = sub.add_parser("del")
    delete.add_argument("proto", choices=sorted(PROTOCOLS))
    delete.add_argument("user")
    delete.set_defaults(func=cmd_del)

    listing = sub.add_parser("list")
    listing.add_argument("--tsv", action="store_true")
    listing.set_defaults(func=cmd_list)

    links = sub.add_parser("links")
    links.add_argument("user")
    links.set_defaults(func=cmd_links)

    test = sub.add_parser("test")
    test.set_defaults(func=lambda _args: 0 if config_test()[0] else 1)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
