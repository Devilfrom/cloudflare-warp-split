import re

REAL = """Tunnel Protocol: MASQUE (HTTPS via UDP)
Endpoints: 162.159.198.2, ::
Time since last handshake: 23s
Sent: 63.2kB; Received: 78.0kB
Estimated latency: 290ms
Estimated loss: 0.36%
TLS Handshake:
\tVersion: TLSv1.3
\tPost-Quantum enabled: true
\tElliptic curve: P256Kyber768Draft00
\tCipher suite: TLS_AES_256_GCM_SHA384
Colo: LAX (1164f21)"""


def _parse_size(s):
    m = re.match(r"^\s*([\d.]+)\s*([KMGT]?B)\s*$", str(s), re.I)
    if not m:
        return None
    mult = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
    try:
        return int(float(m.group(1)) * mult[m.group(2).upper()])
    except Exception:
        return None


st = {"protocol": "", "endpoints": "", "handshake_s": None, "sent": None,
      "received": None, "latency_ms": None, "loss_pct": None,
      "tls_version": "", "post_quantum": False, "colo": ""}
for line in REAL.splitlines():
    line = line.strip()
    low = line.lower()
    if low.startswith("tunnel protocol:"):
        st["protocol"] = line.split(":", 1)[1].strip()
    elif low.startswith("endpoints:"):
        ep = line.split(":", 1)[1].strip()
        st["endpoints"] = ep.split(",")[0].strip() if ep else ""
    elif low.startswith("time since last handshake:"):
        v = line.split(":", 1)[1].strip().rstrip("s")
        try:
            st["handshake_s"] = int(float(v))
        except Exception:
            pass
    elif low.startswith("sent:"):
        m = re.search(r"sent:\s*([\d.]+\s*[KMGT]?B)", line, re.I)
        print("DEBUG sent regex match:", m.group(1) if m else None)
        if m:
            st["sent"] = _parse_size(m.group(1))
        m = re.search(r"received:\s*([\d.]+\s*[KMGT]?B)", line, re.I)
        print("DEBUG recv regex match:", m.group(1) if m else None)
        if m:
            st["received"] = _parse_size(m.group(1))
    elif low.startswith("estimated latency:"):
        v = line.split(":", 1)[1].strip().lower().replace("ms", "")
        try:
            st["latency_ms"] = round(float(v), 1)
        except Exception:
            pass
    elif low.startswith("estimated loss:"):
        v = line.split(":", 1)[1].strip().replace("%", "")
        try:
            st["loss_pct"] = round(float(v), 3)
        except Exception:
            pass
    elif low.startswith("version:"):
        st["tls_version"] = line.split(":", 1)[1].strip()
    elif low.startswith("post-quantum enabled:"):
        st["post_quantum"] = "true" in low
    elif low.startswith("colo:"):
        st["colo"] = line.split(":", 1)[1].strip()
st["ok"] = st["latency_ms"] is not None

for k, v in st.items():
    print("%-14s = %r" % (k, v))
assert st["protocol"] == "MASQUE (HTTPS via UDP)"
assert st["endpoints"] == "162.159.198.2"
assert st["sent"] == int(63.2 * 1024), "sent parse failed"
assert st["received"] == int(78.0 * 1024), "received parse failed"
assert st["latency_ms"] == 290.0 and st["loss_pct"] == 0.36
assert st["tls_version"] == "TLSv1.3" and st["post_quantum"] and st["colo"].startswith("LAX")
print("ALL ASSERTIONS PASS")
