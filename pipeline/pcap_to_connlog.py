#!/usr/bin/env python3
"""
pcap_to_connlog.py -- minimal pcap -> Zeek-conn.log-format TSV, so align_windows.py's
read_zeek_conn() runs on real captured flows without a full Zeek install (INTERIM
stand-in for Zeek; the production network extractor is Zeek on the RPi 5 hub).

Aggregates IPv4 TCP/UDP/ICMP packets into bidirectional flows keyed by the canonical
5-tuple; 'orig' = the endpoint that sent the flow's first packet. Emits the columns
align_windows.read_zeek_conn consumes: ts duration orig_bytes resp_bytes missed_bytes
orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes (+ id fields for readability, dropped
downstream as identity).

Usage: python3 pcap_to_connlog.py in.pcap out_conn.log[.<device>]
"""
import sys, dpkt, socket

def ips(b):
    try: return socket.inet_ntoa(b)
    except Exception: return "?"

def main(pcap_path, out_path):
    flows = {}   # key -> dict
    order = []
    n_pkt = n_ip = 0
    with open(pcap_path, "rb") as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0); reader = dpkt.pcapng.Reader(f)
        for ts, buf in reader:
            n_pkt += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            n_ip += 1
            proto = ip.p
            src, dst = ips(ip.src), ips(ip.dst)
            sp = dp = 0
            l4 = ip.data
            if isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                sp, dp = l4.sport, l4.dport
            iplen = ip.len if ip.len else len(ip)
            # canonical undirected key
            a, b = (src, sp), (dst, dp)
            key = (proto,) + (tuple(sorted((a, b))))
            fl = flows.get(key)
            if fl is None:
                fl = dict(ts=ts, last=ts, orig=a,
                          o_pkts=0, o_bytes=0, r_pkts=0, r_bytes=0)
                flows[key] = fl; order.append(key)
            fl["last"] = max(fl["last"], ts)
            fl["ts"] = min(fl["ts"], ts)
            if a == fl["orig"]:
                fl["o_pkts"] += 1; fl["o_bytes"] += iplen
            else:
                fl["r_pkts"] += 1; fl["r_bytes"] += iplen

    cols = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
            "duration", "orig_bytes", "resp_bytes", "missed_bytes",
            "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]
    pmap = {6: "tcp", 17: "udp", 1: "icmp"}
    with open(out_path, "w", encoding="utf-8") as out:
        out.write("#separator \\x09\n")
        out.write("#fields\t" + "\t".join(cols) + "\n")
        for i, key in enumerate(order):
            fl = flows[key]
            (oh, op) = fl["orig"]
            others = [e for e in key[1:] if e != fl["orig"]]
            rh, rp = others[0] if others else ("?", 0)
            dur = fl["last"] - fl["ts"]
            row = [f"{fl['ts']:.6f}", f"C{i}", oh, str(op), rh, str(rp),
                   pmap.get(key[0], str(key[0])),
                   f"{dur:.6f}", str(fl["o_bytes"]), str(fl["r_bytes"]), "0",
                   str(fl["o_pkts"]), str(fl["o_bytes"]),
                   str(fl["r_pkts"]), str(fl["r_bytes"])]
            out.write("\t".join(row) + "\n")
    print(f"packets={n_pkt} ipv4={n_ip} flows={len(flows)} -> {out_path}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
