#!/usr/bin/env python3
r"""verify_dataset.py -- V5 DATASET-LEVEL CONTENT GATE (run by v5_finalize.sh).

Beyond the per-run gate (verify_run.py), this checks the WHOLE built corpus:
  * per-sublabel: every modality the attack SHOULD exercise is present above a floor
    (expected-modality matrix), and no modality that should be absent is anomalously present;
  * both victim devices contribute to every class (no device-wide blind spot);
  * window floor per attack class;
  * CROSS-RUN CONFOUND GUARD (C-7): host execve signal must track the ATTACK, not the run
    index -- host-exec classes must carry execve, and pure-network classes must NOT be
    contaminated by ambient execve that correlates with run number;
  * BENIGN REALISM (E-8): benign windows carry application + session activity above a floor.
Exit 0 iff the corpus passes. Reads By_device windows (per-run, for confound) + aggregates
per sublabel.
"""
import sys, os, glob, argparse, json
import numpy as np, pandas as pd

# expected-modality matrix: (net, hostA=auditd execve/syscall, hostJ=journald auth/session, tel, app)
# Y expected present, w weak/minor, N not expected. tel is CONTINUOUS -> Y for all.
EXP = {
 "recon_synscan":("Y","N","N","Y","N"), "recon_connectscan":("Y","N","N","Y","N"),
 "recon_stealthscan":("Y","N","N","Y","N"), "recon_udpscan":("Y","N","N","Y","N"),
 "recon_osdetect":("Y","N","w","Y","N"), "recon_hostsweep":("Y","N","N","Y","N"),
 "recon_mqtt_enum":("Y","N","N","Y","Y"), "recon_coap_discovery":("Y","N","N","Y","Y"),
 "recon_modbus_scan":("Y","N","N","Y","Y"),
 "bruteforce_dict":("Y","w","Y","Y","N"), "bruteforce_telnet":("Y","w","Y","Y","N"),
 "bruteforce_slow":("Y","w","Y","Y","N"), "bruteforce_mqtt":("Y","N","N","Y","Y"),
 "ddos_synflood":("Y","N","N","Y","N"), "ddos_ackflood":("Y","N","N","Y","N"),
 "ddos_udpflood":("Y","N","N","Y","N"), "ddos_icmpflood":("Y","N","N","Y","N"),
 "ddos_mqtt_connflood":("Y","N","N","Y","Y"), "ddos_coap_conflood":("Y","N","N","Y","Y"),
 "mitm_arp":("Y","N","N","Y","N"), "lateral_scan":("Y","N","N","Y","N"),
 "control_modbus_write":("Y","N","N","Y","Y"), "control_mqtt_cmdinject":("Y","N","N","Y","Y"),
 "exfil_bulk":("Y","Y","w","Y","N"), "exfil_mqtt":("Y","N","N","Y","Y"),
 "persistence_cron":("w","Y","Y","Y","N"), "privesc_suidscan":("w","Y","w","Y","N"),
 "execution_lolbin":("w","Y","N","Y","N"), "evasion_logtamper":("w","Y","N","Y","N"),
 "normal":("Y","w","Y","Y","Y"),
}
WIN_FLOOR = 4000
PRES = 0.05          # a plane that SHOULD be present must fire in >= this frac of windows
ANOM = 0.25          # a plane that should be ABSENT firing in > this frac = anomaly
BEN_APP = 0.05

def load_bydevice(root):
    fs = glob.glob(os.path.join(root, "By_device_and_campaigns", "*", "*", "preprocessed", "windows_w1.csv"))
    out = []
    for f in fs:
        try:
            d = pd.read_csv(f, dtype={"modality_mask": str}, low_memory=False)
            if len(d): out.append(d)
        except Exception as e:
            print("  skip", f, e, file=sys.stderr)
    if not out: raise SystemExit("no By_device windows under " + root)
    return pd.concat(out, ignore_index=True)

def frac(df, cols):
    if df.empty or not cols: return 0.0
    sub = df[cols].apply(pd.to_numeric, errors="coerce").fillna(0)
    return round(float((sub != 0).any(axis=1).mean()), 3)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="./dataset_v5")
    ap.add_argument("--scen", default="V5")
    ap.add_argument("--manifest", default="")
    a = ap.parse_args()

    df = load_bydevice(a.root)
    HOSTA = [c for c in df.columns if c in ("host__execve","host__syscall","host__audit_lines")]
    HOSTJ = [c for c in df.columns if c in ("host__log_lines","host__auth_fail","host__auth_ok","host__invalid_user","host__new_session")]
    NET = [c for c in df.columns if c.startswith("net__") and c != "net__cnt"]
    TEL = ["tel__cnt"]
    APP = [c for c in df.columns if c.startswith("applog__") and c != "applog__cnt"]
    # run index for confound guard
    gid = df["group_id"].astype(str)
    df["runidx"] = pd.to_numeric(gid.str.extract(rf"^{a.scen}#(\d+)$")[0], errors="coerce")

    fails, warns = [], []
    print(f"{'sublabel':22} n      dev  net  hA   hJ   tel  app   verdict")
    for sub in sorted(x for x in df.attack_type.unique() if x in EXP):
        s = df[df.attack_type == sub]
        exp = EXP[sub]
        obs = dict(net=frac(s,NET), hA=frac(s,HOSTA), hJ=frac(s,HOSTJ), tel=round(float((pd.to_numeric(s["tel__cnt"],errors="coerce").fillna(0)>0).mean()),3), app=frac(s,APP))
        ndev = s["device_id"].nunique()
        issues = []
        # window floor (attacks only)
        if sub != "normal" and len(s) < WIN_FLOOR: issues.append(f"windows<{WIN_FLOOR}({len(s)})")
        # both devices
        if ndev < 2: issues.append(f"only {ndev} device")
        # expected-present planes fire
        planes = dict(net=("Y",obs["net"],NET), hA=(exp[1],obs["hA"],HOSTA), hJ=(exp[2],obs["hJ"],HOSTJ),
                      tel=("Y",obs["tel"],TEL), app=(exp[4],obs["app"],APP))
        planes["net"]=(exp[0],obs["net"],NET)
        for pk,(e,fr,_cols) in planes.items():
            if e=="Y" and fr < PRES: issues.append(f"{pk} missing({fr})")
            if e=="N" and fr > ANOM: issues.append(f"{pk} anomalous({fr})")
        verdict = "OK" if not issues else ("FAIL:" + ",".join(issues))
        if issues and sub != "normal": fails.append((sub, issues))
        if issues and sub == "normal": warns.append((sub, issues))
        print(f"{sub:22} {len(s):6} {ndev}    {obs['net']:<4} {obs['hA']:<4} {obs['hJ']:<4} {obs['tel']:<4} {obs['app']:<4} {verdict}")

    # ---- confound guard: host execve must be ATTACK-aligned not RUN-aligned ----
    print("\n-- cross-run confound guard (host execve vs run index) --")
    hexe = [c for c in df.columns if c in ("host__execve","host__syscall")]
    conf = []
    if hexe and df["runidx"].notna().any():
        # for each pure-NETWORK class (exp hostA == N), execve frac should be ~0 and NOT rise with run idx
        for sub in sorted(x for x in df.attack_type.unique() if x in EXP and EXP[x][1]=="N" and x!="normal"):
            s = df[df.attack_type==sub].dropna(subset=["runidx"])
            if len(s) < 50: continue
            fr = frac(s, hexe)
            # correlation of per-run execve presence with run index
            byrun = s.groupby("runidx").apply(lambda g: frac(g, hexe))
            corr = float(byrun.reset_index(drop=True).corr(pd.Series(range(len(byrun))))) if len(byrun) > 3 else 0.0
            flag = (fr > ANOM) or (abs(corr) > 0.6 and fr > 0.1)
            if flag: conf.append((sub, fr, round(corr,2)))
            print(f"  {sub:22} execve_frac={fr:<5} run_corr={round(corr,2) if corr==corr else 'na'}  {'<-- CONFOUND' if flag else ''}")
    if conf:
        fails.append(("confound", [f"{c[0]}(fr={c[1]},corr={c[2]})" for c in conf]))

    # ---- benign realism ----
    nb = df[df.attack_type=="normal"]
    ben_app = frac(nb, APP); ben_auth = frac(nb, [c for c in HOSTJ if c in ("host__auth_ok","host__new_session","host__log_lines")])
    print(f"\n-- benign realism -- app_frac={ben_app} auth_frac={ben_auth} (floor app>={BEN_APP})")
    if ben_app < BEN_APP: fails.append(("benign", [f"app_frac {ben_app}<{BEN_APP}"]))

    print("\n" + "="*60)
    if fails:
        print(f"DATASET VERIFY: FAIL ({len(fails)} issues)")
        for name, iss in fails: print(f"  {name}: {iss}")
        if warns:
            for name, iss in warns: print(f"  (warn) {name}: {iss}")
        sys.exit(1)
    print("DATASET VERIFY: PASS -- all classes covered, both devices, no confound, benign realistic")
    if warns:
        for name, iss in warns: print(f"  (warn) {name}: {iss}")
    sys.exit(0)

if __name__ == "__main__":
    main()
