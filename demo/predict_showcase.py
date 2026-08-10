#!/usr/bin/env python3
"""
Guaranteed-to-work showcase of the ML model's reasoning/confidence and the
explainability module 
"""

import argparse
import json
import sys
import time

try:
    import requests
except ImportError:
    print("ERROR: requires the 'requests' package: pip install requests")
    sys.exit(1)


DEMO_USER = {
    "username": "demo_presenter",
    "email": "demo_presenter@example.com",
    "password": "DemoPass123",
}

EXAMPLE_RULE = "SYN_Flag_Cnt > 5 AND RST_Flag_Cnt > 3 AND Flow_Byts/s > 1000"

# Feature vectors shaped to resemble the attack classes in CSE-CIC-IDS2018
# (short, one-directional, high SYN/RST counts, high byte rate) vs.
# ordinary completed-session traffic (balanced fwd/bwd, moderate rates,
# more ACK/PSH than SYN/RST). Field names must exactly match
# rules.ast_nodes.FEATURE_FIELDS - see backend/src/rules/ast_nodes.py.
def _base_vector():
    return {f: 0 for f in [
        'Dst_Port', 'Protocol', 'Flow_Duration', 'Tot_Fwd_Pkts', 'Tot_Bwd_Pkts',
        'TotLen_Fwd_Pkts', 'TotLen_Bwd_Pkts', 'Fwd_Pkt_Len_Max', 'Fwd_Pkt_Len_Min',
        'Fwd_Pkt_Len_Mean', 'Fwd_Pkt_Len_Std', 'Bwd_Pkt_Len_Max', 'Bwd_Pkt_Len_Min',
        'Bwd_Pkt_Len_Mean', 'Bwd_Pkt_Len_Std', 'Flow_Byts/s', 'Flow_Pkts/s',
        'Flow_IAT_Mean', 'Flow_IAT_Std', 'Flow_IAT_Max', 'Flow_IAT_Min',
        'Fwd_IAT_Tot', 'Fwd_IAT_Mean', 'Fwd_IAT_Std', 'Fwd_IAT_Max', 'Fwd_IAT_Min',
        'Bwd_IAT_Tot', 'Bwd_IAT_Mean', 'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min',
        'Fwd_PSH_Flags', 'Bwd_PSH_Flags', 'Fwd_URG_Flags', 'Bwd_URG_Flags',
        'Fwd_Header_Len', 'Bwd_Header_Len', 'Fwd_Pkts/s', 'Bwd_Pkts/s',
        'Pkt_Len_Min', 'Pkt_Len_Max', 'Pkt_Len_Mean', 'Pkt_Len_Std', 'Pkt_Len_Var',
        'FIN_Flag_Cnt', 'SYN_Flag_Cnt', 'RST_Flag_Cnt', 'PSH_Flag_Cnt',
        'ACK_Flag_Cnt', 'URG_Flag_Cnt', 'CWE_Flag_Count', 'ECE_Flag_Cnt',
        'Down/Up_Ratio', 'Pkt_Size_Avg', 'Fwd_Seg_Size_Avg', 'Bwd_Seg_Size_Avg',
        'Fwd_Byts/b_Avg', 'Fwd_Pkts/b_Avg', 'Fwd_Blk_Rate_Avg',
        'Bwd_Byts/b_Avg', 'Bwd_Pkts/b_Avg', 'Bwd_Blk_Rate_Avg',
        'Subflow_Fwd_Pkts', 'Subflow_Fwd_Byts', 'Subflow_Bwd_Pkts',
        'Subflow_Bwd_Byts', 'Init_Fwd_Win_Byts', 'Init_Bwd_Win_Byts',
        'Fwd_Act_Data_Pkts', 'Fwd_Seg_Size_Min', 'Active_Mean', 'Active_Std',
        'Active_Max', 'Active_Min', 'Idle_Mean', 'Idle_Std', 'Idle_Max', 'Idle_Min',
    ]}


def syn_flood_vector():
    v = _base_vector()
    v.update({
        "Dst_Port": 80, "Protocol": 6, "Flow_Duration": 50_000,
        "Tot_Fwd_Pkts": 40, "Tot_Bwd_Pkts": 2,
        "TotLen_Fwd_Pkts": 2400, "TotLen_Bwd_Pkts": 108,
        "Fwd_Pkt_Len_Max": 60, "Fwd_Pkt_Len_Mean": 60,
        "Flow_Byts/s": 50160, "Flow_Pkts/s": 840,
        "SYN_Flag_Cnt": 40, "RST_Flag_Cnt": 2, "ACK_Flag_Cnt": 2,
        "Fwd_Pkts/s": 800, "Bwd_Pkts/s": 40,
        "Pkt_Len_Mean": 57, "Down/Up_Ratio": 0.05,
        "Init_Fwd_Win_Byts": 64240,
    })
    return v


def port_scan_vector():
    v = _base_vector()
    v.update({
        "Dst_Port": 443, "Protocol": 6, "Flow_Duration": 500,
        "Tot_Fwd_Pkts": 1, "Tot_Bwd_Pkts": 1,
        "TotLen_Fwd_Pkts": 60, "TotLen_Bwd_Pkts": 60,
        "SYN_Flag_Cnt": 1, "RST_Flag_Cnt": 1,
        "Flow_Byts/s": 240000, "Flow_Pkts/s": 4000,
        "Pkt_Len_Mean": 60,
    })
    return v


def benign_web_vector():
    v = _base_vector()
    v.update({
        "Dst_Port": 443, "Protocol": 6, "Flow_Duration": 2_500_000,
        "Tot_Fwd_Pkts": 18, "Tot_Bwd_Pkts": 22,
        "TotLen_Fwd_Pkts": 3200, "TotLen_Bwd_Pkts": 21000,
        "Fwd_Pkt_Len_Mean": 178, "Bwd_Pkt_Len_Mean": 954,
        "Flow_Byts/s": 9680, "Flow_Pkts/s": 16,
        "SYN_Flag_Cnt": 1, "ACK_Flag_Cnt": 38, "PSH_Flag_Cnt": 14, "FIN_Flag_Cnt": 1,
        "Fwd_Pkts/s": 7.2, "Bwd_Pkts/s": 8.8,
        "Pkt_Len_Mean": 601, "Down/Up_Ratio": 1.2,
        "Init_Fwd_Win_Byts": 64240, "Init_Bwd_Win_Byts": 65535,
        "Active_Mean": 900_000, "Idle_Mean": 200_000,
    })
    return v


def step(msg):
    print(f"\n=== {msg} ===")


def main():
    parser = argparse.ArgumentParser(description="Guaranteed ML/explainability/rule-engine demo showcase")
    parser.add_argument("--api", default="http://localhost:5000/api", help="Backend API base URL")
    args = parser.parse_args()
    api = args.api.rstrip("/")

    step("Registering (or reusing) demo account")
    resp = requests.post(f"{api}/auth/register", json=DEMO_USER)
    if resp.status_code == 409:
        resp = requests.post(f"{api}/auth/login", json={"email": DEMO_USER["email"], "password": DEMO_USER["password"]})
    resp.raise_for_status()
    token = resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("Logged in as", DEMO_USER["username"])

    step("Upgrading to Enterprise (dummy test card - no real payment processor involved)")
    resp = requests.post(
        f"{api}/auth/upgrade",
        headers=headers,
        json={"tier": "enterprise", "card_number": "4111111111111111", "exp_month": 12, "exp_year": 2030, "cvc": "123"},
    )
    if resp.ok:
        token = resp.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        print("Upgraded. Custom rules are now unlocked for this account.")
    else:
        print("Upgrade call failed (continuing anyway):", resp.text)

    step("Creating the example SYN-flood rule")
    resp = requests.post(
        f"{api}/rules/",
        headers=headers,
        json={"name": "Demo: SYN flood", "rule_text": EXAMPLE_RULE, "severity": "high", "enabled": True},
    )
    print(resp.json() if resp.ok else resp.text)

    step("Checking model status")
    resp = requests.get(f"{api}/model/status")
    print(json.dumps(resp.json(), indent=2))
    if not resp.ok:
        print(
            "\nModel isn't installed yet - predictions below will 503.\n"
            "Run: python installer/setup_wizard.py --skip-venv --model-dir <path-to-model-files>"
        )

    scenarios = [
        ("SYN flood shape", syn_flood_vector(), "203.0.113.10"),
        ("Port scan shape", port_scan_vector(), "203.0.113.11"),
        ("Ordinary HTTPS session", benign_web_vector(), "203.0.113.99"),
    ]

    for label, vector, source_ip in scenarios:
        step(f"Prediction: {label}")
        resp = requests.post(
            f"{api}/predict",
            json={"features": vector, "source_ip": source_ip, "dest_ip": "192.168.1.50"},
        )
        if not resp.ok:
            print("Request failed:", resp.text)
            continue
        result = resp.json()["result"]
        print(f"Prediction:  {result['prediction']}")
        print(f"Confidence:  {result['confidence']:.1%}")
        print(f"Explanation: {result['explanation']}")
        if resp.json().get("alert"):
            print("-> Alert raised on the dashboard.")
        time.sleep(1)

    step("Done")
    print("Open the dashboard now - you should see the SYN flood and port scan predictions as alerts.")


if __name__ == "__main__":
    main()
