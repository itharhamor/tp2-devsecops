"""Security gate DAST : lit le rapport JSON de ZAP et échoue au-delà d'un seuil de risque.

Usage : python3 scripts/zap_gate.py zap-report.json --fail-on high
Codes de risque ZAP : 0 = Info, 1 = Low, 2 = Medium, 3 = High
"""
import argparse
import json
import sys

LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3}
NAMES = {v: k.upper() for k, v in LEVELS.items()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--fail-on", choices=LEVELS, default="high")
    args = parser.parse_args()
    seuil = LEVELS[args.fail_on]

    with open(args.report, encoding="utf-8") as f:
        data = json.load(f)

    bloquantes = []
    print(f"{'RISQUE':<8} {'ID':<7} {'NB':<4} ALERTE")
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = int(alert.get("riskcode", 0))
            nb = len(alert.get("instances", []))
            print(f"{NAMES[risk]:<8} {alert.get('pluginid', ''):<7} {nb:<4} {alert.get('name', '')}")
            if risk >= seuil:
                bloquantes.append(alert)

    if bloquantes:
        print(f"\n❌ {len(bloquantes)} alerte(s) de niveau >= {args.fail_on.upper()} : pipeline bloqué.")
        for a in bloquantes:
            for inst in a.get("instances", [])[:3]:
                print(f"   - {a.get('name')} -> {inst.get('method')} {inst.get('uri')} (param: {inst.get('param')})")
        sys.exit(1)

    print(f"\n✅ Aucune alerte de niveau >= {args.fail_on.upper()} : pipeline autorisé.")


if __name__ == "__main__":
    main()
