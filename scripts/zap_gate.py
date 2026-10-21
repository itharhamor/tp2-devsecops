"""Security gate DAST : lit le rapport JSON de ZAP et échoue au-delà d'un seuil de risque.

Usage : python3 scripts/zap_gate.py zap-report.json --fail-on high \
            --exceptions .zap/false-positives.tsv
Codes de risque ZAP : 0 = Info, 1 = Low, 2 = Medium, 3 = High

Fichier d'exceptions (TSV) : une ligne par faux positif analysé et justifié
    <pluginid> <TAB> <regex sur l'URL> <TAB> <justification>
Une exception ne s'applique qu'à CE plugin ET aux URL qui matchent la regex :
la même faille détectée ailleurs reste bloquante.
"""
import argparse
import json
import re
import sys

LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3}
NAMES = {v: k.upper() for k, v in LEVELS.items()}


def load_exceptions(path):
    exceptions = []
    if not path:
        return exceptions
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            pluginid, url_regex, justification = line.split("\t", 2)
            exceptions.append((pluginid.strip(), re.compile(url_regex.strip()), justification.strip()))
    return exceptions


def find_exception(exceptions, pluginid, uri):
    for exc_id, exc_re, justification in exceptions:
        if exc_id == pluginid and exc_re.search(uri or ""):
            return justification
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--fail-on", choices=LEVELS, default="high")
    parser.add_argument("--exceptions", help="fichier TSV des faux positifs justifiés")
    args = parser.parse_args()
    seuil = LEVELS[args.fail_on]
    exceptions = load_exceptions(args.exceptions)

    with open(args.report, encoding="utf-8") as f:
        data = json.load(f)

    bloquantes, acceptees = [], []
    print(f"{'RISQUE':<8} {'ID':<7} {'NB':<4} ALERTE")
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = int(alert.get("riskcode", 0))
            pluginid = str(alert.get("pluginid", ""))
            instances = alert.get("instances", [])
            print(f"{NAMES[risk]:<8} {pluginid:<7} {len(instances):<4} {alert.get('name', '')}")
            if risk < seuil:
                continue
            for inst in instances or [{}]:
                uri = inst.get("uri", "")
                justification = find_exception(exceptions, pluginid, uri)
                entry = (alert.get("name"), inst.get("method"), uri, inst.get("param"), justification)
                (acceptees if justification else bloquantes).append(entry)

    if acceptees:
        print(f"\n⚠️  {len(acceptees)} instance(s) acceptée(s) comme faux positif documenté :")
        for name, method, uri, param, why in acceptees:
            print(f"   - {name} -> {method} {uri} (param: {param})\n     justification : {why}")

    if bloquantes:
        print(f"\n❌ {len(bloquantes)} instance(s) de niveau >= {args.fail_on.upper()} : pipeline bloqué.")
        for name, method, uri, param, _ in bloquantes:
            print(f"   - {name} -> {method} {uri} (param: {param})")
        sys.exit(1)

    print(f"\n✅ Aucune alerte bloquante de niveau >= {args.fail_on.upper()} : pipeline autorisé.")


if __name__ == "__main__":
    main()