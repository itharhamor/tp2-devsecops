# TP 2 — Intégration de la sécurité dans un pipeline CI/CD

Application Flask minimale + pipeline **GitHub Actions** qui joue le rôle de **garde-fou de sécurité** :
aucun code ne peut être fusionné dans `main` si un scanner trouve une faille critique/haute.

> 🛂 **Analogie** : le pipeline est un contrôle d'aéroport. Les tests unitaires vérifient que vous avez
> un billet valide (le code fonctionne). Le SAST passe vos bagages aux rayons X (on lit le code sans
> l'exécuter). Le SCA vérifie que personne dans vos bagages n'est sur une liste noire (dépendances
> avec CVE connues). Le DAST, c'est le test grandeur nature : on fait marcher le passager et on observe
> son comportement (on attaque l'application en cours d'exécution). Un seul voyant rouge = pas d'embarquement.

---

## Structure du dépôt

```
tp2-devsecops/
├── .github/workflows/ci.yml   # Le pipeline (4 jobs)
├── .zap/rules.tsv             # Alertes ZAP informatives ignorées
├── app.py                     # Application SÉCURISÉE
├── demo/app_vulnerable.py     # Version vulnérable pour la démo (exclue des scans)
├── scripts/zap_gate.py        # Security gate DAST (lit le rapport ZAP)
├── tests/test_app.py          # Tests unitaires
├── Dockerfile                 # Image pour l'environnement éphémère
├── requirements.txt
└── requirements-dev.txt
```

## Le pipeline en un coup d'œil

```
build-test ──┬──> sast (Bandit + Semgrep) ──┐
             └──> sca  (Trivy)             ──┴──> dast (Docker + OWASP ZAP)
```

| Job | Outil | Règle de blocage |
|-----|-------|------------------|
| `build-test` | pytest | un test échoue |
| `sast` | Bandit | `--severity-level high` → faille HIGH |
| `sast` | Semgrep | `--severity ERROR --error` → règle de sévérité ERROR |
| `sca` | Trivy | `severity: CRITICAL,HIGH` + `exit-code: 1` |
| `dast` | OWASP ZAP | `zap_gate.py --fail-on high` → alerte de risque High |

---

## Étape 1 — Pipeline de base (45 min)

```bash
# Tester en local avant de pousser
python -m venv .venv && source .venv/bin/activate   # Windows : .venv\Scripts\activate
pip install -r requirements-dev.txt
pytest -v
```

Créez un dépôt vide sur GitHub, puis :

```bash
git init
git add .
git commit -m "TP2 : app + pipeline CI DevSecOps"
git branch -M main
git remote add origin https://github.com/<votre-compte>/tp2-devsecops.git
git push -u origin main
```

Ouvrez l'onglet **Actions** : les 4 jobs doivent passer au vert ✅.

## Étape 2 — SAST + SCA (1 h 30)

Voir les jobs `sast` et `sca` dans `ci.yml`. Points à expliquer dans le compte rendu :

- **Bandit** produit d'abord un rapport complet (toutes sévérités, conservé en artefact) puis une
  2ᵉ exécution « gate » qui n'échoue que sur HIGH → on garde la visibilité sans bloquer pour du bruit.
- **Semgrep** utilise les règles communautaires `p/python` et `p/flask`.
- **Trivy** lit `requirements.txt` et compare chaque version aux bases de CVE.
  `ignore-unfixed` évite de bloquer sur une CVE pour laquelle aucun correctif n'existe encore.

> ⚠️ Sécurité de la chaîne d'approvisionnement : en mars 2026, des tags de `trivy-action` et
> certaines images Trivy (v0.69.4–0.69.6) ont été compromis. Le pipeline épingle donc
> `trivy-action@0.35.0` et Trivy `v0.69.3`. En production, épinglez les actions par **SHA de commit**.

## Étape 3 — DAST (1 h 30)

Job `dast` :
1. `docker build` → construit l'image de l'app.
2. `docker run` → **environnement éphémère** (le conteneur ne vit que le temps du job).
3. Attente active sur `/health` jusqu'à ce que l'app réponde.
4. `zap-full-scan.py` → spider + **scan actif** (ZAP envoie de vraies attaques : injections SQL,
   commandes OS, XSS…). L'option `-I` empêche ZAP d'échouer sur de simples avertissements.
5. `scripts/zap_gate.py` → lit `zap-report.json` et **échoue s'il existe une alerte High**.
6. Rapports HTML/JSON publiés en artefacts, conteneur détruit (`if: always()`).

## Rendre le blocage obligatoire (protection de branche)

Sans cette étape, une PR rouge peut quand même être fusionnée !

**Settings → Branches → Add branch ruleset / protection rule** sur `main` :
- ✅ *Require a pull request before merging*
- ✅ *Require status checks to pass* → ajouter : `Build & tests unitaires`, `SAST (Bandit + Semgrep)`,
  `SCA (Trivy)`, `DAST (OWASP ZAP)`

## Étape 4 — Validation (30 min)

### PR n°1 : vulnérabilité intentionnelle → le pipeline doit ÉCHOUER ❌

```bash
git checkout -b feature/greet-vulnerable
cp demo/app_vulnerable.py app.py
git commit -am "feat: greet via commande système (VULNÉRABLE)"
git push -u origin feature/greet-vulnerable
```
Ouvrez la Pull Request vers `main`. Résultats attendus :

| Job | Résultat | Pourquoi |
|-----|----------|----------|
| build-test | ✅ | les tests fonctionnels passent : **le code « marche »** mais il est dangereux |
| sast | ❌ | Bandit B602 *subprocess shell=True* (HIGH) + Semgrep |
| dast | ⏭️ ignoré | il dépend de `sast` |

> Pour montrer aussi le DAST qui échoue : retirez temporairement `sast` de `needs:` du job `dast`
> (`needs: [build-test]`). ZAP détecte alors *Remote OS Command Injection* (High) et
> *SQL Injection* (High) → `zap_gate.py` bloque.

**Bonus SCA** : dans la même branche, remplacez `flask==3.1.2` par `flask==2.2.1`
(CVE-2023-30861, sévérité HIGH) → le job `sca` échoue aussi.

### PR n°2 : correction → le pipeline doit PASSER ✅

```bash
# On part de la branche vulnérable et on applique le correctif dessus
git checkout feature/greet-vulnerable
git checkout -b fix/greet-secure
git checkout main -- app.py requirements.txt     # restaure la version sécurisée
git commit -m "fix: suppression du shell et requêtes SQL paramétrées"
git push -u origin fix/greet-secure
```
Fermez la PR n°1 (sans fusionner), ouvrez la PR n°2 `fix/greet-secure` → `main`.
Tous les jobs sont verts, le bouton **Merge** est débloqué. Le commit « fix » montre le diff
exact de la correction (utile pour le compte rendu).

### Ce que corrige le patch

| Faille | Avant (vulnérable) | Après (sécurisé) |
|--------|--------------------|------------------|
| Injection de commande | `subprocess.check_output(f"echo Bonjour {name}", shell=True)` | `f"Bonjour {name}"` (aucun shell) |
| Injection SQL | `f"... WHERE name = '{name}'"` | `"... WHERE name = ?", (name,)` |

---

## Captures à mettre dans le compte rendu
1. Onglet Actions avec le pipeline vert sur `main`.
2. PR vulnérable : jobs en rouge + logs Bandit (B602) et/ou sortie de `zap_gate.py`.
3. Rapport `zap-report.html` (téléchargeable dans les artefacts du run).
4. PR corrigée : tous les checks verts et bouton Merge actif.
5. Écran de la règle de protection de branche.
