# TP 2 DevSecOps — Sécurité dans un pipeline CI/CD

Petite application **Flask** protégée par un pipeline **GitHub Actions** qui sert de garde-fou de sécurité.
À chaque push et à chaque pull request, le code est testé puis analysé par trois familles d'outils.
Si une faille de sévérité haute ou critique est détectée, le pipeline échoue et la fusion dans `main` est bloquée.

## Le pipeline

```
Build & tests ──┬──> SAST (Bandit + Semgrep) ──┐
   (pytest)     └──> SCA  (Trivy)             ──┴──> DAST (Docker + OWASP ZAP)
```

| Étape | Outil | Ce qu'elle vérifie | Bloque si |
|-------|-------|--------------------|-----------|
| Build & tests | pytest | Le code fonctionne | un test échoue |
| SAST | Bandit, Semgrep | Le code source, sans l'exécuter | faille High / règle ERROR |
| SCA | Trivy | Les dépendances (CVE connues) | CVE Critical ou High |
| DAST | OWASP ZAP | L'application en cours d'exécution, attaquée | alerte High non justifiée |

## L'application

| Route | Rôle |
|-------|------|
| `GET /` | Page d'accueil avec des liens vers les autres routes |
| `GET /health` | Vérifie que l'application répond |
| `GET /greet?name=` | Renvoie un message de bienvenue |
| `GET /user?name=` | Recherche un utilisateur dans une base SQLite en mémoire |

Chaque réponse porte des en-têtes de sécurité HTTP (CSP, X-Frame-Options, Cross-Origin-*, etc.).

## Les fichiers

```
tp2-devsecops/
├── .github/workflows/ci.yml
├── .zap/
│   ├── rules.tsv
│   └── false-positives.tsv
├── demo/app_vulnerable.py
├── scripts/zap_gate.py
├── tests/test_app.py
├── app.py
├── Dockerfile
├── pytest.ini
├── requirements.txt
├── requirements-dev.txt
├── .gitignore
└── README.md
```

| Fichier | Rôle |
|---------|------|
| `app.py` | L'application Flask, version **sécurisée** : pas d'appel au shell, requêtes SQL paramétrées, en-têtes de sécurité. |
| `tests/test_app.py` | 5 tests unitaires : les 3 routes, le cas « utilisateur introuvable » et la présence des en-têtes de sécurité. |
| `pytest.ini` | Configure pytest : ajoute la racine du projet au chemin Python pour que les tests trouvent `app.py`. |
| `requirements.txt` | Dépendances de l'application (Flask, gunicorn), versions fixées. C'est ce fichier que Trivy analyse. |
| `requirements-dev.txt` | Dépendances de développement en plus : pytest et Bandit. |
| `Dockerfile` | Image de l'application pour le DAST : base `python:3.12-slim`, utilisateur non root, serveur gunicorn sur le port 5000. |
| `.github/workflows/ci.yml` | Le pipeline : les 4 jobs, leurs dépendances et leurs règles de blocage. |
| `scripts/zap_gate.py` | Security gate du DAST : lit le rapport JSON de ZAP et fait échouer le pipeline s'il reste une alerte de risque High. |
| `.zap/false-positives.tsv` | Faux positifs ZAP analysés et justifiés. Chaque exception ne vaut que pour une règle **et** une URL précises. |
| `.zap/rules.tsv` | Alertes ZAP purement informatives, marquées comme ignorées. |
| `demo/app_vulnerable.py` | Version **volontairement vulnérable** (injection de commande dans `/greet`, injection SQL dans `/user`), utilisée pour démontrer que le pipeline bloque. Exclue des scans pour que `main` reste vert. |
| `.gitignore` | Exclut l'environnement virtuel, les caches, les rapports générés et les fichiers `.env`. |

## Lancer le projet en local

PowerShell (Windows) :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pytest -v
flask --app app run
```

L'application est alors accessible sur http://127.0.0.1:5000.

Scan SAST en local :

```powershell
bandit -r . -x ./tests,./demo,./.venv --severity-level high
```

Avec Docker :

```powershell
docker build -t tp2-app .
docker run -p 5000:5000 tp2-app
```

## Rapports

Après chaque exécution du pipeline, les rapports sont téléchargeables dans la section **Artifacts** du run sur GitHub :

- `rapports-sast` : `bandit-report.json`, `semgrep-report.json`
- `rapports-zap` : `zap-report.html`, `zap-report.json`