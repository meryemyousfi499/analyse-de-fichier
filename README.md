# Cabinet Noir — Agent d'analyse de fichiers

Agent de traitement et de triage de fichiers avec dashboard web, conçu
pour analyser un fichier **sans jamais l'exécuter**, produire un score
de risque expliqué, et déclencher une action de réponse adaptée.

## Fonctionnalités couvertes

| Étape | Module | Détail |
|---|---|---|
| 1. Métadonnées | `agent/metadata.py` | nom, extension, taille, MIME réel, propriétaire, permissions, dates, zone Windows (Zone.Identifier) |
| 2. Cohérence de type | `agent/type_check.py` | comparaison extension déclarée vs magic bytes réels (détecte un `.pdf` qui est en réalité un `.exe`) |
| 3. Empreintes | `agent/hashing.py` | SHA-256 / SHA-1 / MD5, comparaison à une base locale de hashs connus |
| 4. Analyse statique | `agent/static_analysis.py` | PE (imports, sections, entropie, packer), Office (macros VBA via oletools), PDF (JS, /Launch, pièces jointes), ELF basique |
| 5. Entropie & obfuscation | `agent/entropy_tools.py` | entropie de Shannon globale et par bloc, détection Base64, XOR mono-octet |
| 6. Extraction d'IOC | `agent/ioc_extraction.py` | IP, domaines, URLs, emails, chemins, clés de registre, processus, chaînes suspectes (LOLBins) |
| 7. Signature numérique | `agent/signatures.py` | présence de la table Authenticode, vérification approfondie si `osslsigncode` est installé |
| 8. Règles YARA | `agent/yara_scan.py` + `rules/generic_rules.yar` | jeu de règles de démarrage (PowerShell obfusqué, macro+shell, injection de processus, note de rançon, LOLBins, PE déguisé) |
| 9. Antivirus | `agent/clamav_scan.py` | intégration ClamAV (clamd) optionnelle, traitée comme un indicateur parmi d'autres |
| 10. Threat Intelligence | `agent/threat_intel.py` | **AbuseIPDB** (IP), **AlienVault OTX** (domaines, URLs, hashs), **MalwareBazaar** et **URLhaus** — abuse.ch — (hashs / URLs / domaines connus malveillants). Chaque source est indépendante et activable via clé d'API |
| 11. Archives protégées | `agent/archive_handler.py` | fichier partagé sous forme d'archive `.zip`/`.7z`/`.rar` chiffrée : extraction avec le mot de passe fourni (ou une liste de mots de passe courants), puis **analyse complète de chaque fichier extrait** |
| 12. Surveillance automatique | `agent/watcher.py` | analyse **automatique** de tout nouveau fichier apparaissant dans un dossier surveillé (ex. Téléchargements), sans dépôt manuel |
| 13. Scoring / ML | `agent/ml_scoring.py` | extraction de features + score heuristique pondéré ; point d'extension pour brancher un modèle XGBoost/Isolation Forest entraîné (voir `ml_train_example.py`) |
| 14. Fusion du score | `agent/scoring_engine.py` | score 0–100 (0–29 faible, 30–59 moyen, 60–79 élevé, 80–100 critique), pondération non-linéaire (un hash connu ou une règle YARA critique pèsent plus qu'un indice isolé), **explication en langage clair** |
| 15. Réponse | `agent/quarantine.py` | autoriser / surveiller / quarantaine / bloquer / alerter / revue humaine. **Aucune suppression automatique n'est jamais effectuée** — la quarantaine déplace, renomme et retire les droits d'exécution, sans détruire la preuve |

## Ce qui est volontairement hors périmètre (par sécurité et honnêteté)

- **Sandbox comportementale d'exécution** (processus enfants, réseau, registre) : cela nécessite une VM isolée dédiée (type Cuckoo/CAPEv2). L'agent ne exécute jamais un fichier inconnu sur la machine qui l'héberge. Vous pouvez brancher un tel sandbox en aval de ce pipeline.
- **Modèle ML pré-entraîné** : sans jeu de données étiqueté propre à votre environnement, un modèle XGBoost n'apporterait pas de garantie réelle. Le module `ml_scoring.py` fournit un score heuristique pondéré honnête, plus un point d'extension clair pour brancher un modèle entraîné dès que vous avez des données (`ml_train_example.py`).
- **Vérification cryptographique complète de signature** : nécessite `osslsigncode` (Linux/Mac) ou l'API Windows native ; l'agent détecte la présence de la signature et l'utilise si l'outil est disponible.

## Installation et lancement

### Pré-requis
- Python 3.9 ou supérieur

### Linux / macOS
```bash
unzip cabinet-noir-agent.zip
cd file-analysis-agent
chmod +x run.sh
./run.sh
```

### Windows
```
Décompressez le zip, puis double-cliquez sur run.bat
(ou depuis un terminal : run.bat)
```

Le script crée automatiquement un environnement virtuel, installe les
dépendances Python (`requirements.txt`), puis démarre le serveur.

Ouvrez ensuite : **http://127.0.0.1:5000**

### Dépendances système optionnelles (l'agent fonctionne sans, en mode dégradé)

| Fonction | Paquet | Sans lui |
|---|---|---|
| Détection MIME réelle | `libmagic` (`sudo apt install libmagic1` / `brew install libmagic`) | le champ MIME reste "inconnu", la détection par magic bytes internes continue de fonctionner |
| Antivirus multi-moteur | `clamav-daemon` + `pip install clamd` | l'indicateur ClamAV est simplement absent du score |
| Threat Intelligence | clés `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `ABUSECH_AUTH_KEY` en variables d'environnement | les vérifications externes correspondantes sont ignorées proprement, chacune indépendamment des autres |
| Vérification de signature approfondie | `osslsigncode` | seule la présence de la signature est indiquée, pas sa validité |
| Archives `.7z` protégées | `pip install py7zr` (déjà dans `requirements.txt`) | le format `.7z` est signalé "non pris en charge sur cette machine", le fichier reste analysé tel quel (comme blob binaire) |
| Archives `.rar` protégées | `pip install rarfile` + le binaire `unrar` sur le système | idem, `.rar` est signalé "non pris en charge" |

## Configurer la Threat Intelligence (comparaison contre des bases de fichiers/IOC déjà documentés)

Quatre sources indépendantes peuvent être activées, chacune se dégradant proprement (aucune erreur, juste `"disponible": false`) si sa clé n'est pas fournie :

| Source | Ce qu'elle vérifie | Où obtenir la clé (gratuite) |
|---|---|---|
| **AbuseIPDB** | réputation d'IP | https://www.abuseipdb.com/register (compte gratuit) |
| **AlienVault OTX** | domaines, URLs **et** hashs de fichiers | https://otx.alienvault.com/ (compte gratuit) |
| **MalwareBazaar** (abuse.ch) | hash SHA-256 contre une base de **malwares déjà confirmés** | https://auth.abuse.ch/ (Auth-Key gratuite) |
| **URLhaus** (abuse.ch) | URLs et domaines déjà documentés comme distribuant du malware | https://auth.abuse.ch/ (même Auth-Key que MalwareBazaar) |

```bash
export ABUSEIPDB_API_KEY="votre_cle_abuseipdb"
export OTX_API_KEY="votre_cle_otx"
export ABUSECH_AUTH_KEY="votre_cle_abusech"   # active MalwareBazaar + URLhaus
export HYBRID_ANALYSIS_API_KEY="votre_cle_hybrid_analysis"   # ne JAMAIS la committer
./run.sh
```

Ce que chaque fichier analysé compare désormais automatiquement contre ces bases :
- le **hash SHA-256 du fichier lui-même** (contre MalwareBazaar + OTX) ;
- les **hashs trouvés à l'intérieur** du fichier (scripts référençant d'autres binaires) ;
- toutes les **IP**, **domaines** et **URLs** extraits du contenu.

Un indicateur "signalé" par au moins une source pèse dans le score final, avec l'explication correspondante affichée dans le rapport (`score_final.explications`).

## Surveillance automatique (l'agent n'attend plus un dépôt manuel)

Par défaut, l'agent démarre avec une surveillance active de vos dossiers de
téléchargement (`~/Downloads` / `~/Téléchargements`, détectés automatiquement) :
chaque nouveau fichier qui y apparaît est **analysé tout seul**, dès qu'il est
stable (téléchargement terminé — les fichiers `.crdownload`/`.part`/`.tmp` en
cours d'écriture sont ignorés jusqu'à leur renommage final).

```bash
# Personnaliser les dossiers surveillés (plusieurs, séparés par ':' sous Linux/macOS ou ';' sous Windows)
export WATCH_DIRS="/home/vous/Downloads:/home/vous/Bureau"

# Désactiver la surveillance automatique au démarrage
export AUTO_WATCH_ENABLED=0
```

Vous pouvez aussi la piloter à la main :
- depuis le dashboard, onglet **"Surveillance auto"** (boutons Démarrer/Arrêter, statut en direct) ;
- via l'API :
  ```bash
  curl -X POST http://127.0.0.1:5000/api/watch/start
  curl -X POST http://127.0.0.1:5000/api/watch/stop
  curl http://127.0.0.1:5000/api/watch/status
  ```

Chaque fichier détecté ainsi est analysé exactement par le même pipeline complet
que pour un dépôt manuel, et apparaît dans l'**Historique** avec `origine: "auto_watch"`.

## Fichiers partagés protégés par une clé (archives chiffrées)

Si on vous partage un fichier "protégé" (`.zip`, `.7z` ou `.rar` avec mot de
passe — pratique courante pour partager un échantillon suspect sans que le
mail/la messagerie ne le bloque), l'agent :

1. détecte que c'est une archive (même si l'extension est trompeuse) ;
2. essaie le mot de passe que vous fournissez, puis une petite liste de mots
   de passe courants (`ARCHIVE_COMMON_PASSWORDS`, ex. `infected`, `malware`, `virus` —
   les valeurs par défaut utilisées par les plateformes d'échange de malware) ;
3. si l'ouverture réussit : **analyse complète de chaque fichier extrait**
   (tout le pipeline, y compris Threat Intelligence) et remonte le score le
   plus élevé trouvé au niveau de l'archive ;
4. si aucun mot de passe ne fonctionne : le signale clairement dans le rapport
   (`"Archive protegee ... contenu NON inspecte"`) et relève le niveau vers
   "revue humaine" plutôt que de rendre un score faussement rassurant.

**Depuis le dashboard** : renseignez le mot de passe dans le champ prévu
au-dessus du coffre de dépôt avant de glisser l'archive.

**Depuis l'API** :
```bash
curl -F "fichier=@partage.zip" -F "mot_de_passe=le_mot_de_passe_recu" \
     http://127.0.0.1:5000/api/analyze
```

## Vérifier vous-même un indicateur (sans déposer de fichier)

Si vous avez reçu un hash, un lien, un domaine ou une IP par un autre moyen
(collègue, email, journal de connexion, rapport tiers) et voulez juste le
vérifier contre les bases de réputation, sans passer par une analyse de
fichier complète :

**Depuis le dashboard** : onglet **"Vérifier un indicateur"**.

**Depuis l'API** :
```bash
curl -X POST http://127.0.0.1:5000/api/check-indicator \
     -H "Content-Type: application/json" \
     -d '{"indicateur": "8f14e45fceea167a5a36dedd4bea2543", "type": "hash"}'

curl -X POST http://127.0.0.1:5000/api/check-indicator \
     -H "Content-Type: application/json" \
     -d '{"indicateur": "exemple-suspect.com", "type": "domaine"}'
```
`type` accepte : `hash`, `domaine`, `url`, `ip`. La réponse indique, pour
chaque source interrogée, si elle est disponible (clé configurée) et si
l'indicateur est signalé.

## Comment tester que tout fonctionne

### 1. Test rapide du pipeline avec un fichier inoffensif de référence : EICAR
Le fichier de test **EICAR** est LE standard de l'industrie antivirus : ce
n'est **pas un vrai virus**, mais tous les antivirus (dont ClamAV) le
détectent comme tel exprès, pour vérifier qu'une chaîne de détection
fonctionne, sans risque réel.

```bash
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
curl -F "fichier=@eicar.com" http://127.0.0.1:5000/api/analyze | python3 -m json.tool
```
- Son SHA-256 doit être `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`
  (visible dans `empreintes.sha256` du rapport).
- Si ClamAV (clamd) tourne sur la machine, `antivirus.infecte` doit valoir `true`.
- Sans ClamAV installé, le rapport l'indique explicitement
  (`antivirus.disponible: false`) plutôt que de faire semblant.

### 2. Vérifier la dégradation propre (sans aucune clé/service configuré)
```bash
curl http://127.0.0.1:5000/api/status | python3 -m json.tool
```
Doit répondre `false`/`disponible: false` pour chaque moteur non configuré,
sans jamais faire planter le serveur — l'agent doit rester utilisable même à
0 dépendance optionnelle installée.

### 3. Tester la surveillance automatique
```bash
curl -X POST http://127.0.0.1:5000/api/watch/start
cp eicar.com ~/Downloads/test_watch.com   # ou le dossier que vous surveillez
sleep 5
curl http://127.0.0.1:5000/api/watch/status   # "fichiers_traites" doit avoir augmenté
curl http://127.0.0.1:5000/api/history        # le rapport doit apparaitre, origine "auto_watch"
```

### 4. Tester une archive protégée
```bash
zip --password test1234 archive_test.zip eicar.com
curl -F "fichier=@archive_test.zip" -F "mot_de_passe=test1234" \
     http://127.0.0.1:5000/api/analyze | python3 -m json.tool
```
Le rapport doit contenir `archive.extraction_reussie: true` et un
`sous_rapports_archive` listant l'analyse de `eicar.com` à l'intérieur.

### 5. Tester la vérification manuelle d'indicateur
```bash
curl -X POST http://127.0.0.1:5000/api/check-indicator \
     -H "Content-Type: application/json" \
     -d '{"indicateur": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "type": "hash"}'
```
Sans clé configurée : chaque source répond `disponible: false` avec la
raison exacte (ex. `"ABUSECH_AUTH_KEY non configuree"`). Avec une clé
`ABUSECH_AUTH_KEY` valide, MalwareBazaar référence effectivement ce hash
comme échantillon connu, ce qui est une bonne façon de confirmer que la clé
est correctement prise en compte.

## Utilisation

1. Ouvrez le dashboard.
2. Glissez-déposez un fichier dans le "coffre de dépôt" (avec un mot de passe si c'est une archive protégée), ou cliquez pour le sélectionner.
3. L'agent exécute les étapes du pipeline (visibles dans la frise en haut du dashboard) puis affiche :
   - le score de risque et son niveau (jauge circulaire) ;
   - l'explication en langage clair de la décision ;
   - les panneaux détaillés (métadonnées, empreintes, entropie, IOC, YARA, analyse statique, antivirus, threat intelligence, features de scoring) ;
   - l'action appliquée (autoriser / surveiller / quarantaine / bloquer / alerter / revue humaine).
4. L'onglet **Vérifier un indicateur** permet de contrôler vous-même un hash/domaine/URL/IP sans déposer de fichier.
5. L'onglet **Surveillance auto** affiche et pilote la surveillance automatique des dossiers de téléchargement.
6. L'onglet **Historique** liste les analyses passées (manuelles, automatiques, ou issues d'une archive). L'onglet **Journal de quarantaine** rappelle où sont les fichiers isolés (`quarantine/journal_quarantaine.jsonl`).

## Enrichir l'agent

- **Règles YARA** : ajoutez vos propres règles dans `rules/generic_rules.yar` (ou pointez `YARA_RULES_PATH` dans `config.py` vers un dossier de règles plus large, ex. YARA-Rules ou flux abuse.ch).
- **Base de hashs connus malveillants** : chargez un `set()` de SHA-256 et passez-le à `run_pipeline(path, known_malicious_hashes=...)` dans `agent/pipeline.py`.
- **Sources de réputation supplémentaires** : ajoutez une fonction `check_xxx()` dans `agent/threat_intel.py` suivant le même modèle (retour `{"disponible": bool, ...}`), puis branchez-la dans `run_threat_intel()` et `check_indicator_manual()`.
- **Modèle ML entraîné** : voir `ml_train_example.py`.
- **Sigma** : les règles Sigma s'appliquent aux logs/événements produits par une exécution réelle (sandbox) plutôt qu'au fichier statique ; branchez-les en aval si vous ajoutez un sandbox.

## Structure du projet

```
file-analysis-agent/
├── app.py                    # Serveur Flask + API (analyse, indicateur manuel, surveillance)
├── config.py                 # Configuration centrale (clés API, dossiers surveillés, archives)
├── requirements.txt
├── run.sh / run.bat          # Scripts de lancement
├── ml_train_example.py       # Exemple pour brancher un modèle entraîné
├── agent/                    # Tous les modules d'analyse
│   ├── threat_intel.py       # AbuseIPDB / OTX / MalwareBazaar / URLhaus
│   ├── archive_handler.py    # Archives protégées par mot de passe
│   ├── watcher.py            # Surveillance automatique de dossiers
│   └── ...                   # metadata, hashing, yara, clamav, scoring, quarantine...
├── rules/generic_rules.yar   # Règles YARA de démarrage
├── templates/dashboard.html  # Dashboard (vue)
├── static/css/style.css      # Thème "Cabinet Noir"
├── static/js/dashboard.js    # Logique du dashboard
├── uploads/                  # Zone de dépôt temporaire (vidée après analyse)
├── quarantine/                # Fichiers neutralisés + journal
└── reports/                   # Historique des rapports JSON
```

## Orchestrateur, verdict et politique (nouveau)

`agent/orchestrator.py` décide quels outils lancer et pourquoi, puis produit un
rapport avec la trace complète (`orchestration.outils`, `orchestration.plan`).
Tous les outils renvoient un `ToolResult` normalisé (`agent/tool_result.py`) :
`ok | detected | error | unavailable | not_applicable | skipped | pending`.

Le **verdict** (`agent/verdict.py`) est distinct du score : `clean`, `suspect`,
`malicious` ou `inconclusive`, avec une confiance et une couverture. Un outil
indisponible ou en erreur n'est jamais interprété comme « sain » : le verdict
devient `inconclusive` et l'action `human_review`.

Variables d'environnement de la politique (valeurs par défaut dans `config.py`) :

| Variable | Défaut | Rôle |
|---|---|---|
| `SANDBOX_MIN_SCORE` | 70 | score statique à partir duquel la sandbox est justifiée (à calibrer) |
| `SANDBOX_ALLOW_EXTERNAL_SUBMISSION` | 0 | 1 = envoi automatique à Hybrid Analysis ; 0 = validation manuelle (« Soumettre ») |
| `SANDBOX_NO_SHARE_THIRD_PARTY` / `SANDBOX_ALLOW_COMMUNITY_ACCESS` | 1 / 0 | paramètres de partage envoyés à l'API (à vérifier dans la doc HA) |
| `SANDBOX_RETENTION_DAYS` | 7 | durée de conservation des copies dans `sandbox/` |
| `ARCHIVE_MAX_DEPTH` / `ARCHIVE_MAX_FILES` | 3 / 200 | limites anti zip-bomb et imbrication |
| `CACHE_TTL_HOURS` | 24 | réutilisation d'un rapport « clean » (même SHA-256 + mêmes règles YARA) pour la surveillance auto |
| `CABINET_NOIR_HOST` / `CABINET_NOIR_PORT` | 127.0.0.1 / 5500 | adresse d'écoute (locale par défaut) |
| `CABINET_NOIR_API_TOKEN` | vide | jeton `X-API-Token` exigé par `/api/ingest-remote` hors machine locale |

Les documents Office / OpenDocument et paquets (`.docx`, `.xlsx`, `.jar`, `.apk`…) ne sont
plus extraits comme des archives : ils sont analysés comme un tout. L'historique est indexé
dans `cabinet_noir.db` (SQLite) ; les rapports restent des fichiers JSON dans `reports/`.

Tests : `python -m unittest discover -s tests`

