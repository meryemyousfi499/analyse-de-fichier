#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
  echo "Creation de l'environnement virtuel..."
  python3 -m venv venv
fi

source venv/bin/activate

echo "Installation des dependances..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo ""
echo "Dependances systeme optionnelles (recommandees, non obligatoires) :"
echo "  - libmagic   : sudo apt install libmagic1      (detection MIME reelle)"
echo "  - ClamAV     : sudo apt install clamav-daemon  (multi-scan antivirus)"
echo ""

echo "Lancement du dashboard sur http://127.0.0.1:5000"
python app.py
