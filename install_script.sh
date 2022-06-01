cd /app
rm -rf venv # Remove venv if it exists
python3 -m venv venv
source venv/bin/activate
pip install .