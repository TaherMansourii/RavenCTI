#!/usr/bin/env bash
# =============================================================================
#  RavenCTI — setup.sh
# =============================================================================

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; N='\033[0m'
info()  { echo -e "${C}[INFO]${N}  $*"; }
ok()    { echo -e "${G}[ OK ]${N}  $*"; }
warn()  { echo -e "${Y}[WARN]${N}  $*"; }
die()   { echo -e "${R}[ERR ]${N}  $*" >&2; exit 1; }
step()  { echo -e "\n${B}── $* ──${N}"; }

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
info "Working directory: $DIR"

# ─────────────────────────────────────────────────────────────────────────────
step "1/6  Creating folder structure"
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p ravencti/{db,collectors,services,routes,utils} data logs
for pkg in ravencti ravencti/db ravencti/collectors ravencti/services ravencti/routes ravencti/utils; do
    touch "$pkg/__init__.py"
done
ok "Directories ready"

# ─────────────────────────────────────────────────────────────────────────────
step "2/6  Placing files"
# ─────────────────────────────────────────────────────────────────────────────
place() {
    local src="$1" dst="$2"
    if   [ -f "$src" ]; then mv "$src" "$dst"; ok "  $src  →  $dst"
    elif [ -f "$dst" ]; then ok "  $dst already in place"
    else warn "  $src not found — skipping"
    fi
}

place "app.py"         "ravencti/app.py"
place "config.py"      "ravencti/config.py"
place "connection.py"  "ravencti/db/connection.py"
place "schema.py"      "ravencti/db/schema.py"
place "base.py"        "ravencti/collectors/base.py"
place "cleanup.py"     "ravencti/collectors/cleanup.py"
place "cve.py"         "ravencti/collectors/cve.py"
place "mitre.py"       "ravencti/collectors/mitre.py"
place "ransomware.py"  "ravencti/collectors/ransomware.py"
place "alerts.py"      "ravencti/services/alerts.py"
place "matching.py"    "ravencti/services/matching.py"
place "queue.py"       "ravencti/services/queue.py"
place "risk.py"        "ravencti/services/risk.py"
place "auth.py"        "ravencti/routes/auth.py"
place "assets.py"      "ravencti/routes/assets.py"
place "cves.py"        "ravencti/routes/cves.py"
place "misc.py"        "ravencti/routes/misc.py"
place "scans.py"       "ravencti/routes/scans.py"
place "helpers.py"     "ravencti/utils/helpers.py"
place "http.py"        "ravencti/utils/http.py"
place "logging.py"     "ravencti/utils/logging.py"

# exposure.py name collision — routes version should be renamed exposure_routes.py
if [ -f "exposure.py" ] && [ -f "exposure_routes.py" ]; then
    place "exposure.py"        "ravencti/collectors/exposure.py"
    place "exposure_routes.py" "ravencti/routes/exposure.py"
elif [ -f "exposure.py" ]; then
    if head -3 "exposure.py" | grep -q "routes/exposure"; then
        mv "exposure.py" "ravencti/routes/exposure.py"
        ok "  exposure.py  →  ravencti/routes/exposure.py"
    else
        mv "exposure.py" "ravencti/collectors/exposure.py"
        ok "  exposure.py  →  ravencti/collectors/exposure.py"
    fi
fi
[ -f "ravencti/collectors/exposure.py" ] && ok "  ravencti/collectors/exposure.py in place"
[ -f "ravencti/routes/exposure.py" ]     && ok "  ravencti/routes/exposure.py in place"

if [ -f "dashboard.html" ] && [ ! -f "ravencti/dashboard.html" ]; then
    cp "dashboard.html" "ravencti/dashboard.html"; ok "  dashboard.html → ravencti/dashboard.html"
elif [ -f "ravencti/dashboard.html" ]; then
    ok "  ravencti/dashboard.html already in place"
fi
ok "All files placed"

# ─────────────────────────────────────────────────────────────────────────────
step "3/6  Environment (.env)"
# ─────────────────────────────────────────────────────────────────────────────
ENV="ravencti/.env"
if [ ! -f "$ENV" ]; then
    if   [ -f ".env.example" ];          then cp ".env.example"          "$ENV"
    elif [ -f "ravencti/.env.example" ]; then cp "ravencti/.env.example" "$ENV"
    else
        cat > "$ENV" << 'ENVEOF'
FLASK_SECRET_KEY=
NVD_API_KEY=
GITHUB_TOKEN=
API_KEY=
MONITORED_COMPANY=soprahr
MONITORED_DOMAIN=soprahr.com
MONITORED_KEYWORDS=soprahr,soprahr.com
CVE_MIN_CVSS=6.0
CVE_MIN_YEAR=2019
ENVEOF
    fi
    ok ".env created"
fi

# Auto-generate FLASK_SECRET_KEY if blank
if grep -qE "^FLASK_SECRET_KEY=\s*$" "$ENV" 2>/dev/null; then
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    sed -i.bak "s|^FLASK_SECRET_KEY=.*|FLASK_SECRET_KEY=${SECRET}|" "$ENV" && rm -f "${ENV}.bak"
    ok "FLASK_SECRET_KEY auto-generated"
fi
ok ".env ready  —  edit ravencti/.env to add NVD_API_KEY / GITHUB_TOKEN"

# ─────────────────────────────────────────────────────────────────────────────
step "4/6  Python & virtual environment"
# ─────────────────────────────────────────────────────────────────────────────
SYS_PY=$(command -v python3 || command -v python || true)
[ -z "$SYS_PY" ] && die "Python 3 not found. Run: sudo apt install python3 python3-venv"
info "System Python: $($SYS_PY --version 2>&1)"

[ -f "requirements.txt" ] || cat > "requirements.txt" << 'REQEOF'
flask>=3.0.0
flask-cors>=4.0.0
requests>=2.31.0
urllib3>=2.0.0
apscheduler>=3.10.0
python-dotenv>=1.0.0
REQEOF

# Create venv if it doesn't exist
if [ ! -d "venv" ]; then
    info "Creating virtual environment…"
    $SYS_PY -m venv venv || die "Failed to create venv. Try: sudo apt install python3-venv"
fi

# Point PYTHON at the venv binary — this is what everything below uses
PYTHON="$DIR/venv/bin/python3"
[ -f "$PYTHON" ] || PYTHON="$DIR/venv/bin/python"
[ -f "$PYTHON" ] || die "venv python not found at $DIR/venv/bin/"

info "Venv Python: $($PYTHON --version 2>&1)"

# Install / upgrade dependencies into the venv
"$DIR/venv/bin/pip" install --quiet --upgrade pip
"$DIR/venv/bin/pip" install --quiet -r requirements.txt
ok "Dependencies installed into venv"

# ─────────────────────────────────────────────────────────────────────────────
step "5/6  Import validation"
# ─────────────────────────────────────────────────────────────────────────────
# Run imports:
#   - using the VENV python (not the system one)
#   - from the PROJECT ROOT with PYTHONPATH=. so 'ravencti.*' resolves

ERRORS=0
chk() {
    local stmt="$1"
    local result
    result=$(cd "$DIR" && PYTHONPATH="$DIR" "$PYTHON" -c "$stmt" 2>&1)
    if [ $? -eq 0 ]; then
        ok "  $stmt"
    else
        warn "  FAILED: $stmt"
        # Print just the last meaningful error line
        echo "$result" | grep -v "^$" | tail -3 | while read -r line; do
            warn "          $line"
        done
        ERRORS=$((ERRORS + 1))
    fi
}

chk "import flask"
chk "import requests"
chk "import apscheduler"
chk "from ravencti.config import MONITORED_DOMAIN"
chk "from ravencti.db.schema import init_db"
chk "from ravencti.collectors.cve import collect_cves"
chk "from ravencti.collectors.ransomware import collect_ransomware"
chk "from ravencti.collectors.exposure import collect_all_exposure"
chk "from ravencti.services.risk import calc_risk"
chk "from ravencti.routes.scans import bp"
chk "from ravencti.routes.exposure import bp as exp_bp"

if [ "$ERRORS" -gt 0 ]; then
    echo ""
    echo -e "${R}  $ERRORS import(s) failed.${N}"
    echo ""
    echo "  To debug a specific failure:"
    echo "    cd $DIR"
    echo "    PYTHONPATH=. $PYTHON -c \"from ravencti.collectors.exposure import collect_all_exposure\""
    exit 1
fi
ok "All imports successful"

# ─────────────────────────────────────────────────────────────────────────────
step "6/6  Starting RavenCTI"
# ─────────────────────────────────────────────────────────────────────────────
PORT="${PORT:-5000}"
echo ""
echo -e "  ${G}${B}RavenCTI is starting${N}"
echo -e "  Dashboard  →  ${C}http://localhost:${PORT}/${N}"
echo -e "  Health     →  ${C}http://localhost:${PORT}/api/test${N}"
echo -e "  Debug      →  ${C}http://localhost:${PORT}/api/debug/scan${N}"
echo -e "  ${Y}Ctrl+C to stop${N}"
echo ""

cd "$DIR"
export PYTHONPATH="$DIR"
exec "$PYTHON" ravencti/app.py
