"""
AutoVerif QC — Backend API
Projet 100% séparé. Scan VIN véhiculaire pour le Québec.
Port: 8930
"""

import os
import json
import time
import requests
import psycopg2
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

# Load .env from parent directory
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

app = Flask(__name__, static_folder='../static', template_folder='../templates')
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ─── Config ───
DB_CONFIG = {
    'host': os.getenv('DB_HOST', '172.18.0.3'),
    'port': int(os.getenv('DB_PORT', 5432)),
    'dbname': os.getenv('DB_NAME', 'autoverif_db'),
    'user': os.getenv('DB_USER', 'autoverif_user'),
    'password': os.getenv('DB_PASS', ''),
}

NHTSA_BASE = os.getenv('NHTSA_BASE', 'https://vpic.nhtsa.dot.gov/api')
NHTSA_RECALLS = os.getenv('NHTSA_RECALLS', 'https://api.nhtsa.gov/recalls/recallsByVehicle')
NHTSA_COMPLAINTS = os.getenv('NHTSA_COMPLAINTS', 'https://api.nhtsa.gov/complaints/complaintsByVehicle')
NHTSA_RATINGS = os.getenv('NHTSA_RATINGS', 'https://api.nhtsa.gov/SafetyRatings')
EPA_BASE = os.getenv('EPA_BASE', 'https://www.fueleconomy.gov/ws/rest')
TC_RECALLS = os.getenv('TC_RECALLS', 'https://data.tc.gc.ca/v1.3/api/eng/vehicle-recall-database')


# ─── Database ───
def get_db():
    return psycopg2.connect(**DB_CONFIG)


def init_db():
    """Create tables if not exist."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            vin VARCHAR(17) NOT NULL,
            make VARCHAR(100),
            model VARCHAR(100),
            year INTEGER,
            result JSONB,
            scanned_at TIMESTAMP DEFAULT NOW(),
            ip_address VARCHAR(45)
        );
        CREATE INDEX IF NOT EXISTS idx_scans_vin ON scans(vin);
        CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scanned_at);

        CREATE TABLE IF NOT EXISTS stats (
            id SERIAL PRIMARY KEY,
            total_scans INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()
    cur.close()
    conn.close()


# ─── NHTSA API calls (server-side, no CORS issues) ───
def decode_vin(vin):
    """Decode VIN via NHTSA vPIC."""
    try:
        r = requests.get(
            f"{NHTSA_BASE}/vehicles/DecodeVin/{vin}?format=json",
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            results = data.get('Results', [])
            decoded = {}
            for item in results:
                var = item.get('Variable', '')
                val = item.get('Value')
                if val and val.strip() and val.strip() != 'Not Applicable':
                    decoded[var] = val.strip()
            return decoded
    except Exception as e:
        print(f"[VIN Decode Error] {e}")
    return {}


def get_recalls(make, model, year):
    """Get NHTSA recalls."""
    try:
        r = requests.get(
            NHTSA_RECALLS,
            params={'make': make, 'model': model, 'modelYear': year},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            return data.get('results', [])
    except Exception as e:
        print(f"[Recalls Error] {e}")
    return []


def get_complaints(make, model, year):
    """Get NHTSA complaints."""
    try:
        r = requests.get(
            NHTSA_COMPLAINTS,
            params={'make': make, 'model': model, 'modelYear': year},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            return data.get('results', [])
    except Exception as e:
        print(f"[Complaints Error] {e}")
    return []


def get_safety_ratings(make, model, year):
    """Get NHTSA safety ratings."""
    try:
        # Step 1: get vehicle ID
        r = requests.get(
            f"{NHTSA_RATINGS}/modelyear/{year}/make/{make}/model/{model}",
            params={'format': 'json'},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            results = data.get('Results', [])
            if results:
                vid = results[0].get('VehicleId')
                if vid:
                    # Step 2: get detailed ratings
                    r2 = requests.get(
                        f"{NHTSA_RATINGS}/VehicleId/{vid}",
                        params={'format': 'json'},
                        timeout=10
                    )
                    if r2.status_code == 200:
                        d2 = r2.json()
                        return d2.get('Results', [{}])[0] if d2.get('Results') else {}
    except Exception as e:
        print(f"[Safety Ratings Error] {e}")
    return {}


def get_tc_recalls(make, model, year):
    """Get Transport Canada recalls."""
    try:
        r = requests.get(
            f"{TC_RECALLS}/recall-summary/by-make-model-year",
            params={'make': make, 'model': model, 'year': year},
            headers={'Accept': 'application/json'},
            timeout=10
        )
        if r.status_code == 200:
            return r.json() if r.text else []
    except Exception as e:
        print(f"[TC Recalls Error] {e}")
    return []


def get_epa_data(make, model, year):
    """Get EPA fuel economy data."""
    try:
        # Step 1: get options
        r = requests.get(
            f"{EPA_BASE}/vehicle/menu/options",
            params={'year': year, 'make': make, 'model': model},
            headers={'Accept': 'application/json'},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            options = data.get('menuItem', [])
            if isinstance(options, dict):
                options = [options]
            if options:
                vid = options[0].get('value')
                if vid:
                    # Step 2: get vehicle detail
                    r2 = requests.get(
                        f"{EPA_BASE}/vehicle/{vid}",
                        headers={'Accept': 'application/json'},
                        timeout=10
                    )
                    if r2.status_code == 200:
                        return r2.json()
    except Exception as e:
        print(f"[EPA Error] {e}")
    return {}


def get_nhtsa_investigations(make, model, year):
    """Get NHTSA investigations/defect probes."""
    try:
        r = requests.get(
            f"https://api.nhtsa.gov/products/vehicle/makes/{make}/models/{model}/modelYears/{year}/investigations",
            params={'format': 'json'},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            return data.get('results', [])
    except Exception as e:
        print(f"[Investigations Error] {e}")
    return []


# ─── Main Scan Endpoint ───
@app.route('/api/scan', methods=['GET', 'POST'])
def scan_vin():
    """Full VIN scan — all sources, server-side."""
    start_time = time.time()

    if request.method == 'POST':
        data = request.get_json() or {}
        vin = data.get('vin', '').strip().upper()
    else:
        vin = request.args.get('vin', '').strip().upper()

    if not vin or len(vin) != 17:
        return jsonify({'error': 'VIN invalide. Doit contenir 17 caractères.'}), 400

    # 1. Decode VIN
    decoded = decode_vin(vin)
    if not decoded:
        return jsonify({'error': 'Impossible de décoder ce VIN.'}), 404

    make = decoded.get('Make', '')
    model = decoded.get('Model', '')
    year = decoded.get('Model Year', '')

    # 2. Parallel-ish calls (sequential for simplicity, can optimize later)
    recalls = get_recalls(make, model, year)
    complaints = get_complaints(make, model, year)
    safety = get_safety_ratings(make, model, year)
    tc_recalls = get_tc_recalls(make, model, year)
    epa = get_epa_data(make, model, year)
    investigations = get_nhtsa_investigations(make, model, year)

    # 3. Build result
    result = {
        'vin': vin,
        'decoded': decoded,
        'vehicle': {
            'make': make,
            'model': model,
            'year': year,
            'type': decoded.get('Vehicle Type', ''),
            'body': decoded.get('Body Class', ''),
            'drive': decoded.get('Drive Type', ''),
            'engine': decoded.get('Displacement (L)', ''),
            'cylinders': decoded.get('Engine Number of Cylinders', ''),
            'fuel': decoded.get('Fuel Type - Primary', ''),
            'transmission': decoded.get('Transmission Style', ''),
            'plant_country': decoded.get('Plant Country', ''),
            'plant_city': decoded.get('Plant City', ''),
        },
        'recalls': {
            'count': len(recalls),
            'items': recalls[:50],
        },
        'complaints': {
            'count': len(complaints),
            'items': complaints[:50],
        },
        'safety_ratings': safety,
        'tc_recalls': {
            'count': len(tc_recalls) if isinstance(tc_recalls, list) else 0,
            'items': tc_recalls[:50] if isinstance(tc_recalls, list) else [],
        },
        'epa': epa,
        'investigations': {
            'count': len(investigations),
            'items': investigations[:20],
        },
        'image_url': f"https://cdn.imagin.studio/getimage?customer=img&make={make}&modelFamily={model}&modelYear={year}&angle=01&width=800",
        'scan_time': round(time.time() - start_time, 2),
        'scanned_at': datetime.now().isoformat(),
        'sources': [
            'NHTSA vPIC (VIN Decode)',
            'NHTSA Recalls',
            'NHTSA Complaints',
            'NHTSA Safety Ratings',
            'NHTSA Investigations',
            'Transport Canada Recalls',
            'EPA Fuel Economy',
            'imagin.studio (Vehicle Image)',
        ],
    }

    # 4. Save to DB
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO scans (vin, make, model, year, result, ip_address) VALUES (%s, %s, %s, %s, %s, %s)",
            (vin, make, model, int(year) if year else None, json.dumps(result), request.remote_addr)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[DB Save Error] {e}")

    return jsonify(result)


@app.route('/api/health', methods=['GET'])
def health():
    """Health check."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM scans")
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        db_status = 'ok'
    except Exception as e:
        count = 0
        db_status = f'error: {e}'

    return jsonify({
        'status': 'ok',
        'service': 'AutoVerif QC',
        'version': '1.0.0',
        'database': db_status,
        'total_scans': count,
        'timestamp': datetime.now().isoformat(),
    })


@app.route('/api/stats', methods=['GET'])
def stats():
    """Public stats."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*), COUNT(DISTINCT vin) FROM scans")
        total, unique = cur.fetchone()
        cur.close()
        conn.close()
    except:
        total, unique = 0, 0

    return jsonify({
        'total_scans': total,
        'unique_vins': unique,
    })


# ─── Serve frontend ───
@app.route('/')
def index():
    return send_from_directory('../static', 'rapport.html')


@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('../static', filename)


# ─── Init & Run ───
if __name__ == '__main__':
    init_db()
    port = int(os.getenv('FLASK_PORT', 8930))
    print(f"[AutoVerif QC] Starting on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
