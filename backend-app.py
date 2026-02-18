"""
AutoVerif QC — Backend API
Projet 100% séparé. Scan VIN véhiculaire pour le Québec.
Port: 8930
"""

import os
import re
import json
import time
import uuid
import hashlib
import requests
import psycopg2
from datetime import datetime
from decimal import Decimal
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

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

UPLOAD_DIR = os.getenv('UPLOAD_DIR', os.path.join(os.path.dirname(__file__), '..', 'uploads'))
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


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

        -- ─── Collecte de données ───
        CREATE TABLE IF NOT EXISTS vehicles (
            id SERIAL PRIMARY KEY,
            vin VARCHAR(17) NOT NULL UNIQUE,
            make VARCHAR(100),
            model VARCHAR(100),
            year INTEGER,
            body_class VARCHAR(100),
            engine VARCHAR(100),
            fuel_type VARCHAR(50),
            transmission VARCHAR(100),
            drive_type VARCHAR(100),
            plant_country VARCHAR(100),
            decoded_json JSONB,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_vehicles_vin ON vehicles(vin);

        CREATE TABLE IF NOT EXISTS submissions (
            id SERIAL PRIMARY KEY,
            vehicle_id INTEGER REFERENCES vehicles(id) ON DELETE CASCADE,
            vin VARCHAR(17) NOT NULL,
            report_type VARCHAR(30) NOT NULL,
            submitted_by_name VARCHAR(200),
            submitted_by_email VARCHAR(200),
            submitted_by_type VARCHAR(30),
            submitted_by_company VARCHAR(200),
            status VARCHAR(20) DEFAULT 'pending',
            ip_address VARCHAR(45),
            submitted_at TIMESTAMP DEFAULT NOW(),
            verified_at TIMESTAMP,
            notes TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_submissions_vin ON submissions(vin);
        CREATE INDEX IF NOT EXISTS idx_submissions_type ON submissions(report_type);

        CREATE TABLE IF NOT EXISTS accident_reports (
            id SERIAL PRIMARY KEY,
            submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
            accident_date DATE NOT NULL,
            severity VARCHAR(20) NOT NULL,
            impact_point VARCHAR(30) NOT NULL,
            airbag_deployed BOOLEAN DEFAULT FALSE,
            structural_damage BOOLEAN DEFAULT FALSE,
            estimated_cost DECIMAL(10,2),
            description TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS service_records (
            id SERIAL PRIMARY KEY,
            submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
            service_date DATE NOT NULL,
            odometer_km INTEGER,
            service_type VARCHAR(50) NOT NULL,
            facility_name VARCHAR(200),
            description TEXT,
            cost DECIMAL(10,2),
            parts_type VARCHAR(20),
            created_at TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS ownership_changes (
            id SERIAL PRIMARY KEY,
            submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
            change_date DATE NOT NULL,
            previous_owner_type VARCHAR(30),
            new_owner_type VARCHAR(30),
            province VARCHAR(4) DEFAULT 'QC',
            sale_price DECIMAL(10,2),
            created_at TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS inspections (
            id SERIAL PRIMARY KEY,
            submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
            inspection_date DATE NOT NULL,
            result VARCHAR(10) NOT NULL,
            odometer_km INTEGER,
            notes TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS recall_completions (
            id SERIAL PRIMARY KEY,
            submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
            recall_number VARCHAR(50) NOT NULL,
            completion_date DATE NOT NULL,
            facility_name VARCHAR(200),
            created_at TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS submission_photos (
            id SERIAL PRIMARY KEY,
            submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
            filename VARCHAR(255) NOT NULL,
            original_name VARCHAR(255),
            mime_type VARCHAR(50),
            file_size INTEGER,
            uploaded_at TIMESTAMP DEFAULT NOW()
        );

        -- ─── Intégrité cryptographique ───
        CREATE TABLE IF NOT EXISTS chain_anchors (
            id SERIAL PRIMARY KEY,
            anchor_hash VARCHAR(64) NOT NULL,
            submission_count INTEGER NOT NULL,
            first_submission_id INTEGER,
            last_submission_id INTEGER,
            created_at TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id SERIAL PRIMARY KEY,
            action VARCHAR(50) NOT NULL,
            target_table VARCHAR(50),
            target_id INTEGER,
            details JSONB,
            ip_address VARCHAR(45),
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_table, target_id);
    """)

    # Migration: add integrity columns to existing submissions table
    try:
        cur.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS integrity_hash VARCHAR(64)")
        cur.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS previous_hash VARCHAR(64)")
        cur.execute("ALTER TABLE submissions ADD COLUMN IF NOT EXISTS data_snapshot JSONB")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_submissions_hash ON submissions(integrity_hash)")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[Migration] Columns may already exist: {e}")
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


# ─── Collecte helpers ───
def validate_vin(vin):
    """Validate VIN format (17 chars, no I/O/Q)."""
    if not vin or len(vin) != 17:
        return False
    return bool(re.match(r'^[A-HJ-NPR-Z0-9]{17}$', vin))


# ─── Intégrité cryptographique (hash chain) ───
def compute_integrity_hash(submission_id, vin, report_type, data_snapshot, previous_hash, timestamp):
    """Compute SHA-256 hash for a submission, chaining to previous."""
    payload = json.dumps({
        'id': submission_id,
        'vin': vin,
        'type': report_type,
        'data': data_snapshot,
        'prev': previous_hash or 'GENESIS',
        'ts': timestamp,
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def get_last_hash():
    """Get the integrity_hash of the most recent submission."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT integrity_hash FROM submissions WHERE integrity_hash IS NOT NULL ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        cur.close()
        conn.close()
        return row[0] if row else None
    except:
        return None


def log_audit(action, target_table, target_id, details=None, ip=None):
    """Write to immutable audit log."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO audit_log (action, target_table, target_id, details, ip_address) VALUES (%s, %s, %s, %s, %s)",
            (action, target_table, target_id, json.dumps(details) if details else None, ip)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[Audit Log Error] {e}")


def get_or_create_vehicle(vin, decoded=None):
    """Get existing vehicle or create from VIN decode."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, make, model, year FROM vehicles WHERE vin = %s", (vin,))
    row = cur.fetchone()
    if row:
        cur.close()
        conn.close()
        return {'id': row[0], 'make': row[1], 'model': row[2], 'year': row[3]}

    if not decoded:
        decoded = decode_vin(vin)
    if not decoded:
        cur.close()
        conn.close()
        return None

    make = decoded.get('Make', '')
    model = decoded.get('Model', '')
    year_str = decoded.get('Model Year', '')
    year = int(year_str) if year_str and year_str.isdigit() else None

    cur.execute("""
        INSERT INTO vehicles (vin, make, model, year, body_class, engine, fuel_type,
            transmission, drive_type, plant_country, decoded_json)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (
        vin, make, model, year,
        decoded.get('Body Class', ''),
        decoded.get('Displacement (L)', ''),
        decoded.get('Fuel Type - Primary', ''),
        decoded.get('Transmission Style', ''),
        decoded.get('Drive Type', ''),
        decoded.get('Plant Country', ''),
        json.dumps(decoded),
    ))
    vehicle_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return {'id': vehicle_id, 'make': make, 'model': model, 'year': year}


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
        'version': '1.2.0',
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


# ─── Collecte API ───
@app.route('/api/collecte/vin-check/<vin>', methods=['GET'])
def collecte_vin_check(vin):
    """Check/decode a VIN for the collecte form."""
    vin = vin.strip().upper()
    if not validate_vin(vin):
        return jsonify({'error': 'VIN invalide (17 caractères alphanumériques).'}), 400

    # Check if vehicle already in our DB
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, make, model, year FROM vehicles WHERE vin = %s", (vin,))
        row = cur.fetchone()
        existing_count = 0
        if row:
            cur.execute("SELECT COUNT(*) FROM submissions WHERE vin = %s", (vin,))
            existing_count = cur.fetchone()[0]
        cur.close()
        conn.close()
    except:
        row = None
        existing_count = 0

    # Decode VIN
    decoded = decode_vin(vin)
    if not decoded:
        return jsonify({'error': 'Impossible de décoder ce VIN.'}), 404

    make = decoded.get('Make', '')
    model = decoded.get('Model', '')
    year = decoded.get('Model Year', '')

    return jsonify({
        'found': row is not None,
        'vehicle': {
            'make': make,
            'model': model,
            'year': year,
            'body': decoded.get('Body Class', ''),
            'engine': decoded.get('Displacement (L)', ''),
            'fuel': decoded.get('Fuel Type - Primary', ''),
            'drive': decoded.get('Drive Type', ''),
            'transmission': decoded.get('Transmission Style', ''),
            'plant_country': decoded.get('Plant Country', ''),
        },
        'image_url': f"https://cdn.imagin.studio/getimage?customer=img&make={make}&modelFamily={model}&modelYear={year}&angle=01&width=800",
        'existing_records': existing_count,
    })


@app.route('/api/collecte/submit', methods=['POST'])
def collecte_submit():
    """Submit a data contribution."""
    body = request.get_json()
    if not body:
        return jsonify({'error': 'Corps JSON requis.'}), 400

    vin = (body.get('vin') or '').strip().upper()
    if not validate_vin(vin):
        return jsonify({'error': 'VIN invalide.'}), 400

    report_type = body.get('report_type', '')
    valid_types = ['accident', 'service', 'ownership', 'inspection', 'recall_completion']
    if report_type not in valid_types:
        return jsonify({'error': f'Type invalide. Valides: {", ".join(valid_types)}'}), 400

    submitter = body.get('submitter', {})
    data = body.get('data', {})

    # Get or create vehicle
    vehicle = get_or_create_vehicle(vin)
    if not vehicle:
        return jsonify({'error': 'Impossible de décoder ce VIN.'}), 404

    try:
        conn = get_db()
        cur = conn.cursor()

        # Get previous hash for chain
        cur.execute("SELECT integrity_hash FROM submissions WHERE integrity_hash IS NOT NULL ORDER BY id DESC LIMIT 1")
        prev_row = cur.fetchone()
        previous_hash = prev_row[0] if prev_row else None

        now = datetime.now().isoformat()

        # Build data snapshot (immutable copy of all submitted data)
        data_snapshot = {
            'vin': vin,
            'report_type': report_type,
            'submitter': submitter,
            'data': data,
            'submitted_at': now,
            'ip': request.remote_addr,
        }

        # Insert submission
        cur.execute("""
            INSERT INTO submissions (vehicle_id, vin, report_type, submitted_by_name,
                submitted_by_email, submitted_by_type, submitted_by_company, ip_address,
                data_snapshot, previous_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            vehicle['id'], vin, report_type,
            submitter.get('name', ''),
            submitter.get('email', ''),
            submitter.get('type', ''),
            submitter.get('company', ''),
            request.remote_addr,
            json.dumps(data_snapshot, sort_keys=True, ensure_ascii=False),
            previous_hash,
        ))
        submission_id = cur.fetchone()[0]

        # Compute integrity hash (includes submission_id, data, and previous hash)
        integrity_hash = compute_integrity_hash(
            submission_id, vin, report_type, data_snapshot, previous_hash, now
        )

        # Store hash
        cur.execute(
            "UPDATE submissions SET integrity_hash = %s WHERE id = %s",
            (integrity_hash, submission_id)
        )

        # Insert type-specific detail
        if report_type == 'accident':
            cur.execute("""
                INSERT INTO accident_reports (submission_id, accident_date, severity,
                    impact_point, airbag_deployed, structural_damage, estimated_cost, description)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('date'),
                data.get('severity', 'minor'),
                data.get('impact_point', 'front'),
                data.get('airbag_deployed', False),
                data.get('structural_damage', False),
                data.get('estimated_cost') or None,
                data.get('description', ''),
            ))

        elif report_type == 'service':
            cur.execute("""
                INSERT INTO service_records (submission_id, service_date, odometer_km,
                    service_type, facility_name, description, cost, parts_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('date'),
                data.get('odometer_km') or None,
                data.get('service_type', 'other'),
                data.get('facility_name', ''),
                data.get('description', ''),
                data.get('cost') or None,
                data.get('parts_type', 'na'),
            ))

        elif report_type == 'ownership':
            cur.execute("""
                INSERT INTO ownership_changes (submission_id, change_date,
                    previous_owner_type, new_owner_type, province, sale_price)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('date'),
                data.get('previous_owner_type', 'unknown'),
                data.get('new_owner_type', 'unknown'),
                data.get('province', 'QC'),
                data.get('sale_price') or None,
            ))

        elif report_type == 'inspection':
            cur.execute("""
                INSERT INTO inspections (submission_id, inspection_date, result,
                    odometer_km, notes)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('date'),
                data.get('result', 'pass'),
                data.get('odometer_km') or None,
                data.get('notes', ''),
            ))

        elif report_type == 'recall_completion':
            cur.execute("""
                INSERT INTO recall_completions (submission_id, recall_number,
                    completion_date, facility_name)
                VALUES (%s, %s, %s, %s)
            """, (
                submission_id,
                data.get('recall_number', ''),
                data.get('date'),
                data.get('facility_name', ''),
            ))

        conn.commit()
        cur.close()
        conn.close()

        # Audit log
        log_audit('submission_created', 'submissions', submission_id,
                  {'report_type': report_type, 'vin': vin, 'hash': integrity_hash},
                  request.remote_addr)

        return jsonify({
            'success': True,
            'submission_id': submission_id,
            'integrity_hash': integrity_hash,
            'message': 'Contribution enregistrée avec succès.',
        })

    except Exception as e:
        print(f"[Collecte Submit Error] {e}")
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500


@app.route('/api/collecte/stats', methods=['GET'])
def collecte_stats():
    """Public stats for the collecte page."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT
                (SELECT COUNT(*) FROM submissions),
                (SELECT COUNT(DISTINCT vin) FROM submissions),
                (SELECT COUNT(*) FROM submissions WHERE report_type = 'accident'),
                (SELECT COUNT(*) FROM submissions WHERE report_type = 'service'),
                (SELECT COUNT(DISTINCT submitted_by_email) FROM submissions WHERE submitted_by_email != '')
        """)
        row = cur.fetchone()
        cur.close()
        conn.close()
        return jsonify({
            'total_submissions': row[0],
            'total_vehicles': row[1],
            'total_accidents': row[2],
            'total_services': row[3],
            'total_contributors': row[4],
        })
    except:
        return jsonify({
            'total_submissions': 0,
            'total_vehicles': 0,
            'total_accidents': 0,
            'total_services': 0,
            'total_contributors': 0,
        })


@app.route('/api/collecte/verify', methods=['GET'])
def collecte_verify():
    """Verify the integrity of the entire hash chain."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, vin, report_type, data_snapshot, integrity_hash, previous_hash, submitted_at
            FROM submissions
            WHERE integrity_hash IS NOT NULL
            ORDER BY id ASC
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()

        if not rows:
            return jsonify({
                'valid': True,
                'chain_length': 0,
                'message': 'Aucune soumission à vérifier.',
            })

        broken = []
        expected_prev = None

        for row in rows:
            sid, vin, rtype, snapshot, stored_hash, prev_hash, sub_at = row

            # Check previous_hash links correctly
            if prev_hash != expected_prev:
                if expected_prev is not None:  # Skip genesis check
                    broken.append({
                        'id': sid,
                        'error': 'chain_break',
                        'detail': f'previous_hash ne correspond pas (attendu: {expected_prev[:12]}..., trouvé: {(prev_hash or "null")[:12]}...)',
                    })

            # Recompute hash from stored data snapshot
            snapshot_data = snapshot if isinstance(snapshot, dict) else json.loads(snapshot) if snapshot else {}
            # Use timestamp from snapshot (same one used at hash creation time)
            ts = snapshot_data.get('submitted_at', sub_at.isoformat() if hasattr(sub_at, 'isoformat') else str(sub_at))
            recomputed = compute_integrity_hash(sid, vin, rtype, snapshot_data, prev_hash, ts)

            if recomputed != stored_hash:
                broken.append({
                    'id': sid,
                    'error': 'hash_mismatch',
                    'detail': f'Hash recalculé ne correspond pas (stocké: {stored_hash[:12]}..., calculé: {recomputed[:12]}...)',
                })

            expected_prev = stored_hash

        return jsonify({
            'valid': len(broken) == 0,
            'chain_length': len(rows),
            'last_hash': rows[-1][4] if rows else None,
            'broken_links': broken,
            'verified_at': datetime.now().isoformat(),
            'message': 'Chaîne intègre — aucune donnée altérée.' if not broken else f'{len(broken)} anomalie(s) détectée(s).',
        })

    except Exception as e:
        print(f"[Verify Error] {e}")
        return jsonify({'error': f'Erreur: {str(e)}'}), 500


@app.route('/api/collecte/verify/<int:submission_id>', methods=['GET'])
def collecte_verify_single(submission_id):
    """Verify a single submission's integrity."""
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, vin, report_type, data_snapshot, integrity_hash, previous_hash, submitted_at
            FROM submissions WHERE id = %s
        """, (submission_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            return jsonify({'error': 'Soumission introuvable.'}), 404

        sid, vin, rtype, snapshot, stored_hash, prev_hash, sub_at = row

        if not stored_hash:
            return jsonify({
                'valid': False,
                'submission_id': sid,
                'message': 'Aucun hash d\'intégrité (soumission antérieure au système).',
            })

        snapshot_data = snapshot if isinstance(snapshot, dict) else json.loads(snapshot) if snapshot else {}
        ts = snapshot_data.get('submitted_at', sub_at.isoformat() if hasattr(sub_at, 'isoformat') else str(sub_at))
        recomputed = compute_integrity_hash(sid, vin, rtype, snapshot_data, prev_hash, ts)

        valid = recomputed == stored_hash
        return jsonify({
            'valid': valid,
            'submission_id': sid,
            'integrity_hash': stored_hash,
            'verified_at': datetime.now().isoformat(),
            'message': 'Donnée intègre — non altérée.' if valid else 'ALERTE: Données possiblement altérées!',
        })

    except Exception as e:
        return jsonify({'error': f'Erreur: {str(e)}'}), 500


@app.route('/api/collecte/upload', methods=['POST'])
def collecte_upload():
    """Upload photos for a submission."""
    if 'files' not in request.files:
        return jsonify({'error': 'Aucun fichier envoyé.'}), 400

    files = request.files.getlist('files')
    if len(files) > 5:
        return jsonify({'error': 'Maximum 5 fichiers par soumission.'}), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    uploaded = []

    for f in files:
        if not f.filename:
            continue
        ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
        if ext not in ALLOWED_EXTENSIONS:
            continue
        f.seek(0, 2)
        size = f.tell()
        f.seek(0)
        if size > MAX_FILE_SIZE:
            continue

        filename = f"{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(UPLOAD_DIR, filename)
        f.save(filepath)
        uploaded.append({
            'filename': filename,
            'original': secure_filename(f.filename),
            'size': size,
        })

    return jsonify({'files': uploaded})


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
