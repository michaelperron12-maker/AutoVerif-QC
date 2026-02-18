"""
AutoVerif QC — Backend API
Projet 100% séparé. Scan VIN véhiculaire pour le Québec.
Port: 8930
"""

import os
import re
import io
import csv
import json
import time
import uuid
import hashlib
import requests
import psycopg2
from datetime import datetime
from decimal import Decimal
from flask import Flask, request, jsonify, send_from_directory, Response
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

    # Migration v2: expanded accident_reports fields (industry standard)
    try:
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS odometer_km INTEGER")
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS flood_damage BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS fire_damage BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS theft_vandalism BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS towing_required BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS drivable BOOLEAN DEFAULT TRUE")
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS total_loss BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS police_report_number VARCHAR(100)")
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS insurance_claim_number VARCHAR(100)")
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS insurance_company VARCHAR(200)")
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS rollover BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS hail_damage BOOLEAN DEFAULT FALSE")
        cur.execute("ALTER TABLE accident_reports ADD COLUMN IF NOT EXISTS accident_location VARCHAR(200)")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[Migration v2 accident] {e}")

    # Migration v2: expanded ownership_changes fields
    try:
        cur.execute("ALTER TABLE ownership_changes ADD COLUMN IF NOT EXISTS odometer_km INTEGER")
        cur.execute("ALTER TABLE ownership_changes ADD COLUMN IF NOT EXISTS title_brand VARCHAR(50)")
        cur.execute("ALTER TABLE ownership_changes ADD COLUMN IF NOT EXISTS usage_type VARCHAR(50)")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[Migration v2 ownership] {e}")

    # Migration v2: expanded inspections fields
    try:
        cur.execute("ALTER TABLE inspections ADD COLUMN IF NOT EXISTS inspection_type VARCHAR(50) DEFAULT 'saaq_mecanique'")
        cur.execute("ALTER TABLE inspections ADD COLUMN IF NOT EXISTS inspector_name VARCHAR(200)")
        cur.execute("ALTER TABLE inspections ADD COLUMN IF NOT EXISTS facility_name VARCHAR(200)")
        cur.execute("ALTER TABLE inspections ADD COLUMN IF NOT EXISTS facility_permit VARCHAR(100)")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[Migration v2 inspections] {e}")

    # Migration v2: expanded recall_completions fields
    try:
        cur.execute("ALTER TABLE recall_completions ADD COLUMN IF NOT EXISTS recall_description TEXT")
        cur.execute("ALTER TABLE recall_completions ADD COLUMN IF NOT EXISTS component VARCHAR(200)")
        cur.execute("ALTER TABLE recall_completions ADD COLUMN IF NOT EXISTS remedy_type VARCHAR(50)")
        cur.execute("ALTER TABLE recall_completions ADD COLUMN IF NOT EXISTS odometer_km INTEGER")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[Migration v2 recalls] {e}")

    # New tables v2: title_brands, liens, theft_records
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS title_brands (
                id SERIAL PRIMARY KEY,
                submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
                brand_date DATE,
                brand_type VARCHAR(50) NOT NULL,
                province VARCHAR(10),
                previous_brand VARCHAR(50),
                insurance_company VARCHAR(200),
                total_loss_amount DECIMAL(10,2),
                source VARCHAR(100),
                notes TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_title_brands_sub ON title_brands(submission_id);

            CREATE TABLE IF NOT EXISTS liens (
                id SERIAL PRIMARY KEY,
                submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
                lien_holder VARCHAR(200) NOT NULL,
                lien_type VARCHAR(50),
                lien_amount DECIMAL(12,2),
                registration_date DATE,
                discharge_date DATE,
                lien_status VARCHAR(30) DEFAULT 'active',
                province VARCHAR(10) DEFAULT 'QC',
                registration_number VARCHAR(100),
                notes TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_liens_sub ON liens(submission_id);

            CREATE TABLE IF NOT EXISTS theft_records (
                id SERIAL PRIMARY KEY,
                submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
                date_stolen DATE,
                police_report_number VARCHAR(100),
                police_jurisdiction VARCHAR(200),
                date_recovered DATE,
                recovery_location VARCHAR(200),
                condition_at_recovery VARCHAR(50),
                parts_missing TEXT,
                insurance_claim BOOLEAN DEFAULT FALSE,
                duration_days INTEGER,
                notes TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_theft_sub ON theft_records(submission_id);
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[Migration v2 new tables] {e}")

    # New tables v3: obd, auction, fleet, import/export, odometer, emissions, modifications
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS obd_diagnostics (
                id SERIAL PRIMARY KEY,
                submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
                scan_date DATE,
                odometer_km INTEGER,
                scan_tool VARCHAR(200),
                mil_status BOOLEAN DEFAULT FALSE,
                dtc_active TEXT,
                dtc_pending TEXT,
                dtc_permanent TEXT,
                readiness_monitors JSONB,
                ecu_odometer_km INTEGER,
                freeze_frame JSONB,
                notes TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_obd_sub ON obd_diagnostics(submission_id);

            CREATE TABLE IF NOT EXISTS auction_records (
                id SERIAL PRIMARY KEY,
                submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
                auction_date DATE,
                auction_house VARCHAR(200),
                auction_location VARCHAR(200),
                lot_number VARCHAR(50),
                sale_type VARCHAR(50),
                seller_type VARCHAR(50),
                naaa_grade DECIMAL(2,1),
                exterior_grade VARCHAR(20),
                interior_grade VARCHAR(20),
                mechanical_grade VARCHAR(20),
                tire_tread_fl DECIMAL(3,1),
                tire_tread_fr DECIMAL(3,1),
                tire_tread_rl DECIMAL(3,1),
                tire_tread_rr DECIMAL(3,1),
                odor VARCHAR(50),
                keys_count INTEGER,
                run_drive BOOLEAN DEFAULT TRUE,
                sale_price DECIMAL(10,2),
                damage_announcements TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_auction_sub ON auction_records(submission_id);

            CREATE TABLE IF NOT EXISTS fleet_history (
                id SERIAL PRIMARY KEY,
                submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
                usage_type VARCHAR(50) NOT NULL,
                company_name VARCHAR(200),
                date_entered DATE,
                date_left DATE,
                mileage_during INTEGER,
                estimated_drivers INTEGER,
                province VARCHAR(10),
                notes TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_fleet_sub ON fleet_history(submission_id);

            CREATE TABLE IF NOT EXISTS import_export_records (
                id SERIAL PRIMARY KEY,
                submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
                direction VARCHAR(10) NOT NULL,
                country_origin VARCHAR(100),
                country_destination VARCHAR(100),
                transfer_date DATE,
                riv_number VARCHAR(100),
                customs_declaration VARCHAR(100),
                odometer_at_import INTEGER,
                odometer_unit VARCHAR(10) DEFAULT 'km',
                tc_compliance BOOLEAN DEFAULT FALSE,
                recalls_cleared BOOLEAN DEFAULT FALSE,
                notes TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_import_sub ON import_export_records(submission_id);

            CREATE TABLE IF NOT EXISTS odometer_readings (
                id SERIAL PRIMARY KEY,
                vin VARCHAR(17) NOT NULL,
                submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
                reading_date DATE NOT NULL,
                odometer_km INTEGER NOT NULL,
                odometer_unit VARCHAR(10) DEFAULT 'km',
                source VARCHAR(50),
                status VARCHAR(30) DEFAULT 'actual',
                ecu_reading INTEGER,
                fraud_flag BOOLEAN DEFAULT FALSE,
                fraud_reason VARCHAR(200),
                notes TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_odo_vin ON odometer_readings(vin);
            CREATE INDEX IF NOT EXISTS idx_odo_date ON odometer_readings(reading_date);

            CREATE TABLE IF NOT EXISTS emissions_tests (
                id SERIAL PRIMARY KEY,
                submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
                test_date DATE,
                test_type VARCHAR(50),
                result VARCHAR(20),
                station_name VARCHAR(200),
                station_number VARCHAR(100),
                inspector_id VARCHAR(100),
                hc_ppm DECIMAL(8,2),
                co_percent DECIMAL(5,2),
                nox_ppm DECIMAL(8,2),
                co2_percent DECIMAL(5,2),
                o2_percent DECIMAL(5,2),
                certificate_number VARCHAR(100),
                certificate_expiry DATE,
                exemption_reason VARCHAR(200),
                notes TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_emissions_sub ON emissions_tests(submission_id);

            CREATE TABLE IF NOT EXISTS vehicle_modifications (
                id SERIAL PRIMARY KEY,
                submission_id INTEGER REFERENCES submissions(id) ON DELETE CASCADE,
                mod_date DATE,
                mod_type VARCHAR(50) NOT NULL,
                description TEXT,
                part_brand VARCHAR(200),
                part_number VARCHAR(100),
                installed_by VARCHAR(200),
                homologated BOOLEAN DEFAULT FALSE,
                saaq_approved BOOLEAN DEFAULT FALSE,
                insurance_notified BOOLEAN DEFAULT FALSE,
                notes TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_mods_sub ON vehicle_modifications(submission_id);
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[Migration v3 new tables] {e}")

    # New table v4: import_batches for CSV/batch imports
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS import_batches (
                id SERIAL PRIMARY KEY,
                batch_ref VARCHAR(20) UNIQUE NOT NULL,
                submitter_name VARCHAR(200),
                submitter_email VARCHAR(200),
                submitter_type VARCHAR(50),
                submitter_company VARCHAR(200),
                filename VARCHAR(300),
                total_rows INTEGER DEFAULT 0,
                processed INTEGER DEFAULT 0,
                success_count INTEGER DEFAULT 0,
                error_count INTEGER DEFAULT 0,
                status VARCHAR(20) DEFAULT 'processing',
                errors JSONB,
                submission_ids JSONB,
                created_at TIMESTAMP DEFAULT NOW(),
                completed_at TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_batch_ref ON import_batches(batch_ref);
        """)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[Migration v4 import_batches] {e}")

    # Migration v3: EV fields on service_records
    try:
        cur.execute("ALTER TABLE service_records ADD COLUMN IF NOT EXISTS ev_battery_soh DECIMAL(5,2)")
        cur.execute("ALTER TABLE service_records ADD COLUMN IF NOT EXISTS ev_battery_kwh DECIMAL(6,2)")
        cur.execute("ALTER TABLE service_records ADD COLUMN IF NOT EXISTS ev_service_type VARCHAR(50)")
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[Migration v3 EV fields] {e}")

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


def track_odometer(vin, odometer_km, source, submission_id=None, reading_date=None, unit='km', ecu_reading=None):
    """Auto-track odometer reading and detect possible fraud (rollback)."""
    if not odometer_km or odometer_km <= 0:
        return
    try:
        conn = get_db()
        cur = conn.cursor()
        # Check for rollback: new reading lower than previous?
        cur.execute("""
            SELECT odometer_km, reading_date FROM odometer_readings
            WHERE vin = %s ORDER BY reading_date DESC, id DESC LIMIT 1
        """, (vin,))
        prev = cur.fetchone()
        fraud_flag = False
        fraud_reason = None
        if prev and prev[0] and odometer_km < prev[0]:
            fraud_flag = True
            fraud_reason = f"Rollback suspect: {odometer_km} km < precedent {prev[0]} km"
        # ECU mismatch check
        if ecu_reading and abs(ecu_reading - odometer_km) > 5000:
            fraud_flag = True
            fraud_reason = (fraud_reason or '') + f" ECU mismatch: ECU={ecu_reading} vs declared={odometer_km}"

        cur.execute("""
            INSERT INTO odometer_readings (vin, submission_id, reading_date, odometer_km,
                odometer_unit, source, ecu_reading, fraud_flag, fraud_reason)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            vin, submission_id, reading_date or datetime.now().date(),
            odometer_km, unit, source, ecu_reading, fraud_flag, fraud_reason,
        ))
        conn.commit()
        cur.close()
        conn.close()
        if fraud_flag:
            log_audit('odometer_fraud_alert', 'odometer_readings', submission_id,
                      {'vin': vin, 'reading': odometer_km, 'reason': fraud_reason})
    except Exception as e:
        print(f"[Odometer Track Error] {e}")


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
    valid_types = ['accident', 'service', 'ownership', 'inspection', 'recall_completion',
                    'title_brand', 'lien', 'theft', 'obd_diagnostic', 'auction',
                    'fleet_history', 'import_export', 'emissions', 'modification']
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
                    impact_point, airbag_deployed, structural_damage, estimated_cost, description,
                    odometer_km, flood_damage, fire_damage, theft_vandalism, towing_required,
                    drivable, total_loss, police_report_number, insurance_claim_number,
                    insurance_company, rollover, hail_damage, accident_location)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('date'),
                data.get('severity', 'minor'),
                data.get('impact_point', 'front'),
                data.get('airbag_deployed', False),
                data.get('structural_damage', False),
                data.get('estimated_cost') or None,
                data.get('description', ''),
                data.get('odometer_km') or None,
                data.get('flood_damage', False),
                data.get('fire_damage', False),
                data.get('theft_vandalism', False),
                data.get('towing_required', False),
                data.get('drivable', True),
                data.get('total_loss', False),
                data.get('police_report_number', '') or None,
                data.get('insurance_claim_number', '') or None,
                data.get('insurance_company', '') or None,
                data.get('rollover', False),
                data.get('hail_damage', False),
                data.get('accident_location', '') or None,
            ))

        elif report_type == 'service':
            cur.execute("""
                INSERT INTO service_records (submission_id, service_date, odometer_km,
                    service_type, facility_name, description, cost, parts_type,
                    ev_battery_soh, ev_battery_kwh, ev_service_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('date'),
                data.get('odometer_km') or None,
                data.get('service_type', 'other'),
                data.get('facility_name', ''),
                data.get('description', ''),
                data.get('cost') or None,
                data.get('parts_type', 'na'),
                data.get('ev_battery_soh') or None,
                data.get('ev_battery_kwh') or None,
                data.get('ev_service_type', '') or None,
            ))

        elif report_type == 'ownership':
            cur.execute("""
                INSERT INTO ownership_changes (submission_id, change_date,
                    previous_owner_type, new_owner_type, province, sale_price,
                    odometer_km, title_brand, usage_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('date'),
                data.get('previous_owner_type', 'unknown'),
                data.get('new_owner_type', 'unknown'),
                data.get('province', 'QC'),
                data.get('sale_price') or None,
                data.get('odometer_km') or None,
                data.get('title_brand', '') or None,
                data.get('usage_type', '') or None,
            ))

        elif report_type == 'inspection':
            cur.execute("""
                INSERT INTO inspections (submission_id, inspection_date, result,
                    odometer_km, notes, inspection_type, inspector_name,
                    facility_name, facility_permit)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('date'),
                data.get('result', 'pass'),
                data.get('odometer_km') or None,
                data.get('notes', ''),
                data.get('inspection_type', 'saaq_mecanique'),
                data.get('inspector_name', '') or None,
                data.get('facility_name', '') or None,
                data.get('facility_permit', '') or None,
            ))

        elif report_type == 'recall_completion':
            cur.execute("""
                INSERT INTO recall_completions (submission_id, recall_number,
                    completion_date, facility_name, recall_description,
                    component, remedy_type, odometer_km)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('recall_number', ''),
                data.get('date'),
                data.get('facility_name', ''),
                data.get('recall_description', '') or None,
                data.get('component', '') or None,
                data.get('remedy_type', '') or None,
                data.get('odometer_km') or None,
            ))

        elif report_type == 'title_brand':
            cur.execute("""
                INSERT INTO title_brands (submission_id, brand_date, brand_type,
                    province, previous_brand, insurance_company, total_loss_amount,
                    source, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('date'),
                data.get('brand_type', 'clean'),
                data.get('province', 'QC'),
                data.get('previous_brand', '') or None,
                data.get('insurance_company', '') or None,
                data.get('total_loss_amount') or None,
                data.get('source', '') or None,
                data.get('notes', ''),
            ))

        elif report_type == 'lien':
            cur.execute("""
                INSERT INTO liens (submission_id, lien_holder, lien_type,
                    lien_amount, registration_date, discharge_date, lien_status,
                    province, registration_number, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('lien_holder', ''),
                data.get('lien_type', '') or None,
                data.get('lien_amount') or None,
                data.get('registration_date') or None,
                data.get('discharge_date') or None,
                data.get('lien_status', 'active'),
                data.get('province', 'QC'),
                data.get('registration_number', '') or None,
                data.get('notes', ''),
            ))

        elif report_type == 'theft':
            cur.execute("""
                INSERT INTO theft_records (submission_id, date_stolen,
                    police_report_number, police_jurisdiction, date_recovered,
                    recovery_location, condition_at_recovery, parts_missing,
                    insurance_claim, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('date_stolen'),
                data.get('police_report_number', '') or None,
                data.get('police_jurisdiction', '') or None,
                data.get('date_recovered') or None,
                data.get('recovery_location', '') or None,
                data.get('condition_at_recovery', '') or None,
                data.get('parts_missing', '') or None,
                data.get('insurance_claim', False),
                data.get('notes', ''),
            ))

        elif report_type == 'obd_diagnostic':
            cur.execute("""
                INSERT INTO obd_diagnostics (submission_id, scan_date, odometer_km,
                    scan_tool, mil_status, dtc_active, dtc_pending, dtc_permanent,
                    readiness_monitors, ecu_odometer_km, freeze_frame, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('date'),
                data.get('odometer_km') or None,
                data.get('scan_tool', '') or None,
                data.get('mil_status', False),
                data.get('dtc_active', '') or None,
                data.get('dtc_pending', '') or None,
                data.get('dtc_permanent', '') or None,
                json.dumps(data.get('readiness_monitors', {})) if data.get('readiness_monitors') else None,
                data.get('ecu_odometer_km') or None,
                json.dumps(data.get('freeze_frame', {})) if data.get('freeze_frame') else None,
                data.get('notes', ''),
            ))

        elif report_type == 'auction':
            cur.execute("""
                INSERT INTO auction_records (submission_id, auction_date, auction_house,
                    auction_location, lot_number, sale_type, seller_type, naaa_grade,
                    exterior_grade, interior_grade, mechanical_grade,
                    tire_tread_fl, tire_tread_fr, tire_tread_rl, tire_tread_rr,
                    odor, keys_count, run_drive, sale_price, damage_announcements, notes)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                submission_id,
                data.get('date'),
                data.get('auction_house', '') or None,
                data.get('auction_location', '') or None,
                data.get('lot_number', '') or None,
                data.get('sale_type', '') or None,
                data.get('seller_type', '') or None,
                data.get('naaa_grade') or None,
                data.get('exterior_grade', '') or None,
                data.get('interior_grade', '') or None,
                data.get('mechanical_grade', '') or None,
                data.get('tire_tread_fl') or None,
                data.get('tire_tread_fr') or None,
                data.get('tire_tread_rl') or None,
                data.get('tire_tread_rr') or None,
                data.get('odor', '') or None,
                data.get('keys_count') or None,
                data.get('run_drive', True),
                data.get('sale_price') or None,
                data.get('damage_announcements', '') or None,
                data.get('notes', ''),
            ))

        elif report_type == 'fleet_history':
            cur.execute("""
                INSERT INTO fleet_history (submission_id, usage_type, company_name,
                    date_entered, date_left, mileage_during, estimated_drivers,
                    province, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('usage_type', ''),
                data.get('company_name', '') or None,
                data.get('date_entered') or None,
                data.get('date_left') or None,
                data.get('mileage_during') or None,
                data.get('estimated_drivers') or None,
                data.get('province', 'QC'),
                data.get('notes', ''),
            ))

        elif report_type == 'import_export':
            cur.execute("""
                INSERT INTO import_export_records (submission_id, direction, country_origin,
                    country_destination, transfer_date, riv_number, customs_declaration,
                    odometer_at_import, odometer_unit, tc_compliance, recalls_cleared, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('direction', 'import'),
                data.get('country_origin', '') or None,
                data.get('country_destination', '') or None,
                data.get('date') or None,
                data.get('riv_number', '') or None,
                data.get('customs_declaration', '') or None,
                data.get('odometer_at_import') or None,
                data.get('odometer_unit', 'km'),
                data.get('tc_compliance', False),
                data.get('recalls_cleared', False),
                data.get('notes', ''),
            ))

        elif report_type == 'emissions':
            cur.execute("""
                INSERT INTO emissions_tests (submission_id, test_date, test_type, result,
                    station_name, station_number, inspector_id,
                    hc_ppm, co_percent, nox_ppm, co2_percent, o2_percent,
                    certificate_number, certificate_expiry, exemption_reason, notes)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                submission_id,
                data.get('date'),
                data.get('test_type', '') or None,
                data.get('result', 'pass'),
                data.get('station_name', '') or None,
                data.get('station_number', '') or None,
                data.get('inspector_id', '') or None,
                data.get('hc_ppm') or None,
                data.get('co_percent') or None,
                data.get('nox_ppm') or None,
                data.get('co2_percent') or None,
                data.get('o2_percent') or None,
                data.get('certificate_number', '') or None,
                data.get('certificate_expiry') or None,
                data.get('exemption_reason', '') or None,
                data.get('notes', ''),
            ))

        elif report_type == 'modification':
            cur.execute("""
                INSERT INTO vehicle_modifications (submission_id, mod_date, mod_type,
                    description, part_brand, part_number, installed_by,
                    homologated, saaq_approved, insurance_notified, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                submission_id,
                data.get('date'),
                data.get('mod_type', ''),
                data.get('description', ''),
                data.get('part_brand', '') or None,
                data.get('part_number', '') or None,
                data.get('installed_by', '') or None,
                data.get('homologated', False),
                data.get('saaq_approved', False),
                data.get('insurance_notified', False),
                data.get('notes', ''),
            ))

        conn.commit()

        # Auto-track odometer from any submission that has it
        odo_val = data.get('odometer_km') or data.get('odometer_at_import')
        if odo_val:
            track_odometer(
                vin, int(odo_val), f'submission_{report_type}',
                submission_id=submission_id,
                reading_date=data.get('date'),
                ecu_reading=data.get('ecu_odometer_km'),
            )
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
    files = request.files.getlist('photos') or request.files.getlist('files')
    if not files:
        return jsonify({'error': 'Aucun fichier envoyé.'}), 400
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


# ─── Internal submit helper (reused by single, batch, CSV) ───
def _process_single_submission(vin, report_type, submitter, data, ip_address='batch'):
    """Process one submission record. Returns dict with success/error info."""
    valid_types = ['accident', 'service', 'ownership', 'inspection', 'recall_completion',
                    'title_brand', 'lien', 'theft', 'obd_diagnostic', 'auction',
                    'fleet_history', 'import_export', 'emissions', 'modification']

    vin = (vin or '').strip().upper()
    if not validate_vin(vin):
        return {'success': False, 'error': f'VIN invalide: {vin}'}

    if report_type not in valid_types:
        return {'success': False, 'error': f'Type invalide: {report_type}'}

    vehicle = get_or_create_vehicle(vin)
    if not vehicle:
        return {'success': False, 'error': f'Impossible de décoder VIN: {vin}'}

    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT integrity_hash FROM submissions WHERE integrity_hash IS NOT NULL ORDER BY id DESC LIMIT 1")
        prev_row = cur.fetchone()
        previous_hash = prev_row[0] if prev_row else None

        now = datetime.now().isoformat()
        data_snapshot = {
            'vin': vin, 'report_type': report_type,
            'submitter': submitter, 'data': data,
            'submitted_at': now, 'ip': ip_address,
        }

        cur.execute("""
            INSERT INTO submissions (vehicle_id, vin, report_type, submitted_by_name,
                submitted_by_email, submitted_by_type, submitted_by_company, ip_address,
                data_snapshot, previous_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            vehicle['id'], vin, report_type,
            submitter.get('name', ''), submitter.get('email', ''),
            submitter.get('type', ''), submitter.get('company', ''),
            ip_address,
            json.dumps(data_snapshot, sort_keys=True, ensure_ascii=False),
            previous_hash,
        ))
        submission_id = cur.fetchone()[0]

        integrity_hash = compute_integrity_hash(
            submission_id, vin, report_type, data_snapshot, previous_hash, now
        )
        cur.execute("UPDATE submissions SET integrity_hash = %s WHERE id = %s", (integrity_hash, submission_id))

        # Insert type-specific detail (same logic as collecte_submit)
        _insert_detail(cur, submission_id, report_type, data)

        conn.commit()
        cur.close()
        conn.close()

        # Auto-track odometer
        odo_val = data.get('odometer_km') or data.get('odometer_at_import')
        if odo_val:
            track_odometer(vin, int(odo_val), f'submission_{report_type}',
                           submission_id=submission_id, reading_date=data.get('date'),
                           ecu_reading=data.get('ecu_odometer_km'))

        log_audit('submission_created', 'submissions', submission_id,
                  {'report_type': report_type, 'vin': vin, 'hash': integrity_hash}, ip_address)

        return {'success': True, 'submission_id': submission_id, 'integrity_hash': integrity_hash}

    except Exception as e:
        print(f"[Submit Helper Error] {e}")
        return {'success': False, 'error': str(e)}


def _insert_detail(cur, submission_id, report_type, data):
    """Insert type-specific detail record."""
    if report_type == 'accident':
        cur.execute("""
            INSERT INTO accident_reports (submission_id, accident_date, severity,
                impact_point, airbag_deployed, structural_damage, estimated_cost, description,
                odometer_km, flood_damage, fire_damage, theft_vandalism, towing_required,
                drivable, total_loss, police_report_number, insurance_claim_number,
                insurance_company, rollover, hail_damage, accident_location)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('date'), data.get('severity', 'minor'),
            data.get('impact_point', 'front'), data.get('airbag_deployed', False),
            data.get('structural_damage', False), data.get('estimated_cost') or None,
            data.get('description', ''), data.get('odometer_km') or None,
            data.get('flood_damage', False), data.get('fire_damage', False),
            data.get('theft_vandalism', False), data.get('towing_required', False),
            data.get('drivable', True), data.get('total_loss', False),
            data.get('police_report_number', '') or None, data.get('insurance_claim_number', '') or None,
            data.get('insurance_company', '') or None, data.get('rollover', False),
            data.get('hail_damage', False), data.get('accident_location', '') or None,
        ))
    elif report_type == 'service':
        cur.execute("""
            INSERT INTO service_records (submission_id, service_date, odometer_km,
                service_type, facility_name, description, cost, parts_type,
                ev_battery_soh, ev_battery_kwh, ev_service_type)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('date'), data.get('odometer_km') or None,
            data.get('service_type', 'other'), data.get('facility_name', ''),
            data.get('description', ''), data.get('cost') or None,
            data.get('parts_type', 'na'), data.get('ev_battery_soh') or None,
            data.get('ev_battery_kwh') or None, data.get('ev_service_type', '') or None,
        ))
    elif report_type == 'ownership':
        cur.execute("""
            INSERT INTO ownership_changes (submission_id, change_date,
                previous_owner_type, new_owner_type, province, sale_price,
                odometer_km, title_brand, usage_type)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('date'), data.get('previous_owner_type', 'unknown'),
            data.get('new_owner_type', 'unknown'), data.get('province', 'QC'),
            data.get('sale_price') or None, data.get('odometer_km') or None,
            data.get('title_brand', '') or None, data.get('usage_type', '') or None,
        ))
    elif report_type == 'inspection':
        cur.execute("""
            INSERT INTO inspections (submission_id, inspection_date, result,
                odometer_km, notes, inspection_type, inspector_name,
                facility_name, facility_permit)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('date'), data.get('result', 'pass'),
            data.get('odometer_km') or None, data.get('notes', ''),
            data.get('inspection_type', 'saaq_mecanique'), data.get('inspector_name', '') or None,
            data.get('facility_name', '') or None, data.get('facility_permit', '') or None,
        ))
    elif report_type == 'recall_completion':
        cur.execute("""
            INSERT INTO recall_completions (submission_id, recall_number,
                completion_date, facility_name, recall_description,
                component, remedy_type, odometer_km)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('recall_number', ''), data.get('date'),
            data.get('facility_name', ''), data.get('recall_description', '') or None,
            data.get('component', '') or None, data.get('remedy_type', '') or None,
            data.get('odometer_km') or None,
        ))
    elif report_type == 'title_brand':
        cur.execute("""
            INSERT INTO title_brands (submission_id, brand_date, brand_type,
                province, previous_brand, insurance_company, total_loss_amount,
                source, notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('date'), data.get('brand_type', 'clean'),
            data.get('province', 'QC'), data.get('previous_brand', '') or None,
            data.get('insurance_company', '') or None, data.get('total_loss_amount') or None,
            data.get('source', '') or None, data.get('notes', ''),
        ))
    elif report_type == 'lien':
        cur.execute("""
            INSERT INTO liens (submission_id, lien_holder, lien_type,
                lien_amount, registration_date, discharge_date, lien_status,
                province, registration_number, notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('lien_holder', ''), data.get('lien_type', '') or None,
            data.get('lien_amount') or None, data.get('registration_date') or None,
            data.get('discharge_date') or None, data.get('lien_status', 'active'),
            data.get('province', 'QC'), data.get('registration_number', '') or None,
            data.get('notes', ''),
        ))
    elif report_type == 'theft':
        cur.execute("""
            INSERT INTO theft_records (submission_id, date_stolen,
                police_report_number, police_jurisdiction, date_recovered,
                recovery_location, condition_at_recovery, parts_missing,
                insurance_claim, notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('date_stolen'), data.get('police_report_number', '') or None,
            data.get('police_jurisdiction', '') or None, data.get('date_recovered') or None,
            data.get('recovery_location', '') or None, data.get('condition_at_recovery', '') or None,
            data.get('parts_missing', '') or None, data.get('insurance_claim', False),
            data.get('notes', ''),
        ))
    elif report_type == 'obd_diagnostic':
        cur.execute("""
            INSERT INTO obd_diagnostics (submission_id, scan_date, odometer_km,
                scan_tool, mil_status, dtc_active, dtc_pending, dtc_permanent,
                readiness_monitors, ecu_odometer_km, freeze_frame, notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('date'), data.get('odometer_km') or None,
            data.get('scan_tool', '') or None, data.get('mil_status', False),
            data.get('dtc_active', '') or None, data.get('dtc_pending', '') or None,
            data.get('dtc_permanent', '') or None,
            json.dumps(data.get('readiness_monitors', {})) if data.get('readiness_monitors') else None,
            data.get('ecu_odometer_km') or None,
            json.dumps(data.get('freeze_frame', {})) if data.get('freeze_frame') else None,
            data.get('notes', ''),
        ))
    elif report_type == 'auction':
        cur.execute("""
            INSERT INTO auction_records (submission_id, auction_date, auction_house,
                auction_location, lot_number, sale_type, seller_type, naaa_grade,
                exterior_grade, interior_grade, mechanical_grade,
                tire_tread_fl, tire_tread_fr, tire_tread_rl, tire_tread_rr,
                odor, keys_count, run_drive, sale_price, damage_announcements, notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('date'), data.get('auction_house', '') or None,
            data.get('auction_location', '') or None, data.get('lot_number', '') or None,
            data.get('sale_type', '') or None, data.get('seller_type', '') or None,
            data.get('naaa_grade') or None, data.get('exterior_grade', '') or None,
            data.get('interior_grade', '') or None, data.get('mechanical_grade', '') or None,
            data.get('tire_tread_fl') or None, data.get('tire_tread_fr') or None,
            data.get('tire_tread_rl') or None, data.get('tire_tread_rr') or None,
            data.get('odor', '') or None, data.get('keys_count') or None,
            data.get('run_drive', True), data.get('sale_price') or None,
            data.get('damage_announcements', '') or None, data.get('notes', ''),
        ))
    elif report_type == 'fleet_history':
        cur.execute("""
            INSERT INTO fleet_history (submission_id, usage_type, company_name,
                date_entered, date_left, mileage_during, estimated_drivers,
                province, notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('usage_type', ''), data.get('company_name', '') or None,
            data.get('date_entered') or None, data.get('date_left') or None,
            data.get('mileage_during') or None, data.get('estimated_drivers') or None,
            data.get('province', 'QC'), data.get('notes', ''),
        ))
    elif report_type == 'import_export':
        cur.execute("""
            INSERT INTO import_export_records (submission_id, direction, country_origin,
                country_destination, transfer_date, riv_number, customs_declaration,
                odometer_at_import, odometer_unit, tc_compliance, recalls_cleared, notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('direction', 'import'), data.get('country_origin', '') or None,
            data.get('country_destination', '') or None, data.get('date') or None,
            data.get('riv_number', '') or None, data.get('customs_declaration', '') or None,
            data.get('odometer_at_import') or None, data.get('odometer_unit', 'km'),
            data.get('tc_compliance', False), data.get('recalls_cleared', False),
            data.get('notes', ''),
        ))
    elif report_type == 'emissions':
        cur.execute("""
            INSERT INTO emissions_tests (submission_id, test_date, test_type, result,
                station_name, station_number, inspector_id,
                hc_ppm, co_percent, nox_ppm, co2_percent, o2_percent,
                certificate_number, certificate_expiry, exemption_reason, notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('date'), data.get('test_type', '') or None,
            data.get('result', 'pass'), data.get('station_name', '') or None,
            data.get('station_number', '') or None, data.get('inspector_id', '') or None,
            data.get('hc_ppm') or None, data.get('co_percent') or None,
            data.get('nox_ppm') or None, data.get('co2_percent') or None,
            data.get('o2_percent') or None, data.get('certificate_number', '') or None,
            data.get('certificate_expiry') or None, data.get('exemption_reason', '') or None,
            data.get('notes', ''),
        ))
    elif report_type == 'modification':
        cur.execute("""
            INSERT INTO vehicle_modifications (submission_id, mod_date, mod_type,
                description, part_brand, part_number, installed_by,
                homologated, saaq_approved, insurance_notified, notes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            submission_id, data.get('date'), data.get('mod_type', ''),
            data.get('description', ''), data.get('part_brand', '') or None,
            data.get('part_number', '') or None, data.get('installed_by', '') or None,
            data.get('homologated', False), data.get('saaq_approved', False),
            data.get('insurance_notified', False), data.get('notes', ''),
        ))


# ─── CSV Import ───
CSV_TEMPLATES = {
    'service': {
        'headers': ['vin','date','odometer_km','service_type','facility_name','description','cost','parts_type'],
        'examples': [
            ['2HGFC2F59MH528491','2025-06-15','45000','oil_change','Garage Laval','Changement huile synthétique 5W-30 + filtre','89.99','oem'],
            ['1FTFW1ET5EKE12345','2025-03-20','82000','brakes','Monsieur Muffler Longueuil','Plaquettes avant + disques','650.00','aftermarket'],
        ],
    },
    'accident': {
        'headers': ['vin','date','severity','impact_point','description','estimated_cost','odometer_km','airbag_deployed','structural_damage'],
        'examples': [
            ['2HGFC2F59MH528491','2024-12-10','moderate','front_left','Collision intersection, feu rouge','8500','42000','false','true'],
            ['1FTFW1ET5EKE12345','2025-01-05','minor','rear','Accrochage stationnement','1200','80000','false','false'],
        ],
    },
    'inspection': {
        'headers': ['vin','date','result','odometer_km','inspection_type','facility_name','inspector_name','notes'],
        'examples': [
            ['2HGFC2F59MH528491','2025-08-01','pass','47000','saaq_mecanique','SAAQ Laval','Jean Tremblay','RAS'],
            ['1FTFW1ET5EKE12345','2025-02-15','fail','83000','saaq_mecanique','Centre Auto Brossard','Marc Gagné','Freins arrière usés'],
        ],
    },
    'ownership': {
        'headers': ['vin','date','previous_owner_type','new_owner_type','province','sale_price','odometer_km','usage_type'],
        'examples': [
            ['2HGFC2F59MH528491','2024-05-10','dealer','individual','QC','28500','35000','personal'],
            ['1FTFW1ET5EKE12345','2023-08-22','individual','individual','QC','22000','75000','personal'],
        ],
    },
    'general': {
        'headers': ['vin','report_type','date','odometer_km','description','facility_name','cost','severity','impact_point','service_type'],
        'examples': [
            ['2HGFC2F59MH528491','service','2025-06-15','45000','Changement huile','Garage Laval','89.99','','','oil_change'],
            ['1FTFW1ET5EKE12345','accident','2025-01-05','80000','Accrochage arrière','','1200','minor','rear',''],
        ],
    },
}


def _auto_detect_report_type(row):
    """Auto-detect report_type from CSV column values."""
    if row.get('report_type'):
        return row['report_type'].strip().lower()
    # Heuristic based on which columns have data
    if row.get('severity') or row.get('impact_point') or row.get('airbag_deployed'):
        return 'accident'
    if row.get('service_type') or (row.get('facility_name') and row.get('cost')):
        return 'service'
    if row.get('previous_owner_type') or row.get('new_owner_type') or row.get('sale_price'):
        return 'ownership'
    if row.get('result') and row.get('result') in ('pass', 'fail'):
        return 'inspection'
    if row.get('recall_number'):
        return 'recall_completion'
    # Default to service if has date + odometer
    if row.get('date') and row.get('odometer_km'):
        return 'service'
    return 'service'


def _csv_row_to_data(row, report_type):
    """Map CSV columns to the data dict expected by _process_single_submission."""
    data = {}
    # Common fields
    for key in ('date', 'description', 'notes', 'facility_name', 'odometer_km', 'cost'):
        if row.get(key):
            val = row[key].strip()
            if key in ('odometer_km', 'cost'):
                try:
                    data[key] = float(val) if '.' in val else int(val)
                except ValueError:
                    pass
            else:
                data[key] = val

    if report_type == 'accident':
        for k in ('severity', 'impact_point', 'police_report_number', 'insurance_company',
                   'insurance_claim_number', 'accident_location'):
            if row.get(k):
                data[k] = row[k].strip()
        for k in ('airbag_deployed', 'structural_damage', 'flood_damage', 'fire_damage',
                   'towing_required', 'drivable', 'total_loss', 'rollover', 'hail_damage'):
            if row.get(k):
                data[k] = row[k].strip().lower() in ('true', '1', 'oui', 'yes')
        if row.get('estimated_cost'):
            try:
                data['estimated_cost'] = float(row['estimated_cost'])
            except ValueError:
                pass

    elif report_type == 'service':
        for k in ('service_type', 'parts_type'):
            if row.get(k):
                data[k] = row[k].strip()

    elif report_type == 'ownership':
        for k in ('previous_owner_type', 'new_owner_type', 'province', 'usage_type', 'title_brand'):
            if row.get(k):
                data[k] = row[k].strip()
        if row.get('sale_price'):
            try:
                data['sale_price'] = float(row['sale_price'])
            except ValueError:
                pass

    elif report_type == 'inspection':
        for k in ('result', 'inspection_type', 'inspector_name', 'facility_permit'):
            if row.get(k):
                data[k] = row[k].strip()

    elif report_type == 'recall_completion':
        for k in ('recall_number', 'recall_description', 'component', 'remedy_type'):
            if row.get(k):
                data[k] = row[k].strip()

    return data


@app.route('/api/collecte/import-csv', methods=['POST'])
def collecte_import_csv():
    """Import data from a CSV file."""
    csv_file = request.files.get('file')
    if not csv_file:
        return jsonify({'error': 'Aucun fichier CSV envoyé.'}), 400

    # Read file content
    try:
        raw = csv_file.read()
        if len(raw) > 2 * 1024 * 1024:
            return jsonify({'error': 'Fichier trop volumineux (max 2 Mo).'}), 400
        content = raw.decode('utf-8-sig')  # Handle BOM
    except UnicodeDecodeError:
        try:
            content = raw.decode('latin-1')
        except:
            return jsonify({'error': 'Encodage du fichier non reconnu.'}), 400

    # Auto-detect delimiter
    delimiter = ',' if content.count(',') >= content.count(';') else ';'

    reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
    rows = list(reader)

    if not rows:
        return jsonify({'error': 'Fichier CSV vide.'}), 400
    if len(rows) > 500:
        return jsonify({'error': f'Maximum 500 lignes ({len(rows)} détectées).'}), 400

    # Check VIN column exists
    headers_lower = [h.lower().strip() for h in (reader.fieldnames or [])]
    if 'vin' not in headers_lower:
        return jsonify({'error': 'Colonne "vin" requise dans le CSV.'}), 400

    # Submitter info from form fields
    submitter = {
        'name': request.form.get('submitter_name', ''),
        'email': request.form.get('submitter_email', ''),
        'type': request.form.get('submitter_type', ''),
        'company': request.form.get('submitter_company', ''),
    }

    batch_ref = f"CSV-{uuid.uuid4().hex[:8].upper()}"
    ip = request.remote_addr

    # Create batch record
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO import_batches (batch_ref, submitter_name, submitter_email,
                submitter_type, submitter_company, filename, total_rows)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id
        """, (batch_ref, submitter['name'], submitter['email'], submitter['type'],
              submitter['company'], secure_filename(csv_file.filename), len(rows)))
        batch_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({'error': f'Erreur DB: {e}'}), 500

    # Process each row
    results = []
    errors = []
    submission_ids = []

    for i, row in enumerate(rows):
        # Normalize keys to lowercase
        row = {k.lower().strip(): v.strip() if v else '' for k, v in row.items()}
        vin = row.get('vin', '').upper()
        if not vin:
            errors.append({'row': i + 2, 'error': 'VIN manquant'})
            continue

        report_type = _auto_detect_report_type(row)
        data = _csv_row_to_data(row, report_type)

        result = _process_single_submission(vin, report_type, submitter, data, ip)
        if result['success']:
            results.append({'row': i + 2, 'vin': vin, 'type': report_type,
                            'submission_id': result['submission_id']})
            submission_ids.append(result['submission_id'])
        else:
            errors.append({'row': i + 2, 'vin': vin, 'error': result['error']})

    # Update batch record
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            UPDATE import_batches SET processed = %s, success_count = %s,
                error_count = %s, status = 'completed', errors = %s,
                submission_ids = %s, completed_at = NOW()
            WHERE id = %s
        """, (len(rows), len(results), len(errors),
              json.dumps(errors) if errors else None,
              json.dumps(submission_ids) if submission_ids else None,
              batch_id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[Batch Update Error] {e}")

    log_audit('csv_import', 'import_batches', batch_id,
              {'batch_ref': batch_ref, 'total': len(rows), 'success': len(results),
               'errors': len(errors)}, ip)

    return jsonify({
        'success': True,
        'batch_ref': batch_ref,
        'total_rows': len(rows),
        'success_count': len(results),
        'error_count': len(errors),
        'results': results,
        'errors': errors,
    })


@app.route('/api/collecte/batch', methods=['POST'])
def collecte_batch():
    """Batch submit multiple records via JSON API."""
    body = request.get_json()
    if not body:
        return jsonify({'error': 'Corps JSON requis.'}), 400

    submitter = body.get('submitter', {})
    records = body.get('records', [])

    if not records:
        return jsonify({'error': 'Aucun record fourni.'}), 400
    if len(records) > 100:
        return jsonify({'error': f'Maximum 100 records par requête ({len(records)} reçus).'}), 400

    batch_ref = f"API-{uuid.uuid4().hex[:8].upper()}"
    ip = request.remote_addr

    # Create batch record
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO import_batches (batch_ref, submitter_name, submitter_email,
                submitter_type, submitter_company, filename, total_rows)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id
        """, (batch_ref, submitter.get('name', ''), submitter.get('email', ''),
              submitter.get('type', ''), submitter.get('company', ''),
              'batch_api', len(records)))
        batch_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        return jsonify({'error': f'Erreur DB: {e}'}), 500

    results = []
    errors = []
    submission_ids = []

    for i, rec in enumerate(records):
        vin = (rec.get('vin') or '').strip().upper()
        report_type = rec.get('report_type', 'service')
        data = rec.get('data', {})

        result = _process_single_submission(vin, report_type, submitter, data, ip)
        if result['success']:
            results.append({'index': i, 'vin': vin, 'type': report_type,
                            'submission_id': result['submission_id'],
                            'integrity_hash': result['integrity_hash']})
            submission_ids.append(result['submission_id'])
        else:
            errors.append({'index': i, 'vin': vin, 'error': result['error']})

    # Update batch
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            UPDATE import_batches SET processed = %s, success_count = %s,
                error_count = %s, status = 'completed', errors = %s,
                submission_ids = %s, completed_at = NOW()
            WHERE id = %s
        """, (len(records), len(results), len(errors),
              json.dumps(errors) if errors else None,
              json.dumps(submission_ids) if submission_ids else None,
              batch_id))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[Batch Update Error] {e}")

    log_audit('batch_import', 'import_batches', batch_id,
              {'batch_ref': batch_ref, 'total': len(records), 'success': len(results)}, ip)

    return jsonify({
        'success': True,
        'batch_ref': batch_ref,
        'total_records': len(records),
        'success_count': len(results),
        'error_count': len(errors),
        'results': results,
        'errors': errors,
    })


@app.route('/api/collecte/templates/<template_name>', methods=['GET'])
def collecte_template(template_name):
    """Download a CSV template."""
    template_name = template_name.replace('.csv', '')
    if template_name not in CSV_TEMPLATES:
        return jsonify({'error': f'Template inconnu. Disponibles: {", ".join(CSV_TEMPLATES.keys())}'}), 404

    tmpl = CSV_TEMPLATES[template_name]
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(tmpl['headers'])
    for ex in tmpl['examples']:
        writer.writerow(ex)

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=autoverif-{template_name}.csv'}
    )


@app.route('/api/collecte/templates', methods=['GET'])
def collecte_templates_list():
    """List available CSV templates."""
    return jsonify({
        'templates': [
            {'name': k, 'columns': v['headers'], 'example_rows': len(v['examples'])}
            for k, v in CSV_TEMPLATES.items()
        ]
    })


# ─── Consultation / Lookup API ───
@app.route('/api/collecte/lookup/<vin>', methods=['GET'])
def collecte_lookup(vin):
    """Lookup all data collected for a VIN."""
    vin = vin.strip().upper()
    if not validate_vin(vin):
        return jsonify({'error': 'VIN invalide.'}), 400

    try:
        conn = get_db()
        cur = conn.cursor()

        # Vehicle info
        cur.execute("SELECT id, make, model, year, body_class, engine, fuel_type FROM vehicles WHERE vin = %s", (vin,))
        veh = cur.fetchone()
        if not veh:
            cur.close()
            conn.close()
            return jsonify({'error': 'Aucun véhicule trouvé pour ce VIN.', 'vin': vin}), 404

        vehicle = {
            'id': veh[0], 'make': veh[1], 'model': veh[2], 'year': veh[3],
            'body_class': veh[4], 'engine': veh[5], 'fuel_type': veh[6],
        }

        # All submissions
        cur.execute("""
            SELECT id, report_type, submitted_by_name, submitted_by_type,
                submitted_by_company, status, submitted_at, integrity_hash
            FROM submissions WHERE vin = %s ORDER BY submitted_at ASC
        """, (vin,))
        subs = cur.fetchall()

        records = {
            'accidents': [], 'services': [], 'ownership': [], 'inspections': [],
            'recalls': [], 'title_brands': [], 'liens': [], 'thefts': [],
            'obd': [], 'auctions': [], 'fleet': [], 'import_export': [],
            'emissions': [], 'modifications': [],
        }

        type_to_key = {
            'accident': 'accidents', 'service': 'services', 'ownership': 'ownership',
            'inspection': 'inspections', 'recall_completion': 'recalls',
            'title_brand': 'title_brands', 'lien': 'liens', 'theft': 'thefts',
            'obd_diagnostic': 'obd', 'auction': 'auctions', 'fleet_history': 'fleet',
            'import_export': 'import_export', 'emissions': 'emissions',
            'modification': 'modifications',
        }

        type_queries = {
            'accident': ("SELECT accident_date, severity, impact_point, estimated_cost, description, odometer_km, structural_damage, total_loss FROM accident_reports WHERE submission_id = %s",
                         ['date', 'severity', 'impact_point', 'estimated_cost', 'description', 'odometer_km', 'structural_damage', 'total_loss']),
            'service': ("SELECT service_date, odometer_km, service_type, facility_name, description, cost, parts_type FROM service_records WHERE submission_id = %s",
                        ['date', 'odometer_km', 'service_type', 'facility', 'description', 'cost', 'parts_type']),
            'ownership': ("SELECT change_date, previous_owner_type, new_owner_type, province, sale_price, odometer_km, title_brand, usage_type FROM ownership_changes WHERE submission_id = %s",
                          ['date', 'previous_owner', 'new_owner', 'province', 'sale_price', 'odometer_km', 'title_brand', 'usage_type']),
            'inspection': ("SELECT inspection_date, result, odometer_km, notes, inspection_type, facility_name FROM inspections WHERE submission_id = %s",
                           ['date', 'result', 'odometer_km', 'notes', 'type', 'facility']),
            'recall_completion': ("SELECT recall_number, completion_date, facility_name, recall_description, component FROM recall_completions WHERE submission_id = %s",
                                  ['recall_number', 'date', 'facility', 'description', 'component']),
            'title_brand': ("SELECT brand_date, brand_type, province, source, notes FROM title_brands WHERE submission_id = %s",
                            ['date', 'brand_type', 'province', 'source', 'notes']),
            'lien': ("SELECT lien_holder, lien_type, lien_amount, registration_date, lien_status, province FROM liens WHERE submission_id = %s",
                     ['holder', 'type', 'amount', 'date', 'status', 'province']),
            'theft': ("SELECT date_stolen, police_report_number, date_recovered, condition_at_recovery FROM theft_records WHERE submission_id = %s",
                      ['date_stolen', 'police_report', 'date_recovered', 'condition']),
            'obd_diagnostic': ("SELECT scan_date, odometer_km, mil_status, dtc_active, dtc_pending, scan_tool FROM obd_diagnostics WHERE submission_id = %s",
                               ['date', 'odometer_km', 'mil_status', 'dtc_active', 'dtc_pending', 'scan_tool']),
            'auction': ("SELECT auction_date, auction_house, naaa_grade, sale_price, sale_type FROM auction_records WHERE submission_id = %s",
                        ['date', 'auction_house', 'naaa_grade', 'sale_price', 'sale_type']),
            'fleet_history': ("SELECT usage_type, company_name, date_entered, date_left, mileage_during, province FROM fleet_history WHERE submission_id = %s",
                              ['usage_type', 'company', 'date_entered', 'date_left', 'mileage', 'province']),
            'import_export': ("SELECT direction, country_origin, country_destination, transfer_date, odometer_at_import FROM import_export_records WHERE submission_id = %s",
                              ['direction', 'origin', 'destination', 'date', 'odometer']),
            'emissions': ("SELECT test_date, result, station_name, hc_ppm, co_percent, nox_ppm FROM emissions_tests WHERE submission_id = %s",
                          ['date', 'result', 'station', 'hc_ppm', 'co_percent', 'nox_ppm']),
            'modification': ("SELECT mod_date, mod_type, description, installed_by, homologated, saaq_approved FROM vehicle_modifications WHERE submission_id = %s",
                             ['date', 'type', 'description', 'installed_by', 'homologated', 'saaq_approved']),
        }

        for sub in subs:
            sid, rtype, by_name, by_type, by_company, status, sub_at, ihash = sub
            key = type_to_key.get(rtype)
            if not key or rtype not in type_queries:
                continue

            query, fields = type_queries[rtype]
            cur.execute(query, (sid,))
            detail_row = cur.fetchone()
            if detail_row:
                detail = {}
                for j, field in enumerate(fields):
                    val = detail_row[j]
                    if hasattr(val, 'isoformat'):
                        val = val.isoformat()
                    elif isinstance(val, Decimal):
                        val = float(val)
                    detail[field] = val
                detail['submitted_by'] = by_name or by_company or by_type
                detail['submission_id'] = sid
                detail['status'] = status
                records[key].append(detail)

        # Odometer history
        cur.execute("""
            SELECT reading_date, odometer_km, source, fraud_flag, fraud_reason
            FROM odometer_readings WHERE vin = %s ORDER BY reading_date ASC, id ASC
        """, (vin,))
        odo_rows = cur.fetchall()
        odometer_history = []
        for orow in odo_rows:
            odometer_history.append({
                'date': orow[0].isoformat() if orow[0] else None,
                'km': orow[1], 'source': orow[2],
                'fraud_flag': orow[3], 'fraud_reason': orow[4],
            })

        cur.close()
        conn.close()

        # Count total records
        total = sum(len(v) for v in records.values())

        return jsonify({
            'vin': vin,
            'vehicle': vehicle,
            'total_records': total,
            'records': records,
            'odometer_history': odometer_history,
            'image_url': f"https://cdn.imagin.studio/getimage?customer=img&make={vehicle['make']}&modelFamily={vehicle['model']}&modelYear={vehicle['year']}&angle=01&width=800",
        })

    except Exception as e:
        print(f"[Lookup Error] {e}")
        return jsonify({'error': f'Erreur: {str(e)}'}), 500


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
