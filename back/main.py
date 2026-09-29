from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from datetime import datetime
import hashlib
import json
import shutil


# ==========================================
# 1. Create FastAPI application
# ==========================================

app = FastAPI(
    title="Trusted System Integrity Platform",
    description="Trusted Computing software prototype using real SHA-256 measurements"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# 2. Define project folders
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent

PROTECTED_DIR = BASE_DIR / "protected_system"

BACKUP_DIR = BASE_DIR / "backup"

BASELINE_FILE = BASE_DIR / "baseline.json"

LOG_FILE = BASE_DIR / "security_log.json"


# ==========================================
# 3. Calculate SHA-256 hash of a real file
# ==========================================

def calculate_sha256(file_path: Path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            data = file.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


# ==========================================
# 4. Get protected files
# ==========================================

def get_protected_files():

    if not PROTECTED_DIR.exists():
        return []

    files = []

    for file in PROTECTED_DIR.iterdir():

        if file.is_file():
            files.append(file)

    return files


# ==========================================
# 5. Get current date and time
# ==========================================

def get_current_time():

    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ==========================================
# Security Logging
# ==========================================

def add_security_log(event, message, details=None):

    if LOG_FILE.exists():

        with open(LOG_FILE, "r", encoding="utf-8") as file:
            logs = json.load(file)

    else:
        logs = []

    log_entry = {
        "timestamp": get_current_time(),
        "event": event,
        "message": message,
        "details": details or {}
    }

    logs.append(log_entry)

    with open(LOG_FILE, "w", encoding="utf-8") as file:
        json.dump(
            logs,
            file,
            indent=4
        )


# ==========================================
# 6. Root endpoint
# ==========================================

@app.get("/")
def home():

    return {
        "message": "Trusted System Integrity Platform is running!"
    }


# ==========================================
# 7. Measure all protected files
# ==========================================

@app.get("/measure")
def measure_files():

    files = get_protected_files()

    measurements = []

    for file in files:

        file_hash = calculate_sha256(file)

        measurements.append({
            "file_name": file.name,
            "sha256": file_hash,
            "size": file.stat().st_size
        })

    return {
        "total_files": len(measurements),
        "measurements": measurements
    }


# ==========================================
# 8. Create Trusted Baseline
# ==========================================

@app.post("/baseline/create")
def create_baseline():

    files = get_protected_files()

    if not files:

        raise HTTPException(
            status_code=400,
            detail="No protected files were found."
        )


    # Make sure backup folder exists

    BACKUP_DIR.mkdir(exist_ok=True)


    baseline = {
        "created_at": get_current_time(),
        "files": {}
    }


    # Process every protected file

    for file in files:

        # Calculate real SHA-256

        file_hash = calculate_sha256(file)


        # Save measurement in baseline

        baseline["files"][file.name] = {
            "sha256": file_hash,
            "size": file.stat().st_size
        }


        # Create trusted backup

        backup_file = BACKUP_DIR / file.name

        shutil.copy2(file, backup_file)


    # Save baseline as JSON

    with open(BASELINE_FILE, "w", encoding="utf-8") as file:

        json.dump(
            baseline,
            file,
            indent=4
        )


    return {
        "message": "Trusted baseline created successfully.",
        "created_at": baseline["created_at"],
        "total_files": len(files)
    }

# ==========================================
# 9. Verify system integrity
# ==========================================

@app.post("/verify")
def verify_system():

    # Check if trusted baseline exists

    if not BASELINE_FILE.exists():

        raise HTTPException(
            status_code=400,
            detail="Trusted baseline has not been created yet."
        )


    # Load trusted baseline

    with open(BASELINE_FILE, "r", encoding="utf-8") as file:

        baseline = json.load(file)


    results = []

    trusted_count = 0
    modified_count = 0
    missing_count = 0


    # Check every file stored in the trusted baseline

    for file_name, trusted_data in baseline["files"].items():

        current_file = PROTECTED_DIR / file_name


        # Check if file still exists

        if not current_file.exists():

            results.append({
                "file_name": file_name,
                "status": "MISSING",
                "expected_hash": trusted_data["sha256"],
                "current_hash": None
            })

            missing_count += 1

            continue


        # Calculate current SHA-256

        current_hash = calculate_sha256(current_file)

        expected_hash = trusted_data["sha256"]


        # Compare current hash with trusted hash

        if current_hash == expected_hash:

            status = "TRUSTED"

            trusted_count += 1

        else:

            status = "MODIFIED"

            modified_count += 1


        results.append({
            "file_name": file_name,
            "status": status,
            "expected_hash": expected_hash,
            "current_hash": current_hash
        })


    # Make final trust decision

    if modified_count == 0 and missing_count == 0:

        system_status = "TRUSTED"

    else:

        system_status = "COMPROMISED"


    return {
        "system_status": system_status,
        "trusted_files": trusted_count,
        "modified_files": modified_count,
        "missing_files": missing_count,
        "results": results
    }

# ==========================================
# 10. Restore trusted files
# ==========================================

@app.post("/recover")
def recover_system():

    if not BASELINE_FILE.exists():
        raise HTTPException(
            status_code=400,
            detail="Trusted baseline has not been created yet."
        )

    with open(BASELINE_FILE, "r", encoding="utf-8") as file:
        baseline = json.load(file)

    restored_files = []
    failed_files = []

    for file_name in baseline["files"]:

        backup_file = BACKUP_DIR / file_name
        target_file = PROTECTED_DIR / file_name

        if backup_file.exists():
            shutil.copy2(backup_file, target_file)
            restored_files.append(file_name)
        else:
            failed_files.append(file_name)

    return {
        "message": "Trusted recovery completed.",
        "restored_files": restored_files,
        "failed_files": failed_files,
        "restored_count": len(restored_files),
        "failed_count": len(failed_files)
    }

# ==========================================
# 11. Trust Decision and Access Control
# ==========================================

@app.post("/access/check")
def check_access():

    if not BASELINE_FILE.exists():
        raise HTTPException(
            status_code=400,
            detail="Trusted baseline has not been created yet."
        )

    with open(BASELINE_FILE, "r", encoding="utf-8") as file:
        baseline = json.load(file)

    modified_files = []
    missing_files = []

    for file_name, trusted_data in baseline["files"].items():

        current_file = PROTECTED_DIR / file_name

        if not current_file.exists():
            missing_files.append(file_name)
            continue

        current_hash = calculate_sha256(current_file)
        expected_hash = trusted_data["sha256"]

        if current_hash != expected_hash:
            modified_files.append(file_name)

    # ------------------------------------------
    # Access is granted only if all files match
    # ------------------------------------------

    if len(modified_files) == 0 and len(missing_files) == 0:

        add_security_log(
            "ACCESS_GRANTED",
            "Access granted because system integrity was verified.",
            {}
        )

        return {
            "access_decision": "GRANTED",
            "system_status": "TRUSTED",
            "message": "System integrity verified. Access is granted.",
            "modified_files": [],
            "missing_files": []
        }

    # ------------------------------------------
    # Access is blocked if any file is modified
    # or missing
    # ------------------------------------------

    add_security_log(
        "ACCESS_BLOCKED",
        "Access blocked because system integrity was compromised.",
        {
            "modified_files": modified_files,
            "missing_files": missing_files
        }
    )

    return {
        "access_decision": "BLOCKED",
        "system_status": "COMPROMISED",
        "message": "System integrity violation detected. Access is blocked.",
        "modified_files": modified_files,
        "missing_files": missing_files
    }

# ==========================================
# 12. View Security Logs
# ==========================================

@app.get("/logs")
def get_security_logs():

    if not LOG_FILE.exists():
        return {
            "total_logs": 0,
            "logs": []
        }

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        logs = json.load(file)

    return {
        "total_logs": len(logs),
        "logs": logs
    }