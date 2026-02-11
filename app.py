from fastapi import FastAPI, UploadFile, File
import os
import time
from feature_store import save_features
from detector import detect_anomaly
from attack_labeler import label_attack

from chunking import chunk_file
from hashing import hash_chunk
from storage import upload_chunk, get_chunk
from dedup_index import chunk_exists, register_chunk
from pow import generate_challenge, compute_proof, verify_proof
from logger import log_request, REQUEST_LOGS
from features import extract_features

app = FastAPI()

# Directory to store raw uploaded files (debugging / inspection)
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    attack_label = "normal"
    
    # 🔑 1️⃣ Create client_id INSIDE request
    client_id = "client_" + str(abs(hash(file.filename)) % 1000)

    # ⏱️ Log upload request start
    log_request(
        client_id=client_id,
        operation_type="upload_start",
        chunk_hash=None,
        pow_result=None
    )

    # 📥 2️⃣ Read file ONCE
    data = await file.read()

    if not data:
        return {"error": "Empty file uploaded"}

    # Save raw upload (debug)
    safe_name = file.filename or "uploaded.bin"
    save_path = os.path.join(UPLOAD_DIR, safe_name)

    with open(save_path, "wb") as f:
        f.write(data)

    # 🧱 3️⃣ Chunk the file
    chunks = chunk_file(data)
    recipe = []

    for chunk in chunks:
        if not chunk:
            continue

        chunk_hash = hash_chunk(chunk)
        recipe.append(chunk_hash)

        # 🔍 Log hash query
        log_request(
            client_id=client_id,
            operation_type="hash_query",
            chunk_hash=chunk_hash,
            pow_result=None
        )

        # 🆕 New chunk
        if not chunk_exists(chunk_hash):
            upload_chunk(chunk_hash, chunk)
            register_chunk(chunk_hash)

            log_request(
                client_id=client_id,
                operation_type="upload_chunk",
                chunk_hash=chunk_hash,
                pow_result="N/A"
            )

        # ♻️ Duplicate chunk → Proof of Ownership
        else:
            challenge = generate_challenge()

            client_proof = compute_proof(
                chunk,
                challenge["nonce"],
                challenge["offset"],
                challenge["length"]
            )

            stored_chunk = get_chunk(chunk_hash)

            verified = verify_proof(
                stored_chunk,
                challenge["nonce"],
                challenge["offset"],
                challenge["length"],
                client_proof
            )

            log_request(
                client_id=client_id,
                operation_type="pow",
                chunk_hash=chunk_hash,
                pow_result=verified
            )

            if not verified:
                return {
                    "error": "Proof of Ownership failed",
                    "chunk_hash": chunk_hash
                }

            register_chunk(chunk_hash)

    # 📊 4️⃣ Feature extraction (Module 2 output)
    client_features = extract_features(
        REQUEST_LOGS[client_id],
        REQUEST_LOGS
    )
    result = detect_anomaly(client_features, client_id=client_id)

    if result["is_anomaly"]:
        print(f"🚨 ALERT: Anomalous behavior detected from {client_id}")
        print(result)
        
    save_features(
        client_id,
        client_features,
        anomaly=result["is_anomaly"],
        label=attack_label
    )


    print(f"[DEBUG] Features saved for {client_id}")

    attack_label = label_attack(client_features)

    if attack_label != "normal":
        print(f"⚠️ Simulated attack detected: {attack_label}")


    return {
        "status": "Upload successful",
        "client_id": client_id,
        "total_chunks": len(recipe),
        "file_recipe": recipe,
        "features": client_features,
        "saved_to": save_path,
        "anomaly_result": result
    }
