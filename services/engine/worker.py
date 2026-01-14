import os, json, re, math, time
from celery import Celery
from core.db.session import SessionLocal
from core.db.models import Target, Asset, Finding

# Initialize Celery
app = Celery("titan", broker=os.getenv("REDIS_URL"), backend=os.getenv("REDIS_URL"))

# --- CONFIGURATION ---
MAX_LINE_LENGTH = 10000  # Skip lines longer than this (prevents crash on minified code)
BATCH_SIZE = 5000        # Save to DB in chunks of 5000 (huge speed boost)

# --- 1. COMPILE REGEX PATTERNS (Global Scope for Speed) ---
RAW_PATTERNS = {
    "VULN_XSS_SINK": r"(\.innerHTML|\.outerHTML|document\.write|document\.writeln|dangerouslySetInnerHTML|v-html|\[innerHTML\])",
    "VULN_JQUERY_SINK": r"(\.html\(|\.append\(|\.prepend\(|\.after\(|\.before\()",
    "VULN_EVAL": r"(eval\(|new Function\(|setTimeout\(.*?['\"].*?['\"].*?,|setInterval\(.*?['\"].*?['\"].*?,)",
    "VULN_POSTMESSAGE": r"postMessage\s*\(.*?, \s*['\"]\*['\"]\)",
    "VULN_PROTO_POLLUTION": r"(\w+\[['\"]__proto__['\"]\]|\.constructor\.prototype)",
    "VULN_OPEN_REDIRECT": r"(window\.location\.(href|replace|assign|pathname)\s*=\s*.*window\.location)",
    "SECRET_AWS": r"AKIA[0-9A-Z]{16}",
    "SECRET_JWT": r"eyJ[a-zA-Z0-9-_=]+\.[a-zA-Z0-9-_=]+\.[a-zA-Z0-9-_.+/=]*",
    "SECRET_PRIVATE_KEY": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
    "SHADOW_API": r"https?://[\w\.-]+(?:/[\w\.-]*)+",
    "INTERNAL_IP": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
}
# Compile them once here so we don't re-compile 500,000 times
COMPILED_SCANNERS = {k: re.compile(v, re.I) for k, v in RAW_PATTERNS.items()}

# --- 2. LOAD WORDLIST ---
WORDLIST_PATH = "/app/services/engine/wordlist.txt"
WORDLIST = set()
if os.path.exists(WORDLIST_PATH):
    with open(WORDLIST_PATH, "r") as f:
        WORDLIST = set([l.strip().lower() for l in f.readlines()])
else:
    print(f"Warning: Wordlist not found at {WORDLIST_PATH}")

@app.task(name="titan.process_file", queue="titan_queue")
def process_file(domain, filename, code):
    db = SessionLocal()
    
    try:
        # --- SETUP FILE SYSTEM ---
        scan_dir = "/tmp/titan_scans"
        if not os.path.exists(scan_dir):
            os.makedirs(scan_dir)
            
        # Save code to disk
        asset_path = os.path.join(scan_dir, f"{int(time.time())}_{filename}")
        with open(asset_path, "w", encoding="utf-8") as f_out:
            f_out.write(code)

        # --- DATABASE SETUP ---
        target = db.query(Target).filter_by(domain=domain).first()
        if not target:
            target = Target(domain=domain)
            db.add(target)
            db.commit()
            db.refresh(target)

        # Create Asset (Using correct columns: url, local_path)
        asset = Asset(
            target_id=target.id, 
            url=filename, 
            local_path=asset_path
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)

        # --- 3. HIGH SPEED STREAMING SCAN ---
        findings_buffer = [] 
        
        # Strings that make a line "Noise" (Safe to ignore)
        NOISE_FILTERS = [
            "www.w3.org",       # SVGs / XML definitions
            "xmlns",            # XML namespaces
            "data:image",       # Base64 images
            "node_modules",     # Webpack dependencies
            "license",          # License headers
            "reactjs.org",      # React Docs
            "mozilla.org",      # MDN Docs
            ".png", ".svg",     # Image file references
            "webpack",          # Webpack internals
            "facebook.com"      # React copyright headers
        ]

        with open(asset_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                ln = i + 1
                
                # OPTIMIZATION: Skip massive lines (Minified code)
                if len(line) > MAX_LINE_LENGTH:
                    continue 

                stripped = line.strip()
                
                # OPTIMIZATION: Skip Comments
                if not stripped or stripped.startswith(("//", "/*", "*")):
                    continue
                
                # NOISE REDUCTION: Skip lines containing noise strings
                # This is much faster than Regex for filtering
                if any(noise in line.lower() for noise in NOISE_FILTERS):
                    continue

                # 1. Regex Scanner (Critical Vulnerabilities)
                for cat, regex in COMPILED_SCANNERS.items():
                    if regex.search(line):
                        findings_buffer.append(Finding(
                            asset_id=asset.id, 
                            type=cat, 
                            severity="CRITICAL", 
                            evidence=stripped[:250], 
                            line=ln
                        ))

                # 2. Intel Scanner (Keywords)
                # Only scan if line looks interesting to save CPU
                if any(key in line.lower() for key in ["admin", "secret", "auth", "key", "token", "api"]):
                    clean = re.sub(r'[^a-zA-Z0-9_]', ' ', line.lower())
                    # Limit word split to avoid memory spikes
                    for word in clean.split()[:500]: 
                        if word in WORDLIST and len(word) > 4:
                            findings_buffer.append(Finding(
                                asset_id=asset.id, 
                                type="INTEL_MATCH", 
                                severity="INFO", 
                                evidence=f"Match: {word}", 
                                line=ln
                            ))

                # 3. Batch Insert (Performance)
                if len(findings_buffer) >= BATCH_SIZE:
                    db.bulk_save_objects(findings_buffer)
                    db.commit()
                    findings_buffer.clear() # Clear RAM

        # Save any remaining findings
        if findings_buffer:
            db.bulk_save_objects(findings_buffer)
            db.commit()
        
    except Exception as e:
        print(f"[ERROR] processing file: {e}")
        db.rollback()
    finally:
        db.close()
        # Optional: Delete temp file to save disk space
        # if os.path.exists(asset_path):
        #    os.remove(asset_path)
