# JS Hunter | Advanced Hybrid SAST Engine

```text
       _  _____   _   _             _            
      | |/ ____| | | | |           | |           
      | | (___   | |_| |_   _ _ __ | |_ ___ _ __ 
  _   | |\___ \  |  _  | | | | '_ \| __/ _ \ '__|
 | |__| |____) | | | | | |_| | | | | ||  __/ |   
  \____/|_____/  |_| |_|\__,_|_| |_|\__\___|_|   
   
   v3.0.0 | Context-Aware JavaScript Security Analysis
```

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Celery](https://img.shields.io/badge/Celery-Distributed-green.svg)](https://docs.celeryproject.org/)
[![Redis](https://img.shields.io/badge/Broker-Redis-red.svg)](https://redis.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**JS Hunter** is an enterprise-grade Static Application Security Testing (SAST) engine built specifically to hunt down vulnerabilities in modern JavaScript and TypeScript applications. 

Unlike traditional scanners that rely solely on "grep-like" pattern matching, JS Hunter employs a **Hybrid Analysis Engine**. It combines high-precision regex signatures with **AST-like Taint Analysis** to track data flow, detect complex vulnerability chains, and significantly reduce false positives.

---

## Key Capabilities

### Deep Taint Analysis
JS Hunter tracks data flow to distinguish between safe code and actual exploits.
- **Source-to-Sink Tracking:** Follows user input (`req.query`, `location.hash`) as it flows through variables, string concatenation, and assignments into dangerous sinks (`eval`, `innerHTML`, `exec`).
- **Sanitizer Awareness:** Automatically detects if a variable has passed through a known sanitizer (e.g., `DOMPurify`), marking it as safe.
- **Inter-procedural Tracking:** Tracks tainted data even when passed between functions.

### ⛓️ Kill Chain Detection
Security flaws often occur in steps. JS Hunter identifies these sequences:
- **XSS Chains:** Input source → Logic/Assignment → DOM Injection.
- **Prototype Pollution Chains:** `JSON.parse` → Recursive Merge → `Object.assign`.
- **Auth Bypass Chains:** LocalStorage Read → Role Check → Admin Access Block.

### ⚡ Framework Intelligence
Built-in context awareness for modern stacks:
- **React:** Detects `dangerouslySetInnerHTML`, insecure Refs.
- **Vue:** Detects `v-html`, dynamic template compilation.
- **Angular:** Detects `$sce.trustAsHtml` bypasses.
- **Node.js:** Detects SSRF, Command Injection, and NoSQL Injection.

### High-Entropy Secret Scanning
Goes beyond simple keywords to validate credentials:
- **Cloud Keys:** AWS (Access/Secret), Google Cloud, Azure.
- **Payment:** Stripe (Live vs Test), PayPal, Square.
- **Cryptography:** Private Keys (RSA/PEM), Hardcoded JWTs.
- **Context Validation:** Distinguishes between `const key = "test"` (Ignored) and production secrets.

---

##  Architecture

JS Hunter runs as a distributed asynchronous task engine using **Celery** and **Redis**.

1.  **Ingestion:** Code is submitted to the `js_hunter_queue`.
2.  **Phase 1 (Flow Mapping):** The engine builds a lightweight AST representation to map variable scopes and taint sources.
3.  **Phase 2 (Deep Scan):** Context-aware pattern matching scans for 200+ vulnerability signatures.
4.  **Phase 3 (Chain Analysis):** Heuristic analysis correlates findings from Phases 1 & 2 to identify multi-step attacks.
5.  **Scoring:** Dynamic severity engine (e.g., *Is this an auth function? Is this a test file?*).
6.  **Report:** Results are structured and stored in the database.

---

## 🛠️ Installation

### Prerequisites
- Python 3.9+
- Redis Server (Running)
- PostgreSQL (Optional, for DB storage)

### Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-org/js-hunter.git
   cd js-hunter
   ```

2. **Install Dependencies**
   ```bash
   pip install celery redis sqlalchemy psycopg2-binary
   ```

3. **Environment Configuration**
   Create a `.env` file:
   ```ini
   REDIS_URL=redis://localhost:6379/0
   DATABASE_URL=postgresql://user:pass@localhost/jshunter_db
   ```

---

##  Usage

### 1. Start the Worker
Start the Celery worker to listen for scanning tasks.
```bash
celery -A js_hunter worker --loglevel=info -Q js_hunter_queue
```

### 2. Trigger a Scan
You can trigger a scan programmatically via Python:

```python
from js_hunter import process_file

# Submit a file for scanning
code_snippet = """
    function handler(req) {
        const userInput = req.query.cmd;
        // JS Hunter will flag this flow
        require('child_process').exec(userInput); 
    }
"""

process_file.delay("target.com", "vulnerable_handler.js", code_snippet)
```

---

## 📊 Detection Capabilities

JS Hunter covers over **20 vulnerability categories**.

| Category | Detection Depth | Example Finding |
| :--- | :--- | :--- |
| **RCE / Injection** | Critical | `VULN_TAINT_FLOW_CONFIRMED`, `VULN_COMMAND_INJECTION` |
| **Database** | Critical | `VULN_SQL_TEMPLATE`, `VULN_NOSQL_OPERATOR` |
| **XSS** | Critical | `VULN_XSS_INNERHTML`, `VULN_REACT_DANGEROUSLY_SET` |
| **Secrets** | Critical | `SECRET_AWS_KEY`, `SECRET_STRIPE_KEY`, `SECRET_PRIVATE_KEY` |
| **Logic** | High | `VULN_PROTO_POLLUTION`, `VULN_AUTH_BYPASS_CHAIN` |
| **Network** | High | `VULN_SSRF_FETCH_USER`, `VULN_WEBSOCKET_NO_AUTH` |
| **DOM** | Medium | `VULN_DOM_CLOBBER_NAME`, `VULN_OPEN_REDIRECT` |

---

## Why JS Hunter?

**The Scenario:**
```javascript
function updateProfile(req) {
    const bio = req.body.bio;       // Source
    const cleanBio = sanitize(bio); // Sanitizer
    const html = cleanBio;          // Propagation
    div.innerHTML = html;           // Sink
}
```

*   **Traditional Regex Scanner:** **FALSE POSITIVE.** Sees `innerHTML = html` and flags it, ignoring the sanitizer.
*   **JS Hunter:** **CLEAN.** Detects the `sanitize` function call in the flow and marks the variable as safe.

---

## Contributing

We welcome contributions!
1.  **Add Patterns:** Update `RAW_PATTERNS` in `js_hunter.py`.
2.  **Add Sinks:** Update `DANGEROUS_SINKS` list.
3.  **Improve Context:** Modify `analyze_context_flow` to support new libraries.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
```
