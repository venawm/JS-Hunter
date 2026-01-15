import os, json, re, math, time, hashlib
from celery import Celery
from core.db.session import SessionLocal
from core.db.models import Target, Asset, Finding

# Initialize Celery
app = Celery("titan", broker=os.getenv("REDIS_URL"), backend=os.getenv("REDIS_URL"))

# --- CONFIGURATION ---
MAX_LINE_LENGTH = 15000
BATCH_SIZE = 3000
MAX_CONTEXT_WINDOW = 15
TAINT_ANALYSIS_DEPTH = 2000

# --- ADVANCED AST-LIKE PATTERN DETECTION ---
class PatternContext:
    def __init__(self):
        self.in_function = False
        self.current_function = None
        self.function_params = []
        self.variable_assignments = {}
        self.taint_sources = set()
        self.dangerous_sinks = set()
        self.data_flows = []
        self.scope_stack = []
        self.sanitization_functions = set()
        self.validation_checks = {}
        self.async_boundaries = []
        self.event_handlers = {}
        
    def track_variable(self, var_name, source_type, line_num, scope='global'):
        """Enhanced variable tracking with scope awareness"""
        self.variable_assignments[f"{scope}::{var_name}"] = {
            'source': source_type,
            'line': line_num,
            'scope': scope,
            'tainted': source_type in [
                'user_input', 'url_param', 'cookie', 'postmessage', 
                'websocket', 'local_storage', 'session_storage', 
                'query_param', 'hash', 'referrer', 'form_input',
                'file_upload', 'import_dynamic', 'jsonp_callback'
            ],
            'sanitized': False,
            'validated': False
        }
    
    def is_tainted(self, var_name, scope='global'):
        """Check if variable is tainted with scope resolution"""
        key = f"{scope}::{var_name}"
        if key in self.variable_assignments:
            var_info = self.variable_assignments[key]
            return var_info.get('tainted', False) and not var_info.get('sanitized', False)
        
        # Check parent scopes
        for s in reversed(self.scope_stack):
            key = f"{s}::{var_name}"
            if key in self.variable_assignments:
                var_info = self.variable_assignments[key]
                return var_info.get('tainted', False) and not var_info.get('sanitized', False)
        
        return False
    
    def mark_sanitized(self, var_name, scope='global'):
        """Mark variable as sanitized"""
        key = f"{scope}::{var_name}"
        if key in self.variable_assignments:
            self.variable_assignments[key]['sanitized'] = True
    
    def track_sanitization(self, func_name, line_num):
        """Track sanitization function definitions"""
        self.sanitization_functions.add((func_name, line_num))

# --- ENHANCED REGEX PATTERNS ---
RAW_PATTERNS = {
    # === CRITICAL XSS PATTERNS ===
    "VULN_XSS_INNERHTML": r"\.innerHTML\s*=",
    "VULN_XSS_OUTERHTML": r"\.outerHTML\s*=",
    "VULN_XSS_DOCUMENT_WRITE": r"document\.write(?:ln)?\s*\(",
    "VULN_XSS_DOCUMENT_WRITELN": r"document\.writeln\s*\(",
    "VULN_XSS_DANGEROUS_REACT": r"dangerouslySetInnerHTML\s*[=:]",
    "VULN_XSS_VUE_HTML": r"v-html\s*=",
    "VULN_XSS_ANGULAR_HTML": r"\[innerHTML\]\s*=",
    "VULN_XSS_ANGULAR_BYPASS": r"\$sce\.trustAsHtml",
    "VULN_XSS_INSERT_ADJACENT": r"insertAdjacentHTML\s*\(",
    "VULN_XSS_JQUERY_HTML": r"\$\([^)]*\)\.html\s*\(",
    "VULN_XSS_JQUERY_APPEND": r"\$\([^)]*\)\.(append|prepend|after|before|replaceWith)\s*\(",
    "VULN_XSS_ATTRIBUTE_INJECTION": r"\.setAttribute\s*\(\s*['\"]on\w+['\"]",
    "VULN_XSS_EVENT_HANDLER": r"\.on(?:click|load|error|mouseover|focus|blur|keypress|keydown|keyup|input|change|submit)\s*=",
    "VULN_XSS_HREF_JAVASCRIPT": r"\.(?:href|src|action|formaction|data)\s*=\s*['\"](?:javascript|data:text/html|vbscript):",
    "VULN_XSS_SRC_INJECTION": r"\.(src|action|formaction|poster|background)\s*=.*(?:\+|\$\{|`)",
    "VULN_XSS_STYLE_INJECTION": r"\.style\.(cssText|background|backgroundImage|content)\s*=",
    "VULN_XSS_STYLE_ATTRIBUTE": r"\.setAttribute\s*\(\s*['\"]style['\"]",
    "VULN_XSS_SRCDOC": r"\.srcdoc\s*=",
    "VULN_XSS_FORMACTION": r"<.*formaction\s*=",
    "VULN_XSS_SVG_INJECTION": r"<svg.*>.*<script",
    "VULN_XSS_MATHML_INJECTION": r"<math.*>.*<script",
    "VULN_XSS_CREATE_ELEMENT_SCRIPT": r"createElement\s*\(\s*['\"]script['\"]",
    "VULN_XSS_TEMPLATE_LITERAL": r"`[^`]*<(?:script|img|svg|iframe|object|embed)(?:\s|>)[^`]*\$\{[^}]*\}",
    
    # === CODE EXECUTION ===
    "VULN_EVAL_DIRECT": r"\beval\s*\(",
    "VULN_EVAL_FUNCTION_CONSTRUCTOR": r"(?:new\s+)?Function\s*\(",
    "VULN_EVAL_SETTIMEOUT_STRING": r"setTimeout\s*\(\s*['\"`]",
    "VULN_EVAL_SETINTERVAL_STRING": r"setInterval\s*\(\s*['\"`]",
    "VULN_EVAL_EXECSCRIPT": r"execScript\s*\(",
    "VULN_EVAL_IMPORT_DYNAMIC": r"import\s*\([^)]*(?:\+|\$\{)",
    "VULN_EVAL_WORKER_URL": r"new\s+Worker\s*\([^)]*(?:\+|\$\{|URL\.createObjectURL)",
    "VULN_EVAL_SHARED_WORKER": r"new\s+SharedWorker\s*\([^)]*(?:\+|\$\{)",
    "VULN_EVAL_SCRIPT_SRC_DYNAMIC": r"script\.src\s*=.*(?:\+|\$\{)",
    "VULN_EVAL_WASM": r"WebAssembly\.(compile|instantiate|compileStreaming|instantiateStreaming)\s*\(",
    "VULN_EVAL_IMPORT_MAPS": r"<script[^>]*type\s*=\s*['\"]importmap['\"]",
    "VULN_EVAL_BLOB_URL": r"URL\.createObjectURL.*Blob",
    "VULN_EVAL_DATA_URL": r"data:(?:text/html|application/javascript)",
    
    # === ADVANCED INJECTION ===
    "VULN_SQL_CONCAT": r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|WHERE|FROM|JOIN)\s+.*['\"]?\s*(?:\+|\|\||concat\()",
    "VULN_SQL_TEMPLATE": r"`(?:SELECT|INSERT|UPDATE|DELETE).*\$\{",
    "VULN_NOSQL_OPERATOR": r"['\"]?\$(?:where|regex|ne|gt|lt|gte|lte|in|nin|exists|type|mod|text|expr|jsonSchema|all|elemMatch|size)\s*['\"]?\s*:",
    "VULN_NOSQL_FUNCTION": r"\$(?:function|where|accumulator|mapReduce)\s*:",
    "VULN_NOSQL_USER_INPUT": r"(?:find|findOne|update|delete|aggregate)\s*\([^)]*(?:\$\{|req\.|params\.|query\.|body\.)",
    "VULN_GRAPHQL_INJECTION": r"(?:query|mutation)\s*\{[^}]*\$\{",
    "VULN_LDAP_INJECTION": r"(?:CN|OU|DC|uid|sn|mail)=.*(?:\+|\$\{)",
    "VULN_XPATH_INJECTION": r"(?:selectNodes|selectSingleNode|evaluate)\s*\([^)]*(?:\+|\$\{)",
    "VULN_COMMAND_INJECTION": r"(?:exec|spawn|execFile|fork|execSync|spawnSync)\s*\([^)]*(?:\+|\$\{|req\.|params\.|query\.)",
    "VULN_TEMPLATE_INJECTION_EJS": r"<%=.*(?:req\.|params\.|query\.|body\.)",
    "VULN_TEMPLATE_INJECTION_PUG": r"#\{.*(?:req\.|params\.|query\.|body\.)",
    "VULN_TEMPLATE_INJECTION_HANDLEBARS": r"\{\{.*(?:req\.|params\.|query\.|body\.)",
    "VULN_TEMPLATE_SERVER_RENDER": r"(?:render|compile)\s*\([^)]*(?:\+|\$\{)",
    
    # === OPEN REDIRECT ===
    "VULN_REDIRECT_LOCATION_HREF": r"(?:window\.|document\.)?location(?:\.href)?\s*=\s*(?![\s'\"](?:/[^/]|https?://(?:localhost|127\.0\.0\.1|[\w\-]+\.(?:company|internal))))",
    "VULN_REDIRECT_LOCATION_REPLACE": r"location\.(replace|assign)\s*\([^)]*(?:\+|\$\{|params\.|query\.|req\.)",
    "VULN_REDIRECT_WINDOW_OPEN": r"window\.open\s*\([^)]*(?:\+|\$\{|params\.|query\.)",
    "VULN_REDIRECT_NAVIGATE": r"(?:history|router|navigate)\.\w+\s*\([^)]*(?:\+|\$\{|params\.|query\.)",
    "VULN_REDIRECT_META_REFRESH": r"<meta.*http-equiv.*refresh.*content.*url=",
    "VULN_REDIRECT_HEADER_LOCATION": r"(?:res|response)\.(redirect|setHeader)\s*\(\s*['\"](?:location|Location)['\"]",
    "VULN_REDIRECT_ANCHOR_HREF": r"<a.*href\s*=.*(?:\$\{|<%=)",
    
    # === PROTOTYPE POLLUTION ===
    "VULN_PROTO_DIRECT_ASSIGN": r"(?:obj|\w+)\[['\"]__proto__['\"]\]\s*=",
    "VULN_PROTO_CONSTRUCTOR_PROTO": r"\.constructor\.(?:prototype|__proto__)\s*=",
    "VULN_PROTO_CONSTRUCTOR_ACCESS": r"\[['\"]\s*constructor\s*['\"]]\s*\[['\"]\s*prototype\s*['\"]\]",
    "VULN_PROTO_RECURSIVE_MERGE": r"(?:function\s+\w*merge\w*|const\s+\w*merge\w*\s*=).*for\s*\(\s*(?:let|const|var)\s+\w+\s+in\s+",
    "VULN_PROTO_OBJECT_ASSIGN": r"Object\.assign\s*\([^)]*(?:req\.|params\.|query\.|body\.|JSON\.parse)",
    "VULN_PROTO_SPREAD_USER": r"\{?\s*\.\.\.\s*(?:req\.|params\.|query\.|body\.|JSON\.parse)",
    "VULN_PROTO_JSON_PARSE_ASSIGN": r"Object\.assign.*JSON\.parse",
    "VULN_PROTO_MERGE_DEEP": r"(?:_|lodash|underscore)\.merge\s*\(",
    "VULN_PROTO_EXTEND": r"(?:\$|jQuery)\.extend\s*\(\s*true",
    "VULN_PROTO_SET_NESTED": r"function\s+set(?:Nested|Path|Value).*\[",
    
    # === AUTHENTICATION & AUTHORIZATION ===
    "VULN_CLIENT_AUTH_ROLE": r"(?:localStorage|sessionStorage)\.getItem\s*\([^)]*(?:role|permission|isAdmin|isAuthenticated|user_type|access_level)",
    "VULN_CLIENT_AUTH_CHECK": r"if\s*\(\s*(?:user|current|session|auth)\.\s*(?:role|isAdmin|permissions|isAuthenticated)\s*(?:===|==|!==|!=)",
    "VULN_CLIENT_AUTH_COOKIE": r"document\.cookie\.match\s*\([^)]*(?:auth|session|token|admin)",
    "VULN_AUTH_TIMING_ATTACK": r"for\s*\([^)]*\.length[^)]*\)\s*\{[^}]*if[^}]*(?:!==|!=)[^}]*return\s+(?:false|true)",
    "VULN_AUTH_WEAK_COMPARE": r"(?:password|token|hash|secret|key)\s*(?:===?|!==?)\s*(?:['\"]|[\w\.]+)",
    "VULN_AUTH_STRING_COMPARE": r"if\s*\([^)]*(?:password|token|hash)\s*(?:===|==)",
    "VULN_JWT_NO_VERIFY": r"jwt\.decode\s*\((?!.*verify)",
    "VULN_JWT_CLIENT_DECODE": r"atob\s*\([^)]*\.split\s*\(\s*['\"]\.['\"]\s*\)",
    "VULN_JWT_NONE_ALGORITHM": r"algorithm\s*:\s*['\"]none['\"]",
    "VULN_SESSION_FIXATION": r"(?:sessionId|session_id|sessid)\s*=\s*(?:req\.|params\.|query\.|cookie\.)",
    "VULN_HARDCODED_ADMIN": r"(?:username|user|login)\s*(?:===|==)\s*['\"](?:admin|administrator|root|superuser)['\"]",
    "VULN_BYPASS_CHECK": r"if\s*\([^)]*(?:bypass|debug|dev|test)(?:\s*===\s*true|\s*&&)",
    
    # === SECRETS & CREDENTIALS (Enhanced) ===
    "SECRET_API_KEY": r"(?:api[_-]?key|apikey|api_token)\s*[=:]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]",
    "SECRET_ACCESS_TOKEN": r"(?:access[_-]?token|accesstoken|bearer[_-]?token)\s*[=:]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]",
    "SECRET_SECRET_KEY": r"(?:secret[_-]?key|secretkey|secret_token)\s*[=:]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]",
    "SECRET_PASSWORD_PLAIN": r"(?:password|passwd|pwd)\s*[=:]\s*['\"](?![\*]{3,})[^'\"]{3,}['\"]",
    "SECRET_AWS_KEY": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "SECRET_AWS_SECRET": r"(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*['\"][a-zA-Z0-9/+=]{40}['\"]",
    "SECRET_PRIVATE_KEY": r"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PGP)?\s*PRIVATE KEY-----",
    "SECRET_JWT_TOKEN": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "SECRET_OAUTH_SECRET": r"(?:client_secret|oauth.*secret|consumer_secret)\s*[=:]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]",
    "SECRET_DATABASE_URL": r"(?:mongodb|mysql|postgres|postgresql|redis|mssql|oracle)://[^'\"]*:[^'\"]*@",
    "SECRET_STRIPE_KEY": r"(?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{20,}",
    "SECRET_GITHUB_TOKEN": r"gh[pousr]_[a-zA-Z0-9]{36,}",
    "SECRET_SLACK_TOKEN": r"xox[baprs]-[a-zA-Z0-9-]{10,}",
    "SECRET_SLACK_WEBHOOK": r"hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "SECRET_GOOGLE_API": r"AIza[0-9A-Za-z\-_]{35}",
    "SECRET_FIREBASE": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "SECRET_TWILIO": r"SK[a-z0-9]{32}",
    "SECRET_MAILGUN": r"key-[a-z0-9]{32}",
    "SECRET_PAYPAL": r"(?:access_token\$production|sk_live_)[a-zA-Z0-9]{32,}",
    "SECRET_SQUARE": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "SECRET_DROPBOX": r"sl\.[a-zA-Z0-9_-]{135}",
    "SECRET_HEROKU": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    
    # === POSTMESSAGE ===
    "VULN_POSTMESSAGE_WILDCARD": r"postMessage\s*\([^)]*,\s*['\"]?\*['\"]?\s*\)",
    "VULN_POSTMESSAGE_NO_ORIGIN": r"addEventListener\s*\(\s*['\"]message['\"](?!.*event\.origin)",
    "VULN_POSTMESSAGE_WEAK_ORIGIN": r"event\.origin\.(?:indexOf|includes|match|endsWith)\s*\(",
    "VULN_POSTMESSAGE_STARTSWITH": r"event\.origin\.startsWith\s*\(\s*['\"]https?://",
    "VULN_POSTMESSAGE_REGEX_WEAK": r"event\.origin\.(?:test|match)\s*\(\/\^?https?:",
    "VULN_POSTMESSAGE_EVAL": r"addEventListener\s*\(\s*['\"]message['\"].*\beval\s*\(",
    "VULN_POSTMESSAGE_FUNCTION": r"addEventListener\s*\(\s*['\"]message['\"].*(?:new\s+)?Function",
    "VULN_POSTMESSAGE_INNERHTML": r"addEventListener\s*\(\s*['\"]message['\"].*innerHTML",
    
    # === WEBSOCKET ===
    "VULN_WEBSOCKET_NEW": r"new\s+(?:WebSocket|WebSocketSecure)\s*\(",
    "VULN_WEBSOCKET_INSECURE": r"new\s+WebSocket\s*\(\s*['\"]ws://",
    "VULN_WEBSOCKET_NO_ORIGIN": r"\.onmessage\s*=.*\{(?!.*origin)",
    "VULN_WEBSOCKET_EVAL": r"\.onmessage.*\beval\s*\(",
    "VULN_WEBSOCKET_INNERHTML": r"\.onmessage.*innerHTML",
    "VULN_WEBSOCKET_FUNCTION": r"\.onmessage.*(?:new\s+)?Function",
    "VULN_WEBSOCKET_NO_AUTH": r"new\s+WebSocket\s*\([^)]*\)(?!.*token|auth|Authorization)",
    
    # === CSRF ===
    "VULN_CSRF_NO_TOKEN": r"(?:fetch|axios|http)\s*\([^)]*method\s*:\s*['\"](?:POST|PUT|DELETE|PATCH)['\"](?!.*csrf|token|xsrf)",
    "VULN_CSRF_CREDENTIALS": r"credentials\s*:\s*['\"]include['\"]",
    "VULN_CSRF_FORM_NO_TOKEN": r"<form[^>]*method\s*=\s*['\"]post['\"](?!.*csrf|token)",
    "VULN_CSRF_STATE_CHANGING": r"fetch\s*\([^)]*(?:/api/(?:delete|remove|transfer|update|admin))",
    
    # === SSRF ===
    "VULN_SSRF_FETCH_USER": r"fetch\s*\([^)]*(?:params\.|query\.|req\.|body\.|location\.|URL\s*\()",
    "VULN_SSRF_AXIOS_USER": r"axios\.\w+\s*\([^)]*(?:params\.|query\.|req\.|body\.)",
    "VULN_SSRF_REQUEST_USER": r"request\s*\([^)]*(?:url|uri)[^)]*(?:\+|\$\{|params\.|query\.)",
    "VULN_SSRF_IMAGE_USER": r"(?:<img|new\s+Image).*src\s*=.*(?:\$\{|<%=|params\.|query\.)",
    "VULN_SSRF_IFRAME_USER": r"<iframe.*src\s*=.*(?:\$\{|<%=|params\.|query\.)",
    "VULN_SSRF_WEBHOOK": r"webhook.*(?:fetch|axios|request)\s*\([^)]*(?:params\.|query\.)",
    
    # === IDOR ===
    "VULN_IDOR_API_ID": r"(?:fetch|axios)\s*\(\s*['\"`]\/api\/(?:user|account|admin|order|invoice|document|file|message)s?\/\$\{",
    "VULN_IDOR_DELETE": r"method\s*:\s*['\"]DELETE['\"].*\/\$\{",
    "VULN_IDOR_UPDATE": r"method\s*:\s*['\"](?:PUT|PATCH)['\"].*\/\$\{",
    "VULN_IDOR_DIRECT_REF": r"\/api\/\w+\/\d+['\"](?!.*authorization|auth|permission|verify)",
    "VULN_IDOR_SEQUENTIAL": r"\/api\/\w+\/\d+(?:\s*\+\s*1|\+\+)",
    
    # === PATH TRAVERSAL ===
    "VULN_PATH_TRAVERSAL_DOTS": r"(?:filename|path|file|dir|filepath)\s*[=:+].*(?:\.\./|\.\.\\|%2e%2e)",
    "VULN_PATH_TRAVERSAL_FETCH": r"fetch\s*\([^)]*(?:\.\./|\.\.\\|%2e%2e)",
    "VULN_PATH_TRAVERSAL_REQUIRE": r"require\s*\([^)]*(?:\.\./|\.\.\\|\+|concat)",
    "VULN_PATH_TRAVERSAL_IMPORT": r"import\s*\([^)]*(?:\.\./|\+|\$\{|concat)",
    "VULN_PATH_TRAVERSAL_READFILE": r"(?:readFile|createReadStream)\s*\([^)]*(?:\+|\$\{|concat)",
    
    # === FILE UPLOAD ===
    "VULN_FILE_UPLOAD_NO_VALIDATION": r"new\s+FileReader\s*\(\s*\)(?!.*(?:type|name|size))",
    "VULN_FILE_UPLOAD_DANGEROUS_EXT": r"\.(?:name|filename)\.match\s*\([^)]*(?:html|svg|xml|js|jsp|php|asp|exe)",
    "VULN_FILE_UPLOAD_NO_SIZE": r"readAs(?:DataURL|Text|ArrayBuffer|BinaryString)(?!.*(?:size|length|maxSize))",
    "VULN_FILE_UPLOAD_EXECUTE": r"FileReader.*(?:eval|Function|innerHTML|document\.write)",
    "VULN_FILE_UPLOAD_NO_MIME": r"<input[^>]*type\s*=\s*['\"]file['\"](?!.*accept)",
    "VULN_FILE_UPLOAD_PATH_CONTROL": r"upload.*(?:path|destination|filename).*(?:\+|\$\{|params\.|query\.)",
    
    # === STORAGE ===
    "VULN_STORAGE_SENSITIVE": r"(?:localStorage|sessionStorage)\.setItem\s*\([^)]*(?:password|token|secret|key|credit|ssn|api|jwt|auth|bearer|session)",
    "VULN_STORAGE_EVAL": r"(?:localStorage|sessionStorage)\.getItem.*\beval\s*\(",
    "VULN_STORAGE_FUNCTION": r"(?:localStorage|sessionStorage)\.getItem.*(?:new\s+)?Function",
    "VULN_STORAGE_XSS": r"(?:localStorage|sessionStorage)\.getItem.*innerHTML",
    "VULN_COOKIE_NO_SECURE": r"document\.cookie\s*=(?!.*[Ss]ecure)",
    "VULN_COOKIE_NO_HTTPONLY": r"document\.cookie\s*=(?!.*[Hh]ttp[Oo]nly)",
    "VULN_COOKIE_NO_SAMESITE": r"document\.cookie\s*=(?!.*[Ss]ame[Ss]ite)",
    "VULN_COOKIE_SENSITIVE": r"document\.cookie\s*=\s*['\"](?:auth|session|token|jwt).*=",
    
    # === REGEX VULNERABILITIES ===
    "VULN_REDOS_NESTED_QUANT": r"\/[^\/]*\([^)]*[\*\+][^)]*\)[\*\+]",
    "VULN_REDOS_ALTERNATION": r"\/[^\/]*\([^)]*\|[^)]*\)[\*\+]",
    "VULN_REDOS_OVERLAPPING": r"\/[^\/]*\.[\*\+][^\/]*\.[\*\+]",
    "VULN_REDOS_BACKTRACK": r"\/[^\/]*\([^)]*[\*\+][^)]*\)\1",
    
    # === DESERIALIZATION ===
    "VULN_DESER_JSON_PARSE_STORAGE": r"JSON\.parse\s*\(\s*(?:localStorage|sessionStorage)",
    "VULN_DESER_JSON_PARSE_COOKIE": r"JSON\.parse\s*\([^)]*cookie",
    "VULN_DESER_JSON_PARSE_URL": r"JSON\.parse\s*\([^)]*(?:location|URLSearchParams|params|query)",
    "VULN_DESER_EVAL_PARSE": r"\beval\s*\([^)]*JSON\.parse",
    "VULN_DESER_YAML_UNSAFE": r"yaml\.load\s*\((?!.*safeLoad)",
    "VULN_DESER_XML_EXTERNAL": r"(?:parseFromString|DOMParser).*(?:<!ENTITY|<!DOCTYPE).*SYSTEM",
    "VULN_DESER_PICKLE": r"(?:pickle|cPickle)\.loads?\s*\(",
    
    # === RACE CONDITIONS ===
    "VULN_RACE_CHECK_USE": r"if\s*\([^)]*(?:balance|credit|amount|quantity|stock|inventory)\s*[><=][^)]*\)(?!.*(?:lock|mutex|semaphore|transaction))",
    "VULN_RACE_DOUBLE_SUBMIT": r"(?:onclick|addEventListener)\s*=.*(?:fetch|axios)(?!.*(?:disabled|submitted|processing))",
    "VULN_RACE_TOCTOU": r"(?:exists|access)\s*\([^)]*\).*(?:read|write|delete|unlink)",
    
    # === CRYPTOGRAPHY ===
    "VULN_WEAK_CRYPTO_MD5": r"(?:crypto\.)?(?:createHash\s*\(\s*['\"])?md5",
    "VULN_WEAK_CRYPTO_SHA1": r"(?:crypto\.)?(?:createHash\s*\(\s*['\"])?sha1",
    "VULN_WEAK_RANDOM": r"Math\.random\s*\(\s*\)(?!.*(?:seed|crypto|secure))",
    "VULN_WEAK_RANDOM_TOKEN": r"(?:token|id|nonce|session|key)\s*=.*Math\.random",
    "VULN_WEAK_RANDOM_UUID": r"uuid.*Math\.random",
    "VULN_CRYPTO_NO_IV": r"crypto\.create(?:Cipher|Decipher)(?!.*(?:iv|initializationVector))",
    "VULN_CRYPTO_ECB_MODE": r"crypto\.createCipher(?:iv)?\s*\(\s*['\"](?:des|aes).*ecb",
    "VULN_CRYPTO_HARDCODED_KEY": r"crypto\.create(?:Cipher|Hmac)\s*\([^)]*['\"][^'\"]{8,}['\"]",
    
    # === CLICKJACKING ===
    "VULN_CLICKJACKING_OPACITY": r"(?:iframe|frame)[^>]*style[^>]*opacity\s*[=:]\s*['\"]?0?\.0*[1-9]",
    "VULN_CLICKJACKING_POSITION": r"(?:iframe|frame)[^>]*style[^>]*position\s*[=:]\s*['\"](?:absolute|fixed)",
    "VULN_CLICKJACKING_ZINDEX": r"(?:iframe|frame)[^>]*style[^>]*z-index\s*[=:]\s*['\"]?(?:999|9999)",
    "VULN_NO_FRAME_OPTIONS": r"<(?:html|head)(?!.*X-Frame-Options)",
    "VULN_NO_CSP_FRAME": r"<(?:html|head)(?!.*frame-ancestors)",
    
    # === DEBUG & INFO LEAKAGE ===
    "VULN_DEBUG_CONSOLE_SECRET": r"console\.(?:log|info|debug|warn|error)\s*\([^)]*(?:password|secret|token|key|api|credit|ssn|auth|bearer)",
    "VULN_DEBUG_ALERT_SECRET": r"alert\s*\([^)]*(?:password|secret|token|auth)",
    "VULN_ERROR_STACK": r"(?:console|alert)\s*\([^)]*\.stack\s*\)",
    "VULN_SOURCE_MAP": r"\/\/[#@]\s*sourceMappingURL=",
    "VULN_DEBUG_FLAG": r"(?:DEBUG|debug|VERBOSE|verbose)\s*[=:]\s*(?:true|1)",
    "VULN_ENV_EXPOSE": r"console\.log\s*\(\s*(?:process\.env|ENV|environment)",
    "VULN_ERROR_MESSAGE_VERBOSE": r"catch\s*\([^)]*\)\s*\{[^}]*(?:console|alert|innerHTML).*\berror\b",
    
    # === JSONP ===
    "VULN_JSONP_CALLBACK": r"<script[^>]*src[^>]*callback=",
    "VULN_JSONP_USER_CALLBACK": r"script\.src\s*=.*(?:callback|jsonp).*(?:\+|\$\{|params\.|query\.)",
    "VULN_JSONP_EVAL_RESPONSE": r"jsonp.*\beval\s*\(",
    
    # === DOM CLOBBERING ===
    "VULN_DOM_CLOBBER_ID": r"(?:getElementById|querySelector|querySelectorAll)\s*\([^)]*(?:\+|\$\{|params\.)",
    "VULN_DOM_CLOBBER_NAME": r"document\.(?:forms|images|links|scripts|anchors|embeds|applets)\[\w+\]",
    "VULN_DOM_CLOBBER_WINDOW": r"window\[\w+\](?!.*(?:location|document|navigator))",
    
    # === MEMORY LEAKS ===
    "VULN_MEMORY_SETINTERVAL": r"setInterval\s*\((?!.*clearInterval)",
    "VULN_MEMORY_SETTIMEOUT_RECURSIVE": r"setTimeout\s*\([^)]*function\s+(\w+).*\1\s*\(",
    "VULN_MEMORY_EVENT_NO_REMOVE": r"addEventListener\s*\([^)]*\)(?!.*removeEventListener)",
    "VULN_MEMORY_OBSERVER_NO_DISCONNECT": r"(?:MutationObserver|IntersectionObserver|ResizeObserver)\s*\((?!.*disconnect)",
    "VULN_MEMORY_WEBSOCKET_NO_CLOSE": r"new\s+WebSocket\s*\((?!.*close\s*\(\s*\))",
    
    # === CORS ===
    "VULN_CORS_WILDCARD": r"Access-Control-Allow-Origin\s*[=:]\s*['\"]?\*",
    "VULN_CORS_NULL": r"Access-Control-Allow-Origin\s*[=:]\s*['\"]?null",
    "VULN_CORS_CREDENTIALS_WILDCARD": r"Access-Control-Allow-Credentials\s*[=:]\s*['\"]?true.*Access-Control-Allow-Origin\s*[=:]\s*['\"]?\*",
    "VULN_CORS_REFLECT_ORIGIN": r"Access-Control-Allow-Origin.*req\.headers?\.origin",
    
    # === UNICODE & ENCODING ===
    "VULN_UNICODE_ESCAPE": r"\\u00[0-9a-fA-F]{2}",
    "VULN_HOMOGRAPH": r"[а-яА-ЯёЁ]",
    "VULN_NULL_BYTE": r"(?:\\x00|%00|\\0)",
    "VULN_DOUBLE_ENCODING": r"%25[0-9a-fA-F]{2}",
    
    # === SHADOW APIs & RECON ===
    "SHADOW_API_ENDPOINT": r"(?:https?:)?\/\/[\w\.-]+\/(?:api|admin|internal|debug|test|dev|staging|v\d+)",
    "SHADOW_INTERNAL_IP": r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|0\.0\.0\.0|localhost)",
    "SHADOW_ADMIN_PATH": r"\/(?:admin|administrator|wp-admin|phpmyadmin|cpanel|adminer|backend|dashboard|manage|control)",
    "SHADOW_API_DISCOVERY": r"['\"`]\/(?:api|v\d+|graphql|rest|endpoint)\/[\w\/-]+['\"`]",
    "SHADOW_COMMENT_TODO": r"(?:TODO|FIXME|HACK|XXX|NOTE|BUG).*(?:security|vuln|fix|temp|bypass)",
    "SHADOW_BACKUP_FILE": r"\.(?:bak|backup|old|orig|save|copy|tmp)(?:['\"]|\s|$)",
    
    # === MUTATION XSS ===
    "VULN_MXSS_DOUBLE_ENCODE": r"innerHTML.*innerHTML",
    "VULN_MXSS_NAMESPACE": r"(?:svg|math|xml).*innerHTML",
    "VULN_MXSS_STYLE_MUTATION": r"style.*innerHTML",
    
    # === FRAMEWORK SPECIFIC ===
    # Angular
    "VULN_ANGULAR_BYPASS_SCE": r"\$sce\.trustAs(?:Html|ResourceUrl|Js)",
    "VULN_ANGULAR_TEMPLATE_INJECT": r"\{\{.*\$\{.*\}\}",
    "VULN_ANGULAR_NG_INCLUDE": r"ng-include\s*=\s*['\"][^'\"]*\$\{",
    
    # React
    "VULN_REACT_REF_EVAL": r"ref\s*=\s*\{[^}]*\beval\b",
    "VULN_REACT_DANGEROUSLY_SET": r"dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html:\s*(?:props|state|\w+)",
    "VULN_REACT_CREATE_ELEMENT_USER": r"React\.createElement\s*\([^)]*(?:props|state|\w+\.\w+)",
    
    # Vue
    "VULN_VUE_VHTML_USER": r"v-html\s*=\s*['\"]?\{\{",
    "VULN_VUE_COMPILE_TEMPLATE": r"Vue\.compile\s*\([^)]*(?:\+|\$\{|props|data)",
    
    # Svelte
    "VULN_SVELTE_HTML": r"\{@html\s+(?:props|\$)",
    
    # CSP BYPASS ===
    "VULN_CSP_UNSAFE_INLINE": r"(?:Content-Security-Policy|CSP).*script-src.*['\"]?unsafe-inline",
    "VULN_CSP_UNSAFE_EVAL": r"(?:Content-Security-Policy|CSP).*script-src.*['\"]?unsafe-eval",
    "VULN_CSP_MISSING": r"<html(?!.*Content-Security-Policy)",
    
    # === ADVANCED PATTERNS ===
    "VULN_PROTO_POLLUTION_CHAIN": r"(?:__proto__|constructor\[.*prototype).*\[",
    "VULN_CONSTRUCTOR_ACCESS": r"\[['\"]constructor['\"]\]\[['\"]prototype['\"]\]",
    "VULN_GETTER_SETTER_DANGEROUS": r"Object\.defineProperty.*(?:get|set)\s*:.*(?:eval|Function)",
    "VULN_PROXY_HANDLER_EVAL": r"new\s+Proxy\s*\([^)]*\{[^}]*(?:get|set|apply)[^}]*(?:eval|Function)",
    "VULN_REFLECT_CONSTRUCT": r"Reflect\.construct\s*\([^)]*Function",
    "VULN_SYMBOL_TOPOPRIMITIVE": r"Symbol\.toPrimitive.*(?:eval|Function)",
    
    # === BUSINESS LOGIC ===
    "VULN_PRICE_MANIPULATION": r"(?:price|amount|total|cost)\s*=\s*(?:params\.|query\.|req\.|body\.)",
    "VULN_QUANTITY_MANIPULATION": r"(?:quantity|count|number)\s*=\s*(?:params\.|query\.|req\.|body\.|\-)",
    "VULN_DISCOUNT_MANIPULATION": r"(?:discount|coupon|promo)\s*=\s*(?:params\.|query\.|req\.|body\.)",
    "VULN_ROLE_ESCALATION": r"(?:role|permission|access_level)\s*=\s*(?:params\.|query\.|req\.|body\.)",
    
    # === BYPASS TECHNIQUES ===
    "VULN_FILTER_BYPASS_COMMENT": r"<script(?:\/\*.*\*\/)?>",
    "VULN_FILTER_BYPASS_NEWLINE": r"<script[\r\n\t ]+>",
    "VULN_FILTER_BYPASS_CASE": r"<ScRiPt>",
    "VULN_FILTER_BYPASS_NULL": r"<script\\x00>",
}

# Compile all patterns with error handling
COMPILED_SCANNERS = {}
for k, v in RAW_PATTERNS.items():
    try:
        COMPILED_SCANNERS[k] = re.compile(v, re.I | re.DOTALL)
    except Exception as e:
        print(f"⚠️  Warning: Failed to compile pattern {k}: {e}")

# === WORDLIST ===
WORDLIST_PATH = "/app/services/engine/wordlist.txt"
WORDLIST = set()
if os.path.exists(WORDLIST_PATH):
    try:
        with open(WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
            WORDLIST = {line.strip().lower() for line in f if len(line.strip()) > 3}
    except Exception as e:
        print(f"⚠️  Warning: Failed to load wordlist: {e}")

# === SECURITY INTELLIGENCE ===
SECURITY_KEYWORDS = {
    "admin", "secret", "auth", "key", "token", "api", "password", "credential",
    "session", "private", "internal", "confidential", "bearer", "jwt", "apikey",
    "access", "refresh", "oauth", "ssn", "credit", "payment", "encrypted", 
    "decrypt", "signature", "certificate", "master", "root", "sudo", "privilege"
}

DANGEROUS_SINKS = {
    "eval", "Function", "setTimeout", "setInterval", "innerHTML", "outerHTML",
    "document.write", "execScript", "postMessage", "exec", "spawn", "require",
    "import", "WebAssembly", "insertAdjacentHTML", "createContextualFragment",
    "Range.createContextualFragment", "$.html", "$.append", "dangerouslySetInnerHTML"
}

USER_INPUT_SOURCES = [
    "location.search", "location.hash", "location.href", "document.cookie",
    "document.referrer", "URLSearchParams", "getElementById", "querySelector",
    "params", "query", "body", "req.", "request.", "event.data", "message.data",
    "postMessage", "websocket", "localStorage", "sessionStorage", "innerText",
    "textContent", "value", "getAttribute", "dataset", "window.name",
    "document.location", "document.URL", "document.documentURI", "document.baseURI"
]

SANITIZATION_FUNCTIONS = {
    "sanitize", "escape", "encode", "encodeURI", "encodeURIComponent",
    "DOMPurify", "sanitizeHTML", "escapeHTML", "htmlspecialchars",
    "textContent", "createTextNode", "validator", "xss", "dompurify"
}

# === NOISE FILTERS ===
NOISE_FILTERS = [
    "www.w3.org", "xmlns", "data:image", "node_modules", "license",
    "reactjs.org", "mozilla.org", "webpack", "facebook.com", ".png",
    ".svg", ".jpg", ".gif", ".ico", "cdn.jsdelivr", "unpkg.com",
    "cdnjs.cloudflare", "@license", "Copyright", "MIT License",
    "BSD License", "Apache License", "SPDX-License", "sourceMapping"
]

# === SEVERITY SCORING ===
SEVERITY_WEIGHTS = {
    "CRITICAL": {"base": 10.0, "multipliers": {"user_input": 1.5, "no_sanitization": 1.3, "authenticated": 0.9}},
    "HIGH": {"base": 7.0, "multipliers": {"user_input": 1.3, "no_sanitization": 1.2, "authenticated": 0.8}},
    "MEDIUM": {"base": 4.0, "multipliers": {"user_input": 1.2, "no_sanitization": 1.1, "authenticated": 0.7}},
    "LOW": {"base": 2.0, "multipliers": {"user_input": 1.1, "no_sanitization": 1.0, "authenticated": 0.6}},
    "INFO": {"base": 0.5, "multipliers": {}}
}

def classify_severity(category, evidence, context):
    """Enhanced severity classification with context-aware scoring"""
    
    # CRITICAL patterns - immediate exploitation possible
    critical_patterns = [
        "VULN_EVAL", "VULN_XSS_DIRECT", "VULN_XSS_INNERHTML", "VULN_SQL", 
        "VULN_COMMAND", "VULN_NOSQL_OPERATOR", "VULN_RCE", "SECRET_AWS",
        "SECRET_PRIVATE_KEY", "VULN_PROTO_POLLUTION", "VULN_TAINT_FLOW",
        "VULN_DESERIALIZATION", "VULN_XSS_DOCUMENT_WRITE"
    ]
    
    # HIGH patterns - significant security impact
    high_patterns = [
        "SECRET_", "VULN_IDOR", "VULN_REDIRECT", "VULN_PROTO",
        "VULN_CSRF", "VULN_CLIENT_AUTH", "VULN_POSTMESSAGE",
        "VULN_FILE_UPLOAD", "VULN_PATH_TRAVERSAL", "VULN_SSRF",
        "VULN_NOSQL_USER", "VULN_AUTH_", "VULN_JWT"
    ]
    
    # MEDIUM patterns - moderate security impact
    medium_patterns = [
        "VULN_STORAGE", "VULN_CORS", "VULN_CLICKJACKING", "VULN_RACE",
        "VULN_WEAK_CRYPTO", "SHADOW_", "VULN_DEBUG", "VULN_MEMORY",
        "VULN_COOKIE", "VULN_WEBSOCKET", "VULN_JSONP"
    ]
    
    # Determine base severity
    base_severity = "LOW"
    for pattern in critical_patterns:
        if pattern in category:
            base_severity = "CRITICAL"
            break
    
    if base_severity == "LOW":
        for pattern in high_patterns:
            if pattern in category:
                base_severity = "HIGH"
                break
    
    if base_severity == "LOW":
        for pattern in medium_patterns:
            if pattern in category:
                base_severity = "MEDIUM"
                break
    
    # Context-aware adjustments
    if context:
        # Upgrade if user input without sanitization
        if context.get('has_user_input') and not context.get('has_sanitization'):
            if base_severity == "MEDIUM":
                base_severity = "HIGH"
            elif base_severity == "LOW":
                base_severity = "MEDIUM"
        
        # Upgrade if in authentication/authorization context
        if any(keyword in evidence.lower() for keyword in ['auth', 'login', 'session', 'admin']):
            if base_severity == "LOW":
                base_severity = "MEDIUM"
        
        # Downgrade if strong validation present
        if context.get('has_validation') and context.get('has_sanitization'):
            if base_severity == "HIGH":
                base_severity = "MEDIUM"
    
    return base_severity

# === CONTEXT ANALYSIS ===
def analyze_context_flow(lines, current_idx, window=MAX_CONTEXT_WINDOW):
    """Advanced context flow analysis with scope tracking"""
    start = max(0, current_idx - window)
    end = min(len(lines), current_idx + window + 1)
    context_lines = lines[start:end]
    
    context_info = {
        'has_user_input': False,
        'has_sanitization': False,
        'has_validation': False,
        'tainted_vars': set(),
        'sanitized_vars': set(),
        'in_try_catch': False,
        'in_auth_function': False,
        'async_context': False,
        'framework': None
    }
    
    # Analyze context window
    for i, line in enumerate(context_lines):
        line_lower = line.lower()
        
        # User input detection
        for source in USER_INPUT_SOURCES:
            if source in line:
                context_info['has_user_input'] = True
                # Extract variable name
                var_match = re.search(r'(?:var|let|const)\s+(\w+)\s*=', line)
                if var_match:
                    context_info['tainted_vars'].add(var_match.group(1))
        
        # Sanitization detection
        for sanitizer in SANITIZATION_FUNCTIONS:
            if sanitizer in line_lower:
                context_info['has_sanitization'] = True
                var_match = re.search(r'(\w+)\s*=.*(?:' + '|'.join(SANITIZATION_FUNCTIONS) + ')', line, re.I)
                if var_match:
                    context_info['sanitized_vars'].add(var_match.group(1))
        
        # Validation detection
        if re.search(r'if\s*\(.*(?:test|match|includes|typeof|instanceof|Array\.isArray|Number\.isInteger)', line):
            context_info['has_validation'] = True
        
        # Try-catch detection
        if re.search(r'try\s*\{|catch\s*\(', line):
            context_info['in_try_catch'] = True
        
        # Authentication function detection
        if re.search(r'function\s+\w*(?:auth|login|verify|check|validate)\w*', line, re.I):
            context_info['in_auth_function'] = True
        
        # Async context
        if re.search(r'async\s+function|await\s+', line):
            context_info['async_context'] = True
        
        # Framework detection
        if 'React' in line or 'useState' in line or 'useEffect' in line:
            context_info['framework'] = 'React'
        elif 'Vue' in line or '@click' in line or 'v-model' in line:
            context_info['framework'] = 'Vue'
        elif '$scope' in line or 'angular' in line_lower:
            context_info['framework'] = 'Angular'
    
    return context_info

# === ADVANCED TAINT TRACKING ===
def track_taint_flow(lines, max_lines=TAINT_ANALYSIS_DEPTH):
    """Enhanced taint tracking with inter-procedural analysis"""
    tainted = {}
    flows = []
    function_params = {}
    current_function = None
    
    for i, line in enumerate(lines[:max_lines], 1):
        # Function definition tracking
        func_match = re.search(r'function\s+(\w+)\s*\(([^)]*)\)', line)
        if func_match:
            current_function = func_match.group(1)
            params = [p.strip() for p in func_match.group(2).split(',') if p.strip()]
            function_params[current_function] = {'params': params, 'line': i}
        
        # Assignment tracking
        assignment = re.search(r'(?:var|let|const)\s+(\w+)\s*=\s*(.+)', line)
        if assignment:
            var_name, value = assignment.groups()
            
            # Direct user input
            is_tainted = any(source in value for source in USER_INPUT_SOURCES)
            
            # Propagation from tainted variable
            if not is_tainted:
                for tainted_var in tainted:
                    if re.search(r'\b' + re.escape(tainted_var) + r'\b', value):
                        is_tainted = True
                        break
            
            # Function call return tracking
            if not is_tainted:
                func_call = re.search(r'(\w+)\s*\(', value)
                if func_call and func_call.group(1) in function_params:
                    # Check if function params are tainted
                    for param in function_params[func_call.group(1)]['params']:
                        if param in tainted:
                            is_tainted = True
                            break
            
            if is_tainted:
                # Check for sanitization
                is_sanitized = any(sanitizer in value.lower() for sanitizer in SANITIZATION_FUNCTIONS)
                tainted[var_name] = {
                    'line': i,
                    'source': value[:150],
                    'sanitized': is_sanitized,
                    'function': current_function
                }
        
        # Property assignment tracking
        prop_assignment = re.search(r'(\w+)\.(\w+)\s*=\s*(.+)', line)
        if prop_assignment:
            obj, prop, value = prop_assignment.groups()
            if obj in tainted or any(source in value for source in USER_INPUT_SOURCES):
                key = f"{obj}.{prop}"
                tainted[key] = {'line': i, 'source': value[:150], 'sanitized': False}
        
        # Usage in dangerous sinks
        for sink in DANGEROUS_SINKS:
            if sink in line:
                for tainted_var in tainted:
                    if not tainted[tainted_var].get('sanitized', False):
                        # Check if tainted var is used in this line
                        if re.search(r'\b' + re.escape(tainted_var.split('.')[0]) + r'\b', line):
                            flows.append({
                                'var': tainted_var,
                                'source_line': tainted[tainted_var]['line'],
                                'sink_line': i,
                                'sink_function': sink,
                                'evidence': line.strip()[:250],
                                'confidence': 'HIGH' if tainted_var in line else 'MEDIUM',
                                'function_context': current_function or 'global'
                            })
    
    return flows

# === CHAIN DETECTION ===
def detect_vulnerability_chains(previous_lines, current_line, line_num):
    """Detect multi-step vulnerability chains"""
    chains = []
    recent_context = ' '.join(previous_lines[-5:]) + ' ' + current_line
    
    # XSS Chain: user input -> assignment -> innerHTML
    if re.search(r'(?:location|params|cookie|query)[^\n]*=\s*(\w+)[^\n]*\1[^\n]*innerHTML', recent_context, re.DOTALL):
        chains.append({
            'type': 'VULN_XSS_CHAIN',
            'severity': 'CRITICAL',
            'evidence': current_line[:200],
            'line': line_num,
            'description': 'Multi-step XSS: user input flows through variable to innerHTML'
        })
    
    # Prototype pollution chain: JSON.parse -> Object.assign
    if re.search(r'JSON\.parse[^\n]*\n[^\n]*Object\.assign', recent_context, re.DOTALL):
        chains.append({
            'type': 'VULN_PROTO_CHAIN',
            'severity': 'CRITICAL',
            'evidence': current_line[:200],
            'line': line_num,
            'description': 'Prototype pollution via JSON.parse and Object.assign'
        })
    
    # Auth bypass chain: localStorage read -> role check -> admin function
    if re.search(r'localStorage\.getItem[^\n]*role[^\n]*if[^\n]*admin', recent_context, re.DOTALL | re.I):
        chains.append({
            'type': 'VULN_AUTH_BYPASS_CHAIN',
            'severity': 'CRITICAL',
            'evidence': current_line[:200],
            'line': line_num,
            'description': 'Client-side auth bypass chain detected'
        })
    
    # SSRF chain: user input -> fetch without validation
    if re.search(r'(?:params|query)[^\n]*=\s*(\w+)[^\n]*fetch[^\n]*\1', recent_context, re.DOTALL):
        chains.append({
            'type': 'VULN_SSRF_CHAIN',
            'severity': 'HIGH',
            'evidence': current_line[:200],
            'line': line_num,
            'description': 'SSRF chain: user-controlled URL in fetch'
        })
    
    return chains

# === MAIN PROCESSING ===
@app.task(name="titan.process_file", queue="titan_queue")
def process_file(domain, filename, code):
    """Enterprise-grade file scanning with advanced vulnerability detection"""
    db = SessionLocal()
    
    try:
        # Setup
        scan_dir = "/tmp/titan_scans"
        os.makedirs(scan_dir, exist_ok=True)
        
        asset_path = os.path.join(scan_dir, f"scan_{int(time.time())}_{hashlib.md5(filename.encode()).hexdigest()[:8]}.js")
        with open(asset_path, "w", encoding="utf-8", errors="ignore") as f_out:
            f_out.write(code)

        # Database setup
        target = db.query(Target).filter_by(domain=domain).first()
        if not target:
            target = Target(domain=domain)
            db.add(target)
            db.commit()
            db.refresh(target)

        asset = Asset(target_id=target.id, url=filename, local_path=asset_path)
        db.add(asset)
        db.commit()
        db.refresh(asset)

        # Load file
        with open(asset_path, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()
        
        print(f"🔍 Scanning {filename} ({len(all_lines)} lines)")
        
        # === PHASE 1: ADVANCED TAINT ANALYSIS ===
        print("  ├─ Phase 1: Taint flow analysis...")
        taint_flows = track_taint_flow(all_lines)
        
        findings_buffer = []
        for flow in taint_flows:
            findings_buffer.append(Finding(
                asset_id=asset.id,
                type="VULN_TAINT_FLOW_CONFIRMED",
                severity="CRITICAL" if flow['confidence'] == 'HIGH' else "HIGH",
                evidence=f"Tainted var '{flow['var']}' from line {flow['source_line']} flows to {flow['sink_function']} at line {flow['sink_line']}: {flow['evidence']}",
                line=flow['sink_line']
            ))

        # === PHASE 2: LINE-BY-LINE DEEP SCAN ===
        print("  ├─ Phase 2: Pattern-based scanning...")
        previous_lines = []
        seen_findings = set()
        
        for i, line in enumerate(all_lines, 1):
            if len(line) > MAX_LINE_LENGTH or not line.strip():
                continue
            
            stripped = line.strip()
            
            # Skip comments and noise
            if stripped.startswith(("//", "/*", "*", "#")) or any(noise in line.lower() for noise in NOISE_FILTERS):
                continue
            
            # Context analysis
            context_info = analyze_context_flow(all_lines, i - 1)
            line_lower = line.lower()
            
            # === Pattern Matching ===
            for cat, regex in COMPILED_SCANNERS.items():
                try:
                    match = regex.search(line)
                    if match:
                        finding_hash = hashlib.md5(f"{cat}:{i}:{stripped[:100]}".encode()).hexdigest()
                        
                        if finding_hash in seen_findings:
                            continue
                        
                        seen_findings.add(finding_hash)
                        
                        # Enhanced severity
                        severity = classify_severity(cat, stripped, context_info)
                        
                        evidence = stripped[:300]
                        
                        # Enhanced evidence for secrets
                        if cat.startswith("SECRET_"):
                            matched_text = match.group(0)
                            # Mask the secret in the evidence to prevent logging sensitive data
                            if len(matched_text) > 15:
                                masked_secret = matched_text[:5] + "..." + matched_text[-3:]
                                evidence = f"{masked_secret} | {evidence}"
                        
                        findings_buffer.append(Finding(
                            asset_id=asset.id,
                            type=cat,
                            severity=severity,
                            evidence=evidence,
                            line=i
                        ))

                except Exception as re_err:
                    # Prevent single regex failure from stopping the whole scan
                    continue

            # === PHASE 3: CHAIN & HEURISTIC ANALYSIS ===
            
            # Detect vulnerability chains (Multi-line analysis)
            chains = detect_vulnerability_chains(previous_lines, line, i)
            for chain in chains:
                chain_hash = hashlib.md5(f"{chain['type']}:{i}:{chain['evidence']}".encode()).hexdigest()
                if chain_hash not in seen_findings:
                    seen_findings.add(chain_hash)
                    findings_buffer.append(Finding(
                        asset_id=asset.id,
                        type=chain['type'],
                        severity=chain['severity'],
                        evidence=f"{chain['description']}: {chain['evidence']}",
                        line=i
                    ))

            # Security Intelligence: Heuristic Keyword Matching
            # (Only runs if no specific vulnerability was found on this line to reduce noise)
            if not any(f.line == i for f in findings_buffer[-5:]):
                line_lower = line.lower()
                for keyword in SECURITY_KEYWORDS:
                    if keyword in line_lower:
                        # Filter out common false positives for keywords
                        clean_line = re.sub(r'[^a-zA-Z0-9]', ' ', line_lower)
                        words = clean_line.split()
                        
                        if keyword in words:
                            # Context check: is it an assignment or definition?
                            if re.search(r'[:=]\s*[\'"`]', line) or "function" in line:
                                intel_hash = hashlib.md5(f"INTEL:{i}:{keyword}".encode()).hexdigest()
                                if intel_hash not in seen_findings:
                                    seen_findings.add(intel_hash)
                                    findings_buffer.append(Finding(
                                        asset_id=asset.id,
                                        type="INTEL_MATCH",
                                        severity="INFO",
                                        evidence=f"Intelligence match: {keyword}",
                                        line=i
                                    ))
                                break

            # Maintain context buffer (Keep last 10 lines)
            previous_lines.append(line)
            if len(previous_lines) > 10:
                previous_lines.pop(0)

            # === PHASE 4: DATABASE BATCHING ===
            if len(findings_buffer) >= BATCH_SIZE:
                try:
                    db.bulk_save_objects(findings_buffer)
                    db.commit()
                    findings_buffer.clear()
                except Exception as e:
                    print(f"⚠️  Database batch error: {e}")
                    db.rollback()
                    # Retry individually or clear buffer to proceed
                    findings_buffer.clear()

        # === FINALIZATION ===
        
        # Save remaining findings
        if findings_buffer:
            try:
                db.bulk_save_objects(findings_buffer)
                db.commit()
            except Exception as e:
                print(f"⚠️  Final save error: {e}")
                db.rollback()
        
        # Statistics
        total_findings = len(seen_findings)
        critical_count = sum(1 for f in findings_buffer if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings_buffer if f.severity == "HIGH")
        
        print(f"✅ Completed {filename}")
        print(f"   Total Findings: {total_findings}")
        print(f"   Critical: {critical_count}, High: {high_count}")
        
    except Exception as e:
        print(f"❌ Critical Scan Error [{filename}]: {str(e)}")
        import traceback
        traceback.print_exc()
        db.rollback()
    finally:
        db.close()
        # Clean up temp file
        if 'asset_path' in locals() and os.path.exists(asset_path):
            try:
                os.remove(asset_path)
            except:
                pass

if __name__ == "__main__":
    app.start()