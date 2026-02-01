# import os, json, re, math, time, hashlib, zlib
# from collections import defaultdict
# from celery import Celery
# from core.db.session import SessionLocal
# from core.db.models import Target, Asset, Finding, SourceFile

# # Initialize Celery
# app = Celery("titan", broker=os.getenv("REDIS_URL"), backend=os.getenv("REDIS_URL"))

# # ╔═══════════════════════════════════════════════════════════════════════════════╗
# # ║                    TITAN V2 - ELITE BUG BOUNTY ENGINE                        ║
# # ║                         10/10 VULNERABILITY SCANNER                           ║
# # ╚═══════════════════════════════════════════════════════════════════════════════╝

# MAX_LINE_LENGTH = 20000
# BATCH_SIZE = 3000
# MAX_CONTEXT_WINDOW = 25
# TAINT_ANALYSIS_DEPTH = 5000

# class PatternContext:
#     def __init__(self):
#         self.variable_assignments = {}
#         self.scope_stack = []
#         self.sanitization_functions = set()
        
#     def track_variable(self, var_name, source_type, line_num, scope='global'):
#         taint_sources = {
#             'location.search', 'location.hash', 'location.href', 'location.pathname',
#             'document.location', 'document.URL', 'document.referrer', 'window.name',
#             'URLSearchParams', 'params', 'query', 'innerHTML', 'value', 'getAttribute',
#             'localStorage', 'sessionStorage', 'cookie', 'fetch', 'XMLHttpRequest',
#             'postMessage', 'event.data', 'WebSocket', 'FileReader', 'req.body',
#             'req.params', 'req.query', 'props', 'state', 'useParams', 'match.params',
#         }
#         is_tainted = any(src in source_type for src in taint_sources)
#         self.variable_assignments[f"{scope}::{var_name}"] = {
#             'source': source_type, 'line': line_num, 'scope': scope,
#             'tainted': is_tainted, 'sanitized': False
#         }
    
#     def is_tainted(self, var_name, scope='global'):
#         key = f"{scope}::{var_name}"
#         if key in self.variable_assignments:
#             v = self.variable_assignments[key]
#             return v.get('tainted', False) and not v.get('sanitized', False)
#         return False

# # ═══════════════════════════════════════════════════════════════════════════════
# # VULNERABILITY PATTERNS - 500+ Elite Bug Bounty Patterns
# # ═══════════════════════════════════════════════════════════════════════════════

# RAW_PATTERNS = {
#     # ══════════════════════════════════════════════════════════════════════════
#     #                              XSS PATTERNS
#     # ══════════════════════════════════════════════════════════════════════════
    
#     # DOM XSS - innerHTML/outerHTML
#     "XSS_INNERHTML_DIRECT": r"\.innerHTML\s*=\s*(?!['\"]<?\s*['\"])",
#     "XSS_INNERHTML_CONCAT": r"\.innerHTML\s*[+]=?\s*.*(?:\+|\$\{|`)",
#     "XSS_INNERHTML_VAR": r"\.innerHTML\s*=\s*[a-zA-Z_$][\w$]*(?:\[|\.|;|\)|\s|$)",
#     "XSS_OUTERHTML": r"\.outerHTML\s*=",
#     "XSS_DOCUMENT_WRITE": r"document\.write(?:ln)?\s*\(",
#     "XSS_INSERT_ADJACENT": r"\.insertAdjacentHTML\s*\(",
#     "XSS_CREATE_FRAGMENT": r"\.createContextualFragment\s*\(",
#     "XSS_SRCDOC": r"\.srcdoc\s*=",
#     "XSS_IFRAME_SRC_JS": r"iframe[^>]*src\s*=\s*['\"]?javascript:",
#     "XSS_IFRAME_SRC_DATA": r"iframe[^>]*src\s*=\s*['\"]?data:text/html",
    
#     # Event Handler XSS
#     "XSS_EVENT_ATTR": r"\.setAttribute\s*\(\s*['\"]on\w+['\"]",
#     "XSS_EVENT_DIRECT": r"\.(onclick|onload|onerror|onmouseover|onfocus|onblur|onkeypress|onkeydown|oninput|onchange|onsubmit)\s*=",
#     "XSS_EVENT_TEMPLATE": r"on\w+\s*=\s*['\"]?(?:\$\{|<%|{{|\[\[)",
#     "XSS_SVG_EVENT": r"<svg[^>]*on\w+\s*=",
#     "XSS_BODY_EVENT": r"<body[^>]*on(?:load|error|focus)\s*=",
#     "XSS_IMG_ONERROR": r"<img[^>]*onerror\s*=",
#     "XSS_INPUT_EVENT": r"<input[^>]*on(?:focus|blur|input|change)\s*=",
#     "XSS_DETAILS_TOGGLE": r"<details[^>]*ontoggle\s*=",
#     "XSS_VIDEO_EVENT": r"<video[^>]*on(?:error|loadeddata|play|pause)\s*=",
#     "XSS_FORM_EVENT": r"<form[^>]*on(?:submit|reset)\s*=",
#     "XSS_MARQUEE_EVENT": r"<marquee[^>]*on(?:start|finish|bounce)\s*=",
    
#     # URL-based XSS
#     "XSS_HREF_JAVASCRIPT": r"\.href\s*=\s*['\"]?javascript:",
#     "XSS_HREF_DATA": r"\.href\s*=\s*['\"]?data:",
#     "XSS_SRC_JAVASCRIPT": r"\.src\s*=\s*['\"]?javascript:",
#     "XSS_SRC_DATA": r"\.src\s*=\s*['\"]?data:(?:text/html|application/javascript|image/svg\+xml)",
#     "XSS_ACTION_JAVASCRIPT": r"\.action\s*=\s*['\"]?javascript:",
#     "XSS_FORMACTION_JS": r"\.formAction\s*=\s*['\"]?javascript:",
#     "XSS_HREF_CONCAT": r"\.href\s*=\s*(?:['\"])?.*(?:\+|\$\{|`)",
#     "XSS_SRC_CONCAT": r"\.src\s*=\s*.*(?:\+|\$\{|`)",
#     "XSS_ACTION_CONCAT": r"\.action\s*=\s*.*(?:\+|\$\{|`)",
    
#     # Style-based XSS
#     "XSS_STYLE_EXPRESSION": r"style[^>]*expression\s*\(",
#     "XSS_STYLE_URL_JS": r"style[^>]*url\s*\([^)]*javascript:",
#     "XSS_STYLE_IMPORT": r"@import\s+['\"]?javascript:",
#     "XSS_STYLE_INJECTION": r"\.style\.(?:cssText|background|backgroundImage)\s*=\s*.*(?:\+|\$\{|`)",
#     "XSS_CSSTEXT": r"\.cssText\s*=",
    
#     # jQuery XSS
#     "XSS_JQUERY_HTML": r"\$\s*\([^)]*\)\.html\s*\(\s*[^)]*(?:\+|\$\{|`|[a-zA-Z_])",
#     "XSS_JQUERY_APPEND": r"\$\s*\([^)]*\)\.(append|prepend|after|before|replaceWith|wrap)\s*\(",
#     "XSS_JQUERY_CONSTRUCTOR": r"\$\s*\(\s*['\"]?<",
#     "XSS_JQUERY_CONSTRUCTOR_VAR": r"\$\s*\(\s*[a-zA-Z_$][\w$]*\s*\)",
#     "XSS_JQUERY_PARSEHTML": r"\$\.parseHTML\s*\(",
#     "XSS_JQUERY_GLOBALEVAL": r"\$\.globalEval\s*\(",
#     "XSS_JQUERY_GETSCRIPT": r"\$\.getScript\s*\(",
#     "XSS_JQUERY_ATTR_HREF": r"\.attr\s*\(\s*['\"](?:href|src|action)['\"]",
#     "XSS_JQUERY_ATTR_EVENT": r"\.attr\s*\(\s*['\"]on\w+['\"]",
    
#     # Framework XSS - React
#     "XSS_REACT_DANGEROUSLY": r"dangerouslySetInnerHTML\s*[=:]\s*\{",
#     "XSS_REACT_HREF_USER": r"href\s*=\s*\{[^}]*(?:props|state|params|query|location|data|user|input)",
#     "XSS_REACT_SRC_USER": r"src\s*=\s*\{[^}]*(?:props|state|params|query|location|data|user|input)",
#     "XSS_REACT_REF_INNERHTML": r"ref[^}]*\.current\.innerHTML",
    
#     # Framework XSS - Vue
#     "XSS_VUE_VHTML": r"v-html\s*=",
#     "XSS_VUE_COMPILE": r"Vue\.compile\s*\(",
#     "XSS_VUE_TEMPLATE": r"template\s*:\s*[^'\"]*(?:\+|\$\{|`)",
    
#     # Framework XSS - Angular
#     "XSS_ANGULAR_INNERHTML": r"\[innerHTML\]\s*=",
#     "XSS_ANGULAR_BYPASS": r"bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)",
#     "XSS_ANGULAR_SCE": r"\$sce\.trustAs(?:Html|Js|Url)",
#     "XSS_ANGULAR_COMPILE": r"\$compile\s*\(",
#     "XSS_ANGULAR_PARSE": r"\$parse\s*\(",
#     "XSS_ANGULAR_NGINCLUDE": r"ng-include\s*=",
#     "XSS_ANGULAR_NGBINDHTML": r"ng-bind-html(?:-unsafe)?\s*=",
    
#     # Framework XSS - Svelte
#     "XSS_SVELTE_HTML": r"\{@html\s+",
    
#     # Template XSS
#     "XSS_HANDLEBARS_TRIPLE": r"\{\{\{[^}]+\}\}\}",
#     "XSS_HANDLEBARS_SAFE": r"Handlebars\.SafeString\s*\(",
#     "XSS_EJS_UNESCAPED": r"<%-[^%]+%>",
#     "XSS_PUG_UNESCAPED": r"!\{[^}]+\}",
    
#     # SVG/MathML XSS
#     "XSS_SVG_SCRIPT": r"<svg[^>]*>.*<script",
#     "XSS_SVG_FOREIGNOBJECT": r"<svg[^>]*>.*<foreignObject",
#     "XSS_SVG_USE_HREF": r"<use[^>]*(?:href|xlink:href)\s*=",
#     "XSS_SVG_ANIMATE": r"<(?:animate|animateTransform|set)[^>]*(?:onbegin|onend)\s*=",
#     "XSS_MATHML_SCRIPT": r"<math[^>]*>.*<script",
    
#     # Template Literal XSS
#     "XSS_TEMPLATE_HTML": r"`[^`]*<(?:script|img|svg|iframe|object|embed|body|input|form)[^`]*\$\{",
#     "XSS_TEMPLATE_EVENT": r"`[^`]*\s+on\w+\s*=\s*['\"]?\$\{",
    
#     # mXSS (Mutation XSS)
#     "XSS_MXSS_NOSCRIPT": r"<noscript[^>]*>.*<",
#     "XSS_MXSS_TEXTAREA": r"<textarea[^>]*>.*<",
#     "XSS_MXSS_TITLE": r"<title[^>]*>.*<",
#     "XSS_MXSS_STYLE": r"<style[^>]*>.*<",
#     "XSS_MXSS_DOUBLE": r"innerHTML[^;]*innerHTML",
    
#     # DOM Clobbering
#     "XSS_CLOBBER_FORM": r"document\.(?:forms|images|links|anchors)\s*\[",
#     "XSS_CLOBBER_WINDOW": r"window\[['\"][a-zA-Z_$]",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                         CODE EXECUTION / RCE
#     # ══════════════════════════════════════════════════════════════════════════
    
#     # Direct Eval
#     "EVAL_DIRECT": r"\beval\s*\(",
#     "EVAL_INDIRECT": r"\(window\|global\|globalThis\|self\)\s*\[\s*['\"]eval['\"]\s*\]",
#     "EVAL_ALIAS": r"(?:var|let|const)\s+\w+\s*=\s*eval\b",
    
#     # Function Constructor
#     "EVAL_FUNCTION_NEW": r"new\s+Function\s*\(",
#     "EVAL_FUNCTION_DIRECT": r"(?<!new\s)Function\s*\(\s*['\"`]",
#     "EVAL_CONSTRUCTOR": r"\.constructor\s*\(\s*['\"]",
#     "EVAL_PROTO_CONSTRUCTOR": r"(?:__proto__|prototype)\.constructor\s*\(",
#     "EVAL_GENERATOR_CTOR": r"\(function\s*\*\s*\(\s*\)\s*\{\s*\}\)\.constructor",
#     "EVAL_ASYNC_CTOR": r"\(async\s+function\s*\(\s*\)\s*\{\s*\}\)\.constructor",
    
#     # setTimeout/setInterval String
#     "EVAL_SETTIMEOUT_STR": r"setTimeout\s*\(\s*['\"`]",
#     "EVAL_SETTIMEOUT_VAR": r"setTimeout\s*\(\s*[a-zA-Z_$][\w$]*\s*(?:,|\))",
#     "EVAL_SETINTERVAL_STR": r"setInterval\s*\(\s*['\"`]",
#     "EVAL_SETIMMEDIATE": r"setImmediate\s*\(\s*['\"`]",
    
#     # Dynamic Import
#     "EVAL_IMPORT_DYNAMIC": r"import\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
    
#     # Workers
#     "EVAL_WORKER_BLOB": r"new\s+Worker\s*\(\s*URL\.createObjectURL",
#     "EVAL_WORKER_DATA": r"new\s+Worker\s*\(\s*['\"`]data:",
#     "EVAL_WORKER_CONCAT": r"new\s+Worker\s*\(\s*.*(?:\+|\$\{)",
#     "EVAL_SHAREDWORKER": r"new\s+SharedWorker\s*\(",
#     "EVAL_SERVICEWORKER": r"(?:navigator\.serviceWorker|registration)\.register\s*\(",
    
#     # WebAssembly
#     "EVAL_WASM_COMPILE": r"WebAssembly\.compile\s*\(",
#     "EVAL_WASM_INSTANTIATE": r"WebAssembly\.instantiate(?:Streaming)?\s*\(",
    
#     # Script Injection
#     "EVAL_SCRIPT_CREATE": r"createElement\s*\(\s*['\"]script['\"]",
#     "EVAL_SCRIPT_TEXT": r"script\.(?:text|textContent|innerHTML)\s*=",
#     "EVAL_SCRIPT_SRC": r"script\.src\s*=\s*(?!['\"]https?://)",
    
#     # Blob/Data URLs
#     "EVAL_BLOB_SCRIPT": r"new\s+Blob\s*\(\s*\[[^\]]*['\"`]<script",
#     "EVAL_BLOB_JS": r"new\s+Blob\s*\([^)]*type[^)]*(?:javascript|text/html)",
#     "EVAL_DATA_URL_JS": r"['\"`]data:(?:text/javascript|application/javascript|text/html)",
    
#     # execScript
#     "EVAL_EXECSCRIPT": r"execScript\s*\(",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                         INJECTION PATTERNS
#     # ══════════════════════════════════════════════════════════════════════════
    
#     # SQL Injection
#     "SQLI_CONCAT_SELECT": r"(?:SELECT|select)\s+.*(?:FROM|from).*(?:\+|\$\{|concat\()",
#     "SQLI_CONCAT_INSERT": r"(?:INSERT|insert)\s+(?:INTO|into).*(?:\+|\$\{|concat\()",
#     "SQLI_CONCAT_UPDATE": r"(?:UPDATE|update)\s+\w+\s+(?:SET|set).*(?:\+|\$\{|concat\()",
#     "SQLI_CONCAT_DELETE": r"(?:DELETE|delete)\s+(?:FROM|from).*(?:\+|\$\{|concat\()",
#     "SQLI_CONCAT_WHERE": r"(?:WHERE|where)\s+.*(?:\+|\$\{|'\s*\+)",
#     "SQLI_TEMPLATE": r"`(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP).*\$\{",
#     "SQLI_RAW_QUERY": r"\.(?:raw|rawQuery|execute|query)\s*\(\s*(?:`|['\"]).*(?:\$\{|\+)",
#     "SQLI_KNEX_RAW": r"knex\.raw\s*\(",
#     "SQLI_SEQUELIZE": r"Sequelize\.literal\s*\(",
#     "SQLI_PRISMA": r"\$(?:queryRaw|executeRaw)\s*`",
    
#     # NoSQL Injection
#     "NOSQLI_OPERATOR": r"['\"]?\$(?:where|regex|ne|gt|lt|gte|lte|in|nin|exists|type|mod|text|expr|jsonSchema|all|elemMatch|size)\s*['\"]?\s*:",
#     "NOSQLI_FUNCTION": r"\$(?:function|where|accumulator|mapReduce)\s*:",
#     "NOSQLI_USER_INPUT": r"\.(?:find|findOne|findById|updateOne|updateMany|deleteOne|deleteMany|aggregate)\s*\([^)]*(?:req\.|params\.|query\.|body\.|JSON\.parse|\$\{)",
#     "NOSQLI_AGGREGATION": r"\.aggregate\s*\(\s*\[[^\]]*(?:\$\{|\+|req\.|params\.)",
    
#     # Command Injection
#     "CMDI_EXEC": r"(?:exec|execSync)\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "CMDI_SPAWN": r"(?:spawn|spawnSync)\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "CMDI_FORK": r"fork\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "CMDI_EXECFILE": r"execFile(?:Sync)?\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "CMDI_USER_INPUT": r"(?:exec|spawn|fork|execFile)\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
    
#     # Template Injection
#     "SSTI_EJS": r"(?:ejs\.render|res\.render)\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
#     "SSTI_PUG": r"(?:pug\.render|res\.render)\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
#     "SSTI_HANDLEBARS": r"(?:Handlebars\.compile|hbs\.compile)\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
#     "SSTI_NUNJUCKS": r"nunjucks\.renderString\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
#     "SSTI_LODASH": r"_\.template\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
    
#     # GraphQL Injection
#     "GRAPHQL_CONCAT": r"(?:query|mutation)\s*\{.*(?:\$\{|\+)",
#     "GRAPHQL_VARIABLE": r"variables\s*:\s*\{[^}]*(?:req\.|params\.|query\.|body\.)",
    
#     # LDAP Injection
#     "LDAPI_FILTER": r"\(\s*(?:&|\|)\s*\([^)]*(?:\+|\$\{)",
#     "LDAPI_DN": r"(?:CN|OU|DC|uid)=.*(?:\+|\$\{)",
    
#     # XPath Injection
#     "XPATH_CONCAT": r"\.(?:evaluate|selectNodes|selectSingleNode)\s*\([^)]*(?:\+|\$\{)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                         OPEN REDIRECT
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "REDIRECT_LOCATION": r"(?:window\.)?location\s*=\s*(?!['\"]https?://(?:localhost|127\.0\.0\.1))",
#     "REDIRECT_LOCATION_HREF": r"location\.href\s*=\s*(?!['\"]https?://(?:localhost|127\.0\.0\.1))",
#     "REDIRECT_LOCATION_REPLACE": r"location\.replace\s*\(\s*(?!['\"]https?://(?:localhost|127\.0\.0\.1))",
#     "REDIRECT_LOCATION_ASSIGN": r"location\.assign\s*\(\s*(?!['\"]https?://(?:localhost|127\.0\.0\.1))",
#     "REDIRECT_WINDOW_OPEN": r"window\.open\s*\(\s*(?!['\"]https?://(?:localhost|127\.0\.0\.1)|['\"]_)",
#     "REDIRECT_USER_INPUT": r"(?:location(?:\.href)?|window\.open)\s*[=\(]\s*(?:params\.|query\.|req\.|body\.|searchParams|URLSearchParams|location\.(search|hash))",
#     "REDIRECT_CONCAT": r"(?:location(?:\.href)?)\s*=\s*.*(?:\+|\$\{|`)",
#     "REDIRECT_HISTORY": r"(?:history|router)\.(?:push|pushState|replaceState|replace)\s*\([^)]*(?:params\.|query\.|req\.|body\.)",
#     "REDIRECT_NAVIGATE": r"(?:navigate|navigation|redirect)\s*\([^)]*(?:params\.|query\.|req\.|body\.)",
#     "REDIRECT_META": r"<meta[^>]*http-equiv\s*=\s*['\"]?refresh['\"]?[^>]*url=",
#     "REDIRECT_ANCHOR": r"<a[^>]*href\s*=\s*['\"]?(?:\$\{|<%=|{{)",
#     "REDIRECT_JS_PROTO": r"(?:location|href|action)\s*=\s*['\"]?javascript:",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                         PROTOTYPE POLLUTION
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "PROTO_DIRECT": r"(?:\[\s*['\"]__proto__['\"]\s*\]|\.__proto__)\s*=",
#     "PROTO_CONSTRUCTOR": r"\.constructor\.(?:prototype|__proto__)\s*=",
#     "PROTO_BRACKET": r"\[\s*['\"]constructor['\"]\s*\]\s*\[\s*['\"]prototype['\"]\s*\]",
#     "PROTO_DYNAMIC": r"\[\s*[a-zA-Z_$][\w$]*\s*\]\s*\[\s*[a-zA-Z_$][\w$]*\s*\]\s*=",
#     "PROTO_MERGE": r"(?:function|const|let|var)\s+\w*[Mm]erge\w*.*for\s*\(\s*(?:let|const|var)\s+\w+\s+in\s+",
#     "PROTO_OBJECT_ASSIGN": r"Object\.assign\s*\([^)]*(?:req\.|params\.|query\.|body\.|JSON\.parse)",
#     "PROTO_SPREAD": r"\{\s*\.\.\.\s*(?:req\.|params\.|query\.|body\.|JSON\.parse)",
#     "PROTO_JSON_ASSIGN": r"Object\.assign.*JSON\.parse",
#     "PROTO_LODASH_MERGE": r"(?:_|lodash)\.(?:merge|mergeWith|defaultsDeep)\s*\(",
#     "PROTO_JQUERY_EXTEND": r"(?:\$|jQuery)\.extend\s*\(\s*(?:true|!0)",
#     "PROTO_DEFINE_PROP": r"Object\.definePropert(?:y|ies)\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
#     "PROTO_SET_PROTO": r"Object\.setPrototypeOf\s*\(",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                     AUTHENTICATION & AUTHORIZATION
#     # ══════════════════════════════════════════════════════════════════════════
    
#     # Client-side Auth
#     "AUTH_CLIENT_ROLE": r"(?:localStorage|sessionStorage)\.getItem\s*\([^)]*(?:role|permission|isAdmin|isAuthenticated|access_level|privilege)",
#     "AUTH_CLIENT_CHECK": r"if\s*\(\s*(?:user|current|session|auth)\s*\.?\s*(?:role|isAdmin|permissions|isAuthenticated|type|level)\s*(?:===?|!==?|&&|\|\|)",
#     "AUTH_CLIENT_COOKIE": r"document\.cookie\.(?:match|includes|indexOf)\s*\([^)]*(?:auth|session|token|admin|role)",
#     "AUTH_CLIENT_HIDDEN": r"<input[^>]*type\s*=\s*['\"]hidden['\"][^>]*(?:role|permission|admin|isAdmin)",
#     "AUTH_CLIENT_NGIF": r"\*ngIf\s*=\s*['\"][^'\"]*(?:isAdmin|role|permission|authenticated)",
#     "AUTH_CLIENT_VSHOW": r"v-(?:if|show)\s*=\s*['\"][^'\"]*(?:isAdmin|role|permission|authenticated)",
    
#     # JWT Vulnerabilities
#     "AUTH_JWT_NO_VERIFY": r"(?:jwt|jose)\.decode\s*\((?!.*verify)",
#     "AUTH_JWT_CLIENT": r"atob\s*\([^)]*\.split\s*\(\s*['\"]\.['\"]\s*\)",
#     "AUTH_JWT_NONE_ALG": r"(?:algorithm|alg)\s*[=:]\s*['\"]none['\"]",
#     "AUTH_JWT_WEAK_SECRET": r"jwt\.sign\s*\([^)]*['\"](?:secret|password|key|1234|test|demo|admin)",
#     "AUTH_JWT_HARDCODED": r"(?:secretKey|jwtSecret|JWT_SECRET)\s*[=:]\s*['\"][a-zA-Z0-9_\-\.]{8,}['\"]",
    
#     # Session Vulnerabilities
#     "AUTH_SESSION_FIXATION": r"(?:sessionId|session_id|sessid)\s*=\s*(?:req\.|params\.|query\.|cookie\.)",
#     "AUTH_SESSION_PREDICTABLE": r"(?:sessionId|session_id)\s*=\s*(?:Date\.now|Math\.random)",
    
#     # Password Vulnerabilities
#     "AUTH_PASSWORD_PLAIN": r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{3,}['\"]",
#     "AUTH_PASSWORD_WEAK_HASH": r"(?:createHash|hash)\s*\(\s*['\"](?:md5|sha1)['\"]",
#     "AUTH_PASSWORD_COMPARE": r"(?:password|passwd|pwd)\s*(?:===?|!==?)\s*(?:req\.|params\.|body\.)",
#     "AUTH_PASSWORD_LOG": r"console\.(?:log|debug|info)\s*\([^)]*(?:password|passwd|pwd|credential)",
    
#     # Hardcoded Credentials
#     "AUTH_HARDCODED_USER": r"(?:username|user|login)\s*(?:===?|!==?)\s*['\"](?:admin|administrator|root|superuser|test)['\"]",
#     "AUTH_HARDCODED_PASS": r"(?:password|passwd|pwd|secret)\s*(?:===?|!==?)\s*['\"][^'\"]{3,}['\"]",
    
#     # Auth Bypass
#     "AUTH_BYPASS_FLAG": r"if\s*\(\s*(?:bypass|debug|dev|test|skip|disable)(?:Auth)?\s*(?:===?\s*true|\))",
#     "AUTH_BYPASS_LOCALHOST": r"if\s*\([^)]*(?:localhost|127\.0\.0\.1)[^)]*\)\s*(?:return|next)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                         SECRETS & CREDENTIALS
#     # ══════════════════════════════════════════════════════════════════════════
    
#     # API Keys
#     "SECRET_API_KEY": r"(?:api[_-]?key|apikey|api[_-]?token)\s*[=:]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]",
#     "SECRET_ACCESS_TOKEN": r"(?:access[_-]?token|bearer[_-]?token|auth[_-]?token)\s*[=:]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]",
#     "SECRET_BEARER": r"['\"]Bearer\s+[a-zA-Z0-9_\-\.]{20,}['\"]",
    
#     # Private Keys
#     "SECRET_PRIVATE_KEY_RSA": r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----",
#     "SECRET_PRIVATE_KEY_EC": r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
#     "SECRET_PRIVATE_KEY_OPENSSH": r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
#     "SECRET_PRIVATE_KEY_PGP": r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
#     "SECRET_PRIVATE_KEY_PKCS8": r"-----BEGIN\s+PRIVATE\s+KEY-----",
    
#     # JWT
#     "SECRET_JWT": r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-]{10,}",
    
#     # Cloud - AWS
#     "SECRET_AWS_ACCESS": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
#     "SECRET_AWS_SECRET": r"(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*['\"][a-zA-Z0-9/+=]{40}['\"]",
    
#     # Cloud - Google
#     "SECRET_GCP_KEY": r"AIza[0-9A-Za-z\-_]{35}",
#     "SECRET_GCP_SERVICE": r"['\"]type['\"]:\s*['\"]service_account['\"]",
    
#     # Payment - Stripe
#     "SECRET_STRIPE_LIVE": r"sk_live_[a-zA-Z0-9]{24,}",
#     "SECRET_STRIPE_TEST": r"sk_test_[a-zA-Z0-9]{24,}",
#     "SECRET_STRIPE_WEBHOOK": r"whsec_[a-zA-Z0-9]{32,}",
    
#     # Communication - Twilio
#     "SECRET_TWILIO_SID": r"AC[a-z0-9]{32}",
#     "SECRET_TWILIO_TOKEN": r"SK[a-z0-9]{32}",
    
#     # Communication - SendGrid
#     "SECRET_SENDGRID": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    
#     # Version Control - GitHub
#     "SECRET_GITHUB_PAT": r"ghp_[a-zA-Z0-9]{36}",
#     "SECRET_GITHUB_OAUTH": r"gho_[a-zA-Z0-9]{36}",
    
#     # Communication - Slack
#     "SECRET_SLACK_TOKEN": r"xox[baprs]-(?:\d{10,13}-){1,3}[a-zA-Z0-9]{10,}",
#     "SECRET_SLACK_WEBHOOK": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    
#     # Database
#     "SECRET_DATABASE_URL": r"(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|mssql)://[^\s'\"\n]+",
    
#     # Firebase
#     "SECRET_FIREBASE": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    
#     # Discord
#     "SECRET_DISCORD_TOKEN": r"(?:N|M|O)[a-zA-Z0-9]{23,}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27}",
#     "SECRET_DISCORD_WEBHOOK": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_\-]+",
    
#     # Telegram
#     "SECRET_TELEGRAM": r"\d{9,10}:[a-zA-Z0-9_\-]{35}",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                         POSTMESSAGE VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "POSTMSG_WILDCARD": r"\.postMessage\s*\([^)]*,\s*['\"]?\*['\"]?\s*\)",
#     "POSTMSG_NO_ORIGIN": r"addEventListener\s*\(\s*['\"]message['\"](?![\s\S]{0,500}(?:event|e|msg)\.origin)",
#     "POSTMSG_WEAK_INDEXOF": r"(?:event|e|msg)\.origin\.indexOf\s*\(",
#     "POSTMSG_WEAK_INCLUDES": r"(?:event|e|msg)\.origin\.includes\s*\(",
#     "POSTMSG_WEAK_STARTSWITH": r"(?:event|e|msg)\.origin\.startsWith\s*\(",
#     "POSTMSG_WEAK_ENDSWITH": r"(?:event|e|msg)\.origin\.endsWith\s*\(",
#     "POSTMSG_WEAK_MATCH": r"(?:event|e|msg)\.origin\.match\s*\(",
#     "POSTMSG_NULL_ORIGIN": r"(?:event|e|msg)\.origin\s*===?\s*['\"]null['\"]",
#     "POSTMSG_DATA_EVAL": r"addEventListener\s*\(\s*['\"]message['\"][\s\S]*\beval\s*\(\s*(?:event|e|msg)\.data",
#     "POSTMSG_DATA_FUNCTION": r"addEventListener\s*\(\s*['\"]message['\"][\s\S]*Function\s*\(\s*(?:event|e|msg)\.data",
#     "POSTMSG_DATA_INNERHTML": r"addEventListener\s*\(\s*['\"]message['\"][\s\S]*\.innerHTML\s*=\s*(?:event|e|msg)\.data",
#     "POSTMSG_DATA_LOCATION": r"addEventListener\s*\(\s*['\"]message['\"][\s\S]*location(?:\.href)?\s*=\s*(?:event|e|msg)\.data",
#     "POSTMSG_SENSITIVE": r"\.postMessage\s*\([^)]*(?:password|token|secret|auth|session|credential)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                         WEBSOCKET VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "WS_INSECURE": r"new\s+WebSocket\s*\(\s*['\"]ws://(?!localhost|127\.0\.0\.1)",
#     "WS_DYNAMIC_URL": r"new\s+WebSocket\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "WS_USER_URL": r"new\s+WebSocket\s*\([^)]*(?:location\.|params\.|query\.|req\.|body\.)",
#     "WS_NO_AUTH": r"new\s+WebSocket\s*\([^)]*\)(?![\s\S]{0,300}(?:token|auth|Authorization|cookie))",
#     "WS_MSG_EVAL": r"\.onmessage[\s\S]*\beval\s*\(",
#     "WS_MSG_FUNCTION": r"\.onmessage[\s\S]*Function\s*\(",
#     "WS_MSG_INNERHTML": r"\.onmessage[\s\S]*\.innerHTML\s*=",
#     "WS_MSG_LOCATION": r"\.onmessage[\s\S]*location(?:\.href)?\s*=",
#     "WS_SENSITIVE": r"\.send\s*\([^)]*(?:password|token|secret|auth|session|credential)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                            CSRF VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "CSRF_CREDENTIALS": r"credentials\s*:\s*['\"]include['\"]",
#     "CSRF_WITHCREDS": r"withCredentials\s*[=:]\s*true",
#     "CSRF_NO_TOKEN_FETCH": r"fetch\s*\([^)]*method\s*:\s*['\"](?:POST|PUT|DELETE|PATCH)['\"](?![\s\S]{0,200}(?:csrf|xsrf|token|X-CSRF))",
#     "CSRF_NO_TOKEN_FORM": r"<form[^>]*method\s*=\s*['\"]post['\"](?![\s\S]{0,200}(?:csrf|xsrf|token|authenticity_token))",
#     "CSRF_STATE_CHANGE_GET": r"fetch\s*\([^)]*(?:delete|remove|update|transfer)(?![\s\S]{0,100}method\s*:\s*['\"](?:POST|PUT|DELETE))",
#     "CSRF_SAMESITE_NONE": r"(?:SameSite|sameSite)\s*[=:]\s*['\"]?None['\"]?",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                            SSRF VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "SSRF_FETCH_USER": r"fetch\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "SSRF_FETCH_PARAMS": r"fetch\s*\([^)]*(?:params\.|query\.|req\.|body\.|location\.|URL\s*\()",
#     "SSRF_AXIOS_USER": r"axios\.(?:get|post|put|delete|patch)\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "SSRF_HTTP_GET": r"(?:http|https)\.(?:get|request)\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "SSRF_IMAGE_SRC": r"(?:new\s+Image|<img)[^>]*src\s*=\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "SSRF_INTERNAL_IP": r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|0\.0\.0\.0|localhost|::1)",
#     "SSRF_METADATA": r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                            IDOR VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "IDOR_API_ID": r"(?:fetch|axios\.?\w*)\s*\(\s*['\"`](?:https?://)?[^'\"`]*/(?:api/)?(?:user|account|profile|order|document|file|message)s?/\$\{",
#     "IDOR_NUMERIC_ID": r"(?:fetch|axios\.?\w*)\s*\(\s*['\"`](?:https?://)?[^'\"`]*/(?:api/)?(?:user|account|profile|order|document)s?/\d+['\"`]",
#     "IDOR_DELETE": r"method\s*:\s*['\"]DELETE['\"][\s\S]*(?:/\$\{|/\d+)",
#     "IDOR_PUT": r"method\s*:\s*['\"](?:PUT|PATCH)['\"][\s\S]*(?:/\$\{|/\d+)",
#     "IDOR_SEQUENTIAL": r"(?:/api/\w+/|id\s*[=:]\s*)\d+(?:\s*\+\s*1|\+\+)",
#     "IDOR_DIRECT_REF": r"\.(?:findById|findOne|findByPk|get)\s*\(\s*(?:req\.|params\.|query\.|body\.)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        PATH TRAVERSAL VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "PATH_DOTDOT": r"(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)",
#     "PATH_FILENAME": r"(?:filename|filepath|file|path|dir)\s*[=:+]\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "PATH_READFILE": r"(?:readFile|readFileSync|createReadStream)\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "PATH_WRITEFILE": r"(?:writeFile|writeFileSync|createWriteStream)\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "PATH_REQUIRE": r"require\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+|\.\./))",
#     "PATH_SENDFILE": r"(?:sendFile|sendfile|download)\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        FILE UPLOAD VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "UPLOAD_NO_VALIDATION": r"new\s+FileReader\s*\(\s*\)(?![\s\S]{0,200}(?:\.type|\.name|\.size|accept|validate))",
#     "UPLOAD_DANGEROUS_EXT": r"\.(?:name|filename)\.(?:match|test|endsWith|includes)\s*\([^)]*(?:\.html|\.svg|\.xml|\.js|\.php|\.jsp|\.exe)",
#     "UPLOAD_EXECUTE": r"FileReader[\s\S]*(?:result|target\.result)[\s\S]*(?:eval|Function|innerHTML)",
#     "UPLOAD_PATH_CONTROL": r"(?:upload|save|store)[\s\S]*(?:path|destination|filename)\s*[=:]\s*(?:req\.|params\.|query\.|body\.)",
#     "UPLOAD_NO_MIME": r"<input[^>]*type\s*=\s*['\"]file['\"](?![^>]*accept)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        STORAGE VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "STORAGE_SENSITIVE": r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"][^'\"]*(?:password|token|secret|key|credit|ssn|api|jwt|auth|session|credential)[^'\"]*['\"]",
#     "STORAGE_EVAL": r"(?:localStorage|sessionStorage)\.getItem[\s\S]*\beval\s*\(",
#     "STORAGE_FUNCTION": r"(?:localStorage|sessionStorage)\.getItem[\s\S]*Function\s*\(",
#     "STORAGE_XSS": r"(?:localStorage|sessionStorage)\.getItem[\s\S]*(?:\.innerHTML|document\.write)",
#     "STORAGE_LOCATION": r"(?:localStorage|sessionStorage)\.getItem[\s\S]*location(?:\.href)?\s*=",
    
#     # Cookie Vulnerabilities
#     "COOKIE_NO_SECURE": r"document\.cookie\s*=\s*['\"][^;]*(?![^;]*[Ss]ecure)",
#     "COOKIE_SENSITIVE": r"document\.cookie\s*=\s*['\"][^'\"]*(?:auth|session|token|jwt|password)[^'\"]*=",
#     "COOKIE_USER_CONTROLLED": r"document\.cookie\s*=\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        REGEX VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "REDOS_NESTED": r"/[^/]*\([^)]*[\*\+][^)]*\)[\*\+]",
#     "REDOS_ALTERNATION": r"/[^/]*\([^)]*\|[^)]*\)[\*\+]",
#     "REDOS_USER_INPUT": r"new\s+RegExp\s*\(\s*(?:[a-zA-Z_$][\w$]*|['\"`][^'\"`]*(?:\$\{|['\"`]\s*\+))",
#     "REGEX_INJECTION": r"new\s+RegExp\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        DESERIALIZATION VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "DESER_JSON_STORAGE": r"JSON\.parse\s*\(\s*(?:localStorage|sessionStorage)\.getItem",
#     "DESER_JSON_COOKIE": r"JSON\.parse\s*\([^)]*(?:document\.)?cookie",
#     "DESER_JSON_URL": r"JSON\.parse\s*\([^)]*(?:location\.|URLSearchParams|params\.|query\.)",
#     "DESER_JSON_POSTMSG": r"JSON\.parse\s*\([^)]*(?:event|e|msg)\.data",
#     "DESER_JSON_WS": r"(?:onmessage|addEventListener[\s\S]*message)[\s\S]*JSON\.parse",
#     "DESER_YAML": r"(?:yaml|js-yaml)\.load\s*\(",
#     "DESER_XML": r"(?:parseFromString|DOMParser|xml2js)[\s\S]*(?:<!ENTITY|SYSTEM)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        RACE CONDITION VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "RACE_CHECK_USE": r"if\s*\(\s*(?:balance|credit|amount|quantity|stock)\s*[><=!]+[^)]*\)[\s\S]*(?:update|decrement|subtract|transfer)(?![\s\S]*(?:lock|mutex|transaction|atomic))",
#     "RACE_DOUBLE_SUBMIT": r"(?:onclick|onsubmit)[\s\S]*(?:fetch|axios)(?![\s\S]*(?:disabled|submitted|processing))",
#     "RACE_TOCTOU": r"(?:exists|access|stat)(?:Sync)?\s*\([^)]*\)[\s\S]*(?:read|write|delete|unlink)(?:Sync)?\s*\(",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        CRYPTOGRAPHY VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "CRYPTO_WEAK_MD5": r"(?:createHash\s*\(\s*)?['\"]md5['\"]",
#     "CRYPTO_WEAK_SHA1": r"(?:createHash\s*\(\s*)?['\"]sha1['\"]",
#     "CRYPTO_WEAK_RANDOM": r"Math\.random\s*\(\s*\)",
#     "CRYPTO_RANDOM_TOKEN": r"(?:token|id|nonce|session|key|secret)\s*[=:][\s\S]*Math\.random",
#     "CRYPTO_NO_IV": r"crypto\.createCipher(?!iv)",
#     "CRYPTO_ECB": r"(?:createCipher|AES)[\s\S]*ecb",
#     "CRYPTO_HARDCODED_KEY": r"crypto\.create(?:Cipher|Hmac)\s*\([^)]*['\"][a-zA-Z0-9_\-]{8,}['\"]",
#     "CRYPTO_PBKDF2_LOW": r"pbkdf2(?:Sync)?\s*\([^)]*,\s*(?:[1-9]|[1-9][0-9]|[1-9][0-9]{2}|[1-9][0-9]{3})\s*[,\)]",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        CLICKJACKING VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "CLICKJACK_OPACITY": r"(?:iframe|frame)[^>]*style[^>]*opacity\s*[=:]\s*['\"]?(?:0(?:\.\d+)?|0?\.0*[1-9])",
#     "CLICKJACK_POSITION": r"(?:iframe|frame)[^>]*style[^>]*position\s*[=:]\s*['\"]?(?:absolute|fixed)",
#     "CLICKJACK_ZINDEX": r"(?:iframe|frame)[^>]*style[^>]*z-index\s*[=:]\s*['\"]?(?:999|9999)",
#     "CLICKJACK_INVISIBLE": r"(?:iframe|frame)[^>]*style[^>]*(?:visibility\s*:\s*hidden|display\s*:\s*none|width\s*:\s*0|height\s*:\s*0)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        DEBUG & INFO LEAKAGE
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "DEBUG_CONSOLE_SENSITIVE": r"console\.(?:log|debug|info|warn|error)\s*\([^)]*(?:password|secret|token|key|api|credit|ssn|auth|credential|private|session|jwt)",
#     "DEBUG_ALERT_SENSITIVE": r"alert\s*\([^)]*(?:password|secret|token|auth|credential)",
#     "DEBUG_ERROR_STACK": r"(?:console|alert|innerHTML)\s*[=\(][^;]*\.stack",
#     "DEBUG_ERROR_MSG": r"catch\s*\(\s*\w+\s*\)[\s\S]*(?:console|alert|innerHTML|res\.send)[\s\S]*(?:\.message|\.stack|error)",
#     "DEBUG_SOURCEMAP": r"//[#@]\s*sourceMappingURL=",
#     "DEBUG_FLAG": r"(?:DEBUG|debug|VERBOSE|verbose|DEV|dev)\s*[=:]\s*(?:true|1)",
#     "DEBUG_ENV_EXPOSE": r"console\.(?:log|debug|info)\s*\([^)]*(?:process\.env|ENV|environment)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                            CORS VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "CORS_WILDCARD": r"Access-Control-Allow-Origin\s*[=:]\s*['\"]?\*['\"]?",
#     "CORS_NULL": r"Access-Control-Allow-Origin\s*[=:]\s*['\"]?null['\"]?",
#     "CORS_CREDS_WILDCARD": r"Access-Control-Allow-Credentials\s*[=:]\s*['\"]?true[\s\S]*Access-Control-Allow-Origin\s*[=:]\s*['\"]?\*",
#     "CORS_REFLECT": r"Access-Control-Allow-Origin[\s\S]*(?:req\.headers?\.origin|request\.headers?\.origin)",
#     "CORS_WEAK_CHECK": r"(?:origin|Origin)\.(?:indexOf|includes|match|startsWith|endsWith)\s*\(",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        BUSINESS LOGIC VULNERABILITIES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "BIZLOGIC_PRICE": r"(?:price|amount|total|cost|fee)\s*[=:]\s*(?:req\.|params\.|query\.|body\.|\$\{|\+)",
#     "BIZLOGIC_QUANTITY": r"(?:quantity|count|number|qty)\s*[=:]\s*(?:req\.|params\.|query\.|body\.|\-)",
#     "BIZLOGIC_DISCOUNT": r"(?:discount|coupon|promo|voucher)\s*[=:]\s*(?:req\.|params\.|query\.|body\.)",
#     "BIZLOGIC_ROLE": r"(?:role|permission|privilege|access_level|isAdmin)\s*[=:]\s*(?:req\.|params\.|query\.|body\.)",
#     "BIZLOGIC_NEGATIVE": r"(?:amount|quantity|price|balance)\s*[=:][\s\S]*-\s*\d+",
#     "BIZLOGIC_TIMESTAMP": r"(?:timestamp|created_at|updated_at|expires)\s*[=:]\s*(?:req\.|params\.|query\.|body\.)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                            CSP BYPASS
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "CSP_UNSAFE_INLINE": r"Content-Security-Policy[\s\S]*script-src[\s\S]*unsafe-inline",
#     "CSP_UNSAFE_EVAL": r"Content-Security-Policy[\s\S]*script-src[\s\S]*unsafe-eval",
#     "CSP_WILDCARD": r"Content-Security-Policy[\s\S]*(?:default-src|script-src)[\s\S]*\*",
#     "CSP_DATA": r"Content-Security-Policy[\s\S]*script-src[\s\S]*data:",
#     "CSP_BLOB": r"Content-Security-Policy[\s\S]*script-src[\s\S]*blob:",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        SHADOW/HIDDEN APIS
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "SHADOW_API": r"['\"`](?:https?:)?//[\w\.\-]+/(?:api|admin|internal|debug|test|dev|staging|v\d+)/[\w\-/]+['\"`]",
#     "SHADOW_ADMIN": r"['\"`]/(?:admin|administrator|wp-admin|phpmyadmin|cpanel|backend|dashboard|manage)/",
#     "SHADOW_INTERNAL_IP": r"['\"`](?:https?:)?//(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost)",
#     "SHADOW_TODO_SECURITY": r"(?://|/\*|#)\s*(?:TODO|FIXME|HACK|XXX)[^*\n]*(?:security|vuln|unsafe|insecure|bypass|hack|temp|remove|fix)",
#     "SHADOW_BACKUP": r"['\"`][^'\"`]*\.(?:bak|backup|old|orig|save|copy|tmp|swp)['\"`]",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        MEMORY/RESOURCE ISSUES
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "MEMORY_SETINTERVAL": r"setInterval\s*\([^)]*\)(?![\s\S]{0,300}clearInterval)",
#     "MEMORY_EVENT_NO_REMOVE": r"addEventListener\s*\([^)]*\)(?![\s\S]{0,300}removeEventListener)",
#     "MEMORY_OBSERVER": r"new\s+(?:MutationObserver|IntersectionObserver|ResizeObserver)\s*\((?![\s\S]{0,300}(?:disconnect|unobserve))",
#     "MEMORY_WS_NO_CLOSE": r"new\s+WebSocket\s*\([^)]*\)(?![\s\S]{0,300}(?:\.close\s*\(|\.onclose))",
#     "MEMORY_INFINITE_LOOP": r"while\s*\(\s*(?:true|1|![0nf])\s*\)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        ADVANCED ATTACK PATTERNS
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "ADVANCED_PROTO_CHAIN": r"(?:__proto__|constructor\.prototype|Object\.prototype)[\s\S]*(?:eval|Function|innerHTML)",
#     "ADVANCED_GADGET": r"(?:Object\.prototype|Array\.prototype|String\.prototype)\.\w+\s*=",
#     "ADVANCED_GETTER_SETTER": r"Object\.definePropert(?:y|ies)\s*\([^)]*(?:get|set)\s*:[\s\S]*(?:eval|Function|innerHTML)",
#     "ADVANCED_PROXY": r"new\s+Proxy\s*\([^)]*(?:get|set|apply)\s*:[\s\S]*(?:eval|Function|innerHTML)",
#     "ADVANCED_WASM": r"WebAssembly\.(?:compile|instantiate)[\s\S]*(?:req\.|params\.|query\.|body\.)",
    
#     # ══════════════════════════════════════════════════════════════════════════
#     #                        ENCODING BYPASS PATTERNS
#     # ══════════════════════════════════════════════════════════════════════════
    
#     "BYPASS_CASE": r"<(?:ScRiPt|SCRIPT|Script|sCrIpT)",
#     "BYPASS_NULL": r"(?:%00|\\x00|\\0|\\u0000)",
#     "BYPASS_DOUBLE_ENCODE": r"%25(?:3C|3E|22|27|28|29)",
#     "BYPASS_HTML_ENTITY": r"&(?:#x?)?(?:60|62|34|39|lt|gt|quot|apos);?",
#     "BYPASS_UNICODE": r"\\u00[0-9a-fA-F]{2}",
#     "BYPASS_PROTOCOL": r"['\"]//[a-zA-Z0-9\-\.]+",
#     "BYPASS_DATA_BASE64": r"data:[^;]*;base64,",
# }

# # Compile patterns
# COMPILED_SCANNERS = {}
# for k, v in RAW_PATTERNS.items():
#     try:
#         COMPILED_SCANNERS[k] = re.compile(v, re.IGNORECASE | re.DOTALL | re.MULTILINE)
#     except Exception as e:
#         print(f"Warning: Failed to compile {k}: {e}")

# # ═══════════════════════════════════════════════════════════════════════════════
# # SECURITY DATA
# # ═══════════════════════════════════════════════════════════════════════════════

# WORDLIST_PATH = "/app/services/engine/wordlist.txt"
# WORDLIST = set()
# if os.path.exists(WORDLIST_PATH):
#     try:
#         with open(WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
#             WORDLIST = {line.strip().lower() for line in f if len(line.strip()) > 3}
#     except Exception:
#         pass

# SECURITY_KEYWORDS = {
#     "admin", "password", "credential", "auth", "token", "session", "jwt",
#     "oauth", "bearer", "apikey", "api_key", "secret", "private", "key",
#     "ssn", "credit", "card", "cvv", "bank", "account", "routing",
#     "encrypt", "decrypt", "hash", "salt", "cipher", "certificate",
#     "permission", "privilege", "role", "access", "authorize", "authenticated",
#     "internal", "debug", "test", "dev", "staging", "prod", "master", "root",
# }

# DANGEROUS_SINKS = {
#     "eval", "Function", "setTimeout", "setInterval", "innerHTML", "outerHTML",
#     "insertAdjacentHTML", "document.write", "$.html", "$.append", "$.prepend",
#     "dangerouslySetInnerHTML", "v-html", "bypassSecurityTrustHtml", "$sce.trustAsHtml",
#     "location", "location.href", "window.open", "navigate", "exec", "spawn",
#     "query", "rawQuery", "postMessage", "fetch", "XMLHttpRequest",
# }

# USER_INPUT_SOURCES = [
#     "location.search", "location.hash", "location.href", "location.pathname",
#     "document.location", "document.URL", "document.referrer", "window.name",
#     "URLSearchParams", "params", "query", "innerHTML", "value", "getAttribute",
#     "localStorage", "sessionStorage", "cookie", "fetch", "XMLHttpRequest",
#     "postMessage", "event.data", "WebSocket", "FileReader", "req.body",
#     "req.params", "req.query", "props", "state", "useParams", "match.params",
# ]

# SANITIZATION_FUNCTIONS = {
#     "sanitize", "sanitizeHTML", "escape", "escapeHTML", "encode", "encodeURI",
#     "encodeURIComponent", "DOMPurify", "xss", "validator", "textContent",
#     "createTextNode", "Handlebars.escapeExpression", "_.escape",
# }

# NOISE_FILTERS = [
#     "www.w3.org", "xmlns", "reactjs.org", "mozilla.org", "facebook.com",
#     "cdn.jsdelivr", "unpkg.com", "cdnjs.cloudflare", "googleapis.com",
#     ".png", ".svg", ".jpg", ".gif", ".ico", ".woff", ".woff2", ".ttf",
#     "node_modules", "webpack", "babel", "sourceMappingURL", "sourceURL",
#     "license", "@license", "Copyright", "MIT License", "BSD License",
# ]

# # ═══════════════════════════════════════════════════════════════════════════════
# # SEVERITY CLASSIFICATION
# # ═══════════════════════════════════════════════════════════════════════════════

# def classify_severity(category, evidence, context):
#     critical_patterns = [
#         "EVAL_", "XSS_INNERHTML", "XSS_DOCUMENT_WRITE", "XSS_REACT_DANGEROUSLY",
#         "SECRET_PRIVATE_KEY", "SECRET_AWS", "SECRET_STRIPE_LIVE", "SECRET_DATABASE",
#         "CMDI_", "SQLI_", "NOSQLI_", "SSTI_", "DESER_", "AUTH_JWT_NONE",
#         "POSTMSG_DATA_EVAL", "WS_MSG_EVAL", "PROTO_DIRECT", "ADVANCED_",
#     ]
    
#     high_patterns = [
#         "XSS_", "SECRET_", "REDIRECT_USER_INPUT", "REDIRECT_LOCATION",
#         "IDOR_", "SSRF_", "PATH_", "UPLOAD_", "CSRF_", "AUTH_",
#         "POSTMSG_", "WS_", "CORS_WILDCARD", "CORS_CREDS", "BIZLOGIC_ROLE",
#     ]
    
#     medium_patterns = [
#         "STORAGE_", "COOKIE_", "CLICKJACK_", "MEMORY_", "DEBUG_",
#         "CRYPTO_WEAK", "CORS_", "CSP_", "REDOS_", "REGEX_", "SHADOW_",
#     ]
    
#     base_severity = "LOW"
    
#     for pattern in critical_patterns:
#         if pattern in category:
#             base_severity = "CRITICAL"
#             break
    
#     if base_severity == "LOW":
#         for pattern in high_patterns:
#             if pattern in category:
#                 base_severity = "HIGH"
#                 break
    
#     if base_severity == "LOW":
#         for pattern in medium_patterns:
#             if pattern in category:
#                 base_severity = "MEDIUM"
#                 break
    
#     if context:
#         if context.get('has_user_input') and not context.get('has_sanitization'):
#             if base_severity == "MEDIUM":
#                 base_severity = "HIGH"
#             elif base_severity == "LOW":
#                 base_severity = "MEDIUM"
        
#         auth_keywords = ['auth', 'login', 'session', 'admin', 'password', 'token', 'jwt']
#         if any(kw in evidence.lower() for kw in auth_keywords):
#             if base_severity == "LOW":
#                 base_severity = "MEDIUM"
#             elif base_severity == "MEDIUM":
#                 base_severity = "HIGH"
        
#         if context.get('has_validation') and context.get('has_sanitization'):
#             if base_severity == "HIGH":
#                 base_severity = "MEDIUM"
#             elif base_severity == "CRITICAL":
#                 base_severity = "HIGH"
    
#     return base_severity

# # ═══════════════════════════════════════════════════════════════════════════════
# # CONTEXT ANALYSIS
# # ═══════════════════════════════════════════════════════════════════════════════

# def analyze_context_flow(lines, current_idx, window=MAX_CONTEXT_WINDOW):
#     start = max(0, current_idx - window)
#     end = min(len(lines), current_idx + window + 1)
#     context_lines = lines[start:end]
    
#     context_info = {
#         'has_user_input': False,
#         'has_sanitization': False,
#         'has_validation': False,
#         'tainted_vars': set(),
#         'sanitized_vars': set(),
#         'in_try_catch': False,
#         'in_auth_function': False,
#         'async_context': False,
#         'framework': None,
#     }
    
#     for line in context_lines:
#         line_lower = line.lower()
        
#         for source in USER_INPUT_SOURCES:
#             if source.lower() in line_lower:
#                 context_info['has_user_input'] = True
#                 var_match = re.search(r'(?:var|let|const)\s+(\w+)\s*=', line)
#                 if var_match:
#                     context_info['tainted_vars'].add(var_match.group(1))
        
#         for sanitizer in SANITIZATION_FUNCTIONS:
#             if sanitizer.lower() in line_lower:
#                 context_info['has_sanitization'] = True
        
#         if re.search(r'if\s*\(.*(?:typeof|instanceof|Array\.isArray|\.test\s*\(|\.match\s*\(|validator\.)', line, re.I):
#             context_info['has_validation'] = True
        
#         if re.search(r'try\s*\{|catch\s*\(', line):
#             context_info['in_try_catch'] = True
        
#         if re.search(r'function\s+\w*(?:auth|login|verify|check|validate)\w*', line, re.I):
#             context_info['in_auth_function'] = True
        
#         if re.search(r'async\s+function|await\s+', line):
#             context_info['async_context'] = True
        
#         if context_info['framework'] is None:
#             if re.search(r'React|useState|useEffect', line):
#                 context_info['framework'] = 'React'
#             elif re.search(r'Vue|v-model|v-bind', line):
#                 context_info['framework'] = 'Vue'
#             elif re.search(r'@Component|@Injectable|angular', line, re.I):
#                 context_info['framework'] = 'Angular'
    
#     return context_info

# # ═══════════════════════════════════════════════════════════════════════════════
# # TAINT TRACKING
# # ═══════════════════════════════════════════════════════════════════════════════

# def track_taint_flow(lines, max_lines=TAINT_ANALYSIS_DEPTH):
#     tainted = {}
#     flows = []
#     function_params = {}
#     current_function = None
    
#     for i, line in enumerate(lines[:max_lines], 1):
#         stripped = line.strip()
#         if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
#             continue
        
#         func_match = re.search(r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\()\s*\(([^)]*)\)', line)
#         if func_match:
#             current_function = func_match.group(1) or func_match.group(2)
#             params = func_match.group(3) if func_match.group(3) else ''
#             params_list = [p.strip().split('=')[0].strip() for p in params.split(',') if p.strip()]
#             function_params[current_function] = {'params': params_list, 'line': i}
            
#             for param in params_list:
#                 if any(src in param.lower() for src in ['req', 'request', 'query', 'params', 'body', 'data', 'input']):
#                     tainted[f"{current_function}::{param}"] = {
#                         'line': i, 'source': f'parameter: {param}', 'sanitized': False
#                     }
        
#         assignment = re.search(r'(?:var|let|const)\s+(\w+)\s*=\s*(.+?)(?:;|$)', line)
#         if assignment:
#             var_name, value = assignment.groups()
            
#             is_tainted = any(src.lower() in value.lower() for src in USER_INPUT_SOURCES)
            
#             if not is_tainted:
#                 for tainted_key in tainted:
#                     tainted_var = tainted_key.split('::')[-1]
#                     if re.search(r'\b' + re.escape(tainted_var) + r'\b', value):
#                         is_tainted = True
#                         break
            
#             is_sanitized = any(san.lower() in value.lower() for san in SANITIZATION_FUNCTIONS)
            
#             if is_tainted:
#                 scope = current_function or 'global'
#                 tainted[f"{scope}::{var_name}"] = {
#                     'line': i, 'source': value[:150], 'sanitized': is_sanitized
#                 }
        
#         for sink in DANGEROUS_SINKS:
#             if sink.lower() in line.lower():
#                 for tainted_key in tainted:
#                     tainted_info = tainted[tainted_key]
#                     tainted_var = tainted_key.split('::')[-1]
                    
#                     if tainted_info.get('sanitized', False):
#                         continue
                    
#                     if re.search(r'\b' + re.escape(tainted_var.split('.')[0]) + r'\b', line):
#                         flows.append({
#                             'var': tainted_var,
#                             'source_line': tainted_info['line'],
#                             'sink_line': i,
#                             'sink_function': sink,
#                             'evidence': line.strip()[:300],
#                             'confidence': 'HIGH' if tainted_var in line else 'MEDIUM',
#                             'function_context': current_function or 'global',
#                             'taint_source': tainted_info.get('source', 'unknown'),
#                         })
    
#     return flows

# # ═══════════════════════════════════════════════════════════════════════════════
# # CHAIN DETECTION
# # ═══════════════════════════════════════════════════════════════════════════════

# def detect_vulnerability_chains(previous_lines, current_line, line_num):
#     chains = []
#     recent_context = ' '.join(previous_lines[-10:]) + ' ' + current_line
    
#     chain_patterns = [
#         (r'(?:location|params|cookie|query)[^\n]*=\s*(\w+)[^\n]*\1[^\n]*innerHTML', 
#          'XSS_CHAIN_DOM', 'CRITICAL', 'User input flows to innerHTML'),
#         (r'(?:fetch|axios)[^\n]*\.then[^\n]*innerHTML',
#          'XSS_CHAIN_FETCH', 'CRITICAL', 'Fetch response flows to innerHTML'),
#         (r'(?:localStorage|sessionStorage)\.getItem[^\n]*innerHTML',
#          'XSS_CHAIN_STORAGE', 'HIGH', 'Storage data flows to innerHTML'),
#         (r'(?:postMessage|event\.data)[^\n]*innerHTML',
#          'XSS_CHAIN_POSTMSG', 'CRITICAL', 'PostMessage data flows to innerHTML'),
#         (r'JSON\.parse[^\n]*Object\.assign', 
#          'PROTO_CHAIN_JSON', 'CRITICAL', 'JSON.parse to Object.assign - prototype pollution'),
#         (r'localStorage\.getItem[^\n]*role[^\n]*if[^\n]*admin',
#          'AUTH_CHAIN_LOCALSTORAGE', 'CRITICAL', 'Client-side role check from localStorage'),
#         (r'atob[^\n]*split[^\n]*JSON\.parse[^\n]*(?:role|admin)',
#          'AUTH_CHAIN_JWT_CLIENT', 'CRITICAL', 'Client-side JWT parsing for auth'),
#         (r'(?:params|query)[^\n]*fetch',
#          'SSRF_CHAIN', 'HIGH', 'User input flows to fetch'),
#         (r'(?:params|query)[^\n]*location',
#          'REDIRECT_CHAIN', 'HIGH', 'User input flows to location'),
#         (r'(?:params|query|body)[^\n]*(?:exec|spawn)',
#          'CMDI_CHAIN', 'CRITICAL', 'User input flows to command execution'),
#         (r'(?:params|query|body)[^\n]*(?:\.query|\.raw|\.execute)',
#          'SQLI_CHAIN', 'CRITICAL', 'User input flows to SQL query'),
#     ]
    
#     for pattern, vuln_type, severity, description in chain_patterns:
#         if re.search(pattern, recent_context, re.DOTALL | re.I):
#             chains.append({
#                 'type': vuln_type,
#                 'severity': severity,
#                 'evidence': current_line[:200],
#                 'line': line_num,
#                 'description': description
#             })
    
#     return chains

# # ═══════════════════════════════════════════════════════════════════════════════
# # MAIN PROCESSING
# # ═══════════════════════════════════════════════════════════════════════════════

# @app.task(name="titan.process_file", queue="titan_queue")
# def process_file(domain, filename, code):
#     """TITAN V2 - Elite Bug Bounty Engine"""
#     db = SessionLocal()

#     try:
#         file_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
        
#         source_exists = db.query(SourceFile).filter_by(hash=file_hash).first()
        
#         if not source_exists:
#             compressed_content = zlib.compress(code.encode('utf-8'))
#             new_source = SourceFile(hash=file_hash, content_compressed=compressed_content)
#             db.add(new_source)
#             db.commit()

#         target = db.query(Target).filter_by(domain=domain).first()
#         if not target:
#             target = Target(domain=domain)
#             db.add(target)
#             db.commit()
#             db.refresh(target)

#         asset = Asset(target_id=target.id, url=filename, source_hash=file_hash)
#         db.add(asset)
#         db.commit()
#         db.refresh(asset)

#         all_lines = code.splitlines()
        
#         print(f"")
#         print(f"╔═══════════════════════════════════════════════════════════════════╗")
#         print(f"║  TITAN V2 - ELITE BUG BOUNTY ENGINE                              ║")
#         print(f"╠═══════════════════════════════════════════════════════════════════╣")
#         print(f"║  🎯 {filename[:55]:<55} ║")
#         print(f"║  📄 {len(all_lines)} lines                                                    ║")
#         print(f"╚═══════════════════════════════════════════════════════════════════╝")
        
#         # Phase 1: Taint Analysis
#         print("  ├─ 🔬 Phase 1: Taint Flow Analysis...")
#         taint_flows = track_taint_flow(all_lines)
        
#         findings_buffer = []
        
#         for flow in taint_flows:
#             findings_buffer.append(Finding(
#                 asset_id=asset.id,
#                 type="TAINT_FLOW_" + flow['confidence'],
#                 severity="CRITICAL" if flow['confidence'] == 'HIGH' else "HIGH",
#                 evidence=f"Tainted '{flow['var']}' → {flow['sink_function']} | L{flow['source_line']}→L{flow['sink_line']} | {flow['evidence']}",
#                 line=flow['sink_line']
#             ))
        
#         print(f"  │  └─ {len(taint_flows)} taint flows found")

#         # Phase 2: Pattern Scan
#         print("  ├─ 🔍 Phase 2: Pattern Scan...")
#         previous_lines = []
#         seen_findings = set()
#         pattern_count = 0
        
#         for i, line in enumerate(all_lines, 1):
#             if len(line) > MAX_LINE_LENGTH or not line.strip():
#                 continue
            
#             stripped = line.strip()
            
#             if stripped.startswith(("//", "/*", "*", "#")):
#                 continue
            
#             if any(noise.lower() in line.lower() for noise in NOISE_FILTERS):
#                 continue
            
#             context_info = analyze_context_flow(all_lines, i - 1)
            
#             for cat, regex in COMPILED_SCANNERS.items():
#                 try:
#                     match = regex.search(line)
#                     if match:
#                         finding_hash = hashlib.md5(f"{cat}:{i}:{stripped[:100]}".encode()).hexdigest()
                        
#                         if finding_hash in seen_findings:
#                             continue
                        
#                         seen_findings.add(finding_hash)
#                         severity = classify_severity(cat, stripped, context_info)
#                         evidence = stripped[:400]
                        
#                         if cat.startswith("SECRET_"):
#                             matched = match.group(0)
#                             if len(matched) > 15:
#                                 evidence = f"🔐 {matched[:8]}...{matched[-4:]} | {evidence[:200]}"
                        
#                         if severity in ['CRITICAL', 'HIGH']:
#                             flags = []
#                             if context_info['has_user_input']:
#                                 flags.append("USER_INPUT")
#                             if not context_info['has_sanitization']:
#                                 flags.append("NO_SANITIZE")
#                             if flags:
#                                 evidence = f"[{', '.join(flags)}] {evidence}"
                        
#                         findings_buffer.append(Finding(
#                             asset_id=asset.id,
#                             type=cat,
#                             severity=severity,
#                             evidence=evidence,
#                             line=i
#                         ))
#                         pattern_count += 1

#                 except Exception:
#                     continue

#             # Chain Detection
#             chains = detect_vulnerability_chains(previous_lines, line, i)
#             for chain in chains:
#                 chain_hash = hashlib.md5(f"{chain['type']}:{i}:{chain['evidence']}".encode()).hexdigest()
#                 if chain_hash not in seen_findings:
#                     seen_findings.add(chain_hash)
#                     findings_buffer.append(Finding(
#                         asset_id=asset.id,
#                         type=chain['type'],
#                         severity=chain['severity'],
#                         evidence=f"🔗 {chain['description']}: {chain['evidence']}",
#                         line=i
#                     ))

#             # Security Keywords
#             if not any(f.line == i for f in findings_buffer[-10:]):
#                 line_lower = line.lower()
#                 for keyword in SECURITY_KEYWORDS:
#                     if keyword in line_lower:
#                         if re.search(r'[:=]\s*[\'"`]|function\s|const\s|let\s|var\s', line):
#                             intel_hash = hashlib.md5(f"INTEL:{i}:{keyword}".encode()).hexdigest()
#                             if intel_hash not in seen_findings:
#                                 seen_findings.add(intel_hash)
#                                 findings_buffer.append(Finding(
#                                     asset_id=asset.id,
#                                     type="INTEL_KEYWORD",
#                                     severity="INFO",
#                                     evidence=f"🔎 '{keyword}': {stripped[:200]}",
#                                     line=i
#                                 ))
#                             break

#             previous_lines.append(line)
#             if len(previous_lines) > 15:
#                 previous_lines.pop(0)

#             if len(findings_buffer) >= BATCH_SIZE:
#                 try:
#                     db.bulk_save_objects(findings_buffer)
#                     db.commit()
#                     findings_buffer.clear()
#                 except Exception as e:
#                     print(f"  │  ⚠️  Batch error: {e}")
#                     db.rollback()
#                     findings_buffer.clear()

#         print(f"  │  └─ {pattern_count} patterns found")

#         # Save remaining
#         print("  └─ 💾 Saving...")
        
#         if findings_buffer:
#             try:
#                 db.bulk_save_objects(findings_buffer)
#                 db.commit()
#             except Exception as e:
#                 print(f"  │  ⚠️  Save error: {e}")
#                 db.rollback()
        
#         total = len(seen_findings)
#         critical = db.query(Finding).filter_by(asset_id=asset.id, severity="CRITICAL").count()
#         high = db.query(Finding).filter_by(asset_id=asset.id, severity="HIGH").count()
#         medium = db.query(Finding).filter_by(asset_id=asset.id, severity="MEDIUM").count()
        
#         print(f"")
#         print(f"╔═══════════════════════════════════════════════════════════════════╗")
#         print(f"║  ✅ SCAN COMPLETE                                                 ║")
#         print(f"╠═══════════════════════════════════════════════════════════════════╣")
#         print(f"║  📊 Total: {total:<52} ║")
#         print(f"║     🔴 CRITICAL: {critical:<47} ║")
#         print(f"║     🟠 HIGH: {high:<51} ║")
#         print(f"║     🟡 MEDIUM: {medium:<49} ║")
#         print(f"╚═══════════════════════════════════════════════════════════════════╝")
        
#     except Exception as e:
#         print(f"❌ Error [{filename}]: {str(e)}")
#         import traceback
#         traceback.print_exc()
#         db.rollback()
#     finally:
#         db.close()

# if __name__ == "__main__":
#     app.start()