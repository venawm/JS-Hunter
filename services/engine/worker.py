
import os
import sys
import json
import hashlib
import zlib
import re
import math
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Any, Union, Callable
from enum import Enum, auto
import copy

# Optional imports with fallbacks
try:
    import tree_sitter_javascript as ts_javascript
    import tree_sitter_typescript as ts_typescript
    from tree_sitter import Language, Parser, Query
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False
    print("⚠️  tree-sitter not available")

try:
    import jsbeautifier
    HAS_BEAUTIFIER = True
except ImportError:
    HAS_BEAUTIFIER = False

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

try:
    from celery import Celery
    from core.db.session import SessionLocal
    from core.db.models import Target, Asset, Finding, SourceFile
    HAS_CELERY = True
except ImportError:
    HAS_CELERY = False

if HAS_CELERY:
    app = Celery("titan", broker=os.getenv("REDIS_URL"), backend=os.getenv("REDIS_URL"))

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: ADVANCED DE-OBFUSCATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class AdvancedDeobfuscator:
    """
    Advanced de-obfuscation engine.
    Handles: Hex encoding, Unicode escapes, Array mapping, Obfuscator.io patterns
    """
    
    def __init__(self):
        self.string_map: Dict[str, str] = {}  # Obfuscated -> Decoded
        self.array_maps: Dict[str, List[str]] = {}  # _0x5a1 -> ['eval', 'alert', ...]
        self.function_renames: Dict[str, str] = {}  # Obfuscated function names -> decoded
    
    def deobfuscate(self, code: str) -> str:
        """Apply all de-obfuscation transformations"""
        
        # Phase 1: Decode hex and unicode escapes
        code = self._decode_hex_strings(code)
        code = self._decode_unicode_escapes(code)
        
        # Phase 2: Extract and resolve string arrays (Obfuscator.io pattern)
        code = self._resolve_string_arrays(code)
        
        # Phase 3: Resolve array-based function calls
        code = self._resolve_array_calls(code)
        
        # Phase 4: Fold string concatenations
        code = self._fold_string_concat(code)
        
        # Phase 5: Resolve atob/btoa
        code = self._resolve_base64(code)
        
        # Phase 6: Resolve String.fromCharCode
        code = self._resolve_fromcharcode(code)
        
        return code
    
    def _decode_hex_strings(self, code: str) -> str:
        """Decode \\x65\\x76\\x61\\x6c -> eval"""
        
        def decode_hex_match(match):
            hex_str = match.group(0)
            try:
                # Handle \xNN patterns
                decoded = bytes.fromhex(
                    hex_str.replace('\\x', '').replace("'", "").replace('"', '')
                ).decode('utf-8')
                return f'"{decoded}"'
            except:
                return hex_str
        
        # Match strings containing hex escapes
        pattern = r'["\'](?:\\x[0-9a-fA-F]{2})+["\']'
        return re.sub(pattern, decode_hex_match, code)
    
    def _decode_unicode_escapes(self, code: str) -> str:
        """Decode \\u0065\\u0076\\u0061\\u006c -> eval"""
        
        def decode_unicode_match(match):
            uni_str = match.group(0)
            try:
                # Decode unicode escapes
                decoded = uni_str.encode().decode('unicode_escape')
                return decoded
            except:
                return uni_str
        
        # Match strings containing unicode escapes
        pattern = r'["\'](?:\\u[0-9a-fA-F]{4})+["\']'
        return re.sub(pattern, decode_unicode_match, code)
    
    def _resolve_string_arrays(self, code: str) -> str:
        """
        Resolve Obfuscator.io style string arrays:
        var _0x5a1 = ['eval', 'alert', 'innerHTML'];
        ... _0x5a1[0] ... -> ... 'eval' ...
        """
        
        # Find string array declarations
        # Pattern: var _0xNNNN = ['...', '...', ...]
        array_pattern = r'(?:var|let|const)\s+(_0x[a-fA-F0-9]+|\w+)\s*=\s*\[((?:[\'"][^\'"]*[\'"],?\s*)+)\]'
        
        for match in re.finditer(array_pattern, code):
            var_name = match.group(1)
            array_content = match.group(2)
            
            # Parse array elements
            elements = re.findall(r'[\'"]([^\'"]*)[\'"]', array_content)
            self.array_maps[var_name] = elements
        
        # Now replace array accesses
        for var_name, elements in self.array_maps.items():
            # Pattern: _0x5a1[0] or _0x5a1[0x0]
            access_pattern = rf'{re.escape(var_name)}\[(?:0x)?(\d+)\]'
            
            def replace_access(m):
                idx = int(m.group(1), 16) if m.group(1).startswith('0x') else int(m.group(1))
                if 0 <= idx < len(elements):
                    return f'"{elements[idx]}"'
                return m.group(0)
            
            code = re.sub(access_pattern, replace_access, code)
        
        return code
    
    def _resolve_array_calls(self, code: str) -> str:
        """
        Resolve: window[_0x5a1[0]](x) -> window['eval'](x)
        Already partially done by string array resolution
        """
        # Convert window['eval'] to window.eval for cleaner analysis
        pattern = r"(\w+)\[(['\"])(\w+)\2\]"
        code = re.sub(pattern, r'\1.\3', code)
        return code
    
    def _fold_string_concat(self, code: str) -> str:
        """Fold 'ev' + 'al' -> 'eval'"""
        
        # Pattern: 'str1' + 'str2' or "str1" + "str2"
        concat_pattern = r'([\'"])([^\'"]*)\1\s*\+\s*([\'"])([^\'"]*)\3'
        
        # Repeat until no more folds possible
        prev_code = ""
        while prev_code != code:
            prev_code = code
            code = re.sub(concat_pattern, lambda m: f'"{m.group(2)}{m.group(4)}"', code)
        
        return code
    
    def _resolve_base64(self, code: str) -> str:
        """Resolve atob('ZXZhbA==') -> 'eval'"""
        import base64
        
        pattern = r'atob\s*\(\s*[\'"]([A-Za-z0-9+/=]+)[\'"]\s*\)'
        
        def decode_b64(m):
            try:
                decoded = base64.b64decode(m.group(1)).decode('utf-8')
                return f'"{decoded}"'
            except:
                return m.group(0)
        
        return re.sub(pattern, decode_b64, code)
    
    def _resolve_fromcharcode(self, code: str) -> str:
        """Resolve String.fromCharCode(101, 118, 97, 108) -> 'eval'"""
        
        pattern = r'String\.fromCharCode\s*\(([0-9,\s]+)\)'
        
        def decode_charcode(m):
            try:
                chars = [int(c.strip()) for c in m.group(1).split(',')]
                decoded = ''.join(chr(c) for c in chars)
                return f'"{decoded}"'
            except:
                return m.group(0)
        
        return re.sub(pattern, decode_charcode, code)
    
    def get_decoded_strings(self) -> Dict[str, str]:
        """Get all decoded strings for analysis"""
        return self.string_map


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: TRUE DATA FLOW ANALYSIS WITH SYMBOL TABLES
# ═══════════════════════════════════════════════════════════════════════════════

class TaintState(Enum):
    """Taint states for data flow analysis"""
    CLEAN = auto()
    TAINTED = auto()
    SANITIZED = auto()
    UNKNOWN = auto()

@dataclass
class Symbol:
    """Symbol table entry for a variable"""
    name: str
    scope: str
    taint_state: TaintState = TaintState.UNKNOWN
    taint_source: Optional[str] = None
    taint_line: int = 0
    aliases: Set[str] = field(default_factory=set)
    transformations: List[str] = field(default_factory=list)
    definition_line: int = 0
    last_assignment_line: int = 0
    
    def propagate_to(self, other: 'Symbol'):
        """Propagate taint to another symbol"""
        if self.taint_state == TaintState.TAINTED:
            other.taint_state = TaintState.TAINTED
            other.taint_source = self.taint_source
            other.taint_line = self.taint_line
            other.transformations = self.transformations.copy()

@dataclass
class Scope:
    """Represents a lexical scope"""
    name: str
    parent: Optional['Scope'] = None
    symbols: Dict[str, Symbol] = field(default_factory=dict)
    children: List['Scope'] = field(default_factory=list)
    
    def define(self, name: str, line: int = 0) -> Symbol:
        """Define a new symbol in this scope"""
        sym = Symbol(name=name, scope=self.name, definition_line=line)
        self.symbols[name] = sym
        return sym
    
    def lookup(self, name: str) -> Optional[Symbol]:
        """Look up symbol in scope chain"""
        if name in self.symbols:
            return self.symbols[name]
        if self.parent:
            return self.parent.lookup(name)
        return None
    
    def get_full_path(self) -> str:
        if self.parent:
            return f"{self.parent.get_full_path()}::{self.name}"
        return self.name

class DataFlowAnalyzer:
    """
    True Data Flow Analysis with Symbol Tables.
    Tracks variable assignments, aliases, and taint propagation.
    """
    
    # Known taint sources
    TAINT_SOURCES = {
        'location.search', 'location.hash', 'location.href', 'location.pathname',
        'document.URL', 'document.documentURI', 'document.referrer', 'document.cookie',
        'window.name', 'window.location',
        'localStorage', 'sessionStorage',
        'URLSearchParams', 'searchParams',
        'req.body', 'req.params', 'req.query', 'req.headers', 'req.cookies',
        'request.body', 'request.params', 'request.query',
        'event.data', 'e.data', 'message.data',
        'props', 'params', 'query', 'state',
        'useRouter', 'useParams', 'useSearchParams', 'useLocation',
        '$route.params', '$route.query',
        'fetch', 'axios', 'XMLHttpRequest',
    }
    
    # Known sanitizers
    SANITIZERS = {
        'encodeURI', 'encodeURIComponent',
        'escape', 'escapeHtml', 'escapeHTML', 'htmlEscape',
        'sanitize', 'sanitizeHtml', 'DOMPurify.sanitize',
        'parseInt', 'parseFloat', 'Number', 'Boolean',
        'textContent', 'innerText', 'createTextNode',
        'validator.escape', 'xss',
    }
    
    # Dangerous sinks
    SINKS = {
        'innerHTML', 'outerHTML', 'insertAdjacentHTML',
        'document.write', 'document.writeln',
        'eval', 'Function', 'setTimeout', 'setInterval',
        'location', 'location.href', 'location.assign', 'location.replace',
        'dangerouslySetInnerHTML', 'v-html',
        'exec', 'execSync', 'spawn', 'query', 'raw',
    }
    
    def __init__(self):
        self.global_scope = Scope(name="global")
        self.current_scope = self.global_scope
        self.scope_stack: List[Scope] = [self.global_scope]
        
        # Track all tainted paths
        self.taint_flows: List[Dict] = []
        
        # Function definitions for inter-procedural analysis
        self.functions: Dict[str, Dict] = {}  # name -> {params, returns_tainted, taints_params}
        
        # Call graph
        self.call_graph: Dict[str, Set[str]] = defaultdict(set)
    
    def analyze(self, code: str) -> List[Dict]:
        """
        Perform data flow analysis on code.
        Returns list of taint flows reaching sinks.
        """
        lines = code.split('\n')
        
        # Phase 1: Build symbol table and initial taint
        self._build_symbol_table(lines)
        
        # Phase 2: Propagate taint through assignments
        self._propagate_taint(lines)
        
        # Phase 3: Inter-procedural analysis
        self._analyze_functions(lines)
        
        # Phase 4: Check for tainted sinks
        self._check_sinks(lines)
        
        return self.taint_flows
    
    def _build_symbol_table(self, lines: List[str]):
        """Build initial symbol table from code"""
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue
            
            # Detect function definitions (enter new scope)
            func_match = re.match(r'(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)', stripped)
            if func_match:
                func_name = func_match.group(1)
                params = [p.strip() for p in func_match.group(2).split(',') if p.strip()]
                
                # Create function scope
                func_scope = Scope(name=func_name, parent=self.current_scope)
                self.current_scope.children.append(func_scope)
                self._push_scope(func_scope)
                
                # Define parameters as symbols
                for param in params:
                    self.current_scope.define(param, line_num)
                
                # Store function info
                self.functions[func_name] = {
                    'params': params,
                    'scope': func_scope,
                    'line': line_num,
                    'returns_tainted': False,
                    'taints_params': set(),
                }
                continue
            
            # Arrow function
            arrow_match = re.match(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>', stripped)
            if arrow_match:
                func_name = arrow_match.group(1)
                params = [p.strip() for p in arrow_match.group(2).split(',') if p.strip()]
                
                func_scope = Scope(name=func_name, parent=self.current_scope)
                self.current_scope.children.append(func_scope)
                
                self.functions[func_name] = {
                    'params': params,
                    'scope': func_scope,
                    'line': line_num,
                    'returns_tainted': False,
                    'taints_params': set(),
                }
            
            # Variable declarations
            decl_match = re.match(r'(?:const|let|var)\s+(\w+)\s*=\s*(.+?)(?:;|$)', stripped)
            if decl_match:
                var_name = decl_match.group(1)
                rhs = decl_match.group(2)
                
                sym = self.current_scope.define(var_name, line_num)
                
                # Check if RHS is a taint source
                for source in self.TAINT_SOURCES:
                    if source in rhs:
                        sym.taint_state = TaintState.TAINTED
                        sym.taint_source = source
                        sym.taint_line = line_num
                        break
                
                # Check if RHS references another variable
                for ref_match in re.finditer(r'\b(\w+)\b', rhs):
                    ref_name = ref_match.group(1)
                    ref_sym = self.current_scope.lookup(ref_name)
                    if ref_sym and ref_sym.taint_state == TaintState.TAINTED:
                        # Check for sanitization
                        is_sanitized = any(san in rhs for san in self.SANITIZERS)
                        if is_sanitized:
                            sym.taint_state = TaintState.SANITIZED
                            sym.transformations.append(f"sanitized at L{line_num}")
                        else:
                            ref_sym.propagate_to(sym)
                            sym.transformations.append(f"from {ref_name} at L{line_num}")
            
            # Destructuring - const { a, b } = source
            destruct_match = re.match(r'(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(\w+(?:\.\w+)*)', stripped)
            if destruct_match:
                vars_str = destruct_match.group(1)
                source = destruct_match.group(2)
                
                # Check if source is tainted
                source_tainted = any(src in source for src in self.TAINT_SOURCES)
                
                # Parse destructured variables
                for var in re.findall(r'(\w+)(?:\s*:\s*\w+)?', vars_str):
                    sym = self.current_scope.define(var, line_num)
                    if source_tainted:
                        sym.taint_state = TaintState.TAINTED
                        sym.taint_source = f"{source}.{var}"
                        sym.taint_line = line_num
    
    def _propagate_taint(self, lines: List[str]):
        """Propagate taint through assignments (iterative data flow)"""
        
        changed = True
        iterations = 0
        max_iterations = 50
        
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                
                # Assignment: x = y or x = y.something
                assign_match = re.match(r'(\w+)\s*=\s*(.+?)(?:;|$)', stripped)
                if assign_match and not stripped.startswith(('const', 'let', 'var', 'function')):
                    lhs = assign_match.group(1)
                    rhs = assign_match.group(2)
                    
                    lhs_sym = self.current_scope.lookup(lhs)
                    if not lhs_sym:
                        lhs_sym = self.current_scope.define(lhs, line_num)
                    
                    # Skip if already tainted
                    if lhs_sym.taint_state == TaintState.TAINTED:
                        continue
                    
                    # Check RHS for tainted variables
                    for ref_match in re.finditer(r'\b(\w+)\b', rhs):
                        ref_name = ref_match.group(1)
                        ref_sym = self.current_scope.lookup(ref_name)
                        
                        if ref_sym and ref_sym.taint_state == TaintState.TAINTED:
                            # Check for sanitization
                            is_sanitized = any(san in rhs for san in self.SANITIZERS)
                            
                            if is_sanitized:
                                if lhs_sym.taint_state != TaintState.SANITIZED:
                                    lhs_sym.taint_state = TaintState.SANITIZED
                                    lhs_sym.transformations.append(f"sanitized at L{line_num}")
                                    changed = True
                            else:
                                ref_sym.propagate_to(lhs_sym)
                                lhs_sym.transformations.append(f"from {ref_name} at L{line_num}")
                                lhs_sym.last_assignment_line = line_num
                                changed = True
                            break
    
    def _analyze_functions(self, lines: List[str]):
        """Analyze function calls for inter-procedural taint"""
        
        code = '\n'.join(lines)
        
        # Find function calls
        call_pattern = r'(\w+)\s*\(([^)]*)\)'
        
        for match in re.finditer(call_pattern, code):
            func_name = match.group(1)
            args_str = match.group(2)
            line_num = code[:match.start()].count('\n') + 1
            
            # Skip built-ins
            if func_name in ('if', 'while', 'for', 'switch', 'catch', 'function'):
                continue
            
            # Check if any argument is tainted
            args = [a.strip() for a in args_str.split(',') if a.strip()]
            
            for i, arg in enumerate(args):
                arg_sym = self.current_scope.lookup(arg)
                if arg_sym and arg_sym.taint_state == TaintState.TAINTED:
                    # Record that this function receives tainted data
                    if func_name in self.functions:
                        self.functions[func_name]['taints_params'].add(i)
                        
                        # If function has param at this position, taint it
                        func_info = self.functions[func_name]
                        if i < len(func_info['params']):
                            param_name = func_info['params'][i]
                            param_sym = func_info['scope'].lookup(param_name)
                            if param_sym:
                                arg_sym.propagate_to(param_sym)
    
    def _check_sinks(self, lines: List[str]):
        """Check for tainted data reaching sinks"""
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            for sink in self.SINKS:
                if sink in line:
                    # Find variables used in this line
                    for var_match in re.finditer(r'\b(\w+)\b', line):
                        var_name = var_match.group(1)
                        sym = self.current_scope.lookup(var_name)
                        
                        if sym and sym.taint_state == TaintState.TAINTED:
                            self.taint_flows.append({
                                'sink': sink,
                                'sink_line': line_num,
                                'source': sym.taint_source,
                                'source_line': sym.taint_line,
                                'variable': var_name,
                                'transformations': sym.transformations,
                                'evidence': stripped[:200],
                            })
    
    def _push_scope(self, scope: Scope):
        self.scope_stack.append(scope)
        self.current_scope = scope
    
    def _pop_scope(self):
        if len(self.scope_stack) > 1:
            self.scope_stack.pop()
            self.current_scope = self.scope_stack[-1]
    
    def get_tainted_symbols(self) -> List[Symbol]:
        """Get all symbols that are tainted"""
        tainted = []
        
        def collect(scope: Scope):
            for sym in scope.symbols.values():
                if sym.taint_state == TaintState.TAINTED:
                    tainted.append(sym)
            for child in scope.children:
                collect(child)
        
        collect(self.global_scope)
        return tainted

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: PROBABILISTIC VARIABLE RENAMING
# ═══════════════════════════════════════════════════════════════════════════════

class VariableRenamer:
    """
    Probabilistic variable renaming for minified code.
    Renames cryptic variables (a, b, n, t) to semantic names (req, res, data)
    based on usage patterns.
    """
    
    # Usage signatures and their semantic names
    SIGNATURES = {
        # Express/HTTP request patterns
        'request': {
            'patterns': ['.body', '.params', '.query', '.headers', '.cookies', '.get(', '.method', '.url', '.path'],
            'names': ['req', 'request', 'httpReq'],
            'position': 0,  # Usually first param in (req, res)
        },
        'response': {
            'patterns': ['.send(', '.json(', '.status(', '.render(', '.redirect(', '.cookie(', '.set(', '.end('],
            'names': ['res', 'response', 'httpRes'],
            'position': 1,  # Usually second param
        },
        'next_middleware': {
            'patterns': ['next(', 'next()'],
            'names': ['next', 'nextFn'],
            'position': 2,
        },
        'error': {
            'patterns': ['.message', '.stack', '.code', 'Error', 'catch'],
            'names': ['err', 'error', 'e'],
        },
        'context': {
            'patterns': ['.request', '.response', '.state', '.body', '.throw'],
            'names': ['ctx', 'context'],
        },
        'element': {
            'patterns': ['.innerHTML', '.outerHTML', '.textContent', '.appendChild', '.querySelector', '.classList'],
            'names': ['el', 'element', 'elem', 'node'],
        },
        'event': {
            'patterns': ['.target', '.currentTarget', '.preventDefault', '.stopPropagation', '.type', '.data'],
            'names': ['e', 'event', 'evt'],
        },
        'data': {
            'patterns': ['JSON.parse', 'JSON.stringify', '.map(', '.filter(', '.reduce(', '.forEach('],
            'names': ['data', 'result', 'items'],
        },
        'callback': {
            'patterns': ['callback(', 'cb(', 'done(', 'resolve(', 'reject('],
            'names': ['callback', 'cb', 'done'],
        },
        'config': {
            'patterns': ['.port', '.host', '.database', '.username', '.password', '.secret'],
            'names': ['config', 'options', 'opts'],
        },
        'user': {
            'patterns': ['.id', '.email', '.name', '.role', '.password', '.token'],
            'names': ['user', 'account', 'profile'],
        },
    }
    
    def __init__(self):
        self.renames: Dict[str, str] = {}  # old_name -> new_name
        self.usage_scores: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    
    def analyze_and_rename(self, code: str) -> Tuple[str, Dict[str, str]]:
        """
        Analyze code and rename minified variables to semantic names.
        Returns (renamed_code, rename_map)
        """
        
        # Phase 1: Score each variable based on usage patterns
        self._score_variables(code)
        
        # Phase 2: Determine best rename for each variable
        self._determine_renames()
        
        # Phase 3: Apply renames
        renamed_code = self._apply_renames(code)
        
        return renamed_code, self.renames
    
    def _score_variables(self, code: str):
        """Score variables based on their usage patterns"""
        
        # Find all single-letter or short variable names
        var_pattern = r'\b([a-z]|[a-z][a-z0-9])\b'
        potential_vars = set(re.findall(var_pattern, code))
        
        for var in potential_vars:
            # Skip JavaScript keywords
            if var in ('if', 'in', 'do', 'of', 'as', 'is', 'or', 'an', 'to'):
                continue
            
            # Score based on usage patterns
            for semantic_type, info in self.SIGNATURES.items():
                for pattern in info['patterns']:
                    # Check for var.pattern or var[pattern]
                    usage_pattern = rf'\b{re.escape(var)}{re.escape(pattern)}'
                    matches = len(re.findall(usage_pattern, code))
                    self.usage_scores[var][semantic_type] += matches * 10
                
                # Check callback position in function signatures
                if 'position' in info:
                    # Pattern: function(a, b, c) - check position
                    func_pattern = rf'\(\s*(\w+)(?:\s*,\s*(\w+))?(?:\s*,\s*(\w+))?\s*\)\s*(?:=>|{{)'
                    for match in re.finditer(func_pattern, code):
                        params = [match.group(i) for i in range(1, 4) if match.group(i)]
                        pos = info['position']
                        if pos < len(params) and params[pos] == var:
                            self.usage_scores[var][semantic_type] += 5
    
    def _determine_renames(self):
        """Determine best semantic name for each variable"""
        
        used_names = set()
        
        for var, scores in self.usage_scores.items():
            if not scores:
                continue
            
            # Get type with highest score
            best_type = max(scores.keys(), key=lambda k: scores[k])
            
            if scores[best_type] < 5:  # Minimum confidence threshold
                continue
            
            # Get available name for this type
            for name in self.SIGNATURES[best_type]['names']:
                if name not in used_names:
                    self.renames[var] = name
                    used_names.add(name)
                    break
    
    def _apply_renames(self, code: str) -> str:
        """Apply variable renames to code"""
        
        # Sort by length descending to avoid partial replacements
        sorted_renames = sorted(self.renames.items(), key=lambda x: len(x[0]), reverse=True)
        
        for old_name, new_name in sorted_renames:
            # Use word boundaries to avoid partial matches
            pattern = rf'\b{re.escape(old_name)}\b'
            code = re.sub(pattern, new_name, code)
        
        return code


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: DOM CONTEXT-AWARE XSS DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

class DOMContext(Enum):
    """HTML/DOM contexts for XSS analysis"""
    HTML_TEXT = auto()      # Between tags: <div>HERE</div>
    HTML_ATTR = auto()      # In attribute: <div class="HERE">
    HTML_ATTR_UNQUOTED = auto()  # <div class=HERE>
    SCRIPT_STRING = auto()  # Inside <script> in a string
    SCRIPT_CODE = auto()    # Inside <script> as code
    URL_PARAM = auto()      # In URL: href="...?param=HERE"
    URL_PATH = auto()       # In URL path
    STYLE = auto()          # In style attribute or <style>
    COMMENT = auto()        # In HTML comment
    TEXTAREA = auto()       # Inside <textarea>
    UNKNOWN = auto()

@dataclass
class DOMXSSFinding:
    """Context-aware DOM XSS finding"""
    sink: str
    context: DOMContext
    source: str
    line: int
    exploitable: bool
    bypass_needed: Optional[str] = None
    evidence: str = ""
    severity: str = "HIGH"

class DOMContextAnalyzer:
    """
    Analyzes XSS vulnerabilities with DOM context awareness.
    Different contexts require different payloads and have different exploitability.
    """
    
    # Context-specific exploitability
    CONTEXT_SEVERITY = {
        DOMContext.SCRIPT_CODE: ('CRITICAL', True, None),  # Direct code injection
        DOMContext.HTML_TEXT: ('CRITICAL', True, None),    # Standard XSS
        DOMContext.HTML_ATTR: ('HIGH', True, 'quote_break'),  # Need to break out of quotes
        DOMContext.HTML_ATTR_UNQUOTED: ('CRITICAL', True, None),  # Easy breakout
        DOMContext.SCRIPT_STRING: ('HIGH', True, 'string_break'),  # Need to break string
        DOMContext.URL_PARAM: ('MEDIUM', True, 'javascript_uri'),  # javascript: URI
        DOMContext.URL_PATH: ('LOW', False, 'protocol_handler'),  # Limited
        DOMContext.STYLE: ('MEDIUM', True, 'expression'),  # CSS expressions
        DOMContext.TEXTAREA: ('LOW', False, 'tag_break'),  # Need </textarea>
        DOMContext.COMMENT: ('LOW', False, 'comment_break'),  # Need -->
    }
    
    def __init__(self):
        self.findings: List[DOMXSSFinding] = []
    
    def analyze(self, code: str, taint_flows: List[Dict]) -> List[DOMXSSFinding]:
        """
        Analyze taint flows with context awareness.
        """
        self.findings = []
        lines = code.split('\n')
        
        for flow in taint_flows:
            sink = flow['sink']
            sink_line = flow['sink_line']
            
            if sink_line <= len(lines):
                line_content = lines[sink_line - 1]
                context = self._determine_context(line_content, sink, code, sink_line)
                
                severity, exploitable, bypass = self.CONTEXT_SEVERITY.get(
                    context, ('MEDIUM', True, None)
                )
                
                self.findings.append(DOMXSSFinding(
                    sink=sink,
                    context=context,
                    source=flow['source'],
                    line=sink_line,
                    exploitable=exploitable,
                    bypass_needed=bypass,
                    evidence=line_content.strip()[:200],
                    severity=severity
                ))
        
        return self.findings
    
    def _determine_context(self, line: str, sink: str, full_code: str, line_num: int) -> DOMContext:
        """Determine the DOM context of a sink"""
        
        # innerHTML/outerHTML - depends on what's being written
        if sink in ('innerHTML', 'outerHTML'):
            # Check if it's inside a script context
            if self._is_in_script_tag(full_code, line_num):
                return DOMContext.SCRIPT_CODE
            
            # Check if target is a textarea
            if 'textarea' in line.lower() or 'TEXTAREA' in line:
                return DOMContext.TEXTAREA
            
            return DOMContext.HTML_TEXT
        
        # document.write - check what's being written
        if sink in ('document.write', 'document.writeln'):
            if '<script' in line.lower():
                return DOMContext.SCRIPT_CODE
            return DOMContext.HTML_TEXT
        
        # eval, Function, setTimeout - script context
        if sink in ('eval', 'Function', 'setTimeout', 'setInterval'):
            # Check if value is passed as string to setTimeout
            if 'setTimeout' in line or 'setInterval' in line:
                if re.search(r'(setTimeout|setInterval)\s*\(\s*[\'"]', line):
                    return DOMContext.SCRIPT_STRING
            return DOMContext.SCRIPT_CODE
        
        # Location sinks - URL context
        if 'location' in sink or sink in ('href', 'src'):
            if '?' in line or 'search' in line:
                return DOMContext.URL_PARAM
            return DOMContext.URL_PATH
        
        # Attribute assignments
        if '.setAttribute' in line or '=' in line:
            # Check for unquoted attribute
            if re.search(r'=\s*\w', line) and not re.search(r'=[\'"]', line):
                return DOMContext.HTML_ATTR_UNQUOTED
            return DOMContext.HTML_ATTR
        
        # Style
        if 'style' in line.lower():
            return DOMContext.STYLE
        
        return DOMContext.UNKNOWN
    
    def _is_in_script_tag(self, code: str, line_num: int) -> bool:
        """Check if line is inside a <script> tag"""
        lines_before = code.split('\n')[:line_num]
        text_before = '\n'.join(lines_before)
        
        script_opens = len(re.findall(r'<script[^>]*>', text_before, re.IGNORECASE))
        script_closes = len(re.findall(r'</script>', text_before, re.IGNORECASE))
        
        return script_opens > script_closes

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: CLIENT-SIDE PATH TRAVERSAL (CSPT) ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class CSPTVulnerability:
    """Client-Side Path Traversal finding"""
    line: int
    sink_type: str  # fetch, XHR, etc.
    url_construction: str
    source: str
    vulnerable_pattern: str
    severity: str
    evidence: str
    exploit_example: str = ""

class CSPTAnalyzer:
    """
    Client-Side Path Traversal (CSPT) detection engine.
    Finds fetch/XHR where URL is constructed with user input without proper prefix.
    """
    
    # URL construction sinks
    URL_SINKS = {
        'fetch': 'Fetch API',
        'XMLHttpRequest': 'XHR',
        'axios': 'Axios',
        '.open(': 'XHR open',
        'http.get': 'Node HTTP',
        'https.get': 'Node HTTPS',
        'request(': 'Request library',
        '.src': 'Element src',
        '.href': 'Element href',
        'Image(': 'Image constructor',
        'new URL': 'URL constructor',
    }
    
    # User input sources that could control paths
    PATH_SOURCES = [
        'location.hash', 'location.search', 'location.pathname',
        'document.URL', 'window.name',
        'URLSearchParams', 'searchParams',
        'params', 'query', 'path',
        'req.params', 'req.path',
        'useParams', 'useRouter',
        '$route.params', '$route.path',
    ]
    
    def __init__(self):
        self.vulnerabilities: List[CSPTVulnerability] = []
    
    def analyze(self, code: str, tainted_vars: Set[str]) -> List[CSPTVulnerability]:
        """
        Analyze code for CSPT vulnerabilities.
        """
        self.vulnerabilities = []
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            for sink, sink_name in self.URL_SINKS.items():
                if sink in line:
                    vuln = self._check_cspt_pattern(stripped, line_num, sink, sink_name, tainted_vars)
                    if vuln:
                        self.vulnerabilities.append(vuln)
        
        return self.vulnerabilities
    
    def _check_cspt_pattern(self, line: str, line_num: int, sink: str, 
                           sink_name: str, tainted_vars: Set[str]) -> Optional[CSPTVulnerability]:
        """Check if a line contains a CSPT vulnerability pattern"""
        
        # Pattern 1: fetch("/api/" + location.hash.slice(1))
        # Vulnerable: User can traverse with ../
        concat_pattern = r'(fetch|axios[.\w]*|XMLHttpRequest|\.\w+)\s*\(\s*[\'"`]([^\'"`]*)[\'"`]\s*\+\s*([^)]+)'
        
        match = re.search(concat_pattern, line)
        if match:
            func = match.group(1)
            base_url = match.group(2)
            appended = match.group(3)
            
            # Check if appended part is user-controlled
            is_tainted = False
            source = ""
            
            for tainted_var in tainted_vars:
                if tainted_var in appended:
                    is_tainted = True
                    source = tainted_var
                    break
            
            for path_source in self.PATH_SOURCES:
                if path_source in appended:
                    is_tainted = True
                    source = path_source
                    break
            
            if is_tainted:
                # Check if base URL ends with / (still vulnerable to ../)
                vulnerable = True
                severity = "HIGH"
                pattern = "String concatenation without validation"
                
                # Less severe if there's validation
                if 'startsWith' in line or 'indexOf' in line or 'includes' in line:
                    severity = "MEDIUM"
                    pattern = "Concatenation with partial validation"
                
                return CSPTVulnerability(
                    line=line_num,
                    sink_type=sink_name,
                    url_construction=f'{base_url} + {appended}',
                    source=source,
                    vulnerable_pattern=pattern,
                    severity=severity,
                    evidence=line[:200],
                    exploit_example=f'Set {source} to "../../../etc/passwd" or "..%2F..%2F"'
                )
        
        # Pattern 2: Template literal: fetch(`/api/${params.id}`)
        template_pattern = r'(fetch|axios[.\w]*)\s*\(\s*`([^`]*\$\{[^}]+\}[^`]*)`'
        
        match = re.search(template_pattern, line)
        if match:
            func = match.group(1)
            template = match.group(2)
            
            # Extract interpolated expressions
            interpolations = re.findall(r'\$\{([^}]+)\}', template)
            
            for interp in interpolations:
                is_tainted = False
                source = ""
                
                for tainted_var in tainted_vars:
                    if tainted_var in interp:
                        is_tainted = True
                        source = tainted_var
                        break
                
                for path_source in self.PATH_SOURCES:
                    if path_source in interp:
                        is_tainted = True
                        source = path_source
                        break
                
                if is_tainted:
                    return CSPTVulnerability(
                        line=line_num,
                        sink_type=sink_name,
                        url_construction=template,
                        source=source,
                        vulnerable_pattern="Template literal interpolation",
                        severity="HIGH",
                        evidence=line[:200],
                        exploit_example=f'Inject "../" sequences via {source}'
                    )
        
        # Pattern 3: Dynamic URL without base: fetch(userInput)
        direct_pattern = r'(fetch|axios(?:\.get|\.post)?)\s*\(\s*(\w+)\s*[,)]'
        
        match = re.search(direct_pattern, line)
        if match:
            func = match.group(1)
            url_var = match.group(2)
            
            if url_var in tainted_vars:
                return CSPTVulnerability(
                    line=line_num,
                    sink_type=sink_name,
                    url_construction=f'Direct: {url_var}',
                    source=url_var,
                    vulnerable_pattern="Direct user input as URL",
                    severity="CRITICAL",
                    evidence=line[:200],
                    exploit_example=f'Set {url_var} to "//attacker.com/steal?data=" for SSRF'
                )
        
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: POSTMESSAGE ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PostMessageVulnerability:
    """PostMessage security finding"""
    line: int
    type: str  # no_origin_check, wildcard_origin, no_source_check, sensitive_data
    severity: str
    evidence: str
    recommendation: str

class PostMessageAnalyzer:
    """
    Analyzes postMessage usage for security issues.
    Checks origin verification, source verification, and data handling.
    """
    
    def __init__(self):
        self.vulnerabilities: List[PostMessageVulnerability] = []
        self.message_handlers: List[Dict] = []
        self.postmessage_calls: List[Dict] = []
    
    def analyze(self, code: str) -> List[PostMessageVulnerability]:
        """
        Analyze postMessage handlers and calls.
        """
        self.vulnerabilities = []
        self.message_handlers = []
        self.postmessage_calls = []
        
        lines = code.split('\n')
        
        # Find message event listeners
        self._find_message_handlers(code, lines)
        
        # Find postMessage calls
        self._find_postmessage_calls(code, lines)
        
        # Analyze handlers for vulnerabilities
        self._analyze_handlers(code, lines)
        
        # Analyze postMessage calls
        self._analyze_calls(code, lines)
        
        return self.vulnerabilities
    
    def _find_message_handlers(self, code: str, lines: List[str]):
        """Find addEventListener('message', ...) handlers"""
        
        # Pattern: addEventListener('message', function(e) { ... })
        patterns = [
            r"addEventListener\s*\(\s*['\"]message['\"]",
            r"onmessage\s*=",
            r"window\.onmessage\s*=",
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                
                # Find the handler function body
                handler_start = match.end()
                brace_count = 0
                handler_end = handler_start
                started = False
                
                for i in range(handler_start, min(handler_start + 2000, len(code))):
                    if code[i] == '{':
                        brace_count += 1
                        started = True
                    elif code[i] == '}':
                        brace_count -= 1
                        if started and brace_count == 0:
                            handler_end = i + 1
                            break
                
                handler_body = code[handler_start:handler_end]
                
                self.message_handlers.append({
                    'line': line_num,
                    'body': handler_body,
                    'start': handler_start,
                    'end': handler_end,
                })
    
    def _find_postmessage_calls(self, code: str, lines: List[str]):
        """Find postMessage() calls"""
        
        # Pattern: target.postMessage(data, origin)
        pattern = r'(\w+(?:\.\w+)?)\.postMessage\s*\(\s*([^,]+),\s*([^)]+)\)'
        
        for match in re.finditer(pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            
            self.postmessage_calls.append({
                'line': line_num,
                'target': match.group(1),
                'data': match.group(2).strip(),
                'origin': match.group(3).strip(),
            })
    
    def _analyze_handlers(self, code: str, lines: List[str]):
        """Analyze message handlers for security issues"""
        
        for handler in self.message_handlers:
            body = handler['body']
            line = handler['line']
            
            # Check 1: No origin verification
            has_origin_check = any([
                'origin' in body and ('===' in body or '==' in body or 'includes' in body),
                '.origin' in body and 'if' in body,
                'event.origin' in body,
                'e.origin' in body,
            ])
            
            if not has_origin_check:
                self.vulnerabilities.append(PostMessageVulnerability(
                    line=line,
                    type="NO_ORIGIN_CHECK",
                    severity="CRITICAL",
                    evidence=f"Message handler at line {line} does not verify event.origin",
                    recommendation="Always verify event.origin against a whitelist of trusted origins"
                ))
            
            # Check 2: Wildcard origin check (origin === '*')
            if re.search(r"origin\s*===?\s*['\"]?\*['\"]?", body):
                self.vulnerabilities.append(PostMessageVulnerability(
                    line=line,
                    type="WILDCARD_ORIGIN",
                    severity="CRITICAL",
                    evidence=f"Message handler accepts messages from any origin (*)",
                    recommendation="Replace '*' with specific trusted origin(s)"
                ))
            
            # Check 3: No source verification
            has_source_check = 'source' in body and ('===' in body or '==' in body)
            
            if not has_source_check and not has_origin_check:
                self.vulnerabilities.append(PostMessageVulnerability(
                    line=line,
                    type="NO_SOURCE_CHECK",
                    severity="HIGH",
                    evidence=f"Message handler does not verify event.source",
                    recommendation="Consider verifying event.source for additional security"
                ))
            
            # Check 4: Dangerous data handling
            dangerous_patterns = [
                (r'eval\s*\(\s*(?:e|event|msg)\.data', "eval() with message data"),
                (r'innerHTML\s*=\s*(?:e|event|msg)\.data', "innerHTML with message data"),
                (r'document\.write\s*\(\s*(?:e|event|msg)\.data', "document.write with message data"),
                (r'location\s*=\s*(?:e|event|msg)\.data', "location redirect with message data"),
                (r'Function\s*\(\s*(?:e|event|msg)\.data', "Function() with message data"),
            ]
            
            for pattern, desc in dangerous_patterns:
                if re.search(pattern, body):
                    self.vulnerabilities.append(PostMessageVulnerability(
                        line=line,
                        type="DANGEROUS_DATA_HANDLING",
                        severity="CRITICAL",
                        evidence=f"Message data used in dangerous sink: {desc}",
                        recommendation="Sanitize message data before use in sensitive operations"
                    ))
    
    def _analyze_calls(self, code: str, lines: List[str]):
        """Analyze postMessage calls for security issues"""
        
        for call in self.postmessage_calls:
            line = call['line']
            origin = call['origin']
            data = call['data']
            
            # Check 1: Wildcard target origin
            if origin.strip("'\"") == '*':
                # Check if sensitive data is being sent
                sensitive_patterns = ['token', 'password', 'secret', 'key', 'auth', 'session', 'cookie']
                is_sensitive = any(p in data.lower() for p in sensitive_patterns)
                
                severity = "HIGH" if is_sensitive else "MEDIUM"
                
                self.vulnerabilities.append(PostMessageVulnerability(
                    line=line,
                    type="WILDCARD_TARGET_ORIGIN",
                    severity=severity,
                    evidence=f"postMessage uses '*' as target origin" + (" with sensitive data" if is_sensitive else ""),
                    recommendation="Specify exact target origin instead of '*'"
                ))
            
            # Check 2: Dynamic/user-controlled origin
            if not (origin.startswith("'") or origin.startswith('"') or origin.startswith('`')):
                # Origin is a variable, could be user-controlled
                self.vulnerabilities.append(PostMessageVulnerability(
                    line=line,
                    type="DYNAMIC_TARGET_ORIGIN",
                    severity="MEDIUM",
                    evidence=f"postMessage target origin is dynamic: {origin}",
                    recommendation="Ensure target origin is validated and not user-controlled"
                ))

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7: WEBPACK SECRET EXTRACTOR WITH SHANNON ENTROPY
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecretFinding:
    """Detected secret or sensitive data"""
    type: str
    value: str
    line: int
    entropy: float
    confidence: str
    context: str = ""

class WebpackSecretExtractor:
    """
    Extracts secrets from webpack bundles using pattern matching
    and Shannon entropy analysis.
    """
    
    # Known secret patterns
    SECRET_PATTERNS = {
        'AWS_ACCESS_KEY': (r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', 'CRITICAL'),
        'AWS_SECRET_KEY': (r'(?:aws)?_?(?:secret)?_?(?:access)?_?key[\'"\s:=]+([A-Za-z0-9/+=]{40})', 'CRITICAL'),
        'GITHUB_TOKEN': (r'gh[pousr]_[A-Za-z0-9_]{36,}', 'CRITICAL'),
        'GITHUB_OAUTH': (r'github[_\-]?(?:oauth)?[_\-]?(?:token)?[\'"\s:=]+([a-f0-9]{40})', 'CRITICAL'),
        'GOOGLE_API_KEY': (r'AIza[0-9A-Za-z_-]{35}', 'HIGH'),
        'GOOGLE_OAUTH': (r'[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com', 'HIGH'),
        'FIREBASE_KEY': (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', 'HIGH'),
        'SLACK_TOKEN': (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', 'CRITICAL'),
        'SLACK_WEBHOOK': (r'https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[a-zA-Z0-9]{24}', 'HIGH'),
        'STRIPE_KEY': (r'sk_(?:live|test)_[0-9a-zA-Z]{24,}', 'CRITICAL'),
        'STRIPE_RESTRICTED': (r'rk_(?:live|test)_[0-9a-zA-Z]{24,}', 'HIGH'),
        'TWILIO_SID': (r'AC[a-f0-9]{32}', 'HIGH'),
        'TWILIO_TOKEN': (r'SK[a-f0-9]{32}', 'HIGH'),
        'SENDGRID_KEY': (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 'CRITICAL'),
        'MAILGUN_KEY': (r'key-[0-9a-zA-Z]{32}', 'HIGH'),
        'JWT_SECRET': (r'(?:jwt|JWT)[_\-]?(?:secret|SECRET|key|KEY)?[\'"\s:=]+([A-Za-z0-9+/=]{20,})', 'CRITICAL'),
        'PRIVATE_KEY': (r'-----BEGIN (?:RSA|EC|DSA|OPENSSH)? ?PRIVATE KEY-----', 'CRITICAL'),
        'BEARER_TOKEN': (r'[Bb]earer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', 'HIGH'),
        'BASIC_AUTH': (r'[Bb]asic\s+[A-Za-z0-9+/=]{20,}', 'HIGH'),
        'DATABASE_URL': (r'(?:postgres|mysql|mongodb)(?:ql)?://[^\'"\s]+:[^\'"\s]+@[^\'"\s]+', 'CRITICAL'),
        'REDIS_URL': (r'redis://[^\'"\s]+:[^\'"\s]+@[^\'"\s]+', 'HIGH'),
        'API_KEY_GENERIC': (r'(?:api[_\-]?key|apikey|API_KEY)[\'"\s:=]+([A-Za-z0-9_\-]{20,})', 'MEDIUM'),
        'SECRET_GENERIC': (r'(?:secret|SECRET)[_\-]?(?:key|KEY)?[\'"\s:=]+([A-Za-z0-9_\-]{20,})', 'MEDIUM'),
        'PASSWORD_FIELD': (r'(?:password|passwd|pwd)[\'"\s:=]+([^\'"\\s]{8,})', 'MEDIUM'),
        'OAUTH_CLIENT_SECRET': (r'client[_\-]?secret[\'"\s:=]+([A-Za-z0-9_\-]{20,})', 'HIGH'),
        'NPM_TOKEN': (r'//registry\.npmjs\.org/:_authToken=([A-Za-z0-9\-_]+)', 'CRITICAL'),
        'HEROKU_API_KEY': (r'[Hh]eroku[_\-]?(?:api)?[_\-]?(?:key)?[\'"\s:=]+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', 'HIGH'),
    }
    
    # Environment variable patterns
    ENV_PATTERNS = [
        r'process\.env\.([A-Z_][A-Z0-9_]*)',
        r'process\.env\[[\'"]([A-Z_][A-Z0-9_]*)[\'"]',
        r'import\.meta\.env\.([A-Z_][A-Z0-9_]*)',
        r'(?:REACT_APP|NEXT_PUBLIC|VITE)_[A-Z_]+',
    ]
    
    def __init__(self):
        self.findings: List[SecretFinding] = []
        self.env_vars: Set[str] = set()
    
    def analyze(self, code: str) -> List[SecretFinding]:
        """
        Analyze code for secrets using pattern matching and entropy analysis.
        """
        self.findings = []
        self.env_vars = set()
        
        lines = code.split('\n')
        
        # Phase 1: Pattern-based detection
        self._pattern_detection(code, lines)
        
        # Phase 2: Extract environment variables
        self._extract_env_vars(code)
        
        # Phase 3: Entropy-based detection for high-entropy strings
        self._entropy_detection(code, lines)
        
        # Phase 4: Look for hardcoded configs
        self._config_detection(code, lines)
        
        return self.findings
    
    def _pattern_detection(self, code: str, lines: List[str]):
        """Detect secrets using known patterns"""
        
        for secret_type, (pattern, severity) in self.SECRET_PATTERNS.items():
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count('\n') + 1
                value = match.group(1) if match.lastindex else match.group(0)
                
                # Skip if it looks like a placeholder
                if self._is_placeholder(value):
                    continue
                
                # Calculate entropy
                entropy = self._calculate_entropy(value)
                
                self.findings.append(SecretFinding(
                    type=secret_type,
                    value=self._mask_secret(value),
                    line=line_num,
                    entropy=entropy,
                    confidence="HIGH" if entropy > 4.0 else "MEDIUM",
                    context=lines[line_num-1].strip()[:100] if line_num <= len(lines) else ""
                ))
    
    def _extract_env_vars(self, code: str):
        """Extract environment variable references"""
        
        for pattern in self.ENV_PATTERNS:
            for match in re.finditer(pattern, code):
                env_var = match.group(1) if match.lastindex else match.group(0)
                self.env_vars.add(env_var)
    
    def _entropy_detection(self, code: str, lines: List[str]):
        """Detect high-entropy strings that might be secrets"""
        
        # Find all string literals
        string_pattern = r'[\'"`]([A-Za-z0-9+/=_\-]{20,})[\'"`]'
        
        for match in re.finditer(string_pattern, code):
            value = match.group(1)
            
            # Skip common non-secrets
            if self._is_placeholder(value):
                continue
            
            if self._is_likely_code(value):
                continue
            
            entropy = self._calculate_entropy(value)
            
            # High entropy strings (> 4.5) are likely secrets
            if entropy > 4.5:
                line_num = code[:match.start()].count('\n') + 1
                
                # Avoid duplicates from pattern detection
                existing = [f for f in self.findings if f.line == line_num]
                if existing:
                    continue
                
                self.findings.append(SecretFinding(
                    type="HIGH_ENTROPY_STRING",
                    value=self._mask_secret(value),
                    line=line_num,
                    entropy=entropy,
                    confidence="MEDIUM",
                    context=lines[line_num-1].strip()[:100] if line_num <= len(lines) else ""
                ))
    
    def _config_detection(self, code: str, lines: List[str]):
        """Detect hardcoded configuration values"""
        
        config_patterns = [
            (r'(?:mongodb|mysql|postgres)://[^\s\'"]+', 'DATABASE_CONNECTION'),
            (r'(?:https?://)?(?:api|internal)[.\w]+\.(?:com|io|net)/[^\s\'"]*', 'INTERNAL_API_URL'),
            (r'(?:0\.0\.0\.0|127\.0\.0\.1|localhost):\d{4,5}', 'INTERNAL_ENDPOINT'),
        ]
        
        for pattern, secret_type in config_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                value = match.group(0)
                
                self.findings.append(SecretFinding(
                    type=secret_type,
                    value=value,
                    line=line_num,
                    entropy=self._calculate_entropy(value),
                    confidence="LOW",
                    context=lines[line_num-1].strip()[:100] if line_num <= len(lines) else ""
                ))
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0.0
        
        # Count character frequencies
        freq = defaultdict(int)
        for char in string:
            freq[char] += 1
        
        # Calculate entropy
        length = len(string)
        entropy = 0.0
        
        for count in freq.values():
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder"""
        placeholders = [
            'xxx', 'XXX', 'your_', 'YOUR_', 'example', 'EXAMPLE',
            'placeholder', 'PLACEHOLDER', 'changeme', 'CHANGEME',
            'secret', 'SECRET', 'password', 'PASSWORD', 'key', 'KEY',
            'insert', 'INSERT', 'replace', 'REPLACE', 'todo', 'TODO',
            '0000', '1111', 'aaaa', 'AAAA', 'test', 'TEST',
        ]
        
        value_lower = value.lower()
        return any(p.lower() in value_lower for p in placeholders)
    
    def _is_likely_code(self, value: str) -> bool:
        """Check if value looks like code rather than a secret"""
        # Base64-encoded common words
        code_indicators = [
            'function', 'return', 'const', 'let', 'var',
            'import', 'export', 'class', 'async', 'await',
        ]
        
        # Check for code-like patterns
        if any(ind in value.lower() for ind in code_indicators):
            return True
        
        # Check for repeated patterns
        if len(set(value)) < len(value) / 4:
            return True
        
        return False
    
    def _mask_secret(self, value: str) -> str:
        """Mask secret for safe display"""
        if len(value) <= 8:
            return '*' * len(value)
        return value[:4] + '*' * (len(value) - 8) + value[-4:]
    
    def get_env_vars(self) -> Set[str]:
        """Get detected environment variable names"""
        return self.env_vars

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8: SINK-TO-SOURCE BACKTRACKING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class BacktrackResult:
    """Result of sink-to-source backtracking"""
    sink: str
    sink_line: int
    source: Optional[str]
    source_line: int
    path: List[str]  # Variable names in the path
    path_lines: List[int]  # Line numbers
    is_tainted: bool
    transformations: List[str]

class SinkToSourceBacktracker:
    """
    Reverse taint analysis: Start from sink, trace backwards to find source.
    More efficient for finding "does this specific sink have a vulnerability?"
    """
    
    # Dangerous sinks to start backtracking from
    SINKS = [
        'innerHTML', 'outerHTML', 'insertAdjacentHTML',
        'document.write', 'document.writeln',
        'eval', 'Function', 'setTimeout', 'setInterval',
        'location.href', 'location.assign', 'location.replace',
        'dangerouslySetInnerHTML', 'v-html',
        'exec', 'execSync', 'spawn', 'query', 'raw',
        '.html(', '.append(', '.prepend(',
    ]
    
    # Taint sources
    SOURCES = {
        'location.search', 'location.hash', 'location.href', 'location.pathname',
        'document.URL', 'document.documentURI', 'document.referrer', 'document.cookie',
        'window.name', 'window.location', 'localStorage', 'sessionStorage',
        'URLSearchParams', 'searchParams',
        'req.body', 'req.params', 'req.query', 'req.headers',
        'request.body', 'request.params', 'request.query',
        'event.data', 'e.data', 'message.data',
        'props', 'params', 'query', 'state',
        'useRouter', 'useParams', 'useSearchParams',
        'fetch', 'axios', 'XMLHttpRequest',
    }
    
    def __init__(self):
        self.results: List[BacktrackResult] = []
        self.assignments: Dict[str, List[Tuple[int, str]]] = defaultdict(list)  # var -> [(line, rhs)]
        self.visited: Set[str] = set()
    
    def analyze(self, code: str) -> List[BacktrackResult]:
        """
        Perform sink-to-source backtracking analysis.
        """
        self.results = []
        self.assignments = defaultdict(list)
        lines = code.split('\n')
        
        # Phase 1: Build assignment map (var -> [(line, rhs_expression)])
        self._build_assignment_map(lines)
        
        # Phase 2: Find all sinks
        sinks_found = self._find_sinks(code, lines)
        
        # Phase 3: Backtrack from each sink
        for sink, sink_line, variable in sinks_found:
            self.visited = set()
            result = self._backtrack(variable, sink, sink_line, [], [], lines)
            if result:
                self.results.append(result)
        
        return self.results
    
    def _build_assignment_map(self, lines: List[str]):
        """Build map of all variable assignments"""
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue
            
            # Variable declaration: const/let/var x = ...
            decl_match = re.match(r'(?:const|let|var)\s+(\w+)\s*=\s*(.+?)(?:;|$)', stripped)
            if decl_match:
                var_name = decl_match.group(1)
                rhs = decl_match.group(2)
                self.assignments[var_name].append((line_num, rhs))
            
            # Plain assignment: x = ...
            assign_match = re.match(r'^(\w+)\s*=\s*(.+?)(?:;|$)', stripped)
            if assign_match and not stripped.startswith(('const', 'let', 'var', 'function', 'if', 'for')):
                var_name = assign_match.group(1)
                rhs = assign_match.group(2)
                self.assignments[var_name].append((line_num, rhs))
            
            # Destructuring: const { a, b } = source
            destruct_match = re.match(r'(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(\w+(?:\.\w+)*)', stripped)
            if destruct_match:
                vars_str = destruct_match.group(1)
                source = destruct_match.group(2)
                
                for var in re.findall(r'(\w+)(?:\s*:\s*(\w+))?', vars_str):
                    var_name = var[1] if var[1] else var[0]
                    prop_name = var[0]
                    self.assignments[var_name].append((line_num, f"{source}.{prop_name}"))
    
    def _find_sinks(self, code: str, lines: List[str]) -> List[Tuple[str, int, str]]:
        """Find all sinks and the variable passed to them"""
        sinks_found = []
        
        for line_num, line in enumerate(lines, 1):
            for sink in self.SINKS:
                if sink in line:
                    # Extract variable used in sink
                    # Pattern: sink = variable or sink(variable)
                    
                    # innerHTML = x
                    assign_pattern = rf'{re.escape(sink)}\s*=\s*(\w+)'
                    match = re.search(assign_pattern, line)
                    if match:
                        sinks_found.append((sink, line_num, match.group(1)))
                        continue
                    
                    # eval(x), document.write(x)
                    call_pattern = rf'{re.escape(sink)}\s*\(\s*(\w+)'
                    match = re.search(call_pattern, line)
                    if match:
                        sinks_found.append((sink, line_num, match.group(1)))
                        continue
                    
                    # For sinks like .html(x)
                    method_pattern = rf'{re.escape(sink)}(\w+)\s*\)'
                    match = re.search(method_pattern, line)
                    if match:
                        sinks_found.append((sink, line_num, match.group(1)))
        
        return sinks_found
    
    def _backtrack(self, variable: str, sink: str, sink_line: int,
                   path: List[str], path_lines: List[int], lines: List[str],
                   depth: int = 0) -> Optional[BacktrackResult]:
        """
        Recursively backtrack from variable to find taint source.
        """
        if depth > 20:  # Prevent infinite recursion
            return None
        
        if variable in self.visited:
            return None
        
        self.visited.add(variable)
        path = path + [variable]
        
        # Check if this variable is directly a source
        for source in self.SOURCES:
            if source in variable or variable in source.split('.')[-1]:
                return BacktrackResult(
                    sink=sink,
                    sink_line=sink_line,
                    source=source,
                    source_line=path_lines[0] if path_lines else sink_line,
                    path=path,
                    path_lines=path_lines + [sink_line],
                    is_tainted=True,
                    transformations=[]
                )
        
        # Check assignments for this variable
        if variable in self.assignments:
            for assign_line, rhs in self.assignments[variable]:
                path_lines = path_lines + [assign_line]
                
                # Check if RHS contains a source
                for source in self.SOURCES:
                    if source in rhs:
                        return BacktrackResult(
                            sink=sink,
                            sink_line=sink_line,
                            source=source,
                            source_line=assign_line,
                            path=path,
                            path_lines=path_lines,
                            is_tainted=True,
                            transformations=self._extract_transformations(rhs)
                        )
                
                # Extract variables from RHS and continue backtracking
                rhs_vars = re.findall(r'\b([a-zA-Z_]\w*)\b', rhs)
                
                for rhs_var in rhs_vars:
                    # Skip common keywords and built-ins
                    if rhs_var in ('const', 'let', 'var', 'function', 'return', 'if', 'else',
                                  'true', 'false', 'null', 'undefined', 'this', 'new',
                                  'parseInt', 'parseFloat', 'String', 'Number', 'Boolean',
                                  'JSON', 'Object', 'Array', 'Math', 'Date', 'console'):
                        continue
                    
                    result = self._backtrack(rhs_var, sink, sink_line, path, path_lines, lines, depth + 1)
                    if result and result.is_tainted:
                        return result
        
        return BacktrackResult(
            sink=sink,
            sink_line=sink_line,
            source=None,
            source_line=0,
            path=path,
            path_lines=path_lines,
            is_tainted=False,
            transformations=[]
        )
    
    def _extract_transformations(self, rhs: str) -> List[str]:
        """Extract transformations applied in RHS expression"""
        transformations = []
        
        if '.split(' in rhs:
            transformations.append('split')
        if '.slice(' in rhs:
            transformations.append('slice')
        if '.substring(' in rhs:
            transformations.append('substring')
        if '.replace(' in rhs:
            transformations.append('replace')
        if '.trim(' in rhs:
            transformations.append('trim')
        if '.toLowerCase(' in rhs:
            transformations.append('toLowerCase')
        if '.toUpperCase(' in rhs:
            transformations.append('toUpperCase')
        if 'encodeURI' in rhs:
            transformations.append('encoded')
        if 'JSON.parse' in rhs:
            transformations.append('JSON.parse')
        if 'atob(' in rhs:
            transformations.append('base64_decoded')
        
        return transformations


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9: TREE-SITTER QUERY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class TreeSitterQueryEngine:
    """
    High-performance pattern matching using Tree-sitter S-expression queries.
    Much faster than manual AST traversal.
    """
    
    # Pre-defined security queries (SCM format)
    QUERIES = {
        'dangerous_eval': '''
            (call_expression
                function: (identifier) @func_name
                (#match? @func_name "^(eval|Function)$")
                arguments: (arguments) @args
            ) @call
        ''',
        
        'dangerous_innerhtml': '''
            (assignment_expression
                left: (member_expression
                    property: (property_identifier) @prop
                    (#match? @prop "^(innerHTML|outerHTML)$")
                )
                right: (_) @value
            ) @assignment
        ''',
        
        'document_write': '''
            (call_expression
                function: (member_expression
                    object: (identifier) @obj
                    (#match? @obj "^document$")
                    property: (property_identifier) @method
                    (#match? @method "^(write|writeln)$")
                )
            ) @call
        ''',
        
        'location_assignment': '''
            (assignment_expression
                left: [
                    (identifier) @loc (#match? @loc "^location$")
                    (member_expression
                        object: (identifier) @obj (#match? @obj "^(location|window)$")
                        property: (property_identifier) @prop (#match? @prop "^(href|assign|replace)$")
                    )
                ]
            ) @assignment
        ''',
        
        'settimeout_string': '''
            (call_expression
                function: (identifier) @func
                (#match? @func "^(setTimeout|setInterval)$")
                arguments: (arguments
                    (string) @string_arg
                )
            ) @call
        ''',
        
        'postmessage_handler': '''
            (call_expression
                function: (member_expression
                    property: (property_identifier) @method
                    (#match? @method "^addEventListener$")
                )
                arguments: (arguments
                    (string) @event_type
                    (#match? @event_type "message")
                )
            ) @handler
        ''',
        
        'fetch_call': '''
            (call_expression
                function: (identifier) @func
                (#match? @func "^(fetch|axios)$")
                arguments: (arguments (_) @url)
            ) @call
        ''',
        
        'prototype_access': '''
            (member_expression
                property: (property_identifier) @prop
                (#match? @prop "^(__proto__|prototype|constructor)$")
            ) @access
        ''',
    }
    
    def __init__(self):
        self.parser = None
        self.language = None
        self.compiled_queries: Dict[str, Any] = {}
        
        if HAS_TREE_SITTER:
            self._initialize()
    
    def _initialize(self):
        """Initialize Tree-sitter parser and compile queries"""
        try:
            self.parser = Parser()
            self.language = Language(ts_javascript.language())
            self.parser.language = self.language
            
            # Compile queries
            for name, query_text in self.QUERIES.items():
                try:
                    self.compiled_queries[name] = self.language.query(query_text)
                except Exception as e:
                    print(f"⚠️  Failed to compile query '{name}': {e}")
        except Exception as e:
            print(f"⚠️  Tree-sitter init failed: {e}")
    
    def run_query(self, code: str, query_name: str) -> List[Dict]:
        """Run a named query and return matches"""
        if not self.parser or query_name not in self.compiled_queries:
            return []
        
        results = []
        
        try:
            tree = self.parser.parse(code.encode('utf-8'))
            query = self.compiled_queries[query_name]
            
            captures = query.captures(tree.root_node)
            
            for node, capture_name in captures:
                results.append({
                    'capture': capture_name,
                    'text': code[node.start_byte:node.end_byte],
                    'line': node.start_point[0] + 1,
                    'column': node.start_point[1],
                    'type': node.type,
                })
        except Exception as e:
            print(f"⚠️  Query execution failed: {e}")
        
        return results
    
    def run_all_security_queries(self, code: str) -> Dict[str, List[Dict]]:
        """Run all security queries and return results"""
        all_results = {}
        
        for query_name in self.QUERIES:
            results = self.run_query(code, query_name)
            if results:
                all_results[query_name] = results
        
        return all_results
    
    def custom_query(self, code: str, query_text: str) -> List[Dict]:
        """Run a custom S-expression query"""
        if not self.parser:
            return []
        
        try:
            query = self.language.query(query_text)
            tree = self.parser.parse(code.encode('utf-8'))
            
            results = []
            captures = query.captures(tree.root_node)
            
            for node, capture_name in captures:
                results.append({
                    'capture': capture_name,
                    'text': code[node.start_byte:node.end_byte],
                    'line': node.start_point[0] + 1,
                    'type': node.type,
                })
            
            return results
        except Exception as e:
            print(f"⚠️  Custom query failed: {e}")
            return []
FlowAnalyzer()
        self.renamer = VariableRenamer()
        self.dom_analyzer = DOMContextAnalyzer()
        self.cspt_analyzer = CSPTAnalyzer()
        self.postmsg_analyzer = PostMessageAnalyzer()
        self.secret_extractor = WebpackSecretExtractor()
        self.backtracker = SinkToSourceBacktracker()
        self.ts_queries = TreeSitterQueryEngine()
        
        # Results
        self.vulnerabilities: List[VulnerabilityV6] = []
        self.secrets: List[SecretFinding] = []
        
        # Code versions
        self.original_code = ""
        self.deobfuscated_code = ""
        self.beautified_code = ""
        self.renamed_code = ""
    
    def scan(self, code: str, filename: str = "", language: str = "javascript") -> List[VulnerabilityV6]:
        """Main scanning entry point"""
        self.vulnerabilities = []
        self.secrets = []
        self.original_code = code
        
        print(f"\n{'═'*80}")
        print(f"  🔥 TITAN V6 - GOD MODE EXPLOIT DISCOVERY ENGINE 🔥")
        print(f"  File: {filename[:60]}")
        print(f"{'═'*80}")
        
        # ─── Phase 1: De-obfuscation ────────────────────────────────────────────
        print("\n  [1/10] Advanced de-obfuscation...")
        self.deobfuscated_code = self.deobfuscator.deobfuscate(code)
        
        if self.deobfuscated_code != code:
            obfuscation_diff = len(code) - len(self.deobfuscated_code)
            print(f"         ✓ De-obfuscated ({abs(obfuscation_diff)} chars changed)")
        else:
            print("         ○ No obfuscation detected")
        
        # ─── Phase 2: Beautification ────────────────────────────────────────────
        print("  [2/10] Code beautification...")
        if HAS_BEAUTIFIER:
            try:
                opts = jsbeautifier.default_options()
                opts.indent_size = 2
                self.beautified_code = jsbeautifier.beautify(self.deobfuscated_code, opts)
                print("         ✓ Code beautified")
            except:
                self.beautified_code = self.deobfuscated_code
        else:
            self.beautified_code = self.deobfuscated_code
        
        # ─── Phase 3: Variable Renaming ─────────────────────────────────────────
        print("  [3/10] Probabilistic variable renaming...")
        self.renamed_code, renames = self.renamer.analyze_and_rename(self.beautified_code)
        
        if renames:
            print(f"         ✓ Renamed {len(renames)} variables: {list(renames.items())[:3]}...")
        else:
            print("         ○ No minified variables detected")
        
        # Use the best processed version
        analysis_code = self.renamed_code or self.beautified_code
        
        # ─── Phase 4: Tree-sitter Queries ───────────────────────────────────────
        print("  [4/10] Tree-sitter S-expression queries...")
        ts_results = self.ts_queries.run_all_security_queries(analysis_code)
        
        ts_findings = sum(len(v) for v in ts_results.values())
        print(f"         ✓ Found {ts_findings} pattern matches across {len(ts_results)} categories")
        
        # Convert TS results to vulnerabilities
        self._process_ts_results(ts_results, analysis_code)
        
        # ─── Phase 5: Data Flow Analysis ────────────────────────────────────────
        print("  [5/10] True data flow analysis with symbol tables...")
        taint_flows = self.dfa.analyze(analysis_code)
        
        tainted_symbols = self.dfa.get_tainted_symbols()
        print(f"         ✓ Tracked {len(tainted_symbols)} tainted symbols")
        print(f"         ✓ Found {len(taint_flows)} taint flows to sinks")
        
        # ─── Phase 6: DOM Context Analysis ──────────────────────────────────────
        print("  [6/10] DOM context-aware XSS analysis...")
        dom_findings = self.dom_analyzer.analyze(analysis_code, taint_flows)
        
        for finding in dom_findings:
            self.vulnerabilities.append(VulnerabilityV6(
                type=f"XSS_{finding.context.name}",
                severity=finding.severity,
                line=finding.line,
                evidence=finding.evidence,
                source=finding.source,
                sink=finding.sink,
                context=finding.context,
                exploitable=finding.exploitable,
                bypass_needed=finding.bypass_needed,
                confidence="HIGH",
                cwe=self.CWE_MAP.get('XSS', '')
            ))
        
        print(f"         ✓ {len(dom_findings)} context-aware XSS findings")
        
        # ─── Phase 7: CSPT Analysis ─────────────────────────────────────────────
        print("  [7/10] Client-Side Path Traversal (CSPT) analysis...")
        tainted_vars = {s.name for s in tainted_symbols}
        cspt_vulns = self.cspt_analyzer.analyze(analysis_code, tainted_vars)
        
        for vuln in cspt_vulns:
            self.vulnerabilities.append(VulnerabilityV6(
                type="CSPT_" + vuln.sink_type.upper().replace(' ', '_'),
                severity=vuln.severity,
                line=vuln.line,
                evidence=vuln.evidence,
                source=vuln.source,
                sink=vuln.sink_type,
                recommendation=vuln.exploit_example,
                confidence="HIGH",
                cwe=self.CWE_MAP.get('CSPT', '')
            ))
        
        print(f"         ✓ {len(cspt_vulns)} CSPT vulnerabilities")
        
        # ─── Phase 8: PostMessage Analysis ──────────────────────────────────────
        print("  [8/10] PostMessage origin/source verification...")
        postmsg_vulns = self.postmsg_analyzer.analyze(analysis_code)
        
        for vuln in postmsg_vulns:
            self.vulnerabilities.append(VulnerabilityV6(
                type=f"POSTMESSAGE_{vuln.type}",
                severity=vuln.severity,
                line=vuln.line,
                evidence=vuln.evidence,
                recommendation=vuln.recommendation,
                confidence="HIGH",
                cwe=self.CWE_MAP.get('POSTMESSAGE', '')
            ))
        
        print(f"         ✓ {len(postmsg_vulns)} PostMessage issues")
        
        # ─── Phase 9: Secret Extraction ─────────────────────────────────────────
        print("  [9/10] Webpack secret extraction (Shannon entropy)...")
        self.secrets = self.secret_extractor.analyze(analysis_code)
        
        for secret in self.secrets:
            if secret.confidence in ('HIGH', 'CRITICAL'):
                self.vulnerabilities.append(VulnerabilityV6(
                    type=f"SECRET_{secret.type}",
                    severity="CRITICAL" if 'KEY' in secret.type or 'TOKEN' in secret.type else "HIGH",
                    line=secret.line,
                    evidence=f"{secret.type}: {secret.value} (entropy: {secret.entropy:.2f})",
                    confidence=secret.confidence,
                    cwe=self.CWE_MAP.get('SECRET_EXPOSURE', '')
                ))
        
        print(f"         ✓ {len(self.secrets)} secrets/credentials found")
        
        # ─── Phase 10: Sink-to-Source Backtracking ──────────────────────────────
        print("  [10/10] Sink-to-source backtracking validation...")
        backtrack_results = self.backtracker.analyze(analysis_code)
        
        # Use backtracking to enrich/validate existing findings
        tainted_results = [r for r in backtrack_results if r.is_tainted]
        
        for result in tainted_results:
            # Check if we already have this finding
            existing = [v for v in self.vulnerabilities 
                       if v.line == result.sink_line and v.sink == result.sink]
            
            if existing:
                # Enrich with backtrack data
                for v in existing:
                    v.backtrack_path = result.path
                    v.source_line = result.source_line
                    v.confidence = "HIGH"  # Confirmed by backtracking
            else:
                # New finding from backtracking
                self.vulnerabilities.append(VulnerabilityV6(
                    type=f"TAINT_FLOW_{result.sink.upper().replace('.', '_')}",
                    severity="HIGH",
                    line=result.sink_line,
                    evidence=f"Taint flows from {result.source} through: {' → '.join(result.path)}",
                    source=result.source,
                    sink=result.sink,
                    source_line=result.source_line,
                    backtrack_path=result.path,
                    confidence="HIGH"
                ))
        
        print(f"         ✓ Validated {len(tainted_results)} taint paths")
        
        # ─── Finalization ───────────────────────────────────────────────────────
        self._deduplicate()
        self._calculate_confidence()
        
        # Print results
        self._print_results(filename)
        
        return self.vulnerabilities
    
    def _process_ts_results(self, results: Dict[str, List[Dict]], code: str):
        """Process Tree-sitter query results into vulnerabilities"""
        
        severity_map = {
            'dangerous_eval': 'CRITICAL',
            'dangerous_innerhtml': 'CRITICAL',
            'document_write': 'CRITICAL',
            'location_assignment': 'HIGH',
            'settimeout_string': 'HIGH',
            'postmessage_handler': 'MEDIUM',
            'fetch_call': 'LOW',  # Need context
            'prototype_access': 'HIGH',
        }
        
        for query_name, matches in results.items():
            severity = severity_map.get(query_name, 'MEDIUM')
            
            for match in matches:
                if match['capture'] in ('call', 'assignment', 'access', 'handler'):
                    self.vulnerabilities.append(VulnerabilityV6(
                        type=f"TS_{query_name.upper()}",
                        severity=severity,
                        line=match['line'],
                        evidence=match['text'][:200],
                        confidence="MEDIUM"
                    ))
    
    def _deduplicate(self):
        """Remove duplicate findings"""
        seen = set()
        unique = []
        
        for vuln in self.vulnerabilities:
            key = (vuln.type, vuln.line, vuln.sink or "")
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        self.vulnerabilities = unique
    
    def _calculate_confidence(self):
        """Adjust confidence based on available evidence"""
        for vuln in self.vulnerabilities:
            score = 0
            
            if vuln.source and vuln.sink:
                score += 30
            
            if vuln.backtrack_path:
                score += 20 + len(vuln.backtrack_path) * 5
            
            if vuln.context:
                score += 15
            
            if vuln.source_line > 0:
                score += 10
            
            if score >= 60:
                vuln.confidence = "HIGH"
            elif score >= 30:
                vuln.confidence = "MEDIUM"
            else:
                vuln.confidence = "LOW"
    
    def _print_results(self, filename: str):
        """Print scan results"""
        
        severity_counts = defaultdict(int)
        for v in self.vulnerabilities:
            severity_counts[v.severity] += 1
        
        print(f"\n{'─'*80}")
        print(f"  RESULTS - {filename}")
        print(f"{'─'*80}")
        
        print(f"\n  📊 Total: {len(self.vulnerabilities)} vulnerabilities, {len(self.secrets)} secrets")
        
        icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity_counts[sev]:
                print(f"     {icons[sev]} {sev}: {severity_counts[sev]}")
        
        # Top findings
        if self.vulnerabilities:
            print(f"\n  🎯 Top Findings:")
            sorted_vulns = sorted(self.vulnerabilities, 
                                 key=lambda x: ['CRITICAL','HIGH','MEDIUM','LOW'].index(x.severity))
            
            for vuln in sorted_vulns[:8]:
                conf_icon = "✓" if vuln.confidence == "HIGH" else "○"
                print(f"     {conf_icon} [{vuln.severity}] L{vuln.line}: {vuln.type}")
                
                if vuln.source and vuln.sink:
                    print(f"        Flow: {vuln.source} → {vuln.sink}")
                
                if vuln.backtrack_path:
                    path_str = ' → '.join(vuln.backtrack_path[:4])
                    if len(vuln.backtrack_path) > 4:
                        path_str += f" → ... ({len(vuln.backtrack_path)} steps)"
                    print(f"        Path: {path_str}")
                
                if vuln.context:
                    print(f"        Context: {vuln.context.name}")
                
                if vuln.cwe:
                    print(f"        CWE: {vuln.cwe}")
        
        print(f"\n{'═'*80}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11: CLI & CELERY
# ═══════════════════════════════════════════════════════════════════════════════

def scan_file(filepath: str, language: str = None) -> List[VulnerabilityV6]:
    """Scan a single file"""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()
    
    if language is None:
        ext = os.path.splitext(filepath)[1].lower()
        lang_map = {'.js': 'javascript', '.jsx': 'javascript', 
                   '.ts': 'typescript', '.tsx': 'tsx', '.mjs': 'javascript'}
        language = lang_map.get(ext, 'javascript')
    
    scanner = TitanV6Scanner()
    return scanner.scan(code, filepath, language)


def print_results(vulns: List[VulnerabilityV6]):
    """Pretty print results"""
    if not vulns:
        print("\n✅ No vulnerabilities found!")
        return
    
    by_severity = defaultdict(list)
    for v in vulns:
        by_severity[v.severity].append(v)
    
    print(f"\n{'═'*70}")
    print(f"  VULNERABILITY REPORT")
    print(f"{'═'*70}")
    
    icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if severity in by_severity:
            print(f"\n{icons[severity]} {severity} ({len(by_severity[severity])})")
            print("─" * 50)
            
            for v in by_severity[severity]:
                print(f"\n  [{v.type}] Line {v.line} ({v.confidence} confidence)")
                print(f"  └─ {v.evidence[:80]}...")
                
                if v.source and v.sink:
                    print(f"  └─ Flow: {v.source} → {v.sink}")
                
                if v.backtrack_path:
                    print(f"  └─ Path: {' → '.join(v.backtrack_path[:5])}")
                
                if v.cwe:
                    print(f"  └─ {v.cwe}")


if HAS_CELERY:
    @app.task(name="titan.process_file", queue="titan_queue")
    def process_file(domain: str, filename: str, code: str):
        """TITAN V6 Celery task"""
        db = SessionLocal()
        try:
            file_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
            
            source_exists = db.query(SourceFile).filter_by(hash=file_hash).first()
            if not source_exists:
                compressed = zlib.compress(code.encode('utf-8'))
                new_source = SourceFile(hash=file_hash, content_compressed=compressed)
                db.add(new_source)
                db.commit()
            
            target = db.query(Target).filter_by(domain=domain).first()
            if not target:
                target = Target(domain=domain)
                db.add(target)
                db.commit()
                db.refresh(target)
            
            asset = Asset(target_id=target.id, url=filename, source_hash=file_hash)
            db.add(asset)
            db.commit()
            db.refresh(asset)
            
            scanner = TitanV6Scanner()
            vulns = scanner.scan(code, filename)
            
            findings = []
            for v in vulns:
                evidence = f"[{v.confidence}] {v.evidence}"
                if v.source and v.sink:
                    evidence += f" | {v.source} → {v.sink}"
                if v.backtrack_path:
                    evidence += f" | Path: {' → '.join(v.backtrack_path[:3])}"
                if v.cwe:
                    evidence += f" | {v.cwe}"
                
                findings.append(Finding(
                    asset_id=asset.id,
                    type=v.type,
                    severity=v.severity,
                    evidence=evidence[:1000],
                    line=v.line
                ))
            
            if findings:
                db.bulk_save_objects(findings)
                db.commit()
            
            print(f"✓ TITAN V6: {len(findings)} findings")
            
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
            db.rollback()
        finally:
            db.close()


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="TITAN V6 - God Mode Exploit Discovery Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python titan_v6_engine.py app.js
  python titan_v6_engine.py --json report.json bundle.min.js
  python titan_v6_engine.py src/

Features:
  🔥 Advanced de-obfuscation (hex, unicode, array mapping)
  🔥 True data flow analysis with symbol tables
  🔥 Probabilistic variable renaming for minified code
  🔥 DOM context-aware XSS detection
  🔥 CSPT (Client-Side Path Traversal) analysis
  🔥 PostMessage origin verification check
  🔥 Shannon entropy secret detection
  🔥 Tree-sitter S-expression queries (100x faster)
  🔥 Sink-to-source backtracking
        """
    )
    
    parser.add_argument('target', help='File or directory to scan')
    parser.add_argument('--json', '-j', help='Output JSON to file')
    parser.add_argument('--verbose', '-v', action='store_true')
    
    args = parser.parse_args()
    
    all_vulns = []
    
    if os.path.isfile(args.target):
        vulns = scan_file(args.target)
        all_vulns.extend(vulns)
    
    elif os.path.isdir(args.target):
        for root, dirs, files in os.walk(args.target):
            dirs[:] = [d for d in dirs if d not in ('node_modules', '.git', 'dist', 'build')]
            
            for file in files:
                if file.endswith(('.js', '.jsx', '.ts', '.tsx', '.mjs')):
                    filepath = os.path.join(root, file)
                    print(f"\n📄 Scanning: {filepath}")
                    
                    try:
                        vulns = scan_file(filepath)
                        all_vulns.extend(vulns)
                    except Exception as e:
                        print(f"   ⚠️ Error: {e}")
    else:
        print(f"❌ Not found: {args.target}")
        sys.exit(1)
    
    if args.json:
        with open(args.json, 'w') as f:
            json.dump([v.to_dict() for v in all_vulns], f, indent=2)
        print(f"\n✓ Results written to {args.json}")
    
    print_results(all_vulns)
    
    critical_high = sum(1 for v in all_vulns if v.severity in ('CRITICAL', 'HIGH'))
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == "__main__":
    main()