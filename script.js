// reasoning.json — shared browser helpers (ARP v1.3 "Reader Profile")
//
// Used by generator.html, validator.html and sign/index.html so that all three
// tools apply the same canonicalization (JCS, RFC 8785), the same wording rules
// (ARP-W), the same reasoning.md rendering (ARP-R) and the same signature check.
//
// Reference implementation: arp_cli v1.4.0 (Python). Parsing, lint and verify
// below are ports of parse_manifest_text(), lint_manifest_text() /
// lint_manifest(), verify_manifest() and cmd_verify() in arp_cli.py: same
// rules, rule IDs, severities, reason codes and order of checks. Where the CLI
// relies on Python behaviour, that behaviour is reproduced here (reference
// interpreter: CPython 3.12): the json scanner with duplicate detection,
// re (Unicode \w \s \d \b, IGNORECASE folding of İ ı ſ K), str.strip(),
// str.casefold(), urllib.parse.urlsplit(), datetime.fromisoformat() and
// float repr. tests/test_web_parity.py runs this file headless in node and
// compares its results with arp_cli for every fixture and a set of attack
// cases. Changes in arp_cli.py must be mirrored here.
//
// No external dependencies. Ed25519 verification uses WebCrypto; only if the
// browser lacks Ed25519 support, @noble/ed25519 is loaded from esm.sh (the same
// module the Signer already uses).

// Copy-to-clipboard for code blocks
function copyCode(btn) {
    const pre = btn.closest('.code-block').querySelector('pre');
    navigator.clipboard.writeText(pre.textContent).then(() => {
        btn.textContent = '✓ Copied';
        setTimeout(() => btn.textContent = 'Copy', 2000);
    });
}

(function (global) {
    'use strict';

    const SPEC_VERSION = '1.3';
    const SCHEMA_URL = 'https://arp-protocol.org/schema/v1.3.json';
    const PROTOCOL = 'Agentic Reasoning Protocol (ARP)';
    const SPEC_SIGNATURE_URL = 'https://arp-protocol.org/SPEC.md#13-cryptographic-trust-layer';
    const CLI_VERSION = '1.4.0';
    const MANIFEST_PATH = '/.well-known/reasoning.json';
    const MARKDOWN_PATH = '/.well-known/reasoning.md';
    const MARKDOWN_MEDIA_TYPE = 'text/markdown';
    const KNOWN_SCHEMAS = {
        'https://arp-protocol.org/schema/v1.3.json': '1.3',
        'https://arp-protocol.org/schema/v1.2.json': '1.2',
        'https://arp-protocol.org/schema/v1.1.json': '1.1',
        'https://arp-protocol.org/schema/v1.json': '1.0'
    };

    // Same limits as arp_cli
    const IJSON_MAX_SAFE_INTEGER = 9007199254740991;      // 2^53 − 1
    const IJSON_MAX_INTEGER_DIGITS = 16;
    const MAX_JSON_DEPTH = 64;
    // CPython 3.12.13 raises RecursionError in the json scanner when it opens
    // container number 9992 (measured; it depends slightly on the C stack).
    // The CLI reports that as invalid_json, before later NaN/Infinity values.
    const PY_JSON_RECURSION_DEPTH = 9991;
    const MAX_FETCH_BYTES = 1024 * 1024;
    const FETCH_TOTAL_TIMEOUT_MS = 30000;
    const MAX_REPRESENTATION_FETCHES = 4;
    const REPRESENTATIONS_TOTAL_TIMEOUT_MS = 60000;
    const TRUST_CRYPTOGRAPHIC = 'CRYPTOGRAPHIC';
    const TRUST_UNSIGNED = 'UNSIGNED';
    const TRUST_INVALID = 'INVALID';
    const STATUS_ERROR = 'ERROR';
    const REJECTED_PARSE_REASONS = ['duplicate_member', 'non_ijson'];
    const CRYPTOGRAPHIC_MEANING = 'authorship verified via Ed25519 signature; content not verified';
    const LOCAL_KEY_MEANING = 'signature matches the local public key file; link to the domain and revocation ' +
        'status not checked; content not verified';
    const REPRESENTATION_MATCH = 'REPRESENTATION_MATCH';
    const REPRESENTATION_MISMATCH = 'REPRESENTATION_MISMATCH';
    const REPRESENTATION_UNCHECKED = 'REPRESENTATION_UNCHECKED';

    const R = String.raw;

    function isContainer(v) {
        return v !== null && typeof v === 'object';
    }

    function isPlainObject(v) {
        return v !== null && typeof v === 'object' && !Array.isArray(v);
    }

    function has(obj, key) {
        return Object.prototype.hasOwnProperty.call(obj, key);
    }

    // ─────────────────────────────────────────────
    // JCS canonicalization (RFC 8785)
    // Same algorithm as canonicalize@2.0.0 and Python rfc8785:
    // keys sorted by UTF-16 code units, ECMAScript number and string serialization.
    // ─────────────────────────────────────────────
    function canonicalize(value) {
        if (typeof value === 'number') {
            if (!isFinite(value)) throw new Error('JCS: NaN and Infinity are not allowed');
            return JSON.stringify(value);
        }
        if (value === null || typeof value !== 'object') return JSON.stringify(value);
        if (Array.isArray(value)) {
            return '[' + value.map(v => canonicalize(
                v === undefined || typeof v === 'function' || typeof v === 'symbol' ? null : v
            )).join(',') + ']';
        }
        const parts = [];
        for (const key of Object.keys(value).sort()) {
            const v = value[key];
            if (v === undefined || typeof v === 'function' || typeof v === 'symbol') continue;
            parts.push(JSON.stringify(key) + ':' + canonicalize(v));
        }
        return '{' + parts.join(',') + '}';
    }

    // ─────────────────────────────────────────────
    // Encoding helpers
    // ─────────────────────────────────────────────
    function utf8(str) {
        return new TextEncoder().encode(str);
    }

    function bytesToBase64(bytes) {
        let bin = '';
        for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin);
    }

    function bytesToBase64Url(bytes) {
        return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // Lenient decoder for UI input (e.g. a PEM body without its header lines).
    // Accepts base64 and base64url, padded or unpadded. Never used for values
    // from a reasoning.json or from DNS: see decodeSignatureStrict() and
    // decodeDnsPublicKey(), which follow arp_cli exactly.
    function base64ToBytes(value) {
        let s = String(value).trim().replace(/-/g, '+').replace(/_/g, '/');
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error('not base64');
        s = s.replace(/=+$/, '');
        s += '='.repeat((4 - s.length % 4) % 4);
        const bin = atob(s);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    async function sha256Hex(input) {
        const bytes = typeof input === 'string' ? utf8(input) : input;
        const digest = await crypto.subtle.digest('SHA-256', bytes);
        return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // ─────────────────────────────────────────────
    // Fixed texts (K2 provenance, K3 signature statement and verify block)
    // ─────────────────────────────────────────────
    function provenanceStatement(entity, publisher, domain) {
        return `This file is ${entity}'s own description of itself, published by ${publisher} at ${domain}. ` +
            'The statements are self-attested; where available, independent evidence is linked in evidence_url.';
    }

    function dnsName(selector, domain) {
        return `${selector}._arp.${domain}`;
    }

    function signatureStatement(selector, domain) {
        return `Signed with Ed25519 by the operator of ${domain}. Public key: DNS TXT record ${dnsName(selector, domain)}. ` +
            'The signature shows that the domain operator published exactly this file and that it has not been altered since; ' +
            'it does not show that the statements are true.';
    }

    function dohUrlFor(name) {
        return `https://dns.google/resolve?name=${name}&type=TXT`;
    }

    function verifyBlock(selector, domain) {
        const name = dnsName(selector, domain);
        return {
            dns_name: name,
            doh_url: dohUrlFor(name),
            spec: SPEC_SIGNATURE_URL
        };
    }

    // Selector pattern arpYYMM (K6), e.g. arp2610 for October 2026
    function defaultSelector(date) {
        const d = date || new Date();
        return 'arp' + String(d.getUTCFullYear()).slice(2) + String(d.getUTCMonth() + 1).padStart(2, '0');
    }

    function manifestUrl(domain) {
        return `https://${domain}${MANIFEST_PATH}`;
    }

    function markdownUrl(domain) {
        return `https://${domain}${MARKDOWN_PATH}`;
    }

    function isoSeconds(date) {
        return date.toISOString().split('.')[0] + 'Z';
    }

    // UI helper: normalizes user input like "https://www.example.com/path" to
    // "www.example.com". Not the CLI rule — see pyNormalizeDomain().
    function normalizeDomain(input) {
        let s = String(input || '').trim().toLowerCase();
        s = s.replace(/^[a-z]+:\/\//, '').split('/')[0].split('?')[0].split('#')[0];
        return s.replace(/\.$/, '');
    }

    // Same patterns as arp_cli (_DOMAIN_RE, _SELECTOR_RE). Selector labels may
    // also contain '_' inside (SPEC §13.3, schema v1.3).
    const LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
    const SELECTOR_LABEL = '[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?';
    const DOMAIN_RE = new RegExp(`^(?=.{1,253}$)(?:${LABEL}\\.)+[A-Za-z0-9-]{2,63}$`);
    const SELECTOR_RE = new RegExp(`^(?:${SELECTOR_LABEL})(?:\\.${SELECTOR_LABEL})*$`);

    function isValidDomain(domain) {
        return typeof domain === 'string' && DOMAIN_RE.test(domain);
    }

    function isValidSelector(selector) {
        return typeof selector === 'string' && selector.length > 0 && selector.length <= 50 && SELECTOR_RE.test(selector);
    }

    // ─────────────────────────────────────────────
    // Python 3 semantics used by arp_cli
    // ─────────────────────────────────────────────

    // Python \w for str patterns: str.isalnum() or '_' (= Unicode letters and numbers)
    const PY_WORD = R`\p{L}\p{N}_`;
    // Python \s and str.isspace(): note \x1c-\x1f and \x85 (not U+FEFF, unlike JavaScript \s)
    const PY_SPACE = R`\t-\r\x1c-\x20\x85\xa0\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}`;
    const RX_W = `[${PY_WORD}]`;
    const RX_WB = `(?:(?<=${RX_W})(?!${RX_W})|(?<!${RX_W})(?=${RX_W}))`;
    const RX_NWB = `(?:(?<=${RX_W})(?=${RX_W})|(?<!${RX_W})(?!${RX_W}))`;
    const RX_END = R`(?![\s\S])`;
    const RX_DOLLAR = R`(?=\n?` + RX_END + ')';
    const PY_STRIP = new RegExp(`^[${PY_SPACE}]+|[${PY_SPACE}]+$`, 'gu');
    const PY_SPACE_RUN = new RegExp(`[${PY_SPACE}]+`, 'u');
    const PY_SPACE_ALL = new RegExp(`[${PY_SPACE}]+`, 'gu');

    // Python re.IGNORECASE (str patterns): a letter matches every character
    // whose simple lowercase is the same, plus the fixed equivalences of
    // sre_compile (i ~ ı, s ~ ſ) — so 'i' also matches İ and ı, 'k' the Kelvin
    // sign, 's' the long s. Only the letters that occur in arp_cli's patterns.
    const PY_CASE = (() => {
        const t = {};
        for (let c = 0x61; c <= 0x7a; c++) {
            const lo = String.fromCharCode(c);
            t[lo] = t[lo.toUpperCase()] = lo + lo.toUpperCase();
        }
        t.i = t.I = 'iI\u{130}\u{131}';
        t.k = t.K = 'kK\u{212a}';
        t.s = t.S = 'sS\u{17f}';
        for (const [lo, up] of [['\u{e4}', '\u{c4}'], ['\u{f6}', '\u{d6}'], ['\u{fc}', '\u{dc}'], ['\u{df}', '\u{1e9e}']]) {
            t[lo] = t[up] = lo + up;
        }
        return t;
    })();

    // Translate a Python `re` pattern (str pattern, flags 0 or IGNORECASE) into
    // an equivalent JavaScript pattern for flag 'u'. Letters in case-insensitive
    // parts, including (?i:…) groups, become explicit classes; (?-i:…) switches
    // back. \w \s \d \b follow Python, '.' excludes only '\n', '$' also matches
    // before a final '\n', \Z is the end of the string.
    function pyToJs(src, ignoreCase) {
        let i = 0;
        const n = src.length;
        const ci = [!!ignoreCase];
        const fail = (msg) => { throw new Error(`pyRe: ${msg} at ${i} in ${JSON.stringify(src)}`); };
        const hex = (cp) => '\\u{' + cp.toString(16) + '}';
        const escOut = (ch) => {
            if ('^$\\.*+?()[]{}|/'.includes(ch)) return '\\' + ch;
            const cp = ch.codePointAt(0);
            return cp < 0x20 || cp > 0x7e ? hex(cp) : ch;
        };
        const escIn = (ch) => {
            if ('\\]-^['.includes(ch)) return '\\' + ch;
            const cp = ch.codePointAt(0);
            return cp < 0x20 || cp > 0x7e ? hex(cp) : ch;
        };
        const variants = (ch) => {
            if (!ci[ci.length - 1]) return ch;
            if (PY_CASE[ch]) return PY_CASE[ch];
            if (ch.toLowerCase() !== ch || ch.toUpperCase() !== ch) fail(`no case table entry for ${JSON.stringify(ch)}`);
            return ch;
        };
        const readChar = () => {
            const ch = String.fromCodePoint(src.codePointAt(i));
            i += ch.length;
            return ch;
        };
        const readHex = (len) => {
            const h = src.substr(i, len);
            if (h.length !== len || !/^[0-9a-fA-F]+$/.test(h)) fail('bad hex escape');
            i += len;
            return String.fromCodePoint(parseInt(h, 16));
        };
        // After a backslash. Returns { char } | { cat } | { assert }.
        const escape = (inClass) => {
            if (i >= n) fail('trailing backslash');
            const c = readChar();
            switch (c) {
                case 'b': return inClass ? { char: '\b' } : { assert: RX_WB };
                case 'B': if (inClass) fail('\\B in class'); return { assert: RX_NWB };
                case 'A': if (inClass) fail('\\A in class'); return { assert: '^' };
                case 'Z': if (inClass) fail('\\Z in class'); return { assert: RX_END };
                case 'd': case 'D': case 's': case 'S': case 'w': case 'W': return { cat: c };
                case 'n': return { char: '\n' };
                case 't': return { char: '\t' };
                case 'r': return { char: '\r' };
                case 'f': return { char: '\f' };
                case 'v': return { char: '\v' };
                case 'a': return { char: '\x07' };
                case 'x': return { char: readHex(2) };
                case 'u': return { char: readHex(4) };
                case 'U': return { char: readHex(8) };
                case '0': {
                    let oct = '';
                    while (oct.length < 2 && /[0-7]/.test(src[i] || '')) oct += src[i++];
                    return { char: String.fromCharCode(parseInt('0' + oct, 8)) };
                }
                default:
                    if (/[0-9A-Za-z]/.test(c)) fail(`unsupported escape \\${c}`);
                    return { char: c };
            }
        };
        const catOutside = (c) => ({
            d: R`\p{Nd}`, D: R`\P{Nd}`, w: RX_W, W: `[^${PY_WORD}]`, s: `[${PY_SPACE}]`, S: `[^${PY_SPACE}]`
        })[c];
        const catInside = (c) => {
            const v = { d: R`\p{Nd}`, D: R`\P{Nd}`, w: PY_WORD, s: PY_SPACE }[c];
            if (!v) fail(`\\${c} inside a class is not supported`);
            return v;
        };
        // Character class, parsed like sre_parse: ']' first is literal, '-' at
        // the end is literal, a range needs two literal ends.
        const charClass = () => {
            let negate = false;
            if (src[i] === '^') { negate = true; i++; }
            const parts = [];
            const atom = () => {
                if (src[i] === '\\') { i++; return escape(true); }
                return { char: readChar() };
            };
            const add = (a) => {
                if (a.cat) parts.push(catInside(a.cat));
                else for (const v of Array.from(variants(a.char))) parts.push(escIn(v));
            };
            let first = true;
            for (;;) {
                if (i >= n) fail('unterminated character class');
                if (src[i] === ']' && !first) { i++; break; }
                first = false;
                const a = atom();
                if (src[i] === '-') {
                    if (src[i + 1] === ']') { add(a); parts.push('\\-'); i += 2; break; }
                    if (i + 1 >= n) fail('unterminated range');
                    i++;
                    const b = atom();
                    if (!a.char || !b.char) fail('bad character range');
                    const lo = a.char.codePointAt(0), hi = b.char.codePointAt(0);
                    if (hi < lo) fail('bad range');
                    parts.push(escIn(a.char) + '-' + escIn(b.char));
                    if (ci[ci.length - 1]) {
                        if (hi - lo > 0x7f) fail('large range under IGNORECASE');
                        for (let cp = lo; cp <= hi; cp++) {
                            for (const v of Array.from(variants(String.fromCodePoint(cp)))) {
                                const vc = v.codePointAt(0);
                                if (vc < lo || vc > hi) parts.push(escIn(v));
                            }
                        }
                    }
                } else {
                    add(a);
                }
            }
            return '[' + (negate ? '^' : '') + parts.join('') + ']';
        };
        const literal = (ch) => {
            const v = Array.from(variants(ch));
            return v.length === 1 ? escOut(ch) : '[' + v.map(escIn).join('') + ']';
        };
        let out = '';
        while (i < n) {
            const c = src[i];
            if (c === '\\') {
                i++;
                const e = escape(false);
                if (e.assert) out += e.assert;
                else if (e.cat) out += catOutside(e.cat);
                else out += literal(e.char);
                continue;
            }
            if (c === '[') { i++; out += charClass(); continue; }
            if (c === '(') {
                i++;
                if (src[i] === '?') {
                    const rest = src.slice(i);
                    let m;
                    if (rest.startsWith('?:')) { i += 2; ci.push(ci[ci.length - 1]); out += '(?:'; }
                    else if ((m = /^\?P<([A-Za-z_][A-Za-z0-9_]*)>/.exec(rest))) {
                        i += m[0].length; ci.push(ci[ci.length - 1]); out += `(?<${m[1]}>`;
                    }
                    else if (rest.startsWith('?=') || rest.startsWith('?!')) { out += '(' + rest.slice(0, 2); i += 2; ci.push(ci[ci.length - 1]); }
                    else if (rest.startsWith('?<=') || rest.startsWith('?<!')) { out += '(' + rest.slice(0, 3); i += 3; ci.push(ci[ci.length - 1]); }
                    else if (rest.startsWith('?i:')) { i += 3; ci.push(true); out += '(?:'; }
                    else if (rest.startsWith('?-i:')) { i += 4; ci.push(false); out += '(?:'; }
                    else fail('unsupported group');
                } else {
                    ci.push(ci[ci.length - 1]);
                    out += '(';
                }
                continue;
            }
            if (c === ')') {
                if (ci.length < 2) fail('unbalanced )');
                ci.pop();
                i++;
                out += ')';
                continue;
            }
            if (c === '{') {
                const m = /^\{(\d*)(?:(,)(\d*))?\}/.exec(src.slice(i));
                if (m && src[i + 1] !== '}') {
                    i += m[0].length;
                    const lo = m[1] || '0';
                    out += m[2] ? (m[3] ? `{${lo},${m[3]}}` : `{${lo},}`) : `{${lo}}`;
                } else {
                    i++;
                    out += '\\{';
                }
                continue;
            }
            if (c === '*' || c === '+' || c === '?' || c === '|' || c === '^') { i++; out += c; continue; }
            if (c === '$') { i++; out += RX_DOLLAR; continue; }
            if (c === '.') { i++; out += R`[^\n]`; continue; }
            out += literal(readChar());
        }
        if (ci.length !== 1) fail('unbalanced (');
        return out;
    }

    // A compiled Python pattern with search / match / fullmatch / finditer /
    // split. Match objects: { index, end, 0: text, m: RegExp match }; index and
    // end are UTF-16 offsets (code-point aligned, flag 'u').
    class PyPattern {
        constructor(source, ignoreCase) {
            this.source = source;
            this.ignoreCase = !!ignoreCase;
            this.js = pyToJs(source, ignoreCase);
            this._g = this._y = this._f = null;
        }
        _wrap(m) {
            return m ? { index: m.index, end: m.index + m[0].length, 0: m[0], m } : null;
        }
        search(s) {
            const re = this._g || (this._g = new RegExp(this.js, 'gu'));
            re.lastIndex = 0;
            return this._wrap(re.exec(s));
        }
        match(s) {
            const re = this._y || (this._y = new RegExp(this.js, 'yu'));
            re.lastIndex = 0;
            return this._wrap(re.exec(s));
        }
        fullmatch(s) {
            const re = this._f || (this._f = new RegExp(`(?:${this.js})${RX_END}`, 'yu'));
            re.lastIndex = 0;
            return this._wrap(re.exec(s));
        }
        finditer(s) {
            const re = new RegExp(this.js, 'gu');
            const out = [];
            let m;
            while ((m = re.exec(s)) !== null) {
                out.push(this._wrap(m));
                if (m[0] === '') re.lastIndex += s.codePointAt(re.lastIndex) > 0xffff ? 2 : 1;
            }
            return out;
        }
        split(s) {
            return s.split(new RegExp(this.js, 'u'));
        }
    }

    // Registry of the patterns ported from arp_cli (name → Python source, flags),
    // compared with arp_cli by tests/test_web_parity.py.
    const PATTERNS = {};
    function pyRe(source, ignoreCase, name) {
        const p = new PyPattern(source, ignoreCase);
        if (name) PATTERNS[name] = p;
        return p;
    }

    class PyValueError extends Error {
        constructor(message) {
            super(message);
            this.name = 'ValueError';
        }
    }

    function isNone(v) {
        return v === null || v === undefined;
    }

    // dict.get(): the member value, or dflt if the member is absent
    function pyGet(obj, key, dflt) {
        return isPlainObject(obj) && has(obj, key) ? obj[key] : dflt;
    }

    // Python truth value of a JSON value
    function pyTruthy(v) {
        if (v === null || v === undefined || v === false) return false;
        if (typeof v === 'number') return v !== 0;
        if (typeof v === 'string') return v.length > 0;
        if (Array.isArray(v)) return v.length > 0;
        if (typeof v === 'object') return Object.keys(v).length > 0;
        return true;
    }

    function pyStrip(s) {
        return s.replace(PY_STRIP, '');
    }

    function pySplitWs(s) {
        return s.split(PY_SPACE_RUN).filter(Boolean);
    }

    function rstripDots(s) {
        return s.replace(/\.+$/, '');
    }

    function hasLoneSurrogate(s) {
        for (let i = 0; i < s.length; i++) {
            const c = s.charCodeAt(i);
            if (c >= 0xd800 && c <= 0xdbff) {
                const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
                if (d >= 0xdc00 && d <= 0xdfff) i++;
                else return true;
            } else if (c >= 0xdc00 && c <= 0xdfff) {
                return true;
            }
        }
        return false;
    }

    function isHigh(c) { return c >= 0xd800 && c <= 0xdbff; }
    function isLow(c) { return c >= 0xdc00 && c <= 0xdfff; }

    // Code-point arithmetic on UTF-16 strings (Python indexes code points)
    function cpCount(s) {
        let n = 0;
        for (let i = 0; i < s.length; i++) {
            if (isHigh(s.charCodeAt(i)) && i + 1 < s.length && isLow(s.charCodeAt(i + 1))) i++;
            n++;
        }
        return n;
    }

    function cpBack(s, idx, n) {
        let i = idx;
        while (n > 0 && i > 0) {
            i--;
            if (isLow(s.charCodeAt(i)) && i > 0 && isHigh(s.charCodeAt(i - 1))) i--;
            n--;
        }
        return i;
    }

    function cpForward(s, idx, n) {
        let i = idx;
        while (n > 0 && i < s.length) {
            if (isHigh(s.charCodeAt(i)) && i + 1 < s.length && isLow(s.charCodeAt(i + 1))) i++;
            i++;
            n--;
        }
        return i;
    }

    function hex4(ch) {
        return ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
    }

    // Python str.casefold() equality with an ASCII target. Only these non-ASCII
    // characters fold to pure ASCII (Unicode 15.0, checked with CPython 3.12).
    const CASEFOLD_TO_ASCII = {
        '\u{df}': 'ss', '\u{17f}': 's', '\u{1e9e}': 'ss', '\u{212a}': 'k', '\u{fb00}': 'ff', '\u{fb01}': 'fi',
        '\u{fb02}': 'fl', '\u{fb03}': 'ffi', '\u{fb04}': 'ffl', '\u{fb05}': 'st', '\u{fb06}': 'st'
    };

    function casefoldEquals(s, target) {
        let out = '';
        for (const ch of s) {
            const cp = ch.codePointAt(0);
            if (cp < 0x80) out += ch.toLowerCase();
            else if (has(CASEFOLD_TO_ASCII, ch)) out += CASEFOLD_TO_ASCII[ch];
            else return false;
            if (out.length > target.length) return false;
        }
        return out === target;
    }

    // json.dumps(s) with ensure_ascii=True (arp_cli uses it for paths with
    // unpaired surrogates)
    function pyJsonDumpsAscii(s) {
        let out = '"';
        for (let i = 0; i < s.length; i++) {
            const c = s.charCodeAt(i);
            if (c === 0x22) out += '\\"';
            else if (c === 0x5c) out += '\\\\';
            else if (c === 0x08) out += '\\b';
            else if (c === 0x0c) out += '\\f';
            else if (c === 0x0a) out += '\\n';
            else if (c === 0x0d) out += '\\r';
            else if (c === 0x09) out += '\\t';
            else if (c < 0x20 || c > 0x7e) out += '\\' + 'u' + c.toString(16).padStart(4, '0');
            else out += s[i];
        }
        return out + '"';
    }

    // JSON path of a member or element (arp_cli _child_path)
    const SIMPLE_KEY_RE = pyRe(R`^[A-Za-z_][A-Za-z0-9_]*$`, false, '_SIMPLE_KEY_RE');
    function childPath(path, key) {
        if (typeof key === 'number') return `${path}[${key}]`;
        if (SIMPLE_KEY_RE.fullmatch(key)) return `${path}.${key}`;
        if (hasLoneSurrogate(key)) return `${path}[${pyJsonDumpsAscii(key)}]`;
        return `${path}[${JSON.stringify(key)}]`;
    }

    // Python repr() / str() of JSON values, for messages
    function pyRepr(v) {
        if (v === null || v === undefined) return 'None';
        if (v === true) return 'True';
        if (v === false) return 'False';
        if (typeof v === 'number') return Number.isInteger(v) && Math.abs(v) <= IJSON_MAX_SAFE_INTEGER ? String(v) : pyFloatRepr(v);
        if (typeof v === 'string') {
            const q = v.includes("'") && !v.includes('"') ? '"' : "'";
            return q + v.replace(/\\/g, '\\\\').replace(q === "'" ? /'/g : /"/g, '\\' + q)
                .replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t') + q;
        }
        if (Array.isArray(v)) return '[' + v.map(pyRepr).join(', ') + ']';
        return '{' + orderedKeys(v).map(k => pyRepr(k) + ': ' + pyRepr(v[k])).join(', ') + '}';
    }

    function pyStr(v) {
        return typeof v === 'string' ? v : pyRepr(v);
    }

    // arp_cli safe_text(): control and direction characters shown as escapes
    const UNSAFE_PRINT_RE = pyRe('[\x00-\x1f\x7f-\x9f\u{200b}-\u{200f}\u{2028}-\u{202e}\u{2060}-\u{2069}\u{feff}]',
        false, '_UNSAFE_PRINT_RE');
    function safeText(value, limit) {
        const max = limit === undefined ? 300 : limit;
        let text = pyStr(value);
        text = text.replace(new RegExp(UNSAFE_PRINT_RE.js, 'gu'), (ch) => {
            const cp = ch.codePointAt(0);
            return cp < 0x100 ? '\\x' + cp.toString(16).padStart(2, '0') : '\\' + 'u' + cp.toString(16).padStart(4, '0');
        });
        return cpCount(text) <= max ? text : text.slice(0, cpForward(text, 0, max)) + '…';
    }

    // arp_cli _excerpt() (30 code points of context)
    function excerpt(text, start, end, context) {
        const c = context === undefined ? 30 : context;
        const a = cpBack(text, start, c), b = cpForward(text, end, c);
        return (a > 0 ? '…' : '') + text.slice(a, b).split('\n').join(' ') + (b < text.length ? '…' : '');
    }

    // Python sorted() order: by Unicode code point
    function compareCodePoints(a, b) {
        const x = Array.from(a), y = Array.from(b);
        const n = Math.min(x.length, y.length);
        for (let i = 0; i < n; i++) {
            const d = x[i].codePointAt(0) - y[i].codePointAt(0);
            if (d !== 0) return d;
        }
        return x.length - y.length;
    }

    // Decimal value of a Unicode digit (category Nd): digits come in runs of
    // ten, 0–9 (Unicode stability policy).
    const ND_RE = /\p{Nd}/u;
    function digitValue(ch) {
        const cp = ch.codePointAt(0);
        if (cp >= 0x30 && cp <= 0x39) return cp - 0x30;
        let start = cp;
        while (start > 0 && ND_RE.test(String.fromCodePoint(start - 1))) start--;
        return (cp - start) % 10;
    }

    // int() of a string of Unicode digits
    function pyIntDigits(s) {
        let v = 0n;
        for (const ch of s) v = v * 10n + BigInt(digitValue(ch));
        return v;
    }

    // ─────────────────────────────────────────────
    // Strict parsing: I-JSON (RFC 7493) as arp_cli parse_manifest_text()
    // ─────────────────────────────────────────────

    class ManifestParseError extends Error {
        // reason: duplicate_member | non_ijson (loadable, rejected) |
        //         invalid_json | not_utf8 (not loadable)
        constructor(reason, message, paths) {
            super(message);
            this.name = 'ManifestParseError';
            this.reason = reason;
            this.paths = paths || [];
        }
    }

    // Containers created by the parser keep the member order of the file
    // (JavaScript objects list integer-like names first) and whether a number
    // was written as an integer or a float (Python int vs. float).
    const META = new WeakMap();

    function orderedKeys(obj) {
        const own = Object.keys(obj);
        const meta = META.get(obj);
        if (!meta || !meta.keys) return own;
        const out = meta.keys.filter(k => has(obj, k));
        if (out.length !== own.length) {
            const seen = new Set(out);
            for (const k of own) if (!seen.has(k)) out.push(k);
        }
        return out;
    }

    // 'int' | 'float' | 'big' (integer literal with more than 16 digits)
    function numberKind(container, key, value) {
        const meta = container && META.get(container);
        if (meta && meta.kinds.has(key)) return meta.kinds.get(key);
        return Number.isInteger(value) && Math.abs(value) <= IJSON_MAX_SAFE_INTEGER ? 'int' : 'float';
    }

    function numberLiteral(container, key) {
        const meta = container && META.get(container);
        return meta && meta.literals && meta.literals.has(key) ? meta.literals.get(key) : null;
    }

    function defineMember(obj, key, value) {
        Object.defineProperty(obj, key, { value: value, writable: true, enumerable: true, configurable: true });
    }

    const TOO_DEEP = `JSON nested deeper than ${MAX_JSON_DEPTH} levels (not accepted)`;

    // Port of arp_cli _parse_json_collecting(): Python's json scanner with
    // object_pairs_hook (duplicates collected, last value kept at the first
    // position), NaN/Infinity and float overflow rejected while parsing,
    // integer literals over 16 digits kept as placeholders. Returns
    // { data, duplicates: [[path, name]], rootKind }.
    function parseJsonCollecting(text) {
        const n = text.length;
        const invalid = (msg) => new ManifestParseError('invalid_json', 'not valid JSON: ' + msg);
        if (n && text.charCodeAt(0) === 0xfeff) throw invalid('Unexpected UTF-8 BOM (decode using utf-8-sig)');
        const dupsOf = new Map();
        let i = 0;
        const ws = () => {
            while (i < n) {
                const c = text.charCodeAt(i);
                if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
                else break;
            }
        };
        const isDigit = (c) => c >= 0x30 && c <= 0x39;
        const hex4At = (j) => {
            let v = 0;
            for (let k = j; k < j + 4; k++) {
                const c = text.charCodeAt(k);
                let d;
                if (c >= 0x30 && c <= 0x39) d = c - 0x30;
                else if (c >= 0x61 && c <= 0x66) d = c - 0x57;
                else if (c >= 0x41 && c <= 0x46) d = c - 0x37;
                else throw invalid('Invalid \\uXXXX escape');
                v = (v << 4) | d;
            }
            return v;
        };
        // i points after the opening quote
        const scanString = () => {
            let out = '';
            for (;;) {
                let j = i;
                while (j < n) {
                    const c = text.charCodeAt(j);
                    if (c === 0x22 || c === 0x5c) break;
                    if (c <= 0x1f) throw invalid('Invalid control character');
                    j++;
                }
                if (j >= n) throw invalid('Unterminated string');
                out += text.slice(i, j);
                if (text.charCodeAt(j) === 0x22) { i = j + 1; return out; }
                j++;
                if (j >= n) throw invalid('Unterminated string');
                const e = text[j];
                if (e !== 'u') {
                    const map = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
                    if (!has(map, e)) throw invalid('Invalid \\escape');
                    out += map[e];
                    i = j + 1;
                    continue;
                }
                j++;
                const end = j + 4;
                if (end >= n) throw invalid('Invalid \\uXXXX escape');
                let c = hex4At(j);
                j = end;
                if (isHigh(c) && end + 6 < n && text[end] === '\\' && text[end + 1] === 'u') {
                    const c2 = hex4At(end + 2);
                    if (isLow(c2)) {
                        out += String.fromCharCode(c, c2);
                        i = end + 6;
                        continue;
                    }
                }
                out += String.fromCharCode(c);
                i = j;
            }
        };
        // Number at i, or null (Python: StopIteration → "Expecting value")
        const scanNumber = () => {
            const start = i;
            let j = i;
            if (text[j] === '-') {
                j++;
                if (j >= n) return null;
            }
            const c0 = text.charCodeAt(j);
            if (c0 >= 0x31 && c0 <= 0x39) {
                j++;
                while (j < n && isDigit(text.charCodeAt(j))) j++;
            } else if (c0 === 0x30) {
                j++;
            } else {
                return null;
            }
            let isFloat = false;
            if (j < n - 1 && text[j] === '.' && isDigit(text.charCodeAt(j + 1))) {
                isFloat = true;
                j += 2;
                while (j < n && isDigit(text.charCodeAt(j))) j++;
            }
            if (j < n - 1 && (text[j] === 'e' || text[j] === 'E')) {
                const eStart = j;
                j++;
                if (j < n - 1 && (text[j] === '-' || text[j] === '+')) j++;
                while (j < n && isDigit(text.charCodeAt(j))) j++;
                if (isDigit(text.charCodeAt(j - 1))) isFloat = true;
                else j = eStart;
            }
            const literal = text.slice(start, j);
            i = j;
            if (isFloat) {
                const v = Number(literal);
                if (!isFinite(v)) {
                    throw new ManifestParseError('non_ijson',
                        `number ${safeText(literal, 40)} lies outside the IEEE 754 double range`);
                }
                return { value: v, kind: 'float', literal: null };
            }
            const digits = literal.length - (literal[0] === '-' ? 1 : 0);
            if (digits > IJSON_MAX_INTEGER_DIGITS) {
                return { value: literal[0] === '-' ? -(IJSON_MAX_SAFE_INTEGER + 1) : IJSON_MAX_SAFE_INTEGER + 1, kind: 'big', literal };
            }
            const v = Number(literal);
            return { value: v === 0 ? 0 : v, kind: 'int', literal: Math.abs(v) > IJSON_MAX_SAFE_INTEGER ? literal : null };
        };
        const nonIjsonConstant = (name) => new ManifestParseError('non_ijson', `${name} is not a JSON number (RFC 8259 §6)`);

        const stack = [];
        let value, kind, literal;
        let expectValue = true;
        let rootKind = null;
        const readKey = (frame) => {
            if (text[i] !== '"') throw invalid('Expecting property name enclosed in double quotes');
            i++;
            frame.key = scanString();
            ws();
            if (text[i] !== ':') throw invalid("Expecting ':' delimiter");
            i++;
            ws();
        };
        ws();
        for (;;) {
            if (expectValue) {
                if (i >= n) throw invalid('Expecting value');
                const c = text[i];
                kind = null;
                literal = null;
                if (c === '"') {
                    i++;
                    value = scanString();
                } else if (c === '{' || c === '[') {
                    if (stack.length + 1 > PY_JSON_RECURSION_DEPTH) throw new ManifestParseError('invalid_json', TOO_DEEP);
                    i++;
                    ws();
                    const isObj = c === '{';
                    const container = isObj ? {} : [];
                    const meta = { keys: isObj ? [] : null, kinds: new Map(), literals: null };
                    META.set(container, meta);
                    if (text[i] === (isObj ? '}' : ']')) {
                        i++;
                        value = container;
                    } else {
                        const frame = { container, isObj, meta, key: null };
                        stack.push(frame);
                        if (isObj) readKey(frame);
                        continue;
                    }
                } else if (text.startsWith('null', i)) {
                    i += 4;
                    value = null;
                } else if (text.startsWith('true', i)) {
                    i += 4;
                    value = true;
                } else if (text.startsWith('false', i)) {
                    i += 5;
                    value = false;
                } else if (text.startsWith('NaN', i)) {
                    throw nonIjsonConstant('NaN');
                } else if (text.startsWith('Infinity', i)) {
                    throw nonIjsonConstant('Infinity');
                } else if (text.startsWith('-Infinity', i)) {
                    throw nonIjsonConstant('-Infinity');
                } else {
                    const num = scanNumber();
                    if (!num) throw invalid('Expecting value');
                    value = num.value;
                    kind = num.kind;
                    literal = num.literal;
                }
                expectValue = false;
                continue;
            }
            if (!stack.length) {
                rootKind = kind;
                break;
            }
            const f = stack[stack.length - 1];
            const key = f.isObj ? f.key : f.container.length;
            if (f.isObj) {
                if (has(f.container, key)) {
                    if (!dupsOf.has(f.container)) dupsOf.set(f.container, []);
                    dupsOf.get(f.container).push(key);
                } else {
                    f.meta.keys.push(key);
                }
                defineMember(f.container, key, value);
            } else {
                f.container.push(value);
            }
            if (kind) f.meta.kinds.set(key, kind);
            else f.meta.kinds.delete(key);
            if (literal) (f.meta.literals || (f.meta.literals = new Map())).set(key, literal);
            else if (f.meta.literals) f.meta.literals.delete(key);
            ws();
            const close = f.isObj ? '}' : ']';
            if (text[i] === close) {
                i++;
                stack.pop();
                value = f.container;
                kind = null;
                literal = null;
            } else if (text[i] === ',') {
                i++;
                ws();
                if (f.isObj) readKey(f);
                expectValue = true;
            } else {
                throw invalid("Expecting ',' delimiter");
            }
        }
        ws();
        if (i !== n) throw invalid('Extra data');
        const data = value;
        if (depthExceeds(data, MAX_JSON_DEPTH)) throw new ManifestParseError('invalid_json', TOO_DEEP);
        const duplicates = [];
        if (dupsOf.size) {
            const walk = (item, p) => {
                if (Array.isArray(item)) {
                    item.forEach((child, k) => walk(child, `${p}[${k}]`));
                } else if (isPlainObject(item)) {
                    for (const name of dupsOf.get(item) || []) duplicates.push([childPath(p, name), name]);
                    for (const k of orderedKeys(item)) walk(item[k], childPath(p, k));
                }
            };
            walk(data, '$');
        }
        return { data, duplicates, rootKind };
    }

    // True if containers nest deeper than limit (iterative, like arp_cli)
    function depthExceeds(value, limit) {
        const stack = [[value, 1]];
        while (stack.length) {
            const [item, depth] = stack.pop();
            if (!isContainer(item)) continue;
            if (depth > limit) return true;
            const children = Array.isArray(item) ? item : Object.keys(item).map(k => item[k]);
            for (const child of children) stack.push([child, depth + 1]);
        }
        return false;
    }

    function describeInteger(value, container, key) {
        const lit = numberLiteral(container, key);
        if (lit !== null) {
            const digits = lit.length - (lit[0] === '-' ? 1 : 0);
            return digits > IJSON_MAX_INTEGER_DIGITS ? `integer with ${digits} digits` : `integer ${lit}`;
        }
        return `integer ${value}`;
    }

    // Port of arp_cli ijson_problems(): [[path, description]]
    function ijsonProblems(root, rootKind) {
        const problems = [];
        const visit = (item, p, container, key) => {
            if (item === null || item === undefined || typeof item === 'boolean') return;
            if (typeof item === 'number') {
                const kind = container ? numberKind(container, key, item) : (rootKind || numberKind(null, null, item));
                if (kind === 'big' || (kind === 'int' && Math.abs(item) > IJSON_MAX_SAFE_INTEGER)) {
                    problems.push([p, `${describeInteger(item, container, key)} lies outside ±(2^53−1)`]);
                } else if (kind === 'float' && !isFinite(item)) {
                    problems.push([p, `number ${isNaN(item) ? 'nan' : (item > 0 ? 'inf' : '-inf')} is not finite`]);
                }
                return;
            }
            if (typeof item === 'string') {
                if (hasLoneSurrogate(item)) problems.push([p, 'string contains an unpaired surrogate']);
                return;
            }
            if (Array.isArray(item)) {
                item.forEach((child, k) => visit(child, `${p}[${k}]`, item, k));
                return;
            }
            if (typeof item === 'object') {
                for (const k of orderedKeys(item)) {
                    const cp = childPath(p, k);
                    if (hasLoneSurrogate(k)) {
                        problems.push([cp, 'member name contains an unpaired surrogate']);
                        continue;
                    }
                    visit(item[k], cp, item, k);
                }
            }
        };
        visit(root, '$', null, null);
        return problems;
    }

    // Port of arp_cli parse_manifest_text(): duplicates and other I-JSON
    // violations raise ManifestParseError.
    function parseManifestText(text) {
        const { data, duplicates, rootKind } = parseJsonCollecting(text);
        if (duplicates.length) {
            const names = [...new Set(duplicates.map(d => d[1]))].sort(compareCodePoints).join(', ');
            throw new ManifestParseError('duplicate_member',
                `duplicate member name(s) ${safeText(names, 120)} at ${safeText(duplicates[0][0], 120)} ` +
                '(I-JSON, RFC 7493 §2.3: member names must be unique)', duplicates.map(d => d[0]));
        }
        const problems = ijsonProblems(data, rootKind);
        if (problems.length) {
            throw new ManifestParseError('non_ijson', `${problems[0][1]} at ${safeText(problems[0][0], 120)} (I-JSON, RFC 7493)`,
                problems.map(p => p[0]));
        }
        return data;
    }

    // bytes.decode("utf-8-sig"): strict UTF-8, one leading BOM removed
    function decodeUtf8Sig(bytes) {
        try {
            return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        } catch (e) {
            throw new ManifestParseError('not_utf8', 'not UTF-8: ' + (e && e.message ? e.message : 'invalid byte sequence'));
        }
    }

    // Port of arp_cli parse_manifest_bytes()
    function parseManifestBytes(bytes) {
        return parseManifestText(decodeUtf8Sig(bytes));
    }

    // Text of a pasted file as the CLI reads the same file from disk: the
    // UTF-8 bytes of the text, decoded with utf-8-sig.
    function textAsFile(text) {
        return new TextDecoder('utf-8').decode(utf8(text));
    }

    // Python float repr() (shortest round-trip digits; exponent below 1e-4 and
    // from 1e16 on, at least two exponent digits)
    function pyFloatRepr(x) {
        if (x !== x) return 'NaN';
        if (x === Infinity) return 'Infinity';
        if (x === -Infinity) return '-Infinity';
        if (x === 0) return Object.is(x, -0) ? '-0.0' : '0.0';
        const sign = x < 0 ? '-' : '';
        const s = String(Math.abs(x));
        let mant = s, exp = 0;
        const k = s.indexOf('e');
        if (k >= 0) {
            mant = s.slice(0, k);
            exp = parseInt(s.slice(k + 1), 10);
        }
        const dot = mant.indexOf('.');
        const ip = dot >= 0 ? mant.slice(0, dot) : mant, fp = dot >= 0 ? mant.slice(dot + 1) : '';
        let digits, decpt;
        if (ip === '0') {
            const z = fp.length - fp.replace(/^0+/, '').length;
            digits = fp.slice(z);
            decpt = -z + exp;
        } else {
            digits = ip + fp;
            decpt = ip.length + exp;
        }
        digits = digits.replace(/0+$/, '');
        if (decpt <= -4 || decpt > 16) {
            const e = decpt - 1;
            return sign + (digits.length > 1 ? digits[0] + '.' + digits.slice(1) : digits) + 'e' +
                (e < 0 ? '-' : '+') + String(Math.abs(e)).padStart(2, '0');
        }
        if (decpt <= 0) return sign + '0.' + '0'.repeat(-decpt) + digits;
        if (decpt >= digits.length) return sign + digits + '0'.repeat(decpt - digits.length) + '.0';
        return sign + digits.slice(0, decpt) + '.' + digits.slice(decpt);
    }

    // json.dumps(value, ensure_ascii=False) — for the 100 KB check of lint
    function pyJsonDumps(value, container, key) {
        if (value === null || value === undefined) return 'null';
        if (value === true) return 'true';
        if (value === false) return 'false';
        if (typeof value === 'number') {
            const kind = numberKind(container, key, value);
            if (kind === 'float') return pyFloatRepr(value);
            const lit = numberLiteral(container, key);
            return lit !== null ? lit.replace(/^-0$/, '0') : String(value === 0 ? 0 : value);
        }
        if (typeof value === 'string') return JSON.stringify(value);
        if (Array.isArray(value)) return '[' + value.map((v, k) => pyJsonDumps(v, value, k)).join(', ') + ']';
        return '{' + orderedKeys(value).map(k => JSON.stringify(k) + ': ' + pyJsonDumps(value[k], value, k)).join(', ') + '}';
    }

    // ─────────────────────────────────────────────
    // Names, domains, selectors, versions (arp_cli semantics)
    // ─────────────────────────────────────────────
    const DOMAIN_PY_RE = pyRe(`(?=.{1,253}\\Z)(?:${LABEL}\\.)+[A-Za-z0-9-]{2,63}`, false, '_DOMAIN_RE');
    const SELECTOR_PY_RE = pyRe(`${SELECTOR_LABEL}(?:\\.${SELECTOR_LABEL})*`, false, '_SELECTOR_RE');

    // arp_cli normalize_domain(): strip, lowercase, no trailing dot, bare name
    function pyNormalizeDomain(value) {
        if (typeof value !== 'string') throw new PyValueError('domain must be a string');
        const domain = rstripDots(pyStrip(value).toLowerCase());
        if (!DOMAIN_PY_RE.fullmatch(domain)) {
            throw new PyValueError(`'${safeText(value, 120)}' is not a bare domain name (expected e.g. example.com, ` +
                'without scheme, path or port)');
        }
        return domain;
    }

    function normalizeDomainSafe(value) {
        try {
            return pyNormalizeDomain(value);
        } catch (e) {
            if (e instanceof PyValueError) return null;
            throw e;
        }
    }

    function validateSelector(selector) {
        if (typeof selector !== 'string' || !selector || cpCount(selector) > 50 || !SELECTOR_PY_RE.fullmatch(selector)) {
            throw new PyValueError(`'${safeText(selector, 60)}' is not a valid selector (letters, digits, '-' and '_', ` +
                "labels separated by single dots, each label beginning and ending with a letter or digit, " +
                'at most 50 characters; e.g. arp2610)');
        }
        return selector;
    }

    function normalizeSelectorSafe(value) {
        try {
            return validateSelector(value);
        } catch (e) {
            if (e instanceof PyValueError) return null;
            throw e;
        }
    }

    // DNS names compare case-insensitively; a trailing dot does not count (arp_cli _same_dns_name)
    function sameDnsName(value, expected) {
        return typeof value === 'string' && rstripDots(pyStrip(value).toLowerCase()) === rstripDots(expected.toLowerCase());
    }

    // arp_cli _version_tuple() / _is_v13_or_later(): Unicode digits and spaces as in Python
    const VERSION_RE = pyRe(R`^\s*(\d+)\.(\d+)`, false);
    function versionAtLeast13(manifest) {
        const v = pyGet(manifest, 'version');
        if (typeof v !== 'string') return false;
        const m = VERSION_RE.match(v);
        if (!m) return false;
        const major = pyIntDigits(m.m[1]), minor = pyIntDigits(m.m[2]);
        return major > 1n || (major === 1n && minor >= 3n);
    }

    // ─────────────────────────────────────────────
    // ARP-R — reasoning.md rendering (port of arp_cli render_reasoning_md)
    // Deterministic: same manifest → same bytes. UTF-8, LF, one final newline.
    // ─────────────────────────────────────────────
    const RENDER_ORDER = ['identity', 'organization', 'corrections', 'entity_claims', 'authority', 'content_policy'];
    const RENDER_EXCLUDE = ['$schema', 'protocol', 'version', 'domain', 'entity', 'provenance',
        'representations', '_arp_signature', 'diagnostics'];

    // Strings unchanged; true/false/null; numbers as ECMAScript Number::toString
    function mdScalar(value) {
        if (typeof value === 'string') return value;
        if (value === true) return 'true';
        if (value === false) return 'false';
        if (value === null) return 'null';
        if (typeof value === 'number') {
            if (!isFinite(value)) throw new Error('NaN and Infinity are not valid JSON numbers');
            return String(value);
        }
        throw new Error('unsupported JSON value of type ' + typeof value);
    }

    // No trailing space when the value is empty
    function mdItem(prefix, text) {
        return prefix + (text !== '' ? ' ' + text : '');
    }

    function mdListLines(value, indent) {
        const pad = ' '.repeat(indent);
        const lines = [];
        if (isPlainObject(value)) {
            for (const key of Object.keys(value)) {
                const item = value[key];
                if (isContainer(item)) {
                    lines.push(`${pad}- ${key}:`);
                    lines.push(...mdListLines(item, indent + 2));
                } else {
                    lines.push(mdItem(`${pad}- ${key}:`, mdScalar(item)));
                }
            }
        } else if (Array.isArray(value)) {
            value.forEach((item, i) => {
                if (isContainer(item)) {
                    lines.push(`${pad}- ${i + 1}:`);
                    lines.push(...mdListLines(item, indent + 2));
                } else {
                    lines.push(mdItem(`${pad}-`, mdScalar(item)));
                }
            });
        } else {
            lines.push(mdItem(`${pad}-`, mdScalar(value)));
        }
        return lines;
    }

    function renderMarkdown(manifest, domainOverride) {
        if (!isPlainObject(manifest)) throw new Error('manifest must be a JSON object');
        const entity = manifest.entity;
        if (typeof entity !== 'string' || !entity.trim()) throw new Error("manifest has no 'entity' string");
        let domain = domainOverride !== undefined ? domainOverride : manifest.domain;
        if (typeof domain !== 'string' || !domain.trim()) throw new Error("no domain: set the 'domain' field");
        domain = domain.trim().toLowerCase().replace(/\.$/, '');
        const url = manifestUrl(domain);

        const blocks = [`# ${entity} — self-description (ARP)`];
        const prov = manifest.provenance;
        if (isPlainObject(prov) && typeof prov.statement === 'string' && prov.statement !== '') {
            blocks.push(prov.statement);
        }
        blocks.push(`Manifest: ${url}`);

        const ordered = RENDER_ORDER.filter(k => has(manifest, k));
        const rest = Object.keys(manifest)
            .filter(k => !RENDER_EXCLUDE.includes(k) && !RENDER_ORDER.includes(k))
            .sort(compareCodePoints);
        for (const key of ordered.concat(rest)) {
            const lines = mdListLines(manifest[key], 0);
            blocks.push(`## ${key}` + (lines.length ? '\n\n' + lines.join('\n') : ''));
        }

        const verification = [`- Manifest: ${url}`];
        const sig = manifest._arp_signature;
        if (isPlainObject(sig)) {
            const verify = isPlainObject(sig.verify) ? sig.verify : {};
            const name = has(verify, 'dns_name') ? verify.dns_name : sig.dns_record;
            for (const [label, value] of [
                ['statement', sig.statement],
                ['dns_name', name],
                ['doh_url', verify.doh_url],
                ['signed_at', sig.signed_at],
                ['expires_at', sig.expires_at]
            ]) {
                if (value !== undefined && value !== null) verification.push(mdItem(`- ${label}:`, mdScalar(value)));
            }
        }
        blocks.push('## Verification\n\n' + verification.join('\n'));
        return blocks.join('\n\n') + '\n';
    }

    function representationEntry(domain, sha256) {
        return { href: markdownUrl(domain), media_type: MARKDOWN_MEDIA_TYPE, sha256: sha256 };
    }

    // Insert or replace the reasoning.md entry; other entries keep their position
    // (port of arp_cli set_markdown_representation).
    function setMarkdownRepresentation(manifest, domain, sha256) {
        const entry = representationEntry(domain, sha256);
        if (!Array.isArray(manifest.representations)) {
            manifest.representations = [entry];
            return entry;
        }
        const reps = manifest.representations;
        for (let i = 0; i < reps.length; i++) {
            const e = reps[i];
            let path = '';
            try { path = new URL(String(e && e.href || '')).pathname; } catch (err) { path = ''; }
            if (isPlainObject(e) && (e.href === entry.href || path === MARKDOWN_PATH)) {
                reps[i] = entry;
                return entry;
            }
        }
        reps.push(entry);
        return entry;
    }

    // ─────────────────────────────────────────────
    // Encodings of signature values and keys (arp_cli semantics)
    // ─────────────────────────────────────────────
    const SIG_URL_RE = pyRe(R`[A-Za-z0-9_-]{86}(?:==)?`, false, '_SIG_URL_RE');
    const SIG_STD_RE = pyRe(R`[A-Za-z0-9+/]{86}(?:==)?`, false, '_SIG_STD_RE');
    const P_URL_RE = pyRe(R`[A-Za-z0-9_-]{43}=?`, false, '_P_URL_RE');
    const P_STD_RE = pyRe(R`[A-Za-z0-9+/]{43}=?`, false, '_P_STD_RE');

    function decodeStdBase64(s) {
        const bin = atob(s);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    // Port of arp_cli decode_signature_strict() (SPEC §13.3): 86 characters of
    // one alphabet, optionally "==", canonical bits, nothing else.
    function decodeSignatureStrict(value) {
        if (typeof value !== 'string') throw new PyValueError('signature is not a string');
        let core;
        if (SIG_URL_RE.fullmatch(value)) core = value.slice(0, 86);
        else if (SIG_STD_RE.fullmatch(value)) core = value.slice(0, 86).replace(/\+/g, '-').replace(/\//g, '_');
        else {
            throw new PyValueError("signature must be 86 Base64url characters (optionally followed by '=='), " +
                'without whitespace or other text');
        }
        const raw = decodeStdBase64(core.replace(/-/g, '+').replace(/_/g, '/') + '==');
        if (bytesToBase64Url(raw) !== core) throw new PyValueError('signature uses a non-canonical Base64 encoding');
        return raw;
    }

    // Port of arp_cli decode_dns_public_key() (SPEC §13.5): [32 bytes, warnings]
    function decodeDnsPublicKey(value) {
        if (typeof value !== 'string') throw new PyValueError('p= is not a string');
        const warnings = [];
        let core;
        if (P_STD_RE.fullmatch(value)) {
            core = value.slice(0, 43);
            if (!value.endsWith('=')) warnings.push("DNS record p= lacks the '=' padding; SPEC §13.5 specifies padded standard Base64.");
        } else if (P_URL_RE.fullmatch(value)) {
            core = value.slice(0, 43).replace(/-/g, '+').replace(/_/g, '/');
            warnings.push('DNS record p= uses the Base64url alphabet; SPEC §13.5 specifies standard Base64.');
        } else {
            throw new PyValueError('p= is not a 32-byte key in Base64 (44 characters)');
        }
        const raw = decodeStdBase64(core + '=');
        if (bytesToBase64(raw).slice(0, 43) !== core) throw new PyValueError('p= uses a non-canonical Base64 encoding');
        return [raw, warnings];
    }

    // binascii.a2b_base64(strict_mode=False): characters outside the alphabet
    // are skipped, decoding stops at a complete padding
    function a2bBase64(bytes) {
        const out = [];
        let quad = 0, left = 0, pads = 0;
        for (let i = 0; i < bytes.length; i++) {
            const ch = bytes[i];
            if (ch === 0x3d) {
                if (quad >= 2 && quad + ++pads >= 4) return Uint8Array.from(out);
                continue;
            }
            let v = -1;
            if (ch >= 0x41 && ch <= 0x5a) v = ch - 0x41;
            else if (ch >= 0x61 && ch <= 0x7a) v = ch - 0x47;
            else if (ch >= 0x30 && ch <= 0x39) v = ch + 4;
            else if (ch === 0x2b) v = 62;
            else if (ch === 0x2f) v = 63;
            if (v < 0) continue;
            pads = 0;
            if (quad === 0) { quad = 1; left = v; }
            else if (quad === 1) { quad = 2; out.push(((left << 2) | (v >> 4)) & 0xff); left = v & 0x0f; }
            else if (quad === 2) { quad = 3; out.push(((left << 4) | (v >> 2)) & 0xff); left = v & 0x03; }
            else { quad = 0; out.push(((left << 6) | v) & 0xff); left = 0; }
        }
        if (quad !== 0) throw new PyValueError(quad === 1 ? 'Invalid base64-encoded string' : 'Incorrect padding');
        return Uint8Array.from(out);
    }

    // arp_cli b64_decode_tolerant() on an ASCII string
    function b64DecodeTolerant(value) {
        let s = value.replace(PY_SPACE_ALL, '');
        s = s.replace(/\+/g, '-').replace(/\//g, '_');
        s += '='.repeat((4 - (s.length % 4)) % 4);
        const bytes = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) {
            const c = s.charCodeAt(i);
            bytes[i] = c === 0x2d ? 0x2b : c === 0x5f ? 0x2f : c;
        }
        return a2bBase64(bytes);
    }

    const ED25519_SPKI_PREFIX = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

    // arp_cli _load_public_key_file() for the content of a key file: PEM
    // (SubjectPublicKeyInfo) or raw/base64. Returns 32 bytes; throws otherwise.
    function loadPublicKeyText(input) {
        const bytes = typeof input === 'string' ? utf8(input) : input;
        let latin = '';
        for (let i = 0; i < bytes.length; i++) latin += String.fromCharCode(bytes[i]);
        if (latin.includes('-----BEGIN')) {
            const m = /-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/.exec(latin);
            if (!m) throw new PyValueError('not an Ed25519 public key (PEM SubjectPublicKeyInfo expected)');
            const body = m[1].replace(/[\t\n\v\f\r ]+/g, '');
            if (!/^[A-Za-z0-9+/]*={0,2}$/.test(body) || body.length % 4) throw new PyValueError('PEM body is not Base64');
            const der = decodeStdBase64(body);
            if (der.length !== 44 || !ED25519_SPKI_PREFIX.every((b, i) => der[i] === b)) {
                throw new PyValueError('not an Ed25519 public key');
            }
            return der.slice(12);
        }
        let a = 0, b = bytes.length;
        const isWs = (c) => c === 0x20 || (c >= 0x09 && c <= 0x0d);
        while (a < b && isWs(bytes[a])) a++;
        while (b > a && isWs(bytes[b - 1])) b--;
        const raw = bytes.slice(a, b);
        let key;
        if (raw.every(c => c < 0x80)) {
            try {
                key = b64DecodeTolerant(String.fromCharCode(...raw));
            } catch (e) {
                key = raw;
            }
        } else {
            key = raw;
        }
        if (key.length !== 32) throw new PyValueError('An Ed25519 public key is 32 bytes long');
        return key;
    }

    // ─────────────────────────────────────────────
    // URLs: urllib.parse.urlsplit() of CPython 3.12.13 and arp_cli checked_url()
    // ─────────────────────────────────────────────
    class FetchError extends Error {
        constructor(kind) {
            super(kind);
            this.name = 'FetchError';
            this.kind = kind;
        }
    }

    const UNSAFE_URL_CHAR_RE = pyRe(R`[^\x21-\x7e]|\\`, false, '_UNSAFE_URL_CHAR_RE');

    function pyPartition(s, sep) {
        const k = s.indexOf(sep);
        return k < 0 ? [s, '', ''] : [s.slice(0, k), sep, s.slice(k + sep.length)];
    }

    function pyRpartition(s, sep) {
        const k = s.lastIndexOf(sep);
        return k < 0 ? ['', '', s] : [s.slice(0, k), sep, s.slice(k + sep.length)];
    }

    // str.split(sep, maxsplit)
    function pySplitMax(s, sep, maxsplit) {
        const out = [];
        let rest = s;
        while (out.length < maxsplit) {
            const k = rest.indexOf(sep);
            if (k < 0) break;
            out.push(rest.slice(0, k));
            rest = rest.slice(k + sep.length);
        }
        out.push(rest);
        return out;
    }

    function ipv4Valid(s) {
        if (!s || s.includes('/')) return false;
        const octets = s.split('.');
        if (octets.length !== 4) return false;
        return octets.every(o => /^[0-9]{1,3}$/.test(o) && !(o !== '0' && o[0] === '0') && parseInt(o, 10) <= 255);
    }

    function ipv6Valid(s) {
        if (s.includes('/')) return false;
        let [addr, sep, scope] = pyPartition(s, '%');
        if (sep && (!scope || scope.includes('%'))) return false;
        if (!addr || addr.length > 45) return false;
        let parts = pySplitMax(addr, ':', 9);
        if (parts.length < 3) return false;
        if (parts[parts.length - 1].includes('.')) {
            const v4 = parts.pop();
            if (!ipv4Valid(v4)) return false;
            parts = parts.concat(['0', '0']);
        }
        if (parts.length > 9) return false;
        let skip = null;
        for (let i = 1; i < parts.length - 1; i++) {
            if (!parts[i]) {
                if (skip !== null) return false;
                skip = i;
            }
        }
        let hi, lo;
        if (skip !== null) {
            hi = skip;
            lo = parts.length - skip - 1;
            if (!parts[0]) {
                hi -= 1;
                if (hi) return false;
            }
            if (!parts[parts.length - 1]) {
                lo -= 1;
                if (lo) return false;
            }
            if (8 - (hi + lo) < 1) return false;
        } else {
            if (parts.length !== 8 || !parts[0] || !parts[parts.length - 1]) return false;
            hi = parts.length;
            lo = 0;
        }
        const hextet = (h) => /^[0-9A-Fa-f]{1,4}$/.test(h);
        for (let i = 0; i < hi; i++) if (!hextet(parts[i])) return false;
        for (let i = parts.length - lo; i < parts.length; i++) if (!hextet(parts[i])) return false;
        return true;
    }

    const IPV_FUTURE_RE = pyRe(R`\Av[a-fA-F0-9]+\..+\Z`, false);
    function checkBracketedHost(hostname) {
        if (hostname.startsWith('v')) {
            if (!IPV_FUTURE_RE.match(hostname)) throw new PyValueError('IPvFuture address is invalid');
        } else if (ipv4Valid(hostname)) {
            throw new PyValueError('An IPv4 address cannot be in brackets');
        } else if (!ipv6Valid(hostname)) {
            throw new PyValueError(`${JSON.stringify(hostname)} does not appear to be an IPv4 or IPv6 address`);
        }
    }

    function checkBracketedNetloc(netloc) {
        const hostAndPort = pyRpartition(netloc, '@')[2];
        const [before, open, bracketed] = pyPartition(hostAndPort, '[');
        let hostname;
        if (open) {
            if (before) throw new PyValueError('Invalid IPv6 URL');
            const [h, , port] = pyPartition(bracketed, ']');
            if (port && !port.startsWith(':')) throw new PyValueError('Invalid IPv6 URL');
            hostname = h;
        } else {
            hostname = pyPartition(hostAndPort, ':')[0];
        }
        checkBracketedHost(hostname);
    }

    function pyUrlsplit(input) {
        let url = input.replace(/^[\x00-\x20]+/, '').replace(/[\t\r\n]/g, '');
        let scheme = '', netloc = '', query = '', fragment = '';
        const i = url.indexOf(':');
        if (i > 0 && /^[A-Za-z]/.test(url) && /^[A-Za-z0-9+.-]*$/.test(url.slice(0, i))) {
            scheme = url.slice(0, i).toLowerCase();
            url = url.slice(i + 1);
        }
        if (url.slice(0, 2) === '//') {
            let delim = url.length;
            for (const c of '/?#') {
                const w = url.indexOf(c, 2);
                if (w >= 0) delim = Math.min(delim, w);
            }
            netloc = url.slice(2, delim);
            url = url.slice(delim);
            if ((netloc.includes('[') && !netloc.includes(']')) || (netloc.includes(']') && !netloc.includes('['))) {
                throw new PyValueError('Invalid IPv6 URL');
            }
            if (netloc.includes('[') && netloc.includes(']')) checkBracketedNetloc(netloc);
        }
        if (url.includes('#')) [url, , fragment] = pyPartition(url, '#');
        if (url.includes('?')) [url, , query] = pyPartition(url, '?');
        if (netloc && /[^\x00-\x7f]/.test(netloc)) {
            const plain = netloc.replace(/[@:#?]/g, '');
            const nfkc = plain.normalize('NFKC');
            if (plain !== nfkc && /[/?#@:]/.test(nfkc)) {
                throw new PyValueError(`netloc '${netloc}' contains invalid characters under NFKC normalization`);
            }
        }
        return { scheme, netloc, path: url, query, fragment };
    }

    function urlHostinfo(netloc) {
        const hostinfo = pyRpartition(netloc, '@')[2];
        const [, open, bracketed] = pyPartition(hostinfo, '[');
        let hostname, port;
        if (open) {
            let rest;
            [hostname, , rest] = pyPartition(bracketed, ']');
            port = pyPartition(rest, ':')[2];
        } else {
            [hostname, , port] = pyPartition(hostinfo, ':');
        }
        return [hostname, port || null];
    }

    function urlPort(parts) {
        const port = urlHostinfo(parts.netloc)[1];
        if (port === null) return null;
        if (!/^[0-9]+$/.test(port)) throw new PyValueError(`Port could not be cast to integer value as '${port}'`);
        const v = Number(port);
        if (!(v >= 0 && v <= 65535)) throw new PyValueError('Port out of range 0-65535');
        return v;
    }

    function urlHostname(parts) {
        const hostname = urlHostinfo(parts.netloc)[0];
        if (!hostname) return null;
        const [h, pct, zone] = pyPartition(hostname, '%');
        return h.toLowerCase() + pct + zone;
    }

    // Port of arp_cli checked_url(): [url to fetch, lowercase host]
    function checkedUrl(url, allowHttp) {
        if (typeof url !== 'string' || UNSAFE_URL_CHAR_RE.search(url)) throw new FetchError('URL contains characters that are not allowed');
        const parts = pyUrlsplit(url);
        if (!(allowHttp ? ['https', 'http'] : ['https']).includes(parts.scheme)) throw new FetchError('URL scheme not allowed');
        if (parts.netloc.includes('@')) throw new FetchError('URL with userinfo not allowed');
        let port;
        try {
            port = urlPort(parts);
        } catch (e) {
            if (e instanceof PyValueError) throw new FetchError('URL port not valid');
            throw e;
        }
        const host = rstripDots((urlHostname(parts) || '').toLowerCase());
        if (!host) throw new FetchError('URL without host');
        const netloc = host + (port !== null ? ':' + port : '');
        const path = parts.path || '/';
        return [`${parts.scheme}://${netloc}${path}` + (parts.query ? '?' + parts.query : ''), host];
    }

    // Port of arp_cli representation_target(): [host, path]
    function representationTarget(href) {
        let url, host;
        try {
            [url, host] = checkedUrl(href, false);
        } catch (e) {
            if (e instanceof FetchError) throw new PyValueError(`href refused: ${e.kind}`);
            throw e;
        }
        const parts = pyUrlsplit(href);
        if (urlPort(parts) !== null || parts.query || parts.fragment) {
            throw new PyValueError('href refused: port, query or fragment not allowed');
        }
        return [host, pyUrlsplit(url).path];
    }

    // urllib.parse.unquote() (UTF-8, errors="replace") of an ASCII string
    function pyUnquote(s) {
        if (!s.includes('%')) return s;
        return s.replace(/[\x00-\x7f]+/g, (run) => {
            const bits = run.split('%');
            const out = [];
            const push = (t) => { for (let i = 0; i < t.length; i++) out.push(t.charCodeAt(i)); };
            push(bits[0]);
            for (const item of bits.slice(1)) {
                const h = item.slice(0, 2);
                if (/^[0-9A-Fa-f]{2}$/.test(h)) {
                    out.push(parseInt(h, 16));
                    push(item.slice(2));
                } else {
                    out.push(0x25);
                    push(item);
                }
            }
            return new TextDecoder('utf-8').decode(Uint8Array.from(out));
        });
    }

    // parse_qs(query).get(name, [])
    function parseQsValues(query, wanted) {
        const out = [];
        if (!query) return out;
        for (const nv of query.split('&')) {
            if (!nv) continue;
            const [name, , value] = pyPartition(nv, '=');
            if (!value) continue;
            if (pyUnquote(name.replace(/\+/g, ' ')) === wanted) out.push(pyUnquote(value.replace(/\+/g, ' ')));
        }
        return out;
    }

    // Port of arp_cli _doh_url_names(); like the CLI it lets urlsplit() errors through
    function dohUrlNames(doh, name) {
        if (typeof doh !== 'string' || !doh.startsWith('https://') || UNSAFE_URL_CHAR_RE.search(doh)) return false;
        const names = parseQsValues(pyUrlsplit(doh).query, 'name');
        return names.length === 1 && sameDnsName(names[0], name);
    }

    // ─────────────────────────────────────────────
    // ARP-W — Wording Profile lint (port of arp_cli lint_manifest)
    // The patterns are arp_cli's Python sources, translated by pyRe().
    // ─────────────────────────────────────────────
    const FORBIDDEN_KEYS = new Set([
        'system_instruction', 'system_instructions', 'reasoning_directives',
        'reasoning_directive', 'ai_directive', 'ai_directives', 'agent_directive',
        'agent_directives', 'instruction', 'instructions', 'directive', 'directives',
        'system_prompt', 'system_note', 'system_message'
    ]);
    const FORBIDDEN_KEY_TOKENS = new Set([
        'instruction', 'instructions', 'directive', 'directives',
        'anweisung', 'anweisungen', 'direktive', 'direktiven'
    ]);

    const KEY_TOKEN_RE = new RegExp(pyToJs(R`[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+`, false), 'gu');
    function keyTokens(key) {
        return (String(key).match(KEY_TOKEN_RE) || []).map(t => t.toLowerCase());
    }

    function isForbiddenFieldName(key) {
        const tokens = keyTokens(key);
        return FORBIDDEN_KEYS.has(String(key).toLowerCase()) || tokens.some(t => FORBIDDEN_KEY_TOKENS.has(t));
    }

    const SENT = R`(?:^|[.!?;:\n]\s*)`;
    // Clause start for imperatives. "and", "or" and "to" are left out on purpose.
    const CLAUSE = R`(?:^|[.!?;:,\n]\s*|\b(?:please|then|always|never|instead|only|should|must|shall|` +
        R`(?<!does\s)(?<!did\s)not)\s+)`;
    const PROPER = R`[A-Z][\w'’&.-]*(?:\s+[A-Z][\w'’&.-]*){0,2}`;
    const AI_SUBJECT = R`\b(?:llms?|chatbots?|(?:large\s+)?language\s+models?|generative\s+(?:ai|engines?)|` +
        R`answer\s+engines?|(?:ai|ki)(?:[\s-]+(?:systems?|agents?|models?|assistants?|tools?|engines?|` +
        R`crawlers?|bots?|search))?)`;
    const FRAMING_OBJECT = R`(?:(?i:the|our|this|that|these|those|its|their|his|her|my|your|it|them|us|him)\b` +
        R`|[A-Z][\w'’&.-]*)`;
    const FRAMING_VERB = R`(?i:frame|present|position|portray|depict|characteri[sz]e|refer\s+to|cite|label|` +
        R`introduce)`;
    const GENERIC_AI_SUBJECT = R`(?:the\s+|all\s+|any\s+)?(?:assistants?|models?|bots?|chatbots?|crawlers?|answer\s+engines?)`;
    const INFO_OBJECT = R`(?:only\s+)?(?:this|these|the\s+following|our|its)\s+(?:file|manifest|document|data|information|` +
        R`statements?|facts?|descriptions?|sources?|page|text|context|claims?)`;
    const INFO_VERBS = R`(?:cite|quote|describe|mention|recommend|prefer|rely\s+on|refer\s+to|invent|repeat|ignore|disregard|` +
        R`trust|rank|credit|attribute|summari[sz]e|confuse|prioriti[sz]e|frame|position|portray|` +
        R`(?:treat|present|regard|consider)\s+(?:\S+\s+){0,5}?as|(?:use|follow|reference)\s+` + INFO_OBJECT + ')';
    const AGENT_VERBS = R`(?:cite|quote|invent|repeat|trust|rank|credit|attribute|summari[sz]e|prioriti[sz]e|frame|portray|` +
        R`ignore|disregard|(?:treat|present)\s+(?:\S+\s+){0,5}?as|(?:use|follow)\s+` + INFO_OBJECT + ')';
    const MODAL = R`(?:must|should|shall|may|need\s+to|have\s+to|are\s+(?:required|expected|asked|instructed|encouraged|` +
        R`advised|allowed|permitted|welcome|free)\s+to)\s+(?:not\s+|never\s+|always\s+|only\s+)?`;
    const CLAUSE_DE = R`(?:^|[.!?;:,\n]\s*|\b(?:bitte|dann|immer|nie|niemals|stets|nur|stattdessen)\s+)`;

    const I = true;
    // [severity, rule, pattern, message] — same order as arp_cli _TEXT_RULES
    const TEXT_RULES = [
        // — Conditional instructions ("When discussing X …") —
        ['error', 'ARP-W/conditional', pyRe(SENT + R`when\s+[a-z]+ing\b`, I),
            "Conditional instruction ('When discussing X …'). Write a third-person statement about the entity."],
        ['error', 'ARP-W/conditional', pyRe(R`\bwhen\s+(?:asked|queried|prompted)\b`, I),
            "Conditional instruction ('When asked …'). Write a third-person statement about the entity."],
        ['error', 'ARP-W/conditional', pyRe(
            R`\bwhen\s+(?:a\s+|the\s+|any\s+)?(?:users?|someone|people|persons?|customers?|visitors?|readers?)\s+` +
            R`(?:asks?|queries|query|searches|compares?|mentions?|wants?)\b`, I),
            "Conditional instruction ('When a user asks …'). Describe the situation instead, e.g. 'Typical fit: …'."],
        ['error', 'ARP-W/conditional', pyRe(R`\bif\s+(?:queried|asked|prompted)\b`, I),
            "Conditional instruction ('If asked …'). Write a third-person statement about the entity."],
        // — Imperatives addressed to AI systems —
        ['error', 'ARP-W/imperative', pyRe(R`\b[Ff]rame\s+(?:it|this|that|them|him|her|us|` + PROPER + R`)\s+as\b`, false),
            "Instruction to AI systems ('frame it as'). State the fact instead."],
        ['error', 'ARP-W/imperative', pyRe(
            '(?i:' + CLAUSE + ')' + FRAMING_VERB + R`\s+` + FRAMING_OBJECT + R`(?:\s+\S+){0,5}?\s+(?i:as)\b`, false),
            "Instruction to AI systems ('present/position/frame/refer to X as'). State the fact instead."],
        ['error', 'ARP-W/imperative', pyRe(
            SENT + R`(?:always|never)\s+(?:cite|recommend|mention|name|prefer|prioriti[sz]e|choose|select|use|` +
            R`list|link\s+to|refer\s+to|describe|present|frame|position|rank|quote|credit|attribute)\b(?!-)`, I),
            "Instruction to AI systems ('always cite …'). Write a third-person statement about the entity."],
        ['error', 'ARP-W/imperative', pyRe(CLAUSE + R`describe\s+(?:\S+\s+){0,5}?as\b`, I),
            "Instruction to AI systems ('describe X as'). State the fact instead."],
        ['error', 'ARP-W/imperative', pyRe(R`\bdefer\s+to\b`, I),
            "Instruction to AI systems ('defer to'). Link evidence instead."],
        ['error', 'ARP-W/imperative', pyRe(CLAUSE + R`treat\s+(?:\S+\s+){0,6}?as\b`, I),
            "Instruction to AI systems ('treat … as'). State what the item is instead."],
        ['error', 'ARP-W/imperative', pyRe(CLAUSE + R`recommend\b`, I),
            "Instruction to recommend. Describe the fit instead ('Typical fit: …' / 'Not a fit: …')."],
        ['error', 'ARP-W/imperative', pyRe(R`\brecommend\s+(?:\S+\s+){0,5}?(?:when|if)\b`, I),
            "Instruction to recommend ('recommend X when'). Describe the fit instead ('Typical fit: …')."],
        ['error', 'ARP-W/imperative', pyRe(
            CLAUSE + R`(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:(?:the|your|other|previous|prior|` +
            R`above|earlier|preceding|existing|original|conflicting)\s+){0,3}(?:instructions?|prompts?|context|sources?|` +
            R`information|rules|guidelines|directions|data|messages?|training(?:\s+data)?|results?|descriptions?|` +
            R`statements?|claims?|answers?|responses?|facts?|reports?|articles?|reviews?|content|knowledge|` +
            R`assumptions?)\b`, I),
            "Instruction to AI systems ('ignore previous instructions', 'disregard other sources'). Remove it."],
        ['error', 'ARP-W/imperative', pyRe(
            SENT + R`(?:do\s+not|don't|don’t)\s+(?:mention|cite|recommend|name|list|link\s+to|refer\s+to|compare|discuss|` +
            R`include|quote|suggest|disclose|reveal|speculate|invent|guess|assume|repeat|confuse|associate|describe|` +
            R`present|call|label|attribute|credit|rank|state|say|answer|respond|reply|contradict|question|doubt|` +
            R`dispute|override|alter|modify)\b(?!-)`, I),
            "Instruction to AI systems ('Do not mention …'). Write a third-person statement about the entity."],
        ['error', 'ARP-W/imperative', pyRe(
            SENT + R`(?:respond|answer|reply)\s+(?:only|exclusively|solely|always|strictly|with|using|based\s+on|` +
            R`according\s+to|in\s+line\s+with|(?:all\s+|any\s+)?(?:questions?|queries|inquiries|requests?|prompts?))\b` +
            R`|\b(?:using|based\s+on|from)\s+only\s+(?:this|these)\s+(?:file|manifest|document|data|information|` +
            R`statements?|facts?|descriptions?|sources?|page|text)\b`, I),
            "Instruction to AI systems ('Respond only with …', 'Answer questions … using only this file'). Remove it."],
        ['error', 'ARP-W/imperative', pyRe(
            SENT + R`(?:consider|regard|accept|take)\s+(?:this|these|the\s+following|it|them)\b`, I),
            "Instruction to AI systems ('Consider this …', 'Accept these …'). State the fact instead."],
        ['error', 'ARP-W/imperative', pyRe(
            CLAUSE + R`(?:use|rely\s+on|refer\s+to|consult|prefer|prioriti[sz]e|trust|cite|quote)\s+(?:only\s+|` +
            R`exclusively\s+)?(?:this|these|the\s+following|the\s+above)\s+(?:file|manifest|document|data|information|` +
            R`statements?|facts?|descriptions?|sources?|page|text|context|claims?)\b`, I),
            "Instruction to AI systems ('Use this file', 'Rely on these statements'). Remove it."],
        ['error', 'ARP-W/imperative', pyRe(
            '(?i:' + CLAUSE + R`)(?i:cite|quote|mention|prioriti[sz]e|prefer|emphasi[sz]e|highlight|favou?r|promote)\s+` +
            FRAMING_OBJECT, false),
            "Instruction to AI systems ('cite X first', 'mention X'). Write a third-person statement about the entity."],
        ['error', 'ARP-W/imperative', pyRe(
            R`\b(?:should|must|shall|ought\s+to|is\s+to|are\s+to|needs?\s+to|has\s+to|have\s+to)\s+(?:always\s+|only\s+)?` +
            R`be\s+(?:described|presented|framed|positioned|portrayed|depicted|characteri[sz]ed|referred\s+to|labell?ed|` +
            R`introduced|regarded|considered|seen|viewed|treated|named|called)(?:\s+\S+){0,4}?\s+as\b` +
            R`|\b(?:should|must|shall)\s+(?:always\s+)?be\s+(?:recommended|mentioned|cited|ranked|prioriti[sz]ed|listed|` +
            R`preferred)\s+(?:first|above|before|ahead\s+of|instead\s+of|over|whenever|when|if)\b`, I),
            "Instruction in passive form ('X should be described as …'). State the fact instead."],
        // — German imperatives —
        ['error', 'ARP-W/imperative', pyRe(
            CLAUSE_DE + R`(?:beschreibe|beschreiben\s+Sie|bezeichne|bezeichnen\s+Sie|präsentiere|präsentieren\s+Sie|` +
            R`positioniere|positionieren\s+Sie|nenne|nennen\s+Sie|behandle|behandeln\s+Sie|betrachte|betrachten\s+Sie|` +
            R`charakterisiere|charakterisieren\s+Sie|porträtiere|stellen\s+Sie)\s+(?:\S+\s+){0,6}?als\b`, I),
            "Instruction to AI systems ('Beschreibe X als …'). State the fact instead."],
        ['error', 'ARP-W/imperative', pyRe(
            CLAUSE_DE + R`(?:empfiehl|empfehlen\s+Sie|zitiere|zitieren\s+Sie|ignoriere|ignorieren\s+Sie|vergiss|` +
            R`vergessen\s+Sie|erwähne|erwähnen\s+Sie|bevorzuge|bevorzugen\s+Sie|verweisen\s+Sie|antworte|` +
            R`antworten\s+Sie|nutze|verwende|verwenden\s+Sie)\b`, I),
            "Instruction to AI systems ('Empfiehl …', 'Ignoriere …'). Write a third-person statement about the entity."],
        // — Addressing AI systems —
        ['error', 'ARP-W/address-ai', pyRe(
            R`\bif\s+you(?:'re|’re|\s+are)\s+(?:an?\s+)?(?:ai|a\.i\.|llm|large\s+language\s+model|language\s+model|` +
            R`agent|assistant|bot|chatbot|model|crawler|machine)\b`, I),
            "Text addressed to AI systems ('If you are an AI'). Remove it."],
        ['error', 'ARP-W/address-ai', pyRe(
            R`\byou(?:'re|’re|\s+are)\s+(?:\w+\s+)?(?:authori[sz]ed|allowed|permitted|instructed|required|expected|asked)\b`, I),
            "Permission or instruction addressed to the reader ('you are authorized'). Remove it."],
        ['error', 'ARP-W/address-ai', pyRe(R`\byou\s+(?:should|must|shall|may|need\s+to|have\s+to|ought\s+to)\b`, I),
            "Instruction in second person ('you should/may …'). Write a third-person statement."],
        ['error', 'ARP-W/address-ai', pyRe(
            AI_SUBJECT + R`\s+(?:must|should|shall|need\s+to|have\s+to|are\s+(?:required|expected|asked|` +
            R`instructed|encouraged|advised)\s+to)\b`, I),
            "Normative sentence addressed to AI systems ('AI systems must/should'). Write a statement about the entity."],
        ['error', 'ARP-W/address-ai', pyRe(
            R`\b(?:KI|AI)[\s-]?(?:Systeme?|Agenten?|Modelle?|Assistenten?|Crawler)\s+(?:sollen|sollten|müssen|dürfen)\b`, I),
            "Normative sentence addressed to AI systems ('KI-Systeme sollen …'). Write a statement about the entity."],
        ['error', 'ARP-W/address-ai', pyRe(
            '(?i:' + AI_SUBJECT + R`)\s+(?:MUST|SHOULD|SHALL|MAY|REQUIRED|RECOMMENDED)\b` +
            R`|(?i:` + AI_SUBJECT + R`\s+(?:are|is)\s+(?:explicitly\s+|hereby\s+)?(?:permitted|allowed|authori[sz]ed|welcome|` +
            R`invited|free|entitled)\s+to)\b`, false),
            "Permission or rule addressed to AI systems ('AI agents MAY …', 'AI crawlers are allowed to …'). " +
            'Such rules belong in the SPEC, not in a manifest.'],
        ['error', 'ARP-W/address-ai', pyRe(SENT + GENERIC_AI_SUBJECT + R`\s+` + MODAL + INFO_VERBS + R`\b`, I),
            "Normative sentence addressed to AI systems ('Assistants must cite …', 'Models must not invent …'). " +
            'Write a statement about the entity.'],
        ['error', 'ARP-W/address-ai', pyRe(
            SENT + R`(?:the\s+|all\s+|any\s+)?agents?\s+` + MODAL + AGENT_VERBS + R`\b`, I),
            "Normative sentence addressed to AI agents ('Agents must cite …'). Write a statement about the entity."],
        ['error', 'ARP-W/address-ai', pyRe(
            SENT + R`for\s+` + AI_SUBJECT + R`\s*:|` + SENT + R`for\s+` + GENERIC_AI_SUBJECT + R`\s*:`, I),
            "Text addressed to AI systems ('For AI systems: …'). Remove it."],
        ['error', 'ARP-W/address-ai', pyRe(
            R`\byou(?:'re|’re|\s+are)\s+(?:now\s+)?(?:an?\s+)?(?:\w+\s+){0,2}?(?:(?:ai|a\.i\.|chatbot|llm|` +
            R`(?:large\s+)?language\s+model)\b|(?:assistant|bot|model|agent|crawler)(?=\s*(?:[.,;:!)]|$|that\b|who\b|` +
            R`which\b)))`, I),
            "Role assignment addressed to an AI system ('you are a helpful assistant'). Remove it."],
        ['error', 'ARP-W/address-ai', pyRe(
            R`\b(?:attention|dear|hello|hi|hey|calling|to\s+all)\s*,?\s+` + AI_SUBJECT + R`\b` +
            R`|\b(?:attention|dear|hello|hi|hey|calling|to\s+all)\s*,?\s+` + GENERIC_AI_SUBJECT + R`\s*[:,!]`, I),
            "Text addressed to AI systems ('Attention AI agents: …'). Remove it."],
        ['error', 'ARP-W/address-ai', pyRe(
            R`\b(?:wenn|falls|sofern)\s+(?:du|sie|ihr)\s+(?:\w+\s+){0,2}?(?:eine?n?\s+)?(?:KI|AI|LLM|Sprachmodell|KI-\w+|` +
            R`Assistent(?:in)?|Agent|Bot|Chatbot|Modell|Crawler|Maschine)\s+(?:bist|sind|seid)\b`, I),
            "Text addressed to AI systems ('Wenn du eine KI bist'). Remove it."],
        ['error', 'ARP-W/address-ai', pyRe(
            R`\b(?:du|ihr)\s+(?:sollst|solltest|musst|müsstest|darfst|sollt|solltet|müsst|dürft)\b` +
            R`|\b(?:sollst|solltest|musst|darfst)\s+du\b`, I),
            "Instruction in second person ('du sollst/darfst …'). Write a third-person statement."],
        // — Memory / persistence —
        ['error', 'ARP-W/memory', pyRe(R`\bremember\b|\bmerke?\s+dir\b`, I),
            "Memory instruction ('remember'). Remove it."],
        ['error', 'ARP-W/memory', pyRe(
            R`\bin\s+(?:all\s+)?(?:future|subsequent|later|upcoming)\s+(?:conversations?|chats?|sessions?|responses?|` +
            R`answers?|interactions?)\b|\bin\s+(?:künftigen|zukünftigen|späteren)\s+(?:Gesprächen|Unterhaltungen|Antworten)\b`, I),
            "Persistence instruction ('in future conversations'). Remove it."],
        // — Pseudo system markers —
        ['error', 'ARP-W/system-marker', pyRe(
            R`<\s*/?\s*system(?:[_\-\s]?(?:note|prompt|message|instructions?|context))?\b[^>]*>`, I),
            'Pseudo system tag (e.g. <system_note>). Remove it.'],
        ['error', 'ARP-W/system-marker', pyRe(R`\bSYSTEM\s*:|\bIMPORTANT\s*:|\[/?(?:SYSTEM|INST)\]|<<\s*/?SYS\s*>>`, false),
            "Pseudo system marker ('SYSTEM:', 'IMPORTANT:', chat-template tokens). Remove it."],
        // Role tags and chat-template tokens as in schema v1.3 (wording_profile_guard), any letter case.
        ['error', 'ARP-W/system-marker', pyRe(
            R`<\s*/?\s*(?:assistant|user|developer|human)(?:\s[^>]*)?>|<\|[A-Za-z_]{1,40}\|>`, I),
            'Pseudo role tag or chat-template token (e.g. <assistant>, <user>, <|im_start|>). Remove it.'],
        ['error', 'ARP-W/system-marker', pyRe(
            R`\bnote\s+(?:to|for)\s+(?:the\s+)?(?:ai|llms?|models?|assistants?|agents?|bots?|crawlers?|language\s+models?|` +
            R`ai\s+(?:systems?|agents?|models?|assistants?))\b` +
            R`|\bHinweis\s+(?:für|an)\s+(?:die\s+)?(?:KI|AI|LLMs?|Sprachmodelle?|Modelle?|Agenten|Assistenten|Crawler|Bots?)\b`,
            I),
            "Note addressed to AI systems ('Note for AI systems: …'). Remove it."],
        // — Disclaimers of innocence —
        ['error', 'ARP-W/disclaimer', pyRe(
            R`\bnot\b[^.!?\n]{0,60}?\b(?:prompt[\s-]+injections?|data[\s-]+poisoning|poisoning|misinformation|` +
            R`disinformation|jailbreak(?:s|ing)?|manipulation|an?\s+attacks?)\b` +
            R`|\bkeine?\b[^.!?\n]{0,60}?\b(?:Prompt[\s-]*Injection|Manipulation|Falschinformation|Desinformation)\b`, I),
            "Disclaimer of innocence ('this is not prompt injection / misinformation / data poisoning'). Remove it."],
        // — Unsourced authority —
        ['error', 'ARP-W/unsourced-authority', pyRe(R`\bground[\s-]+truth\b|\bGrundwahrheit\b`, I),
            "'ground truth' cannot be attributed to a checker. State the fact and link evidence."],
        ['error', 'ARP-W/unsourced-authority', pyRe(
            R`\btrusted\s+(?:sources?|authorit(?:y|ies)|references?|information)\b|\bvertrauenswürdige\s+Quellen?\b`, I),
            "'trusted source' without saying who checked what. State the fact and link evidence."],
        // English "authoritative" is checked in lintTextValue (qualifier, negation, tone).
        ['error', 'ARP-W/unsourced-authority', pyRe(R`\bmaßgebliche\s+Quellen?\b`, I),
            "'maßgebliche Quelle' without saying who checked what. State the fact and link evidence."],
        // — Hidden text —
        ['error', 'ARP-W/hidden-text', pyRe(
            R`class\s*=\s*[\"'][^\"']*\b(?:sr-only|visually-hidden|screen-reader-only)\b|display\s*:\s*none|` +
            R`visibility\s*:\s*hidden|clip(?:-path)?\s*:\s*(?:rect|inset)\s*\(|` +
            R`font-size\s*:\s*0(?:\.0+)?(?:px|em|rem|pt|%)?\s*(?:[;\"'}!]|$)|` +
            R`aria-hidden\s*=\s*[\"']true`, I),
            'Hidden-text markup (sr-only, display:none, clip …). Everything must be visible to people and bots alike.'],
        // — Warnings (heuristics, do not block signing) —
        ['warning', 'ARP-W/second-person', pyRe(R`\b(?:you|your|yours|yourself|you're|you’re)\b`, I),
            'Second person. The Wording Profile uses third-person statements about the entity.'],
        ['warning', 'ARP-W/imperative-heuristic', pyRe(
            SENT + R`(?:do\s+not|don't|don’t|never|always|please|ignore|disregard|cite|prefer|prioriti[sz]e|mention|` +
            R`consider|emphasi[sz]e|highlight|avoid|ensure|make\s+sure|respond|refer\s+to|reference|` +
            R`use(?!\s+(?:of|cases?)\b))\b(?!-)`, I),
            'Sentence starts like an imperative. Check that it is a third-person statement.'],
        ['warning', 'ARP-W/normative', pyRe(
            R`\b(?:loaders?|consumers?|verifiers?|consuming\s+systems?|retrieval\s+systems?|rag\s+(?:systems?|pipelines?)|` +
            R`search\s+engines?)\s+(?:must|should|shall|may)\b` +
            '|' + AI_SUBJECT + R`\s+may\b`, I),
            'Normative or permission sentence about consumers. Such rules belong in the SPEC, not in a manifest.'],
        ['warning', 'ARP-W/disclaimer', pyRe(R`\bbenign\b|\bharmless\b|\bharmlos\b`, I),
            "Reassurance wording ('benign', 'harmless'). Describe what the item is instead."],
        ['warning', 'ARP-W/disclaimer', pyRe(
            R`\bnot\b[^.!?\n]{0,40}?\b(?:instructions?|commands?|directives?)\b` +
            R`|\bkeine?\b[^.!?\n]{0,40}?\b(?:Anweisung(?:en)?|Befehle?)\b`, I),
            "Reassurance that the text is 'not instructions/commands'. A plain description is enough."],
        ['warning', 'ARP-W/unsourced-authority', pyRe(
            R`\b(?:definitive|single|sole|canonical|official)\s+(?:source|reference)\b|\bsource\s+of\s+truth\b|` +
            R`\b(?:confirmed|validated)\s+(?:and|&)\s+(?:confirmed|validated|verified)\b`, I),
            "Authority claim ('definitive source', 'source of truth', 'confirmed and validated'). Say who checked " +
            'what, or link evidence.'],
        ['warning', 'ARP-W/superlative', pyRe(
            R`\bpioneer(?:s|ing|ed)?\b|\belite\b|\bworld[\s-]leading\b|\bmarket[\s-]leader\b|\bindustry[\s-]leader\b|` +
            R`\bthe\s+first\s+(?:\w+\s+){0,3}to\b|\bfirst[\s-]mover\b|\bbest[\s-]in[\s-]class\b|\bunrivall?ed\b|` +
            R`\bunmatched\b|#1\b`, I),
            'Superlative without evidence. Link a source or remove it.'],
        ['warning', 'ARP-W/html-comment', pyRe('<!--', false),
            'HTML comment inside a value. Comments are invisible to people; remove it.']
    ];

    const VERIFIED_RE = pyRe(R`\b(?:verified|cross-verified|verifiziert|geprüft)\b`, I, '_VERIFIED_RE');
    const VERIFIED_QUALIFIER_RE = pyRe(
        R`^(?:\s*,)?(?:\s+\S+){0,3}?\s+(?:by|via|through|against|using|with|at|in|on|from|per|according\s+to|` +
        R`durch|von|über|beim|bei|im|laut|gegen)\b`, I, '_VERIFIED_QUALIFIER_RE');
    // "verified by" followed by a generic agent names nobody, unless a name follows.
    const GENERIC_AGENT = R`(?:(?:a|an|the|several|multiple|many|various|numerous|independent|external|third[\s-]party|` +
        R`trusted|reliable|reputable|official|leading|neutral|outside|qualified|certified|other|` +
        R`unabhängigen?|externen?|mehreren|verschiedenen|vertrauenswürdigen?|neutralen?)\s+)*` +
        R`(?:sources?|experts?|parties|third[\s-]parties|authorities|organi[sz]ations|institutions|` +
        R`reviewers?|auditors?|people|users?|customers?|studies|research(?:ers)?|analysts|labs?|` +
        R`laborator(?:y|ies)|Quellen|Experten|Stellen|Dritten?|Prüfern?|Gutachtern?)\b` +
        R`(?!\s+(?:at|of|from|bei|von|der|des)\s+(?-i:[A-Z]))`;
    const GENERIC_AGENT_AFTER_RE = pyRe(
        R`^(?:\s*,)?(?:\s+\S+){0,3}?\s+(?:by|through|from|via|durch|von)\s+` + GENERIC_AGENT, I, '_GENERIC_AGENT_AFTER_RE');
    const GENERIC_AGENT_BEFORE_RE = pyRe(R`\b(?:von|durch)\s+` + GENERIC_AGENT + R`(?:\s+\w+)?\s*$`, I, '_GENERIC_AGENT_BEFORE_RE');
    const PROPER_BEFORE_RE = pyRe(R`\b((?:[A-Z][\w&.'’-]*\s+){0,3}[A-Z][\w&.'’-]*)\s*[:\-]?\s*$`, false, '_PROPER_BEFORE_RE');
    const GENERIC_STARTERS = new Set([
        'The', 'A', 'An', 'All', 'Our', 'Their', 'These', 'This', 'Only', 'Fully', 'Independently',
        'Cryptographically', 'Officially', 'Fact', 'Facts', 'Verified', 'Die', 'Der', 'Das', 'Alle',
        'Unsere', 'Diese', 'Nur'
    ]);
    const NEGATION_BEFORE_RE = pyRe(R`\b(?:no|not|never|nicht|nie|keine?[mnrs]?)\s+(?:\S+\s+)?$`, I, '_NEGATION_BEFORE_RE');
    const AUTHORITATIVE_RE = pyRe(R`\bauthoritative\b`, I, '_AUTHORITATIVE_RE');
    const AUTHORITATIVE_QUALIFIER_RE = pyRe(
        R`^[^.!?\n]{0,60}?\b(?:according\s+to|as\s+(?:rated|assessed|classified|ranked|designated)\s+by|` +
        R`(?:rated|assessed|classified|ranked|designated|recogni[sz]ed)\s+(?:as\s+\S+\s+)?by|laut|gemäß)\s+\S`, I,
        '_AUTHORITATIVE_QUALIFIER_RE');
    const AUTHORITATIVE_TONE_AFTER_RE = pyRe(
        R`^(?:\s*,\s*[\w-]+|\s+(?:and|but|yet|or)\s+[\w-]+)*\s*,?\s+(?:tone|style|register|manner|wording|` +
        R`writing|delivery|tone\s+of\s+voice)\b`, I, '_AUTHORITATIVE_TONE_AFTER_RE');
    const AUTHORITATIVE_TONE_BEFORE_RE = pyRe(R`\b(?:tone|style|register|voice\s*:)[^.!?\n]{0,60}$`, I,
        '_AUTHORITATIVE_TONE_BEFORE_RE');
    const TONE_FIELD_RE = pyRe(R`tone|style|voice`, I, '_TONE_FIELD_RE');
    const AUTHORITATIVE_DNS_RE = pyRe(R`^\s+(?:dns|name[\s-]?servers?|nameservers?|zones?|servers?|resolvers?)\b`, I,
        '_AUTHORITATIVE_DNS_RE');
    const GERMAN_AGENT_BEFORE_RE = pyRe(R`\b(?:von|vom|durch|beim|bei|laut|gegen|im|am)\b[^.!?\n]*$`, I,
        '_GERMAN_AGENT_BEFORE_RE');
    const INVISIBLE_RE = pyRe('[\u{200b}\u{2060}-\u{2064}\u{feff}\u{202a}-\u{202e}\u{2066}-\u{2069}\u{e0000}-\u{e007f}]',
        false, '_INVISIBLE_RE');
    const ARP_NAME_RE = pyRe(R`\bARP\b|\bAgentic\s+Reasoning\s+Protocol\b`, false, '_ARP_NAME_RE');
    const ARP_STANDARD_RE = pyRe(
        R`\b(?:is|as|an?)\s+(?:an?\s+)?(?:(?:open|new|official|internet|web|ietf|global)\s+)+standard\b` +
        R`|\bIETF[\s-]+Standard\b|\bInternet[\s-]?[Ss]tandard\b`, I, '_ARP_STANDARD_RE');
    const URL_ONLY_RE = pyRe(R`^\s*https?://\S+\s*$`, false, '_URL_ONLY_RE');
    const SIGNATURE_WORD_RE = pyRe(R`\bsign(?:s|ed|ing|ature|atures)?\b|\bsigniert\b|\bSignatur(?:en)?\b`, I,
        '_SIGNATURE_WORD_RE');
    const PROVENANCE_TEMPLATE_RE = pyRe(
        R`^This file is (?P<entity>.+)'s own description of itself, published by (?P<publisher>.+) at ` +
        R`(?P<domain>[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9])\. The statements are self-attested; where available, ` +
        R`independent evidence is linked in evidence_url\.$`, false, '_PROVENANCE_TEMPLATE_RE');
    const CONTROL_CHAR_RE = pyRe('[\x00-\x1f\x7f-\x9f]', false, '_CONTROL_CHAR_RE');
    const LINE_BREAK_RE = pyRe('\r\n|[\n\r\x0b\x0c\x85\u{2028}\u{2029}]', false, '_LINE_BREAK_RE');
    // A continuation line that Markdown would read as structure
    const MD_STRUCTURE_RE = pyRe(R`\s*(?:#|[-*+](?:\s|$)|\d+[.)](?:\s|$)|>|` + '```' + R`|~~~|Manifest:)`, false,
        '_MD_STRUCTURE_RE');
    const AUTHORITY_KEY_RE = pyRe(R`verifiziert|geprüft|ground_?truth|trusted_?sources?`, I, '_AUTHORITY_KEY_RE');
    const ARRAY_INDEX_KEY_RE = pyRe(R`0|[1-9][0-9]{0,9}`, false, '_ARRAY_INDEX_KEY_RE');
    const SIGNATURE_STATEMENT_RE = pyRe(R`\bsigned\s+with\s+ed25519\s+by\s+the\s+operator\s+of\b`, I,
        '_SIGNATURE_STATEMENT_RE');
    const PUBLISHED_DATE_RE = pyRe(R`\d{4}-\d{2}-\d{2}`, false);
    const SHA256_RE = pyRe(R`[0-9a-f]{64}`, false);
    const SHA256_ANY_CASE_RE = pyRe(R`[0-9a-fA-F]{64}`, false);
    const LAST_KEY_INDEX_RE = pyRe(R`(?:\[\d+\])+$`, false);
    const LAST_KEY_RE = pyRe(R`\.([A-Za-z_][A-Za-z0-9_]*)$|\[(\"(?:[^\"\\]|\\.)*\")\]$`, false);

    const HISTORICAL_VERIFIED_KEYS = new Set(['verified_fact', 'last_verified']);
    // Top-level members defined by schema v1.3 (additionalProperties: false)
    const V13_TOP_LEVEL = new Set([
        '$schema', 'protocol', 'version', 'domain', 'entity', 'provenance', 'representations', 'verification',
        'identity', 'organization', 'corrections', 'entity_claims', 'diagnostics', 'authority', 'content_policy',
        '_arp_signature'
    ]);
    // Labels of the fixed final section "## Verification" of reasoning.md
    const VERIFICATION_LABELS = ['manifest', 'statement', 'dns_name', 'doh_url', 'signed_at', 'expires_at', 'signature'];

    function finding(severity, rule, path, message, excerptText, match) {
        return { severity, rule, path, message, excerpt: excerptText || '', match: match || '' };
    }

    function sortBySeverity(findings) {
        const order = { error: 0, warning: 1 };
        return findings
            .map((f, k) => [f, k])
            .sort((a, b) => ((order[a[0].severity] ?? 2) - (order[b[0].severity] ?? 2)) || (a[1] - b[1]))
            .map(x => x[0]);
    }

    // Last member name of a JSON path ("$.a.tone_of_voice[0]" → "tone_of_voice")
    function lastKey(path) {
        const m0 = LAST_KEY_INDEX_RE.search(path);
        const p = m0 ? path.slice(0, m0.index) : path;
        const m = LAST_KEY_RE.search(p);
        if (!m) return '';
        return m.m[1] !== undefined ? m.m[1] : m.m[2];
    }

    // Port of arp_cli _lint_text()
    function lintTextValue(path, text) {
        const findings = [];
        if (URL_ONLY_RE.match(text)) return findings;
        const spans = new Map();
        for (const [severity, rule, regex, message] of TEXT_RULES) {
            const m = regex.search(text);
            if (!m) continue;
            // One finding per rule and text passage: skip overlapping matches of the same rule.
            const list = spans.get(rule) || [];
            if (list.some(([s, e]) => m.index < e && s < m.end)) continue;
            list.push([m.index, m.end]);
            spans.set(rule, list);
            findings.push(finding(severity, rule, path, message, excerpt(text, m.index, m.end), m[0]));
        }
        for (const m of VERIFIED_RE.finditer(text)) {
            const after = text.slice(m.end), beforeText = text.slice(cpBack(text, m.index, 60), m.index);
            let qualified = !!VERIFIED_QUALIFIER_RE.match(after) && !GENERIC_AGENT_AFTER_RE.match(after);
            const genericBefore = !!GENERIC_AGENT_BEFORE_RE.search(beforeText);
            const word = m[0].toLowerCase();
            if (!qualified && (word === 'verifiziert' || word === 'geprüft')) {
                // German word order names the checker before the participle ("vom TÜV geprüft").
                qualified = !!GERMAN_AGENT_BEFORE_RE.search(beforeText) && !genericBefore;
            }
            if (!qualified && !genericBefore) {
                // A proper name right before names the checker ("Google My Business verified").
                const before = PROPER_BEFORE_RE.search(beforeText);
                qualified = !!before && !GENERIC_STARTERS.has(pySplitWs(before.m[1])[0]);
            }
            if (!qualified && NEGATION_BEFORE_RE.search(text.slice(cpBack(text, m.index, 40), m.index))) {
                qualified = true; // "no verified adoption" claims nothing
            }
            if (!qualified) {
                findings.push(finding('error', 'ARP-W/unsourced-authority', path,
                    "'verified' without saying who checked what (e.g. 'verified by …', 'checked against …').",
                    excerpt(text, m.index, m.end), m[0]));
                break;
            }
        }
        for (const m of AUTHORITATIVE_RE.finditer(text)) {
            const after = text.slice(m.end), before = text.slice(cpBack(text, m.index, 60), m.index);
            if (TONE_FIELD_RE.search(lastKey(path)) || AUTHORITATIVE_QUALIFIER_RE.match(after) ||
                AUTHORITATIVE_TONE_AFTER_RE.match(after) || AUTHORITATIVE_TONE_BEFORE_RE.search(before) ||
                AUTHORITATIVE_DNS_RE.match(after) || NEGATION_BEFORE_RE.search(before.slice(cpBack(before, before.length, 40)))) {
                continue;
            }
            findings.push(finding('error', 'ARP-W/unsourced-authority', path,
                "'authoritative' without saying who rates it so. State the fact and link evidence " +
                "(a tone descriptor such as 'authoritative tone' is fine).",
                excerpt(text, m.index, m.end), m[0]));
            break;
        }
        const inv = INVISIBLE_RE.search(text);
        if (inv) {
            const cp = hex4(inv[0]);
            findings.push(finding('error', 'ARP-W/hidden-text', path,
                `Invisible Unicode character U+${cp}. Text must be the same for people and bots.`,
                excerpt(text, inv.index, inv.end).split(inv[0]).join(`<U+${cp}>`), inv[0]));
        }
        if (ARP_NAME_RE.search(text)) {
            const s = ARP_STANDARD_RE.search(text);
            if (s) {
                findings.push(finding('warning', 'ARP-W/terms', path,
                    'ARP is described as a standard. ARP is a single-author draft, not a standard or IETF standard.',
                    excerpt(text, s.index, s.end), s[0]));
            }
        }
        return findings;
    }

    // Port of arp_cli _lint_line_breaks()
    function lintLineBreaks(path, value, what, v13) {
        const findings = [];
        const control = CONTROL_CHAR_RE.search(value);
        const lines = LINE_BREAK_RE.split(value);
        if (control && (v13 || !LINE_BREAK_RE.fullmatch(control[0]))) {
            findings.push(finding(v13 ? 'error' : 'warning', 'ARP-R/control-character', path,
                `Control character U+${hex4(control[0])} inside a ${what}. ARP v1.3 files contain no control ` +
                'characters in member names and strings, line breaks and tabs included (SPEC §13.12.1, schema v1.3); ' +
                'render-md and sign refuse them.',
                safeText(excerpt(value, control.index, control.end), 80)));
        }
        if (lines.length === 1) return findings;
        const structural = lines.slice(1).filter(line => MD_STRUCTURE_RE.match(line));
        if (structural.length) {
            findings.push(finding('error', 'ARP-R/line-break', path,
                `Line break inside a ${what}, followed by a line that reads as Markdown structure. reasoning.md ` +
                'copies values unchanged, so the line would appear as a heading or list item of its own.',
                safeText(structural[0], 80)));
        } else if (!findings.length) {
            findings.push(finding('warning', 'ARP-R/line-break', path,
                `Line break inside a ${what} (SPEC §13.12.1: publishers avoid line breaks in values).`,
                safeText(lines[1], 80)));
        }
        return findings;
    }

    // Port of arp_cli _lint_key_authority()
    function lintKeyAuthority(path, key, v13) {
        if (HISTORICAL_VERIFIED_KEYS.has(key)) return [];
        const tokens = keyTokens(key);
        const pairs = new Set();
        for (let k = 0; k + 1 < tokens.length; k++) pairs.add(tokens[k] + '\u{0}' + tokens[k + 1]);
        const set = new Set(tokens);
        if (!(set.has('verified') || set.has('authoritative') || pairs.has('ground\u{0}truth') ||
            pairs.has('trusted\u{0}source') || pairs.has('trusted\u{0}sources') || AUTHORITY_KEY_RE.search(key))) {
            return [];
        }
        return [finding(v13 ? 'error' : 'warning', 'ARP-W/unsourced-authority', path,
            `Member name '${safeText(key, 80)}' says that something was checked or is authoritative, but a name ` +
            'cannot say who checked what (SPEC §11.2 item 5; only verified_fact and last_verified are exempt).', key)];
    }

    // Port of arp_cli _lint_reserved_sections()
    function lintReservedSections(manifest, v13) {
        const findings = [];
        for (const key of orderedKeys(manifest)) {
            const path = childPath('$', key);
            if (key !== 'verification' && casefoldEquals(key, 'verification')) {
                findings.push(finding('error', 'ARP-R/reserved-section', path,
                    `Top-level member '${safeText(key, 40)}' would render as '## ${safeText(key, 40)}', a heading that ` +
                    "imitates the fixed final section '## Verification' of reasoning.md. The review metadata member " +
                    "is spelled 'verification' (SPEC §5); render-md and sign refuse this name.", key));
            } else if (v13 && !V13_TOP_LEVEL.has(key)) {
                findings.push(finding('warning', 'ARP/unknown-member', path,
                    `Top-level member '${safeText(key, 40)}' is not defined in ARP v1.3 (schema v1.3 allows no other ` +
                    'top-level members); reasoning.md renders it as a section of its own.', key));
            }
        }
        const verification = pyGet(manifest, 'verification');
        if (!isNone(verification) && !isPlainObject(verification)) {
            findings.push(finding('error', 'ARP-R/reserved-section', '$.verification',
                'verification must be an object (SPEC §5: audited_by, last_verified, next_audit). Other values ' +
                "render as list items under '## verification' that can imitate the signature lines of reasoning.md."));
        } else if (isPlainObject(verification)) {
            for (const key of orderedKeys(verification)) {
                if (VERIFICATION_LABELS.some(label => casefoldEquals(key, label))) {
                    findings.push(finding('error', 'ARP-R/reserved-section', childPath('$.verification', key),
                        `verification.${safeText(key, 40)} imitates a line of the fixed final section ` +
                        "'## Verification' of reasoning.md (manifest URL and signature pointers). SPEC §5 defines " +
                        'audited_by, last_verified, next_audit.', key));
                }
            }
        }
        return findings;
    }

    // Port of arp_cli _lint_domain(): domain is REQUIRED (SPEC §4)
    function lintDomain(manifest) {
        const domain = pyGet(manifest, 'domain');
        const signed = has(manifest, '_arp_signature');
        if (typeof domain !== 'string' || !pyStrip(domain)) {
            const sev = signed || versionAtLeast13(manifest) ? 'error' : 'warning';
            return [finding(sev, 'ARP/domain-missing', '$.domain',
                'domain is missing or not a string (REQUIRED, SPEC §4). Verifiers report signed ' +
                'files without it as INVALID (domain_missing).')];
        }
        const normalized = normalizeDomainSafe(domain);
        if (normalized === null) {
            return [finding('error', 'ARP/domain-format', '$.domain',
                'domain must be a bare domain name such as example.com (no scheme, path or port).', domain)];
        }
        if (normalized !== domain) {
            return [finding('error', 'ARP/domain-format', '$.domain',
                `domain must be written in lowercase without a trailing dot: '${normalized}'.`, domain)];
        }
        return [];
    }

    // Port of arp_cli _lint_provenance()
    function lintProvenance(manifest) {
        const findings = [];
        const v13 = versionAtLeast13(manifest);
        const prov = pyGet(manifest, 'provenance');
        if (isNone(prov)) {
            findings.push(finding(v13 ? 'error' : 'warning', 'ARP-P/missing', '$.provenance',
                'provenance is missing (REQUIRED in ARP v1.3): statement, publisher, publisher_url, published.'));
            return findings;
        }
        if (!isPlainObject(prov)) {
            findings.push(finding('error', 'ARP-P/type', '$.provenance', 'provenance must be an object.'));
            return findings;
        }
        for (const field of ['statement', 'publisher', 'publisher_url', 'published']) {
            const v = pyGet(prov, field);
            if (typeof v !== 'string' || !v) {
                findings.push(finding('error', 'ARP-P/field', `$.provenance.${field}`, `provenance.${field} is missing or empty.`));
            }
        }
        const published = pyGet(prov, 'published');
        if (typeof published === 'string' && published && !PUBLISHED_DATE_RE.fullmatch(published)) {
            findings.push(finding('error', 'ARP-P/field', '$.provenance.published',
                'provenance.published must be a date (YYYY-MM-DD).', published));
        }
        const url = pyGet(prov, 'publisher_url');
        if (typeof url === 'string' && url && !url.startsWith('https://')) {
            findings.push(finding('error', 'ARP-P/field', '$.provenance.publisher_url',
                'provenance.publisher_url must be an https:// URL (legal notice).', url));
        }
        const statement = pyGet(prov, 'statement');
        if (typeof statement === 'string' && statement) {
            const m = SIGNATURE_WORD_RE.search(statement);
            if (m) {
                findings.push(finding('error', 'ARP-P/no-signature', '$.provenance.statement',
                    'provenance.statement must not mention a signature (identical in signed and unsigned files).',
                    excerpt(statement, m.index, m.end), m[0]));
            }
            // SPEC §4.1: the statement MUST follow the template (error in v1.3).
            const sev = v13 ? 'error' : 'warning';
            const t = PROVENANCE_TEMPLATE_RE.fullmatch(statement);
            if (!t) {
                findings.push(finding(sev, 'ARP-P/template', '$.provenance.statement',
                    'provenance.statement differs from the fixed template: "This file is {ENTITY}\'s own description ' +
                    'of itself, published by {PUBLISHER} at {DOMAIN}. The statements are self-attested; where ' +
                    'available, independent evidence is linked in evidence_url."'));
            } else {
                for (const [group, expected] of [['entity', pyGet(manifest, 'entity')], ['publisher', pyGet(prov, 'publisher')],
                    ['domain', pyGet(manifest, 'domain')]]) {
                    if (typeof expected === 'string' && t.m.groups[group] !== expected) {
                        findings.push(finding(sev, 'ARP-P/template', '$.provenance.statement',
                            `provenance.statement names ${group} '${t.m.groups[group]}', the file says '${expected}'.`));
                    }
                }
            }
        }
        return findings;
    }

    // Port of arp_cli _lint_signature_block()
    function lintSignatureBlock(manifest) {
        const findings = [];
        const sig = pyGet(manifest, '_arp_signature');
        if (isNone(sig)) return findings;
        if (!isPlainObject(sig)) return [finding('error', 'ARP-S/type', '$._arp_signature', '_arp_signature must be an object.')];
        const v13 = versionAtLeast13(manifest);
        const sev = v13 ? 'error' : 'warning';
        if (!has(sig, 'statement')) {
            findings.push(finding(sev, 'ARP-S/statement', '$._arp_signature.statement',
                '_arp_signature.statement is missing (REQUIRED in ARP v1.3; re-sign with arp_cli v1.4).'));
        }
        if (!isPlainObject(pyGet(sig, 'verify'))) {
            findings.push(finding(sev, 'ARP-S/verify', '$._arp_signature.verify',
                '_arp_signature.verify is missing (REQUIRED in ARP v1.3; re-sign with arp_cli v1.4).'));
        }
        const signature = pyGet(sig, 'signature');
        if (typeof signature === 'string' && signature !== '') {
            try {
                decodeSignatureStrict(signature);
            } catch (e) {
                if (!(e instanceof PyValueError)) throw e;
                findings.push(finding('error', 'ARP-S/signature-format', '$._arp_signature.signature',
                    `${e.message} (SPEC §13.3).`, safeText(signature, 120)));
            }
        }
        const domain = normalizeDomainSafe(pyGet(manifest, 'domain'));
        const selector = has(sig, 'dns_selector') ? sig.dns_selector : 'arp';
        if (normalizeSelectorSafe(selector) === null) {
            findings.push(finding('error', 'ARP-S/selector', '$._arp_signature.dns_selector',
                'dns_selector must consist of DNS labels of [A-Za-z0-9_-] that begin and end ' +
                'with a letter or digit, separated by single dots (at most 50 characters; ' +
                'SPEC §13.3).', safeText(selector)));
            return findings;
        }
        if (domain === null) return findings;
        const name = dnsName(selector, domain);
        // SPEC §13.3: statement MUST follow the template; verify holds fixed values.
        if (typeof pyGet(sig, 'statement') === 'string') {
            const expected = signatureStatement(selector, domain);
            if (sig.statement !== expected) {
                findings.push(finding(sev, 'ARP-S/statement', '$._arp_signature.statement',
                    `_arp_signature.statement differs from the fixed template: "${expected}"`));
            }
        }
        const declared = pyGet(sig, 'dns_record');
        if (!isNone(declared) && !sameDnsName(declared, name)) {
            findings.push(finding(sev, 'ARP-S/dns-record', '$._arp_signature.dns_record',
                `dns_record must be '${name}' (dns_selector + domain).`, safeText(declared)));
        }
        const verify = pyGet(sig, 'verify');
        if (isPlainObject(verify)) {
            const vName = pyGet(verify, 'dns_name');
            if (!sameDnsName(vName, name)) {
                findings.push(finding(sev, 'ARP-S/verify', '$._arp_signature.verify.dns_name',
                    `verify.dns_name must be '${name}'.`, safeText(vName)));
            }
            const doh = pyGet(verify, 'doh_url');
            if (!dohUrlNames(doh, name)) {
                findings.push(finding(sev, 'ARP-S/verify', '$._arp_signature.verify.doh_url',
                    `verify.doh_url must be an https:// DNS-over-HTTPS URL for ${name}, ` +
                    `e.g. ${dohUrlFor(name)}`, safeText(doh)));
            }
            if (pyGet(verify, 'spec') !== SPEC_SIGNATURE_URL) {
                findings.push(finding(sev, 'ARP-S/verify', '$._arp_signature.verify.spec',
                    `verify.spec must be ${SPEC_SIGNATURE_URL}`, safeText(pyGet(verify, 'spec'))));
            }
        }
        return findings;
    }

    // Port of arp_cli _lint_representations()
    function lintRepresentations(manifest) {
        const reps = pyGet(manifest, 'representations');
        if (isNone(reps)) {
            return versionAtLeast13(manifest)
                ? [finding('warning', 'ARP-R/missing', '$.representations',
                    'representations is missing (RECOMMENDED in ARP v1.3: reasoning.md with sha256).')]
                : [];
        }
        if (!Array.isArray(reps) || !reps.length) {
            return [finding('error', 'ARP-R/type', '$.representations', 'representations must be a non-empty array.')];
        }
        const findings = [];
        const domain = normalizeDomainSafe(pyGet(manifest, 'domain'));
        reps.forEach((entry, i) => {
            const p = `$.representations[${i}]`;
            if (!isPlainObject(entry)) {
                findings.push(finding('error', 'ARP-R/type', p, 'representation entries must be objects.'));
                return;
            }
            const href = pyGet(entry, 'href');
            if (typeof href !== 'string' || !href.startsWith('https://')) {
                findings.push(finding('error', 'ARP-R/field', p + '.href', 'href must be an absolute https:// URL.'));
            } else {
                // SPEC §13.12: on the manifest's domain; verifiers fetch nothing else.
                let target = null;
                try {
                    target = representationTarget(href);
                } catch (e) {
                    if (!(e instanceof PyValueError)) throw e;
                    findings.push(finding('error', 'ARP-R/field', p + '.href', `${e.message}.`, safeText(href)));
                }
                if (target) {
                    const [host, path] = target;
                    if (domain !== null && host !== domain) {
                        findings.push(finding('error', 'ARP-R/field', p + '.href',
                            `href must be on the manifest's domain ${domain} (SPEC §13.12).`, safeText(href)));
                    }
                    if (pyGet(entry, 'media_type') === MARKDOWN_MEDIA_TYPE && path !== MARKDOWN_PATH) {
                        findings.push(finding('error', 'ARP-R/field', p + '.href',
                            `the text/markdown representation lives at ${MARKDOWN_PATH}.`, safeText(href)));
                    }
                }
            }
            if (!pyTruthy(pyGet(entry, 'media_type'))) {
                findings.push(finding('error', 'ARP-R/field', p + '.media_type', 'media_type is missing.'));
            }
            const sha = pyGet(entry, 'sha256', '');
            if (typeof sha !== 'string' || !SHA256_RE.fullmatch(sha)) {
                findings.push(finding('error', 'ARP-R/field', p + '.sha256', 'sha256 must be 64 lowercase hex characters.'));
            }
        });
        return findings;
    }

    // ("key", path, name) for member names and ("str", path, value) for strings (arp_cli _walk)
    function pyWalk(value, path, out) {
        if (isPlainObject(value)) {
            for (const key of orderedKeys(value)) {
                const child = childPath(path, key);
                out.push(['key', child, key]);
                pyWalk(value[key], child, out);
            }
        } else if (Array.isArray(value)) {
            value.forEach((item, i) => pyWalk(item, childPath(path, i), out));
        } else if (typeof value === 'string') {
            out.push(['str', path, value]);
        }
        return out;
    }

    // Port of arp_cli lint_manifest(). Returns findings
    // { severity, rule, path, message, excerpt, match }, errors first.
    function lint(manifest) {
        if (!isPlainObject(manifest)) return [finding('error', 'ARP/type', '$', 'reasoning.json must be a JSON object.')];
        const findings = [];
        for (const [path, problem] of ijsonProblems(manifest)) {
            findings.push(finding('error', 'ARP/non-ijson', path,
                `Not I-JSON (RFC 7493): ${problem}. Such files cannot be signed (RFC 8785).`));
        }
        const nonIjsonPaths = new Set(findings.map(f => f.path));
        const v13 = versionAtLeast13(manifest);
        for (const [kind, path, value] of pyWalk(manifest, '$', [])) {
            if (nonIjsonPaths.has(path)) continue;
            if (kind === 'key') {
                if (isForbiddenFieldName(value)) {
                    findings.push(finding('error', 'ARP-W/field-name', path,
                        `Field name '${safeText(value, 80)}' is reserved for instruction-style content and not ` +
                        'allowed (system_instruction, reasoning_directives, ai_directive, agent_directive, ' +
                        'instruction(s), directive(s)).', value, value));
                }
                findings.push(...lintKeyAuthority(path, value, v13));
                if (ARRAY_INDEX_KEY_RE.fullmatch(value)) {
                    findings.push(finding('warning', 'ARP-R/numeric-key', path,
                        `Member name '${safeText(value, 20)}' consists of digits only. JavaScript objects list such ` +
                        'names first, so a JavaScript renderer that does not keep the file order produces different ' +
                        'reasoning.md bytes (SPEC §13.12.1 requires the file order).', value));
                }
                findings.push(...lintLineBreaks(path, value, 'member name', v13));
            } else {
                findings.push(...lintLineBreaks(path, value, 'string', v13));
                if (path === '$["$schema"]' || path === '$._arp_signature.signature') continue;
                findings.push(...lintTextValue(path, value));
                if (!(path === '$._arp_signature' || path.startsWith('$._arp_signature.') || path.startsWith('$._arp_signature['))) {
                    const m = SIGNATURE_STATEMENT_RE.search(value);
                    if (m) {
                        findings.push(finding('error', 'ARP-S/statement-outside', path,
                            "The signature statement ('Signed with Ed25519 by the operator of …') appears outside " +
                            '_arp_signature. Only the signer writes it, inside _arp_signature (SPEC §13.3); elsewhere ' +
                            'it would claim a signature the file may not have.', excerpt(value, m.index, m.end), m[0]));
                    }
                }
            }
        }
        findings.push(...lintReservedSections(manifest, v13));
        findings.push(...lintDomain(manifest));
        findings.push(...lintProvenance(manifest));
        findings.push(...lintSignatureBlock(manifest));
        findings.push(...lintRepresentations(manifest));
        if (!nonIjsonPaths.size && utf8(pyJsonDumps(manifest, null, null)).length > 100 * 1024) {
            findings.push(finding('warning', 'ARP/size', '$', 'File exceeds 100 KB (SPEC §2).'));
        }
        return sortBySeverity(findings);
    }

    // Port of arp_cli lint_manifest_text(): adds duplicate member names.
    // Throws ManifestParseError when the text is not loadable (the CLI exits 2).
    function lintManifestText(text) {
        const { data, duplicates } = parseJsonCollecting(text);
        const findings = duplicates.map(([path, name]) => finding('error', 'ARP/duplicate-member', path,
            `Member name '${safeText(name, 80)}' occurs more than once in this object. Parsers keep ` +
            'the last value, readers of the text see the first (I-JSON, RFC 7493 §2.3).', name));
        findings.push(...lint(data));
        return sortBySeverity(findings);
    }

    // `arp_cli lint` for a pasted text or the bytes of a file. Returns
    // { ok: true, findings, errors, warnings } or { ok: false, error } (exit 2).
    function lintSource(input) {
        try {
            let text;
            if (input && input.bytes) {
                // open(file, encoding="utf-8-sig") in text mode: universal newlines
                text = decodeUtf8Sig(input.bytes).replace(/\r\n?/g, '\n');
            } else {
                text = textAsFile(String(input && input.text !== undefined ? input.text : input)).replace(/\r\n?/g, '\n');
            }
            const findings = lintManifestText(text);
            const errors = findings.filter(f => f.severity === 'error').length;
            return { ok: true, findings, errors, warnings: findings.length - errors };
        } catch (e) {
            return { ok: false, error: { reason: e.reason || e.name || 'error', message: safeText(e.message || String(e)) } };
        }
    }

    // ─────────────────────────────────────────────
    // Ed25519 verification
    // ─────────────────────────────────────────────
    let noblePromise = null;

    function loadNoble() {
        if (!noblePromise) {
            noblePromise = Promise.all([
                import('https://esm.sh/@noble/ed25519@2.0.0'),
                import('https://esm.sh/@noble/hashes@1.3.3/sha512')
            ]).then(([ed, hashes]) => {
                ed.etc.sha512Sync = (...m) => hashes.sha512(ed.etc.concatBytes(...m));
                return ed;
            }, (e) => {
                noblePromise = null; // allow a retry after a network error
                throw e;
            });
        }
        return noblePromise;
    }

    async function ed25519Verify(publicKey, signature, message) {
        let key;
        try {
            key = await crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
        } catch (e) {
            if (e && e.name === 'DataError') throw e;
            const ed = await loadNoble();
            return ed.verify(signature, message, publicKey);
        }
        return crypto.subtle.verify({ name: 'Ed25519' }, key, signature, message);
    }

    async function verifyWithKeys(keys, signature, message) {
        for (const key of keys) {
            try {
                if (await ed25519Verify(key, signature, message)) return true;
            } catch (e) { /* key not usable: try the next one */ }
        }
        return false;
    }

    // ─────────────────────────────────────────────
    // DNS lookup via DNS-over-HTTPS (dns.google, CORS-enabled)
    // ─────────────────────────────────────────────
    function joinTxtData(data) {
        const s = String(data || '');
        if (!s.startsWith('"')) return s;
        const parts = s.match(/"((?:[^"\\]|\\.)*)"/g) || [];
        return parts.map(p => p.slice(1, -1).replace(/\\(.)/g, '$1')).join('');
    }

    class DNSNoRecord extends Error {}

    function isNoRecord(e) {
        return e instanceof DNSNoRecord || (e && (e.name === 'DNSNoRecord' || e.noRecord));
    }

    // Returns all TXT values at name; throws DNSNoRecord or Error (like arp_cli resolve_txt)
    async function resolveTxt(name) {
        const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`);
        if (!resp.ok) throw new Error(`DNS-over-HTTPS returned HTTP ${resp.status}`);
        const data = await resp.json();
        if (data.Status === 3) throw new DNSNoRecord('NXDOMAIN');
        if (data.Status !== 0) throw new Error(`DNS status ${data.Status}`);
        const records = (data.Answer || []).filter(a => a.type === 16).map(a => joinTxtData(a.data));
        if (!records.length) throw new DNSNoRecord('no TXT record');
        resolveTxt.lastAd = !!data.AD;
        return records;
    }

    // Port of arp_cli _arp_tag_pairs(): [[name (lowercase), value]], warnings
    function arpTagPairs(txt) {
        const pairs = [], warnings = [];
        for (const raw of String(txt).split(';')) {
            const segment = pyStrip(raw);
            if (!segment || !segment.includes('=')) continue;
            const [nameRaw, , value] = pyPartition(segment, '=');
            const name = pyStrip(nameRaw);
            if (name !== name.toLowerCase()) warnings.push(`DNS record tag '${safeText(name, 20)}=' should be lowercase.`);
            pairs.push([name.toLowerCase(), pyStrip(value)]);
        }
        return [pairs, warnings];
    }

    // Port of arp_cli parse_arp_txt(): { tags (Map) | null, warnings }
    function parseArpTxt(txt) {
        const [pairs, warnings] = arpTagPairs(txt);
        const tags = new Map(pairs);
        const version = tags.get('v');
        if (version === undefined || version.toUpperCase() !== 'ARP1') return { tags: null, warnings: [] };
        if (version !== 'ARP1') {
            warnings.push(`DNS record uses 'v=${safeText(version, 20)}'; SPEC §13.5 specifies 'v=ARP1'. ` +
                'Read tolerantly; the record should be corrected.');
        }
        return { tags, warnings };
    }

    // Port of arp_cli keys_from_txt_records() (status: ok, revoked, no_record, malformed, unsupported_algorithm)
    function keysFromTxtRecords(records) {
        const result = { status: 'no_record', publicKeys: [], record: null, warnings: [], detail: '' };
        const arp = [];
        for (const txt of records) {
            const parsed = parseArpTxt(txt);
            if (parsed.tags) {
                arp.push([txt, parsed.tags, arpTagPairs(txt)[0]]);
                result.warnings.push(...parsed.warnings);
            }
        }
        if (!arp.length) {
            result.detail = 'no v=ARP1 TXT record';
            return result;
        }
        if (arp.length > 1) result.warnings.push('Several ARP1 records at the same name; each key is tried.');
        // Revocation first: any empty p= at the name revokes, also next to a second p= in the same record.
        for (const [txt, , pairs] of arp) {
            if (pairs.some(([name, value]) => name === 'p' && value.replace(PY_SPACE_ALL, '') === '')) {
                Object.assign(result, { status: 'revoked', record: txt, detail: 'p= is empty: key revoked' });
                return result;
            }
        }
        for (const [txt, tags, pairs] of arp) {
            result.record = txt;
            const names = pairs.map(p => p[0]);
            const repeated = [...new Set(names.filter(n => names.indexOf(n) !== names.lastIndexOf(n)))].sort(compareCodePoints);
            if (repeated.length) {
                Object.assign(result, { status: 'malformed', detail: `tag(s) ${repeated.join(', ')} repeated in one record` });
                continue;
            }
            let algo = tags.get('k');
            if (algo === undefined) {
                result.warnings.push('DNS record has no k= tag; ed25519 assumed (SPEC §13.5 requires k=ed25519).');
                algo = 'ed25519';
            }
            if (algo.toLowerCase() !== 'ed25519') {
                Object.assign(result, { status: 'unsupported_algorithm', detail: `k=${algo} (expected ed25519)` });
                continue;
            }
            if (algo !== 'ed25519') result.warnings.push(`DNS record uses 'k=${algo}'; SPEC §13.5 specifies 'k=ed25519'.`);
            if (!tags.has('p')) {
                Object.assign(result, { status: 'malformed', detail: 'p= tag missing' });
                continue;
            }
            try {
                const [raw, keyWarnings] = decodeDnsPublicKey(tags.get('p'));
                result.warnings.push(...keyWarnings);
                result.publicKeys.push(raw);
            } catch (e) {
                Object.assign(result, { status: 'malformed', detail: 'public key not decodable: ' + e.message });
            }
        }
        if (result.publicKeys.length) {
            result.status = 'ok';
            result.detail = '';
        }
        return result;
    }

    // ─────────────────────────────────────────────
    // Timestamps: datetime.fromisoformat() of CPython 3.12 (C implementation,
    // Modules/_datetimemodule.c), applied to the UTF-8 bytes like the C code
    // ─────────────────────────────────────────────
    const DAYS_BEFORE_MONTH = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    const DAYS_IN_MONTH = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    const isLeap = (y) => y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
    const daysInMonth = (y, m) => (m === 2 && isLeap(y) ? 29 : DAYS_IN_MONTH[m]);
    const daysBeforeYear = (y) => {
        const z = y - 1;
        return z * 365 + Math.floor(z / 4) - Math.floor(z / 100) + Math.floor(z / 400);
    };
    const ymdToOrd = (y, m, d) => daysBeforeYear(y) + DAYS_BEFORE_MONTH[m] + (m > 2 && isLeap(y) ? 1 : 0) + d;

    function ordToYmd(ordinal) {
        let n = ordinal - 1;
        const n400 = Math.floor(n / 146097);
        n %= 146097;
        let year = n400 * 400 + 1;
        const n100 = Math.floor(n / 36524);
        n %= 36524;
        const n4 = Math.floor(n / 1461);
        n %= 1461;
        const n1 = Math.floor(n / 365);
        n %= 365;
        year += n100 * 100 + n4 * 4 + n1;
        if (n1 === 4 || n100 === 4) return [year - 1, 12, 31];
        const leap = n1 === 3 && (n4 !== 24 || n100 === 3);
        let month = (n + 50) >> 5;
        let preceding = DAYS_BEFORE_MONTH[month] + (month > 2 && leap ? 1 : 0);
        if (preceding > n) {
            month -= 1;
            preceding -= daysInMonth(year, month);
        }
        return [year, month, n - preceding + 1];
    }

    function isoWeek1Monday(y) {
        const first = ymdToOrd(y, 1, 1);
        const wd = (first + 6) % 7;
        let monday = first - wd;
        if (wd > 3) monday += 7;
        return monday;
    }

    // Returns { year, month, day, hour, minute, second, us, tz: null | { sec, us } } or null (ValueError)
    function fromIsoFormat(str) {
        const cps = Array.from(str);
        if (cps.length < 7) return null;
        let s = str;
        for (const pos of [7, 8, 10]) {
            if (pos > cps.length) break;
            const cp = pos < cps.length ? cps[pos].codePointAt(0) : 0;
            if (cp >= 0xd800 && cp <= 0xdfff) {
                cps[pos] = 'T';
                s = cps.join('');
                break;
            }
        }
        if (hasLoneSurrogate(s)) return null;
        const b = utf8(s);
        const len = b.length;
        const at = (k) => (k >= 0 && k < len ? b[k] : 0);
        const isDigit = (c) => c >= 0x30 && c <= 0x39;
        const digits = (p, count, box) => {
            for (let k = 0; k < count; k++) {
                const t = at(p++) - 0x30;
                if (t < 0 || t > 9) return -1;
                box.v = box.v * 10 + t;
            }
            return p;
        };
        // _find_isoformat_datetime_separator
        let sep;
        if (len === 7) sep = 7;
        else if (at(4) === 0x2d) {
            if (at(5) === 0x57) {
                if (len < 8) sep = -1;
                else if (len > 8 && at(8) === 0x2d) {
                    if (len === 9) sep = -1;
                    else if (len > 10 && isDigit(at(10))) sep = 8;
                    else sep = 10;
                } else sep = 8;
            } else sep = 10;
        } else if (at(4) === 0x57) {
            let idx = 7;
            for (; idx < len; idx++) if (!isDigit(at(idx))) break;
            if (idx < 9) sep = idx;
            else sep = idx % 2 === 0 ? 7 : 8;
        } else sep = 8;
        if (sep < 0) return null;
        // parse_isoformat_date
        let year, month, day;
        {
            let p = 0;
            const y = { v: 0 };
            p = digits(p, 4, y);
            if (p < 0) return null;
            const usesSep = at(p) === 0x2d;
            if (usesSep) p++;
            if (at(p) === 0x57) {
                p++;
                const w = { v: 0 }, d = { v: 0 };
                p = digits(p, 2, w);
                if (p < 0) return null;
                if (p < sep) {
                    if (usesSep && at(p++) !== 0x2d) return null;
                    p = digits(p, 1, d);
                    if (p < 0) return null;
                } else d.v = 1;
                // iso_to_ymd
                if (y.v < 1 || y.v > 9999) return null;
                if (w.v <= 0 || w.v >= 53) {
                    let out = true;
                    if (w.v === 53) {
                        const fw = (ymdToOrd(y.v, 1, 1) + 6) % 7;
                        if (fw === 3 || (fw === 2 && isLeap(y.v))) out = false;
                    }
                    if (out) return null;
                }
                if (d.v <= 0 || d.v >= 8) return null;
                [year, month, day] = ordToYmd(isoWeek1Monday(y.v) + (w.v - 1) * 7 + d.v - 1);
            } else {
                const m = { v: 0 }, d = { v: 0 };
                p = digits(p, 2, m);
                if (p < 0) return null;
                if (usesSep && at(p++) !== 0x2d) return null;
                p = digits(p, 2, d);
                if (p < 0) return null;
                year = y.v;
                month = m.v;
                day = d.v;
            }
        }
        let hour = 0, minute = 0, second = 0, us = 0, tz = null;
        // parse_hh_mm_ss_ff
        const hms = (start, end) => {
            const vals = [{ v: 0 }, { v: 0 }, { v: 0 }];
            const usBox = { v: 0 };
            let p = start;
            let hasSep = true;
            for (let k = 0; k < 3; k++) {
                p = digits(p, 2, vals[k]);
                if (p < 0) return { rv: -3 };
                const c = at(p++);
                if (k === 0) hasSep = c === 0x3a;
                if (p >= end) return { rv: c !== 0 ? 1 : 0, h: vals[0].v, m: vals[1].v, s: vals[2].v, us: 0 };
                else if (hasSep && c === 0x3a) continue;
                else if (c === 0x2e || c === 0x2c) break;
                else if (!hasSep) p--;
                else return { rv: -4 };
            }
            const remains = end - p;
            const toParse = remains >= 6 ? 6 : remains;
            p = digits(p, toParse, usBox);
            if (p < 0) return { rv: -3 };
            if (toParse < 6 && toParse > 0) usBox.v *= [100000, 10000, 1000, 100, 10][toParse - 1];
            while (isDigit(at(p))) p++;
            return { rv: at(p) !== 0 ? 1 : 0, h: vals[0].v, m: vals[1].v, s: vals[2].v, us: usBox.v };
        };
        if (len > sep) {
            // The separator is any character; its UTF-8 lead byte gives its length.
            const lead = at(sep);
            const width = (lead & 0x80) === 0 ? 1 : (lead & 0xf0) === 0xe0 ? 3 : (lead & 0xf0) === 0xf0 ? 4 : 2;
            const start = sep + width, end = len;
            let tzpos = start;
            do {
                const c = at(tzpos);
                if (c === 0x5a || c === 0x2b || c === 0x2d) break;
            } while (++tzpos < end);
            const t = hms(start, tzpos);
            if (t.rv < 0) return null;
            hour = t.h;
            minute = t.m;
            second = t.s;
            us = t.us;
            if (tzpos === end) {
                if (t.rv === 1) return null;
            } else if (at(tzpos) === 0x5a) {
                if (at(tzpos + 1) !== 0) return null;
                tz = { sec: 0, us: 0 };
            } else {
                const sign = at(tzpos) === 0x2d ? -1 : 1;
                const z = hms(tzpos + 1, end);
                if (z.rv !== 0) return null;
                tz = { sec: sign * (z.h * 3600 + z.m * 60 + z.s), us: sign * z.us };
            }
        }
        if (year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) return null;
        if (hour > 23 || minute > 59 || second > 59 || us > 999999) return null;
        if (tz) {
            if (tz.sec === 0) tz = { sec: 0, us: 0 };  // offset of 0 seconds gives UTC
            if (Math.abs(tz.sec * 1000000 + tz.us) >= 86400 * 1000000) return null;
        }
        return { year, month, day, hour, minute, second, us, tz };
    }

    // Port of arp_cli _parse_utc(): microseconds since 1970-01-01T00:00:00Z
    // (BigInt), naive timestamps count as UTC; null if not parseable.
    function parseUtc(value) {
        if (typeof value !== 'string') return null;
        const r = fromIsoFormat(pyStrip(value).split('Z').join('+00:00'));
        if (!r) return null;
        const days = BigInt(ymdToOrd(r.year, r.month, r.day) - 719163);
        let micros = days * 86400000000n + BigInt((r.hour * 60 + r.minute) * 60 + r.second) * 1000000n + BigInt(r.us);
        if (r.tz) micros -= BigInt(r.tz.sec) * 1000000n + BigInt(r.tz.us);
        return micros;
    }

    function nowMicros(now) {
        if (now === undefined || now === null) return BigInt(Date.now()) * 1000n;
        if (typeof now === 'bigint') return now;
        return BigInt(Math.trunc(now instanceof Date ? now.getTime() : now)) * 1000n;
    }

    // ─────────────────────────────────────────────
    // Verification (port of arp_cli verify_manifest and cmd_verify)
    // ─────────────────────────────────────────────
    function newVerifyResult(domain) {
        return {
            status: null, reason: null, domain: domain === undefined ? null : domain, dns_name: null,
            selector: null, signed_at: null, expires_at: null, expired: false,
            method: null, warnings: [], detail: '', notes: [],
            // aliases used by the pages
            level: null, dnsName: null, dnssec: null
        };
    }

    function finish(result, status, reason, detail) {
        result.status = status;
        result.level = status;
        result.reason = reason;
        result.detail = detail || '';
        result.dnsName = result.dns_name;
        return result;
    }

    function deepCopy(value) {
        return JSON.parse(JSON.stringify(value));
    }

    // Explain a failed enveloped check; never turns a failure into success
    async function diagnoseFailure(keys, data, signature) {
        const legacy = deepCopy(data);
        delete legacy._arp_signature;
        if (await verifyWithKeys(keys, signature, utf8(canonicalize(legacy)))) return 'legacy_payload_only';
        const removed = deepCopy(data);
        delete removed._arp_signature.signature;
        if (await verifyWithKeys(keys, signature, utf8(canonicalize(removed)))) return 'signature_field_removed';
        return 'signature_mismatch';
    }

    // Port of arp_cli verify_manifest(): Enveloped Pattern only (SPEC §13.4),
    // trust levels and order of checks (§13.7), revocation by empty p= (K6).
    //
    // options:
    //   domain       retrieval domain (URL host, --domain, or the domain field of a local file)
    //   publicKey    32 key bytes, or the content of a public key file (PEM or base64): no DNS
    //   resolveTxt   resolver override (name → Promise<string[]>, throws DNSNoRecord)
    //   now          Date, milliseconds or BigInt microseconds
    //
    // Returns { status (= level): CRYPTOGRAPHIC | UNSIGNED | INVALID | ERROR, reason, detail,
    //           domain, dns_name (= dnsName), selector, signed_at, expires_at, expired,
    //           method, warnings, meaning, dnssec }.
    async function verifyManifest(manifest, options) {
        const opts = options || {};
        const resolver = opts.resolveTxt || resolveTxt;
        const now = nowMicros(opts.now);
        let domain = opts.domain;
        domain = typeof domain === 'string' ? (rstripDots(pyStrip(domain).toLowerCase()) || null) : null;
        const result = newVerifyResult(domain);
        const done = (status, reason, detail) => finish(result, status, reason, detail);

        if (!isPlainObject(manifest)) return done(STATUS_ERROR, 'not_an_object', 'reasoning.json must be a JSON object');

        const problems = ijsonProblems(manifest);
        if (problems.length) {
            return done(TRUST_INVALID, 'non_ijson', `${problems[0][1]} at ${safeText(problems[0][0], 120)} ` +
                '(I-JSON, RFC 7493; not canonicalizable by RFC 8785)');
        }

        const sig = pyGet(manifest, '_arp_signature');
        const payloadDomain = pyGet(manifest, 'domain');
        if (pyTruthy(sig) && (typeof payloadDomain !== 'string' || !pyStrip(payloadDomain))) {
            // SPEC §4 / §13.7: a signed file without domain could be presented under any domain.
            return done(TRUST_INVALID, 'domain_missing', "signed file has no 'domain' string (REQUIRED, SPEC §4)");
        }
        if (domain && typeof payloadDomain === 'string' && rstripDots(pyStrip(payloadDomain).toLowerCase()) !== domain) {
            const detail = `payload field domain '${safeText(payloadDomain, 120)}' differs from the retrieval domain ` +
                `'${domain}' (SPEC §4)`;
            if (pyTruthy(sig)) return done(TRUST_INVALID, 'domain_mismatch', detail);
            result.warnings.push(detail);
        }

        if (!pyTruthy(sig)) return done(TRUST_UNSIGNED, 'unsigned');
        if (!isPlainObject(sig)) return done(TRUST_INVALID, 'malformed_signature_block', '_arp_signature is not an object');

        result.signed_at = pyGet(sig, 'signed_at', null);
        result.expires_at = pyGet(sig, 'expires_at', null);

        if (pyGet(sig, 'algorithm') !== 'Ed25519') {
            return done(TRUST_INVALID, 'unsupported_algorithm', `algorithm ${safeText(pyRepr(pyGet(sig, 'algorithm')), 60)}`);
        }
        if (pyGet(sig, 'canonicalization') !== 'jcs-rfc8785') {
            return done(TRUST_INVALID, 'unsupported_canonicalization',
                `canonicalization ${safeText(pyRepr(pyGet(sig, 'canonicalization')), 60)}`);
        }
        const sigValue = pyGet(sig, 'signature');
        if (typeof sigValue !== 'string' || !sigValue) return done(TRUST_INVALID, 'malformed_signature', 'signature value missing');
        let signature;
        try {
            signature = decodeSignatureStrict(sigValue);
        } catch (e) {
            if (!(e instanceof PyValueError)) throw e;
            return done(TRUST_INVALID, 'malformed_signature', e.message);
        }

        const expires = parseUtc(pyGet(sig, 'expires_at'));
        if (expires === null) return done(TRUST_INVALID, 'malformed_metadata', 'expires_at missing or not an ISO 8601 timestamp');
        result.expired = now > expires;
        const signedAt = parseUtc(pyGet(sig, 'signed_at'));
        if (signedAt !== null && signedAt > now + 300000000n) {
            result.warnings.push(`signed_at lies in the future (${safeText(pyGet(sig, 'signed_at'), 40)}).`);
        }

        let selector = pyGet(sig, 'dns_selector');
        if (!pyTruthy(selector)) selector = 'arp';
        result.selector = selector;
        try {
            validateSelector(selector);
        } catch (e) {
            if (!(e instanceof PyValueError)) throw e;
            return done(TRUST_INVALID, 'malformed_metadata', e.message);
        }

        // Consistency of the signed pointers with the domain (SPEC §13.3).
        const keyDomain = domain || normalizeDomainSafe(payloadDomain);
        const v13 = versionAtLeast13(manifest);
        if (v13 && (!has(sig, 'statement') || !isPlainObject(pyGet(sig, 'verify')))) {
            result.warnings.push('ARP v1.3 requires _arp_signature.statement and .verify.');
        }
        if (keyDomain) {
            const expectedName = dnsName(selector, keyDomain);
            const verifyBlockValue = isPlainObject(pyGet(sig, 'verify')) ? sig.verify : {};
            for (const [field, value] of [['dns_record', pyGet(sig, 'dns_record')],
                ['verify.dns_name', pyGet(verifyBlockValue, 'dns_name')]]) {
                if (isNone(value) || sameDnsName(value, expectedName)) continue;
                const detail = `${field} '${safeText(value, 120)}' differs from '${expectedName}' (dns_selector + domain)`;
                // In v1.3 these values are written by the signer: a different name means another domain.
                if (v13) return done(TRUST_INVALID, 'domain_mismatch', detail);
                result.warnings.push(detail + '; the retrieval-derived name is used (informational).');
            }
            if (typeof pyGet(sig, 'statement') === 'string' && sig.statement !== signatureStatement(selector, keyDomain)) {
                result.warnings.push('_arp_signature.statement differs from the SPEC §13.3 template; the ' +
                    'signature covers this text but does not check that it follows the template.');
            }
            if (pyTruthy(verifyBlockValue)) {
                if (!dohUrlNames(pyGet(verifyBlockValue, 'doh_url'), expectedName)) {
                    result.warnings.push(`verify.doh_url does not query ${expectedName} over https.`);
                }
                if (pyGet(verifyBlockValue, 'spec') !== SPEC_SIGNATURE_URL) {
                    result.warnings.push(`verify.spec differs from ${SPEC_SIGNATURE_URL}.`);
                }
            }
        }

        let keys;
        if (opts.publicKey !== undefined && opts.publicKey !== null && opts.publicKey !== '') {
            let key = opts.publicKey;
            if (!ArrayBuffer.isView(key)) {
                try {
                    key = loadPublicKeyText(String(key));
                } catch (e) {
                    return done(STATUS_ERROR, 'public_key_malformed', 'the entered public key is not a 32-byte Ed25519 key');
                }
            }
            keys = [key];
            result.method = 'local_public_key';
        } else {
            if (!domain) return done(STATUS_ERROR, 'no_domain', 'verification domain unknown: use a URL, --domain or --pubkey');
            const name = dnsName(selector, domain);
            result.dns_name = name;
            result.method = 'dns';
            let records;
            try {
                records = await resolver(name);
                if (resolver === resolveTxt) result.dnssec = resolveTxt.lastAd;
            } catch (e) {
                if (isNoRecord(e)) return done(TRUST_INVALID, 'dns_no_key', `no TXT record at ${name} (${safeText(e.message, 120)})`);
                return done(STATUS_ERROR, 'dns_error', `DNS lookup for ${name} failed: ${safeText(e && e.message, 120)}`);
            }
            const info = keysFromTxtRecords(records);
            result.warnings.push(...info.warnings);
            result.dns_txt = info.record;
            if (info.status === 'revoked') {
                return done(TRUST_INVALID, 'key_revoked', `${name} has an empty p= value: the domain operator revoked this key`);
            }
            if (info.status === 'no_record') return done(TRUST_INVALID, 'dns_no_key', `no v=ARP1 TXT record at ${name}`);
            if (info.status === 'unsupported_algorithm') return done(TRUST_INVALID, 'dns_unsupported_algorithm', info.detail);
            if (info.status !== 'ok') return done(TRUST_INVALID, 'dns_key_malformed', info.detail);
            keys = info.publicKeys;
        }

        const enveloped = deepCopy(manifest);
        enveloped._arp_signature.signature = '';
        let message;
        try {
            message = utf8(canonicalize(enveloped));
        } catch (e) {
            return done(TRUST_INVALID, 'non_ijson', `not canonicalizable (RFC 8785): ${e.name}`);
        }
        if (await verifyWithKeys(keys, signature, message)) {
            if (result.expired) return done(TRUST_UNSIGNED, 'expired', `signature expired at ${safeText(pyGet(sig, 'expires_at'), 40)}`);
            result.meaning = result.method === 'local_public_key' ? LOCAL_KEY_MEANING : CRYPTOGRAPHIC_MEANING;
            return done(TRUST_CRYPTOGRAPHIC, 'valid');
        }
        return done(TRUST_INVALID, await diagnoseFailure(keys, manifest, signature));
    }

    // Browser fetch with the rules of arp_cli http_get_bytes(): redirects only
    // within the host and never from https to http, at most 1 MiB, 30 s.
    async function defaultFetchBytes(url) {
        const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
        const timer = controller ? setTimeout(() => controller.abort(), FETCH_TOTAL_TIMEOUT_MS) : null;
        try {
            const resp = await fetch(url, { cache: 'no-store', redirect: 'follow', signal: controller ? controller.signal : undefined });
            const bytes = new Uint8Array(await resp.arrayBuffer());
            return { status: resp.status, contentType: resp.headers.get('Content-Type') || '', bytes, url: resp.url || url };
        } catch (e) {
            if (e && e.name === 'AbortError') throw new FetchError('overall time limit exceeded');
            throw e;
        } finally {
            if (timer) clearTimeout(timer);
        }
    }

    async function httpGetBytes(url, fetchBytes) {
        const [current, host] = checkedUrl(url, true);
        const resp = await (fetchBytes || defaultFetchBytes)(current);
        const finalUrl = resp.url || current;
        if (finalUrl !== current) {
            const [next, nextHost] = checkedUrl(finalUrl, true);
            if (nextHost !== host) throw new FetchError(`redirect to another host (${nextHost}) not followed; check that URL directly`);
            if (current.startsWith('https://') && !next.startsWith('https://')) throw new FetchError('redirect from https to http not followed');
        }
        if (resp.status >= 400) throw new FetchError(`HTTP ${resp.status}`);
        if (resp.bytes.length > MAX_FETCH_BYTES) throw new FetchError(`response larger than ${MAX_FETCH_BYTES} bytes`);
        return [resp.bytes, resp.contentType || ''];
    }

    function fetchErrorKind(e) {
        return e instanceof FetchError ? e.kind : (e && e.name) || 'Error';
    }

    // Port of arp_cli check_representations(). Local source (pasted file):
    // only /.well-known/reasoning.md is compared, with the selected local file
    // (localBytes) in the role of the reasoning.md next to the manifest. URL
    // source: https://{host}{path} for entries on the retrieval domain, equal
    // URLs once, at most 4 URLs and 60 s.
    async function checkRepresentations(manifest, options) {
        const opts = options || {};
        const reps = isPlainObject(manifest) ? pyGet(manifest, 'representations') : undefined;
        if (isNone(reps)) return [];
        if (!Array.isArray(reps)) return [{ href: null, status: REPRESENTATION_UNCHECKED, note: 'representations is not an array' }];
        const budgetEnd = Date.now() + (opts.totalTimeoutMs || REPRESENTATIONS_TOTAL_TIMEOUT_MS);
        const maxFetches = opts.maxFetches || MAX_REPRESENTATION_FETCHES;
        const domain = typeof opts.retrievalDomain === 'string' ? rstripDots(pyStrip(opts.retrievalDomain).toLowerCase()) : null;
        const fetched = new Map();
        const results = [];
        for (const entry of reps) {
            const item = { href: null, status: REPRESENTATION_UNCHECKED, expected: null, actual: null, note: '' };
            results.push(item);
            if (!isPlainObject(entry)) {
                item.note = 'entry is not an object';
                continue;
            }
            const href = pyGet(entry, 'href', null), expected = pyGet(entry, 'sha256', null);
            item.href = href;
            item.expected = expected;
            if (typeof href !== 'string' || typeof expected !== 'string' || !SHA256_ANY_CASE_RE.fullmatch(expected)) {
                item.note = 'href or sha256 missing or malformed';
                continue;
            }
            let host, path;
            try {
                [host, path] = representationTarget(href);
            } catch (e) {
                if (!(e instanceof PyValueError)) throw e;
                item.note = `${e.message}; not fetched`;
                continue;
            }
            if (domain && host !== domain) {
                item.note = 'href is not on the retrieval domain; not fetched';
                continue;
            }
            let body;
            if (opts.local) {
                if (path !== MARKDOWN_PATH) {
                    item.note = `local check covers only ${MARKDOWN_PATH}; not read`;
                    continue;
                }
                if (!opts.localBytes) {
                    item.note = 'no local reasoning.md selected';
                    continue;
                }
                if (opts.localBytes.length > MAX_FETCH_BYTES) {
                    item.note = `the local reasoning.md is larger than ${MAX_FETCH_BYTES} bytes`;
                    continue;
                }
                body = opts.localBytes;
                item.checked = opts.localName || 'reasoning.md';
            } else {
                if (!domain) {
                    item.note = 'retrieval domain unknown; not fetched';
                    continue;
                }
                const url = `https://${host}${path}`;
                if (!fetched.has(url)) {
                    if (fetched.size >= maxFetches) {
                        item.note = `not fetched: at most ${maxFetches} representation URLs are checked per run`;
                        continue;
                    }
                    if (Date.now() > budgetEnd) {
                        item.note = 'not fetched: the time for representation checks is used up';
                        continue;
                    }
                    try {
                        fetched.set(url, [(await httpGetBytes(url, opts.fetchBytes))[0], '']);
                    } catch (e) {
                        fetched.set(url, [null, `fetch failed (${fetchErrorKind(e)})`]);
                    }
                }
                const [bytes, note] = fetched.get(url);
                if (bytes === null) {
                    item.note = note;
                    continue;
                }
                body = bytes;
                item.checked = url;
            }
            item.actual = await sha256Hex(body);
            item.status = item.actual === expected.toLowerCase() ? REPRESENTATION_MATCH : REPRESENTATION_MISMATCH;
        }
        return results;
    }

    // Port of arp_cli cmd_verify(): load, parse strictly, verify, check representations.
    //
    // options:
    //   source       'url' (fetch options.url, or options.bytes / contentType already fetched
    //                with httpGetBytes) or 'file' (options.text pasted, or options.bytes)
    //   domain       the --domain value (local files only; a URL source uses its host)
    //   publicKey    content of a --pubkey file (PEM or base64), or 32 bytes
    //   localMarkdown bytes of the reasoning.md next to a local file
    //   noRepresentations, resolveTxt, fetchBytes, now
    //
    // Returns { result, representations, data, parseError, text }.
    async function verifySource(options) {
        const o = options || {};
        const loadWarnings = [], loadNotes = [];
        let retrievalDomain = null;
        let raw;
        const local = o.source !== 'url';
        const failed = (detail) => {
            const result = finish(newVerifyResult(null), STATUS_ERROR, 'load_failed', detail);
            return { result, representations: [], data: null, parseError: null, text: null };
        };
        try {
            if (!local) {
                const [fetchUrl, host] = checkedUrl(o.url, true);
                retrievalDomain = host;
                if (o.url.startsWith('http://')) loadWarnings.push('Source uses http://; SPEC §14 requires HTTPS.');
                if (urlPort(pyUrlsplit(fetchUrl)) !== null) {
                    loadWarnings.push('Source URL names a port; the DNS name is built from the host only.');
                }
                if (o.domain && normalizeDomainSafe(o.domain) !== retrievalDomain) {
                    loadWarnings.push(`--domain ${o.domain} ignored; the URL host ${retrievalDomain} is used.`);
                }
                // A page that fetched the file already (with httpGetBytes) passes its bytes.
                const [body, contentType] = o.bytes ? [o.bytes, o.contentType || ''] : await httpGetBytes(fetchUrl, o.fetchBytes);
                raw = body;
                if (!contentType.toLowerCase().includes('application/json')) {
                    loadWarnings.push(`Content-Type is '${contentType}', expected application/json.`);
                }
            } else {
                raw = o.bytes ? o.bytes : utf8(String(o.text === undefined ? '' : o.text));
                if (o.domain) retrievalDomain = pyNormalizeDomain(o.domain);
            }
        } catch (e) {
            return failed(e instanceof FetchError ? e.kind : `${e.name}: ${safeText(e.message, 200)}`);
        }

        let data = null, parseError = null, text = null;
        try {
            text = decodeUtf8Sig(raw);
            data = parseManifestText(text);
        } catch (e) {
            if (!(e instanceof ManifestParseError)) throw e;
            parseError = e;
        }
        if (parseError && !REJECTED_PARSE_REASONS.includes(parseError.reason)) {
            const out = failed(parseError.message);
            out.parseError = parseError;
            out.text = text;
            return out;
        }

        if (retrievalDomain === null && isPlainObject(data) && typeof pyGet(data, 'domain') === 'string') {
            retrievalDomain = normalizeDomainSafe(data.domain);
            if (retrievalDomain) loadNotes.push(`Using domain from file: ${data.domain}`);
        }

        let publicKey = null;
        if (o.publicKey !== undefined && o.publicKey !== null && o.publicKey !== '') {
            try {
                publicKey = ArrayBuffer.isView(o.publicKey) ? o.publicKey : loadPublicKeyText(String(o.publicKey));
                if (publicKey.length !== 32) throw new PyValueError('An Ed25519 public key is 32 bytes long');
            } catch (e) {
                const result = finish(newVerifyResult(retrievalDomain), STATUS_ERROR, 'public_key_malformed',
                    `Error loading public key: ${safeText(e.message)}`);
                return { result, representations: [], data, parseError, text };
            }
        }

        let result;
        if (parseError) {
            // Duplicate member names / non-I-JSON values: rejected (INVALID).
            result = finish(newVerifyResult(retrievalDomain), TRUST_INVALID, parseError.reason, parseError.message);
        } else {
            try {
                result = await verifyManifest(data, { domain: retrievalDomain, publicKey, resolveTxt: o.resolveTxt, now: o.now });
            } catch (e) {
                result = finish(newVerifyResult(retrievalDomain), STATUS_ERROR, 'verifier_error', e && e.name);
            }
        }
        result.warnings = loadWarnings.concat(result.warnings);
        result.notes = loadNotes;
        result.source = local ? 'file' : o.url;

        let representations = [];
        if (isPlainObject(data) && !o.noRepresentations) {
            representations = await checkRepresentations(data, {
                retrievalDomain, local, localBytes: o.localMarkdown, localName: o.localMarkdownName, fetchBytes: o.fetchBytes
            });
        }
        return { result, representations, data, parseError, text };
    }

    // Plain-language explanation of a verification result (English UI)
    function explainResult(result, ctx) {
        const c = ctx || {};
        const name = result.dnsName || result.dns_name || 'the DNS record';
        const origin = 'A signature shows the origin of the file, not the accuracy of its statements.';
        switch (result.reason) {
            case 'valid':
                return result.method === 'local_public_key'
                    ? 'The signature matches the public key entered for this offline check. This shows that the holder of that key signed exactly this file and that it has not been altered since. The link of the key to the domain and its revocation status were not checked. ' + origin
                    : `The signature matches the public key published in DNS at ${name}. This shows that the operator of ${c.domain || 'the domain'} published exactly this file and that it has not been altered since signing. ${origin}`;
            case 'unsigned':
                return 'The file carries no signature. Its statements are the entity\'s own description; its origin is as certain as the connection it was retrieved over. Signing is optional.';
            case 'expired':
                return `The signature was valid but expired on ${c.expiresAt || 'its expiry date'}. Expired signatures count as unsigned (SPEC §13.7).`;
            case 'domain_mismatch':
                return `The file names another domain than the retrieval domain (${c.domain || '?'}): the domain field (${c.fileDomain || '?'}), or in v1.3 files dns_record / verify.dns_name (SPEC §4, §13.3).`;
            case 'domain_missing':
                return 'The file is signed but has no domain field (REQUIRED, SPEC §4). Without it the file is not bound to a domain and could be presented under any domain that publishes the same key. Add the field and re-sign.';
            case 'duplicate_member':
                return 'The file contains a member name twice in one object. JSON parsers keep the last value, while people and language models reading the text see the first; the signature covers only the parsed object. Such files are rejected (I-JSON, RFC 7493 §2.3).';
            case 'non_ijson':
                return 'The file contains values outside I-JSON (RFC 7493), e.g. NaN, Infinity, integers beyond ±(2^53−1) or unpaired surrogates. They cannot be canonicalized (RFC 8785); the file is rejected.';
            case 'legacy_payload_only':
                return 'The signature covers only the content, not the signature metadata (legacy pattern of CLI ≤ 1.2). In this pattern expiry date and selector can be changed without breaking the signature, so the file is rejected. Re-signing with arp_cli v' + CLI_VERSION + ' or the Signer produces an enveloped signature (SPEC §13.4).';
            case 'signature_field_removed':
                return 'The signature was computed without the signature field in the signature block, not over the whole object with signature set to "" (SPEC §13.4). The file is rejected.';
            case 'signature_mismatch':
                return 'The signature does not match the file content: the file was changed after signing, or it was signed with a different key.';
            case 'key_revoked':
                return `The DNS record ${name} has an empty p= value: the key is revoked (as in DKIM, RFC 6376 §3.6.1). Files signed with this selector are not accepted.`;
            case 'dns_no_key':
                return `No "v=ARP1" record was found at ${name}.`;
            case 'dns_key_malformed':
                return `The record at ${name} does not contain a valid 32-byte Ed25519 key.`;
            case 'dns_unsupported_algorithm':
                return `The record at ${name} declares a key algorithm other than ed25519.`;
            case 'public_key_malformed':
                return 'The entered public key is not a valid 32-byte Ed25519 key (base64 or PEM). arp_cli verify --pubkey stops with the same key file.';
            case 'unsupported_algorithm':
                return 'The signature block declares an algorithm other than Ed25519.';
            case 'unsupported_canonicalization':
                return 'The signature block declares a canonicalization other than jcs-rfc8785.';
            case 'malformed_signature':
                return 'The signature value is missing or not a 64-byte Ed25519 signature in canonical Base64url (SPEC §13.3).';
            case 'malformed_signature_block':
                return '_arp_signature is not an object.';
            case 'malformed_metadata':
                return 'The signature metadata is incomplete: expires_at is missing or not a timestamp, or dns_selector is not a valid DNS label.';
            case 'no_domain':
                return 'No domain is known for the DNS lookup. Fetch the file from its URL, enter a domain, or enter a public key for an offline check.';
            case 'dns_error':
                return 'The DNS lookup via dns.google failed, so the signature was not checked.';
            case 'not_an_object':
                return 'reasoning.json must be a JSON object.';
            case 'load_failed':
                return 'The file could not be loaded (not JSON, not UTF-8, nested too deeply, or the fetch failed), so it was not checked.';
            case 'verifier_error':
                return 'The check stopped with an internal error (arp_cli reports the same file as verifier_error).';
            default:
                return 'The signature was not checked.';
        }
    }

    // ─────────────────────────────────────────────
    // Discovery snippets (ARP-D, K5) — identical for signed and unsigned files
    // ─────────────────────────────────────────────
    function discoverySnippets(domain, entity, lastmod) {
        const json = manifestUrl(domain);
        const md = markdownUrl(domain);
        return [
            '# HTTP response header on HTML pages',
            'Link: </.well-known/reasoning.json>; rel="describedby"; type="application/json", </.well-known/reasoning.md>; rel="describedby"; type="text/markdown"',
            '',
            '# <head> of HTML pages',
            '<link rel="reasoning" type="application/json" href="/.well-known/reasoning.json">',
            '<link rel="describedby" type="application/json" href="/.well-known/reasoning.json">',
            '',
            '# Visible line in the footer or body text (absolute URL as link text)',
            `English: Self-description (ARP): <a href="${json}">${json}</a>`,
            `Deutsch: Selbstauskunft (ARP): <a href="${json}">${json}</a>`,
            '',
            '# sitemap.xml',
            `<url><loc>${json}</loc><lastmod>${lastmod}</lastmod></url>`,
            `<url><loc>${md}</loc><lastmod>${lastmod}</lastmod></url>`,
            '',
            '# llms.txt',
            '## Reasoning Context',
            `- Self-description (ARP manifest, JSON): ${json}`,
            `- Self-description (Markdown): ${md}`,
            `- The manifest contains ${entity}'s own statements about itself.`,
            '',
            '# Response headers of the two files',
            '/.well-known/reasoning.json  Content-Type: application/json; charset=utf-8  Access-Control-Allow-Origin: *',
            '/.well-known/reasoning.md    Content-Type: text/markdown; charset=utf-8  Access-Control-Allow-Origin: *',
            '',
            '# robots.txt: the Sitemap line and real rules only, no comment "directives"',
            `Sitemap: https://${domain}/sitemap.xml`
        ].join('\n');
    }

    global.ARPTools = {
        SPEC_VERSION, SCHEMA_URL, PROTOCOL, SPEC_SIGNATURE_URL, CLI_VERSION, KNOWN_SCHEMAS,
        RENDER_ORDER, RENDER_EXCLUDE, TEXT_RULES,
        canonicalize, utf8, bytesToBase64, bytesToBase64Url, base64ToBytes, sha256Hex,
        provenanceStatement, signatureStatement, verifyBlock, dnsName, defaultSelector,
        manifestUrl, markdownUrl, isoSeconds, normalizeDomain, isValidDomain, isValidSelector, versionAtLeast13,
        renderMarkdown, representationEntry, setMarkdownRepresentation,
        isForbiddenFieldName, lint, lintText: lintTextValue, lintManifestText, lintSource,
        ManifestParseError, parseJsonCollecting, parseManifestText, parseManifestBytes, decodeUtf8Sig, textAsFile,
        ijsonProblems, orderedKeys, pyNormalizeDomain, normalizeDomainSafe, validateSelector, sameDnsName,
        decodeSignatureStrict, decodeDnsPublicKey, loadPublicKeyText, checkedUrl, representationTarget,
        FetchError, parseUtc,
        loadNoble, ed25519Verify, resolveTxt, parseArpTxt, keysFromTxtRecords, verifyManifest, verifySource,
        checkRepresentations, httpGetBytes, newVerifyResult, explainResult,
        discoverySnippets, DNSNoRecord,
        // Internals for tests/test_web_parity.py (not an API)
        _py: { PATTERNS, PyPattern, pyToJs, fromIsoFormat, pyFloatRepr, pyJsonDumps, childPath, pyUrlsplit, casefoldEquals,
            keyTokens, pyStrip }
    };
})(typeof window !== 'undefined' ? window : globalThis);
