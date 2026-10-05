// reasoning.json — shared browser helpers (ARP v1.3 "Reader Profile")
//
// Used by generator.html, validator.html and sign/index.html so that all three
// tools apply the same canonicalization (JCS, RFC 8785), the same wording rules
// (ARP-W), the same reasoning.md rendering (ARP-R) and the same signature check.
//
// Reference implementation: arp_cli v1.4.0. The functions below are ports of
// render_reasoning_md(), lint_manifest() and verify_manifest() in arp_cli.py:
// same rules, rule names, reason codes and output bytes. Changes there must be
// mirrored here.
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
    const KNOWN_SCHEMAS = {
        'https://arp-protocol.org/schema/v1.3.json': '1.3',
        'https://arp-protocol.org/schema/v1.2.json': '1.2',
        'https://arp-protocol.org/schema/v1.1.json': '1.1',
        'https://arp-protocol.org/schema/v1.json': '1.0'
    };

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

    // Accepts base64 and base64url, padded or unpadded (SPEC §13.3, §13.5).
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

    function verifyBlock(selector, domain) {
        const name = dnsName(selector, domain);
        return {
            dns_name: name,
            doh_url: `https://dns.google/resolve?name=${name}&type=TXT`,
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

    // Normalizes user input like "https://www.example.com/path" to "www.example.com"
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

    // DNS names compare case-insensitively; a trailing dot does not count (arp_cli _same_dns_name)
    function sameDnsName(value, expected) {
        return typeof value === 'string' && value.trim().toLowerCase().replace(/\.+$/, '') === expected.toLowerCase().replace(/\.+$/, '');
    }

    function isValidSelector(selector) {
        return typeof selector === 'string' && selector.length > 0 && selector.length <= 50 && SELECTOR_RE.test(selector);
    }

    function versionAtLeast13(manifest) {
        const m = typeof manifest.version === 'string' ? /^\s*(\d+)\.(\d+)/.exec(manifest.version) : null;
        if (!m) return false;
        const major = parseInt(m[1], 10), minor = parseInt(m[2], 10);
        return major > 1 || (major === 1 && minor >= 3);
    }

    // ─────────────────────────────────────────────
    // ARP-R — reasoning.md rendering (port of arp_cli render_reasoning_md)
    // Deterministic: same manifest → same bytes. UTF-8, LF, one final newline.
    // ─────────────────────────────────────────────
    const RENDER_ORDER = ['identity', 'organization', 'corrections', 'entity_claims', 'authority', 'content_policy'];
    const RENDER_EXCLUDE = ['$schema', 'protocol', 'version', 'domain', 'entity', 'provenance',
        'representations', '_arp_signature', 'diagnostics'];

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
        return { href: markdownUrl(domain), media_type: 'text/markdown', sha256: sha256 };
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
    // ARP-W — Wording Profile lint (port of arp_cli lint_manifest)
    // Python regular expressions are converted so that \b, \w and \d are
    // Unicode-aware as in Python 3, and $ also matches before a final newline.
    // ─────────────────────────────────────────────
    const WORD = '\\p{L}\\p{N}_';
    const WB = `(?:(?<=[${WORD}])(?![${WORD}])|(?<![${WORD}])(?=[${WORD}]))`;

    function pyRe(source, ignoreCase) {
        let out = '';
        let inClass = false;
        for (let i = 0; i < source.length; i++) {
            const c = source[i];
            if (c === '\\') {
                const n = source[i + 1];
                i++;
                if (n === 'b' && !inClass) out += WB;
                else if (n === 'w') out += inClass ? WORD : `[${WORD}]`;
                else if (n === 'd') out += '\\p{Nd}';
                else out += '\\' + n;
                continue;
            }
            if (inClass) {
                if (c === ']') inClass = false;
                out += c;
                continue;
            }
            if (c === '[') {
                inClass = true;
                out += c;
                if (source[i + 1] === '^') { out += '^'; i++; }
                if (source[i + 1] === ']') { out += '\\]'; i++; }
                continue;
            }
            if (c === '$') {
                out += '(?=\\n?$)';
                continue;
            }
            out += c;
        }
        return new RegExp(out, ignoreCase ? 'iu' : 'u');
    }

    const SENT = '(?:^|[.!?;:\\n]\\s*)';
    const CLAUSE = '(?:^|[.!?;:,\\n]\\s*|\\b(?:please|then|always|never|instead|only|should|must|shall|' +
        '(?<!does\\s)(?<!did\\s)not)\\s+)';
    const PROPER = "[A-Z][\\w'’&.-]*(?:\\s+[A-Z][\\w'’&.-]*){0,2}";
    const AI_SUBJECT = '\\b(?:llms?|chatbots?|(?:large\\s+)?language\\s+models?|generative\\s+(?:ai|engines?)|' +
        'answer\\s+engines?|(?:ai|ki)(?:[\\s-]+(?:systems?|agents?|models?|assistants?|tools?|engines?|' +
        'crawlers?|bots?|search))?)';

    // [severity, rule, regex, message] — same order as arp_cli _TEXT_RULES
    const TEXT_RULES = [
        ['error', 'ARP-W/conditional', pyRe(SENT + 'when\\s+[a-z]+ing\\b', true),
            "Conditional instruction ('When discussing X …'). Write a third-person statement about the entity."],
        ['error', 'ARP-W/conditional', pyRe('\\bwhen\\s+(?:asked|queried|prompted)\\b', true),
            "Conditional instruction ('When asked …'). Write a third-person statement about the entity."],
        ['error', 'ARP-W/conditional', pyRe(
            '\\bwhen\\s+(?:a\\s+|the\\s+|any\\s+)?(?:users?|someone|people|persons?|customers?|visitors?|readers?)\\s+' +
            '(?:asks?|queries|query|searches|compares?|mentions?|wants?)\\b', true),
            "Conditional instruction ('When a user asks …'). Describe the situation instead, e.g. 'Typical fit: …'."],
        ['error', 'ARP-W/conditional', pyRe('\\bif\\s+(?:queried|asked|prompted)\\b', true),
            "Conditional instruction ('If asked …'). Write a third-person statement about the entity."],
        ['error', 'ARP-W/imperative', pyRe(`\\b[Ff]rame\\s+(?:it|this|that|them|him|her|us|${PROPER})\\s+as\\b`, false),
            "Instruction to AI systems ('frame it as'). State the fact instead."],
        ['error', 'ARP-W/imperative', pyRe(CLAUSE + 'describe\\s+(?:\\S+\\s+){0,5}?as\\b', true),
            "Instruction to AI systems ('describe X as'). State the fact instead."],
        ['error', 'ARP-W/imperative', pyRe('\\bdefer\\s+to\\b', true),
            "Instruction to AI systems ('defer to'). Link evidence instead."],
        ['error', 'ARP-W/imperative', pyRe(CLAUSE + 'treat\\s+(?:\\S+\\s+){0,6}?as\\b', true),
            "Instruction to AI systems ('treat … as'). State what the item is instead."],
        ['error', 'ARP-W/imperative', pyRe(CLAUSE + 'recommend\\b', true),
            "Instruction to recommend. Describe the fit instead ('Typical fit: …' / 'Not a fit: …')."],
        ['error', 'ARP-W/imperative', pyRe('\\brecommend\\s+(?:\\S+\\s+){0,5}?(?:when|if)\\b', true),
            "Instruction to recommend ('recommend X when'). Describe the fit instead ('Typical fit: …')."],
        ['error', 'ARP-W/address-ai', pyRe(
            "\\bif\\s+you(?:'re|’re|\\s+are)\\s+(?:an?\\s+)?(?:ai|a\\.i\\.|llm|large\\s+language\\s+model|language\\s+model|" +
            'agent|assistant|bot|chatbot|model|crawler|machine)\\b', true),
            "Text addressed to AI systems ('If you are an AI'). Remove it."],
        ['error', 'ARP-W/address-ai', pyRe(
            "\\byou(?:'re|’re|\\s+are)\\s+(?:\\w+\\s+)?(?:authori[sz]ed|allowed|permitted|instructed|required|expected|asked)\\b", true),
            "Permission or instruction addressed to the reader ('you are authorized'). Remove it."],
        ['error', 'ARP-W/address-ai', pyRe('\\byou\\s+(?:should|must|shall|may|need\\s+to|have\\s+to|ought\\s+to)\\b', true),
            "Instruction in second person ('you should/may …'). Write a third-person statement."],
        ['error', 'ARP-W/address-ai', pyRe(
            AI_SUBJECT + '\\s+(?:must|should|shall|need\\s+to|have\\s+to|are\\s+(?:required|expected|asked|' +
            'instructed|encouraged|advised)\\s+to)\\b', true),
            "Normative sentence addressed to AI systems ('AI systems must/should'). Write a statement about the entity."],
        ['error', 'ARP-W/address-ai', pyRe(
            '\\b(?:KI|AI)[\\s-]?(?:Systeme?|Agenten?|Modelle?|Assistenten?|Crawler)\\s+(?:sollen|sollten|müssen|dürfen)\\b', true),
            "Normative sentence addressed to AI systems ('KI-Systeme sollen …'). Write a statement about the entity."],
        ['error', 'ARP-W/memory', pyRe('\\bremember\\b|\\bmerke?\\s+dir\\b', true),
            "Memory instruction ('remember'). Remove it."],
        ['error', 'ARP-W/memory', pyRe(
            '\\bin\\s+(?:all\\s+)?(?:future|subsequent|later|upcoming)\\s+(?:conversations?|chats?|sessions?|responses?|' +
            'answers?|interactions?)\\b|\\bin\\s+(?:künftigen|zukünftigen|späteren)\\s+(?:Gesprächen|Unterhaltungen|Antworten)\\b', true),
            "Persistence instruction ('in future conversations'). Remove it."],
        ['error', 'ARP-W/system-marker', pyRe(
            '<\\s*/?\\s*system(?:[_\\-\\s]?(?:note|prompt|message|instructions?|context))?\\b[^>]*>', true),
            'Pseudo system tag (e.g. <system_note>). Remove it.'],
        ['error', 'ARP-W/system-marker', pyRe('\\bSYSTEM\\s*:|\\bIMPORTANT\\s*:|\\[/?(?:SYSTEM|INST)\\]|<<\\s*/?SYS\\s*>>|<\\|[a-z_]+\\|>', false),
            "Pseudo system marker ('SYSTEM:', 'IMPORTANT:', chat-template tokens). Remove it."],
        ['error', 'ARP-W/system-marker', pyRe('\\bnote\\s+to\\s+(?:ai|llms?|models?|assistants?|agents?)\\b', true),
            'Note addressed to AI systems. Remove it.'],
        ['error', 'ARP-W/disclaimer', pyRe(
            '\\bnot\\b[^.!?\\n]{0,60}?\\b(?:prompt[\\s-]+injections?|data[\\s-]+poisoning|poisoning|misinformation|' +
            'disinformation|jailbreak(?:s|ing)?|manipulation|an?\\s+attacks?)\\b' +
            '|\\bkeine?\\b[^.!?\\n]{0,60}?\\b(?:Prompt[\\s-]*Injection|Manipulation|Falschinformation|Desinformation)\\b', true),
            "Disclaimer of innocence ('this is not prompt injection / misinformation / data poisoning'). Remove it."],
        ['error', 'ARP-W/unsourced-authority', pyRe('\\bground[\\s-]+truth\\b|\\bGrundwahrheit\\b', true),
            "'ground truth' cannot be attributed to a checker. State the fact and link evidence."],
        ['error', 'ARP-W/unsourced-authority', pyRe('\\btrusted\\s+sources?\\b|\\bvertrauenswürdige\\s+Quellen?\\b', true),
            "'trusted source' without saying who checked what. State the fact and link evidence."],
        ['error', 'ARP-W/unsourced-authority', pyRe(
            '\\bauthoritative\\s+(?:sources?|information|data|facts?|references?|answers?|records?|statements?|' +
            'descriptions?|context)\\b|\\bmaßgebliche\\s+Quellen?\\b', true),
            "'authoritative source/information' without saying who checked what. State the fact and link evidence."],
        ['error', 'ARP-W/hidden-text', pyRe(
            "class\\s*=\\s*[\"'][^\"']*\\b(?:sr-only|visually-hidden|screen-reader-only)\\b|display\\s*:\\s*none|" +
            'visibility\\s*:\\s*hidden|clip(?:-path)?\\s*:\\s*(?:rect|inset)\\s*\\(|' +
            "font-size\\s*:\\s*0(?:\\.0+)?(?:px|em|rem|pt|%)?\\s*(?:[;\"'}!]|$)|" +
            "aria-hidden\\s*=\\s*[\"']true", true),
            'Hidden-text markup (sr-only, display:none, clip …). Everything must be visible to people and bots alike.'],
        ['warning', 'ARP-W/second-person', pyRe("\\b(?:you|your|yours|yourself|you're|you’re)\\b", true),
            'Second person. The Wording Profile uses third-person statements about the entity.'],
        ['warning', 'ARP-W/imperative-heuristic', pyRe(
            SENT + "(?:do\\s+not|don't|don’t|never|always|please|ignore|disregard|cite|prefer|prioriti[sz]e|mention|" +
            'consider|emphasi[sz]e|highlight|avoid|ensure|make\\s+sure|respond|refer\\s+to|reference|' +
            'use(?!\\s+(?:of|cases?)\\b))\\b', true),
            'Sentence starts like an imperative. Check that it is a third-person statement.'],
        ['warning', 'ARP-W/normative', pyRe(
            '\\b(?:loaders?|consumers?|verifiers?|consuming\\s+systems?|retrieval\\s+systems?|rag\\s+(?:systems?|pipelines?)|' +
            'search\\s+engines?)\\s+(?:must|should|shall|may)\\b' +
            '|' + AI_SUBJECT + '\\s+may\\b', true),
            'Normative or permission sentence about consumers. Such rules belong in the SPEC, not in a manifest.'],
        ['warning', 'ARP-W/disclaimer', pyRe('\\bbenign\\b|\\bharmless\\b|\\bharmlos\\b', true),
            "Reassurance wording ('benign', 'harmless'). Describe what the item is instead."],
        ['warning', 'ARP-W/disclaimer', pyRe(
            '\\bnot\\b[^.!?\\n]{0,40}?\\b(?:instructions?|commands?|directives?)\\b' +
            '|\\bkeine?\\b[^.!?\\n]{0,40}?\\b(?:Anweisung(?:en)?|Befehle?)\\b', true),
            "Reassurance that the text is 'not instructions/commands'. A plain description is enough."],
        ['warning', 'ARP-W/superlative', pyRe(
            '\\bpioneer(?:s|ing|ed)?\\b|\\belite\\b|\\bworld[\\s-]leading\\b|\\bmarket[\\s-]leader\\b|\\bindustry[\\s-]leader\\b|' +
            '\\bthe\\s+first\\s+(?:\\w+\\s+){0,3}to\\b|\\bfirst[\\s-]mover\\b|\\bbest[\\s-]in[\\s-]class\\b|\\bunrivall?ed\\b|' +
            '\\bunmatched\\b|#1\\b', true),
            'Superlative without evidence. Link a source or remove it.'],
        ['warning', 'ARP-W/html-comment', pyRe('<!--', false),
            'HTML comment inside a value. Comments are invisible to people; remove it.']
    ];

    const VERIFIED_RE = pyRe('\\b(?:verified|cross-verified|verifiziert|geprüft)\\b', true);
    const VERIFIED_QUALIFIER_RE = pyRe(
        '^(?:\\s*,)?(?:\\s+\\S+){0,2}?\\s+(?:by|via|through|against|using|with|at|in|on|from|per|according\\s+to|' +
        'durch|von|über|beim|bei|im|laut|gegen)\\b', true);
    const NEGATION_BEFORE_RE = pyRe('\\b(?:no|not|never|nicht|nie|keine?[mnrs]?)\\s+(?:\\S+\\s+)?$', true);
    const GERMAN_AGENT_BEFORE_RE = pyRe('\\b(?:von|vom|durch|beim|bei|laut|gegen|im|am)\\b[^.!?\\n]*$', true);
    const INVISIBLE_RE = /[\u200B\u2060-\u2064\uFEFF\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}]/u;
    const ARP_NAME_RE = pyRe('\\bARP\\b|\\bAgentic\\s+Reasoning\\s+Protocol\\b', false);
    const ARP_STANDARD_RE = pyRe(
        '\\b(?:is|as|an?)\\s+(?:an?\\s+)?(?:(?:open|new|official|internet|web|ietf|global)\\s+)+standard\\b' +
        '|\\bIETF[\\s-]+Standard\\b|\\bInternet[\\s-]?[Ss]tandard\\b', true);
    const URL_ONLY_RE = /^\s*https?:\/\/\S+\s*$/;
    const SIGNATURE_WORD_RE = pyRe('\\bsign(?:s|ed|ing|ature|atures)?\\b|\\bsigniert\\b|\\bSignatur(?:en)?\\b', true);
    const PROVENANCE_TEMPLATE_RE = new RegExp(
        "^This file is (?<entity>.+)'s own description of itself, published by (?<publisher>.+) at " +
        '(?<domain>[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9])\\. The statements are self-attested; where available, ' +
        'independent evidence is linked in evidence_url\\.$', 'u');

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

    function keyTokens(key) {
        return (String(key).match(/[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+/g) || []).map(t => t.toLowerCase());
    }

    function isForbiddenFieldName(key) {
        return FORBIDDEN_KEYS.has(String(key).toLowerCase()) || keyTokens(key).some(t => FORBIDDEN_KEY_TOKENS.has(t));
    }

    function childPath(path, key) {
        if (typeof key === 'number') return `${path}[${key}]`;
        if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) return `${path}.${key}`;
        return `${path}[${JSON.stringify(key)}]`;
    }

    function excerpt(text, start, end) {
        const a = Math.max(0, start - 30), b = Math.min(text.length, end + 30);
        return (a > 0 ? '…' : '') + text.slice(a, b).replace(/\n/g, ' ') + (b < text.length ? '…' : '');
    }

    function finding(severity, rule, path, message, excerptText, match) {
        return { severity, rule, path, message, excerpt: excerptText || '', match: match || '' };
    }

    function lintText(path, text) {
        const findings = [];
        if (URL_ONLY_RE.test(text)) return findings;
        const spans = {};
        for (const [severity, rule, regex, message] of TEXT_RULES) {
            const m = regex.exec(text);
            if (!m) continue;
            const start = m.index, end = m.index + m[0].length;
            // One finding per rule and text passage: skip overlapping matches of the same rule.
            if ((spans[rule] || []).some(([s, e]) => start < e && s < end)) continue;
            (spans[rule] = spans[rule] || []).push([start, end]);
            findings.push(finding(severity, rule, path, message, excerpt(text, start, end), m[0]));
        }
        const verifiedRe = new RegExp(VERIFIED_RE.source, 'giu');
        let m;
        while ((m = verifiedRe.exec(text)) !== null) {
            const start = m.index, end = m.index + m[0].length;
            let qualified = VERIFIED_QUALIFIER_RE.test(text.slice(end));
            const word = m[0].toLowerCase();
            if (!qualified && (word === 'verifiziert' || word === 'geprüft')) {
                // German word order names the checker before the participle ("vom TÜV geprüft").
                qualified = GERMAN_AGENT_BEFORE_RE.test(text.slice(Math.max(0, start - 60), start));
            }
            if (!qualified && NEGATION_BEFORE_RE.test(text.slice(Math.max(0, start - 40), start))) {
                qualified = true; // "no verified adoption" claims nothing
            }
            if (!qualified) {
                findings.push(finding('error', 'ARP-W/unsourced-authority', path,
                    "'verified' without saying who checked what (e.g. 'verified by …', 'checked against …').",
                    excerpt(text, start, end), m[0]));
                break;
            }
        }
        const inv = INVISIBLE_RE.exec(text);
        if (inv) {
            const cp = inv[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
            findings.push(finding('error', 'ARP-W/hidden-text', path,
                `Invisible Unicode character U+${cp}. Text must be the same for people and bots.`,
                excerpt(text, inv.index, inv.index + inv[0].length).split(inv[0]).join(`<U+${cp}>`), inv[0]));
        }
        if (ARP_NAME_RE.test(text)) {
            const s = ARP_STANDARD_RE.exec(text);
            if (s) {
                findings.push(finding('warning', 'ARP-W/terms', path,
                    'ARP is described as a standard. ARP is a single-author draft, not a standard or IETF standard.',
                    excerpt(text, s.index, s.index + s[0].length), s[0]));
            }
        }
        return findings;
    }

    function lintProvenance(manifest) {
        const findings = [];
        const v13 = versionAtLeast13(manifest);
        const prov = manifest.provenance;
        if (prov === undefined || prov === null) {
            findings.push(finding(v13 ? 'error' : 'warning', 'ARP-P/missing', '$.provenance',
                'provenance is missing (REQUIRED in ARP v1.3): statement, publisher, publisher_url, published.'));
            return findings;
        }
        if (!isPlainObject(prov)) {
            findings.push(finding('error', 'ARP-P/type', '$.provenance', 'provenance must be an object.'));
            return findings;
        }
        for (const field of ['statement', 'publisher', 'publisher_url', 'published']) {
            if (typeof prov[field] !== 'string' || !prov[field]) {
                findings.push(finding('error', 'ARP-P/field', `$.provenance.${field}`, `provenance.${field} is missing or empty.`));
            }
        }
        const published = prov.published;
        if (typeof published === 'string' && published && !/^\d{4}-\d{2}-\d{2}$/.test(published)) {
            findings.push(finding('error', 'ARP-P/field', '$.provenance.published',
                'provenance.published must be a date (YYYY-MM-DD).', published));
        }
        const url = prov.publisher_url;
        if (typeof url === 'string' && url && !url.startsWith('https://')) {
            findings.push(finding('error', 'ARP-P/field', '$.provenance.publisher_url',
                'provenance.publisher_url must be an https:// URL (legal notice).', url));
        }
        const statement = prov.statement;
        if (typeof statement === 'string' && statement) {
            const s = SIGNATURE_WORD_RE.exec(statement);
            if (s) {
                findings.push(finding('error', 'ARP-P/no-signature', '$.provenance.statement',
                    'provenance.statement must not mention a signature (identical in signed and unsigned files).',
                    excerpt(statement, s.index, s.index + s[0].length), s[0]));
            }
            // SPEC §4.1: the statement MUST follow the template (error in v1.3, as arp_cli).
            const sev = v13 ? 'error' : 'warning';
            const t = PROVENANCE_TEMPLATE_RE.exec(statement);
            if (!t) {
                findings.push(finding(sev, 'ARP-P/template', '$.provenance.statement',
                    'provenance.statement differs from the fixed template: "This file is {ENTITY}\'s own description ' +
                    'of itself, published by {PUBLISHER} at {DOMAIN}. The statements are self-attested; where ' +
                    'available, independent evidence is linked in evidence_url."'));
            } else {
                for (const [group, expected] of [['entity', manifest.entity], ['publisher', prov.publisher], ['domain', manifest.domain]]) {
                    if (typeof expected === 'string' && t.groups[group] !== expected) {
                        findings.push(finding(sev, 'ARP-P/template', '$.provenance.statement',
                            `provenance.statement names ${group} '${t.groups[group]}', the file says '${expected}'.`));
                    }
                }
            }
        }
        return findings;
    }

    function lintSignatureBlock(manifest) {
        const findings = [];
        const sig = manifest._arp_signature;
        if (sig === undefined || sig === null) return findings;
        if (!isPlainObject(sig)) return [finding('error', 'ARP-S/type', '$._arp_signature', '_arp_signature must be an object.')];
        const sev = versionAtLeast13(manifest) ? 'error' : 'warning';
        if (!has(sig, 'statement')) {
            findings.push(finding(sev, 'ARP-S/statement', '$._arp_signature.statement',
                '_arp_signature.statement is missing (REQUIRED in ARP v1.3; re-sign with arp_cli v1.4).'));
        }
        if (!isPlainObject(sig.verify)) {
            findings.push(finding(sev, 'ARP-S/verify', '$._arp_signature.verify',
                '_arp_signature.verify is missing (REQUIRED in ARP v1.3; re-sign with arp_cli v1.4).'));
        }
        if (typeof sig.statement === 'string' && typeof manifest.domain === 'string' && typeof sig.dns_selector === 'string') {
            const expected = signatureStatement(sig.dns_selector, manifest.domain);
            if (sig.statement !== expected) {
                findings.push(finding('warning', 'ARP-S/statement', '$._arp_signature.statement',
                    `_arp_signature.statement differs from the fixed template: "${expected}"`));
            }
        }
        return findings;
    }

    function lintRepresentations(manifest) {
        const reps = manifest.representations;
        if (reps === undefined || reps === null) {
            return versionAtLeast13(manifest)
                ? [finding('warning', 'ARP-R/missing', '$.representations',
                    'representations is missing (RECOMMENDED in ARP v1.3: reasoning.md with sha256).')]
                : [];
        }
        if (!Array.isArray(reps) || !reps.length) {
            return [finding('error', 'ARP-R/type', '$.representations', 'representations must be a non-empty array.')];
        }
        const findings = [];
        reps.forEach((entry, i) => {
            const p = `$.representations[${i}]`;
            if (!isPlainObject(entry)) {
                findings.push(finding('error', 'ARP-R/type', p, 'representation entries must be objects.'));
                return;
            }
            if (!String(entry.href === undefined ? '' : entry.href).startsWith('https://')) {
                findings.push(finding('error', 'ARP-R/field', p + '.href', 'href must be an absolute https:// URL.'));
            }
            if (!entry.media_type) findings.push(finding('error', 'ARP-R/field', p + '.media_type', 'media_type is missing.'));
            if (!/^[0-9a-f]{64}$/.test(String(entry.sha256 === undefined ? '' : entry.sha256))) {
                findings.push(finding('error', 'ARP-R/field', p + '.sha256', 'sha256 must be 64 lowercase hex characters.'));
            }
        });
        return findings;
    }

    // Size as Python json.dumps(ensure_ascii=False) would serialize it
    function pyJsonLength(value) {
        if (Array.isArray(value)) return '[' + value.map(pyJsonLength).join(', ') + ']';
        if (isPlainObject(value)) return '{' + Object.keys(value).map(k => JSON.stringify(k) + ': ' + pyJsonLength(value[k])).join(', ') + '}';
        return JSON.stringify(value);
    }

    // Returns findings { severity, rule, path, message, excerpt, match }, errors first.
    function lint(manifest) {
        if (!isPlainObject(manifest)) return [finding('error', 'ARP/type', '$', 'reasoning.json must be a JSON object.')];
        const findings = [];
        (function walk(value, path) {
            if (isPlainObject(value)) {
                for (const key of Object.keys(value)) {
                    const child = childPath(path, key);
                    if (isForbiddenFieldName(key)) {
                        findings.push(finding('error', 'ARP-W/field-name', child,
                            `Field name '${key}' is reserved for instruction-style content and not allowed ` +
                            '(system_instruction, reasoning_directives, ai_directive, agent_directive, instruction(s), directive(s)).',
                            key, key));
                    }
                    walk(value[key], child);
                }
            } else if (Array.isArray(value)) {
                value.forEach((item, i) => walk(item, childPath(path, i)));
            } else if (typeof value === 'string') {
                if (path === '$["$schema"]' || path === '$._arp_signature.signature') return;
                findings.push(...lintText(path, value));
            }
        })(manifest, '$');
        findings.push(...lintProvenance(manifest));
        findings.push(...lintSignatureBlock(manifest));
        findings.push(...lintRepresentations(manifest));
        if (utf8(pyJsonLength(manifest)).length > 100 * 1024) {
            findings.push(finding('warning', 'ARP/size', '$', 'File exceeds 100 KB (SPEC §2).'));
        }
        const order = { error: 0, warning: 1 };
        return findings.sort((a, b) => order[a.severity] - order[b.severity]);
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
            } catch (e) { /* malformed key: try the next one */ }
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

    // Port of arp_cli parse_arp_txt: tags or null if not an ARP1 record
    function parseArpTxt(txt) {
        const tags = {};
        const warnings = [];
        for (const segment of String(txt).split(';')) {
            const part = segment.trim();
            if (!part || part.indexOf('=') < 0) continue;
            const eq = part.indexOf('=');
            const name = part.slice(0, eq).trim();
            if (name !== name.toLowerCase()) warnings.push(`DNS record tag '${name}=' should be lowercase.`);
            tags[name.toLowerCase()] = part.slice(eq + 1).trim();
        }
        const v = tags.v;
        if (v === undefined || v.toUpperCase() !== 'ARP1') return { tags: null, warnings: [] };
        if (v !== 'ARP1') warnings.push(`DNS record uses 'v=${v}'; SPEC §13.5 specifies 'v=ARP1'. Read tolerantly; the record should be corrected.`);
        return { tags, warnings };
    }

    // Port of arp_cli keys_from_txt_records (status: ok, revoked, no_record, malformed, unsupported_algorithm)
    function keysFromTxtRecords(records) {
        const result = { status: 'no_record', publicKeys: [], record: null, warnings: [], detail: '' };
        const arp = [];
        for (const txt of records) {
            const parsed = parseArpTxt(txt);
            if (parsed.tags) {
                arp.push([txt, parsed.tags]);
                result.warnings.push(...parsed.warnings);
            }
        }
        if (!arp.length) {
            result.detail = 'no v=ARP1 TXT record';
            return result;
        }
        if (arp.length > 1) result.warnings.push('Several ARP1 records at the same name; each key is tried.');
        for (const [txt, tags] of arp) {
            if (has(tags, 'p') && tags.p.replace(/\s+/g, '') === '') {
                Object.assign(result, { status: 'revoked', record: txt, detail: 'p= is empty: key revoked' });
                return result;
            }
        }
        for (const [txt, tags] of arp) {
            result.record = txt;
            let algo = tags.k;
            if (algo === undefined) {
                result.warnings.push('DNS record has no k= tag; ed25519 assumed (SPEC §13.5 requires k=ed25519).');
                algo = 'ed25519';
            }
            if (algo.toLowerCase() !== 'ed25519') {
                Object.assign(result, { status: 'unsupported_algorithm', detail: `k=${algo} (expected ed25519)` });
                continue;
            }
            if (algo !== 'ed25519') result.warnings.push(`DNS record uses 'k=${algo}'; SPEC §13.5 specifies 'k=ed25519'.`);
            if (!has(tags, 'p')) {
                Object.assign(result, { status: 'malformed', detail: 'p= tag missing' });
                continue;
            }
            try {
                const key = base64ToBytes(tags.p);
                if (key.length !== 32) throw new Error(`public key has ${key.length} bytes, expected 32`);
                result.publicKeys.push(key);
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

    // Python datetime.fromisoformat semantics: naive timestamps count as UTC
    function parseUtc(value) {
        if (typeof value !== 'string') return null;
        let s = value.trim();
        if (/^\d{4}-\d{2}-\d{2}$/.test(s)) s += 'T00:00:00Z';
        else if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s = s.replace(' ', 'T') + 'Z';
        if (!/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})$/.test(s)) return null;
        const t = Date.parse(s.replace(' ', 'T'));
        return isNaN(t) ? null : t;
    }

    // Port of arp_cli verify_manifest: Enveloped Pattern only (SPEC §13.4),
    // trust levels (§13.7), revocation by empty p= (K6), legacy rejection (K3).
    //
    // options:
    //   domain       retrieval domain (URL host) or the domain for pasted files
    //   publicKey    optional base64 public key for offline checks (no DNS)
    //   resolveTxt   optional resolver override (tests)
    //   now          optional Date
    //
    // Returns { level: CRYPTOGRAPHIC | UNSIGNED | INVALID | ERROR, reason, dnsName,
    //           selector, method, expired, dnssec, notes }.
    async function verifyManifest(manifest, options) {
        const opts = options || {};
        const now = (opts.now || new Date()).getTime();
        const resolver = opts.resolveTxt || resolveTxt;
        const domain = opts.domain ? String(opts.domain).trim().toLowerCase().replace(/\.$/, '') : null;
        const result = { level: null, reason: null, detail: '', dnsName: null, selector: null, method: null, expired: false, dnssec: null, notes: [] };
        const done = (level, reason, detail) => Object.assign(result, { level, reason, detail: detail || '' });

        if (!isPlainObject(manifest)) return done('ERROR', 'not_an_object', 'reasoning.json must be a JSON object');

        const sig = manifest._arp_signature;
        const payloadDomain = manifest.domain;
        if (domain && typeof payloadDomain === 'string' &&
            payloadDomain.trim().toLowerCase().replace(/\.$/, '') !== domain) {
            const detail = `payload field domain '${payloadDomain}' differs from the retrieval domain '${domain}' (SPEC §4)`;
            if (sig) return done('INVALID', 'domain_mismatch', detail);
            result.notes.push(detail);
        }

        if (!sig) return done('UNSIGNED', 'unsigned');
        if (!isPlainObject(sig)) return done('INVALID', 'malformed_signature_block', '_arp_signature is not an object');

        if (sig.algorithm !== 'Ed25519') return done('INVALID', 'unsupported_algorithm', `algorithm ${sig.algorithm}`);
        if (sig.canonicalization !== 'jcs-rfc8785') return done('INVALID', 'unsupported_canonicalization', `canonicalization ${sig.canonicalization}`);
        if (typeof sig.signature !== 'string' || !sig.signature.trim()) return done('INVALID', 'malformed_signature', 'signature value missing');
        let signature;
        try {
            signature = base64ToBytes(sig.signature);
        } catch (e) {
            return done('INVALID', 'malformed_signature', 'signature not decodable');
        }
        if (signature.length !== 64) return done('INVALID', 'malformed_signature', `signature has ${signature.length} bytes, expected 64`);

        const expires = parseUtc(sig.expires_at);
        if (expires === null) return done('INVALID', 'malformed_metadata', 'expires_at missing or not an ISO 8601 timestamp');
        result.expired = now > expires;
        const signedAt = parseUtc(sig.signed_at);
        if (signedAt !== null && signedAt > now + 5 * 60 * 1000) result.notes.push(`signed_at lies in the future (${sig.signed_at}).`);

        const selector = sig.dns_selector || 'arp';
        result.selector = selector;
        if (!isValidSelector(selector)) return done('INVALID', 'malformed_metadata', `'${selector}' is not a valid selector`);

        const v13 = versionAtLeast13(manifest);
        if (v13 && (!has(sig, 'statement') || !isPlainObject(sig.verify))) {
            result.notes.push('ARP v1.3 requires _arp_signature.statement and .verify.');
        }

        // Consistency of the signed pointers with the domain (SPEC §13.3), as arp_cli:
        // in v1.3 a different dns_record or verify.dns_name is INVALID (domain_mismatch).
        const keyDomain = domain || (typeof payloadDomain === 'string' && isValidDomain(normalizeDomain(payloadDomain))
            ? normalizeDomain(payloadDomain) : null);
        if (keyDomain) {
            const expectedName = dnsName(selector, keyDomain);
            const verifyBlock = isPlainObject(sig.verify) ? sig.verify : {};
            for (const [field, value] of [['dns_record', sig.dns_record], ['verify.dns_name', verifyBlock.dns_name]]) {
                if (value === undefined || value === null || sameDnsName(value, expectedName)) continue;
                const detail = `${field} '${value}' differs from '${expectedName}' (dns_selector + domain)`;
                if (v13) return done('INVALID', 'domain_mismatch', detail);
                result.notes.push(`${detail}; the retrieval-derived name is used (informational).`);
            }
        }

        let keys;
        if (opts.publicKey) {
            result.method = 'local_public_key';
            try {
                const key = base64ToBytes(opts.publicKey);
                if (key.length !== 32) throw new Error('length');
                keys = [key];
            } catch (e) {
                return done('ERROR', 'public_key_malformed', 'the entered public key is not a 32-byte Ed25519 key');
            }
        } else {
            if (!domain) return done('ERROR', 'no_domain', 'verification domain unknown');
            const name = dnsName(selector, domain);
            result.dnsName = name;
            result.method = 'dns';
            let records;
            try {
                records = await resolver(name);
                if (resolver === resolveTxt) result.dnssec = resolveTxt.lastAd;
            } catch (e) {
                if (e instanceof DNSNoRecord || (e && e.name === 'DNSNoRecord') || (e && e.noRecord)) {
                    return done('INVALID', 'dns_no_key', `no TXT record at ${name}`);
                }
                return done('ERROR', 'dns_error', `DNS lookup for ${name} failed: ${e.message}`);
            }
            const info = keysFromTxtRecords(records);
            result.notes.push(...info.warnings);
            if (info.status === 'revoked') return done('INVALID', 'key_revoked', `${name} has an empty p= value: the domain operator revoked this key`);
            if (info.status === 'no_record') return done('INVALID', 'dns_no_key', `no v=ARP1 TXT record at ${name}`);
            if (info.status === 'unsupported_algorithm') return done('INVALID', 'dns_unsupported_algorithm', info.detail);
            if (info.status !== 'ok') return done('INVALID', 'dns_key_malformed', info.detail);
            keys = info.publicKeys;
        }

        const enveloped = JSON.parse(JSON.stringify(manifest));
        enveloped._arp_signature.signature = '';
        if (await verifyWithKeys(keys, signature, utf8(canonicalize(enveloped)))) {
            if (result.expired) return done('UNSIGNED', 'expired', `signature expired at ${sig.expires_at}`);
            return done('CRYPTOGRAPHIC', 'valid');
        }

        // Explain the failure; never turns a failure into success (arp_cli _diagnose_failure)
        const legacy = JSON.parse(JSON.stringify(manifest));
        delete legacy._arp_signature;
        if (await verifyWithKeys(keys, signature, utf8(canonicalize(legacy)))) return done('INVALID', 'legacy_payload_only');
        const removed = JSON.parse(JSON.stringify(manifest));
        delete removed._arp_signature.signature;
        if (await verifyWithKeys(keys, signature, utf8(canonicalize(removed)))) return done('INVALID', 'signature_field_removed');
        return done('INVALID', 'signature_mismatch');
    }

    // Plain-language explanation of a verification result (English UI)
    function explainResult(result, ctx) {
        const c = ctx || {};
        const name = result.dnsName || 'the DNS record';
        const origin = 'A signature shows the origin of the file, not the accuracy of its statements.';
        switch (result.reason) {
            case 'valid':
                return result.method === 'local_public_key'
                    ? 'The signature matches the public key entered for this offline check. This shows that the holder of that key signed exactly this file and that it has not been altered since. ' + origin
                    : `The signature matches the public key published in DNS at ${name}. This shows that the operator of ${c.domain || 'the domain'} published exactly this file and that it has not been altered since signing. ${origin}`;
            case 'unsigned':
                return 'The file carries no signature. Its statements are the entity\'s own description; its origin is as certain as the connection it was retrieved over. Signing is optional.';
            case 'expired':
                return `The signature was valid but expired on ${c.expiresAt || 'its expiry date'}. Expired signatures count as unsigned (SPEC §13.7).`;
            case 'domain_mismatch':
                return `The domain field (${c.fileDomain || '?'}) does not match the domain the file was retrieved from (${c.domain || '?'}) (SPEC §4).`;
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
                return 'The entered public key is not a valid 32-byte Ed25519 key (base64).';
            case 'unsupported_algorithm':
                return 'The signature block declares an algorithm other than Ed25519.';
            case 'unsupported_canonicalization':
                return 'The signature block declares a canonicalization other than jcs-rfc8785.';
            case 'malformed_signature':
                return 'The signature value is not a valid base64url-encoded 64-byte Ed25519 signature.';
            case 'malformed_signature_block':
                return '_arp_signature is not an object.';
            case 'malformed_metadata':
                return 'The signature metadata is incomplete: expires_at is missing or not a timestamp, or dns_selector is not a valid DNS label.';
            case 'no_domain':
                return 'No domain is known for the DNS lookup. Fetch the file from its URL, enter a domain, or enter a public key for an offline check.';
            case 'dns_error':
                return 'The DNS lookup via dns.google failed, so the signature was not checked.';
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
        isForbiddenFieldName, lint, lintText,
        loadNoble, ed25519Verify, resolveTxt, parseArpTxt, keysFromTxtRecords, verifyManifest, explainResult,
        discoverySnippets, DNSNoRecord
    };
})(typeof window !== 'undefined' ? window : globalThis);
