#!/usr/bin/env node
// Headless runner for the browser logic in script.js (used by tests/test_web_parity.py).
//
// Loads ../script.js with node's vm module into this context, with minimal
// window/document stubs, and runs the jobs read from stdin (JSON):
//
//   { "cases": [
//       { "id", "op": "verify", "source": "file" | "url", "bytes_b64", "url", "domain", "pubkey",
//         "local_md_b64", "no_reps", "zone": { name: [txt, ...] | { "error": text } },
//         "pages": { url: { "status", "content_type", "body_b64" } } },
//       { "id", "op": "lint", "bytes_b64" },
//       { "id", "op": "lint_object", "json" },          // lint() on a plain object (Generator/Signer path)
//       { "id", "op": "patterns" },                      // pattern sources for comparison
//       { "id", "op": "regex", "refs": [name | index], "strings": [...] },
//       { "id", "op": "parse_utc", "values": [...] },
//       { "id", "op": "signer_selfcheck", "json", "domain", "selector" },
//       { "id", "op": "generator", "json", "domain" } ] }
//
// Writes { id: result } as JSON to stdout. DNS and HTTP are taken from the job
// ("zone", "pages"); without "pages" a URL source is fetched for real.
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

function loadTools() {
    const code = fs.readFileSync(path.join(__dirname, '..', 'script.js'), 'utf8');
    const element = () => ({ textContent: '', innerHTML: '', style: {}, classList: { add() {}, remove() {} } });
    const document = { getElementById: element, querySelector: element, querySelectorAll: () => [], createElement: element };
    globalThis.window = { document, location: { search: '' }, navigator: {} };
    globalThis.document = document;
    vm.runInThisContext(code, { filename: 'script.js' });
    return globalThis.window.ARPTools;
}

const T = loadTools();
const b64 = (s) => (s === null || s === undefined ? null : new Uint8Array(Buffer.from(s, 'base64')));

function resolverFor(zone) {
    return async (name) => {
        const v = zone ? zone[name] : undefined;
        if (v === undefined || v === null) throw new T.DNSNoRecord(`NXDOMAIN ${name}`);
        if (!Array.isArray(v)) throw new Error(v.error || 'lookup failed');
        return v.slice();
    };
}

function fetcherFor(pages) {
    if (!pages) return undefined;
    return async (url) => {
        const page = pages[url];
        if (!page) throw new Error(`KeyError: ${url}`);
        return { status: page.status || 200, contentType: page.content_type || '', bytes: b64(page.body_b64), url };
    };
}

function lintResult(out) {
    if (!out.ok) return { ok: false, reason: out.error.reason };
    return { ok: true, findings: out.findings.map(f => [f.severity, f.rule, f.path]) };
}

async function runCase(c) {
    switch (c.op) {
        case 'verify': {
            const options = {
                source: c.source,
                url: c.url,
                bytes: c.source === 'url' ? undefined : b64(c.bytes_b64),
                domain: c.domain || undefined,
                publicKey: c.pubkey || undefined,
                localMarkdown: b64(c.local_md_b64),
                noRepresentations: !!c.no_reps,
                resolveTxt: resolverFor(c.zone),
                fetchBytes: fetcherFor(c.pages)
            };
            const summary = (out) => ({
                status: out.result.status, reason: out.result.reason, dns_name: out.result.dns_name,
                selector: out.result.selector, expired: out.result.expired, method: out.result.method,
                representations: out.representations.map(x => x.status)
            });
            const direct = summary(await T.verifySource(options));
            if (c.source !== 'url') return direct;
            // validator.html: fetch first (T.httpGetBytes), then verify the fetched bytes
            let prefetched;
            try {
                const [bytes, contentType] = await T.httpGetBytes(c.url, options.fetchBytes);
                prefetched = summary(await T.verifySource(Object.assign({}, options, { bytes, contentType })));
            } catch (e) {
                // FetchError: the page shows ERROR (load_failed); other errors (network, CORS,
                // redirect loop in fetch()) end with the "could not fetch" notice — no result either.
                prefetched = { status: 'ERROR', reason: 'load_failed', dns_name: null, selector: null, expired: false,
                    method: null, representations: [], fetch_error: e instanceof T.FetchError ? 'FetchError' : e.name };
            }
            return Object.assign(direct, { prefetched });
        }
        case 'lint':
            return lintResult(T.lintSource({ bytes: b64(c.bytes_b64) }));
        case 'lint_text':
            return lintResult(T.lintSource({ text: c.text }));
        case 'lint_object':
            return { ok: true, findings: T.lint(JSON.parse(c.json)).map(f => [f.severity, f.rule, f.path]) };
        case 'patterns':
            return {
                text_rules: T.TEXT_RULES.map(([severity, rule, rx]) => [severity, rule, rx.source, rx.ignoreCase]),
                patterns: Object.fromEntries(Object.entries(T._py.PATTERNS).map(([k, rx]) => [k, [rx.source, rx.ignoreCase]]))
            };
        case 'regex': {
            const cpIndex = (s, i) => Array.from(s.slice(0, i)).length;
            const span = (s, m) => (m ? [cpIndex(s, m.index), cpIndex(s, m.end)] : null);
            return c.refs.map((ref) => {
                const rx = typeof ref === 'number' ? T.TEXT_RULES[ref][2] : T._py.PATTERNS[ref];
                return c.strings.map(s => [span(s, rx.search(s)), span(s, rx.match(s)), span(s, rx.fullmatch(s))]);
            });
        }
        case 'parse_utc':
            return c.values.map(v => {
                const r = T.parseUtc(v);
                return r === null ? null : r.toString();
            });
        case 'signer_selfcheck': {
            // The Signer's path: strict parse, lint before signing, render, sign, self-check.
            const { webcrypto } = require('crypto');
            const keyPair = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
            const pub = new Uint8Array(await webcrypto.subtle.exportKey('raw', keyPair.publicKey));
            const payload = T.parseManifestText(c.json);
            const unsigned = Object.assign({}, payload);
            delete unsigned._arp_signature;
            const lintErrors = T.lint(unsigned).filter(f => f.severity === 'error' && !f.rule.startsWith('ARP-P/')).map(f => f.rule);
            delete payload._arp_signature;
            const now = new Date();
            const sigBlock = {
                algorithm: 'Ed25519', dns_selector: c.selector, dns_record: T.dnsName(c.selector, c.domain),
                canonicalization: 'jcs-rfc8785', signed_at: T.isoSeconds(now),
                expires_at: T.isoSeconds(new Date(now.getTime() + 90 * 86400000)),
                statement: T.signatureStatement(c.selector, c.domain), verify: T.verifyBlock(c.selector, c.domain), signature: ''
            };
            payload._arp_signature = sigBlock;
            const markdown = T.renderMarkdown(payload, c.domain);
            const mdHash = await T.sha256Hex(markdown);
            delete payload._arp_signature;
            T.setMarkdownRepresentation(payload, c.domain, mdHash);
            payload._arp_signature = sigBlock;
            const sig = new Uint8Array(await webcrypto.subtle.sign('Ed25519', keyPair.privateKey, T.utf8(T.canonicalize(payload))));
            payload._arp_signature.signature = T.bytesToBase64Url(sig);
            const check = await T.verifyManifest(payload, { domain: c.domain, publicKey: T.bytesToBase64(pub) });
            const md = T.renderMarkdown(payload, c.domain);
            return {
                lint_errors: lintErrors, level: check.level, reason: check.reason,
                md_ok: (await T.sha256Hex(md)) === mdHash,
                signed_json: JSON.stringify(payload, null, 2) + '\n', markdown: md, pubkey: T.bytesToBase64(pub)
            };
        }
        case 'generator': {
            const result = JSON.parse(c.json);
            const markdown = T.renderMarkdown(result);
            const hash = await T.sha256Hex(markdown);
            result.representations = [T.representationEntry(c.domain, hash)];
            return {
                markdown, json: JSON.stringify(result, null, 2) + '\n',
                findings: T.lint(result).map(f => [f.severity, f.rule, f.path]),
                snippets: T.discoverySnippets(c.domain, result.entity, '2026-10-05').length > 0
            };
        }
        default:
            throw new Error(`unknown op ${c.op}`);
    }
}

async function main() {
    const input = JSON.parse(fs.readFileSync(0, 'utf8'));
    const out = {};
    for (const c of input.cases) {
        try {
            out[c.id] = await runCase(c);
        } catch (e) {
            out[c.id] = { exception: `${e && e.name}: ${e && e.message}` };
        }
    }
    process.stdout.write(JSON.stringify(out));
}

main().catch((e) => {
    process.stderr.write(String(e && e.stack || e));
    process.exit(1);
});
