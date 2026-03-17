const CODES = {
    DECODE_FAILED_INVALID_BASE64URL: "decode_failed_invalid_base64url",
    UTF8_INVALID: "utf8_invalid",
    JSON_INVALID: "json_invalid",
    SCHEMA_MISSING_REQUIRED_FIELD: "schema_missing_required_field",
    SCHEMA_UNKNOWN_FIELD: "schema_unknown_field",
    SCHEMA_WRONG_TYPE: "schema_wrong_type",
    IDENTITY_MISMATCH: "identity_mismatch",
    SIGNATURE_INVALID: "signature_invalid",
    SIGNATURE_MISSING: "signature_missing",
    SIGNER_UNSUPPORTED: "signer_unsupported",
    FRAGMENT_TOO_LARGE: "fragment_too_large"
};

const MAX_FRAGMENT_SIZE = 256 * 1024;

function jcsCanonicalize(o) {
    if (o === null) throw new Error("Null forbidden");
    if (typeof o === 'string') return JSON.stringify(o);
    if (typeof o === 'number') {
        if (!Number.isInteger(o)) throw new Error("Float forbidden");
        return o.toString();
    }
    if (typeof o === 'boolean') throw new Error("Boolean forbidden in core");
    if (Array.isArray(o)) return "[" + o.map(jcsCanonicalize).join(",") + "]";
    if (typeof o === 'object') {
        const k = Object.keys(o).sort();
        return "{" + k.map(k => JSON.stringify(k) + ":" + jcsCanonicalize(o[k])).join(",") + "}"
    }
}

function b64urlToBytes(s) {
    // STRICT: No padding, no invalid chars
    if (s.includes('=') || /[^A-Za-z0-9_-]/.test(s)) {
        throw new Error("Strict Base64url violation");
    }
    let m = s.replace(/-/g, '+').replace(/_/g, '/');
    const p = m.length % 4;
    if (p === 1) throw new Error("Invalid base64 length");
    if (p > 0) m += '='.repeat(4 - p);
    const b = atob(m);
    return Uint8Array.from(b, c => c.charCodeAt(0));
}

async function sha256(d) {
    const b = typeof d === 'string' ? new TextEncoder().encode(d) : d;
    return new Uint8Array(await crypto.subtle.digest('SHA-256', b));
}

function bytesToHex(b) {
    return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function decodeFragment(hash) {
    const raw = hash.startsWith('#') ? hash.slice(1) : hash;
    if (!raw) throw { code: 'EMPTY', message: 'No proof in URL fragment' };
    
    if (raw.length > MAX_FRAGMENT_SIZE) {
        throw { code: CODES.FRAGMENT_TOO_LARGE, message: 'Fragment exceeds 256KB' };
    }

    try {
        const bin = b64urlToBytes(raw);
        return new TextDecoder('utf-8', { fatal: true }).decode(bin);
    } catch (e) {
        throw { code: CODES.DECODE_FAILED_INVALID_BASE64URL, message: 'Invalid base64url' };
    }
}

function strictParse(json) {
    let keys = [];
    JSON.parse(json, (k, v) => {
        if (k !== "" && keys.includes(k)) throw new Error("Duplicate key: " + k);
        if (k !== "") keys.push(k);
        return v;
    });
    const parsed = JSON.parse(json);
    
    // Check for nulls which JSON.parse allows but we forbid in OEP
    const walk = (o) => {
        if (o === null) throw new Error("Null values forbidden");
        if (typeof o === 'object') Object.values(o).forEach(walk);
    };
    walk(parsed);
    return parsed;
}

function validateSchema(p) {
    const req = ['execution_core', 'execution_id', 'signer', 'signature', 'proof_class'];
    const act = Object.keys(p);
    for (const k of req) if (!(k in p)) throw { code: CODES.SCHEMA_MISSING_REQUIRED_FIELD, message: 'Missing: ' + k };
    // OEP-1: Ignore unknown top-level fields
    if (p.proof_class !== 'portable') throw { code: CODES.SCHEMA_WRONG_TYPE, message: 'proof_class must be portable' };

    const core = p.execution_core;
    const creq = ['protocol_version', 'command', 'stdout_hash', 'stderr_hash', 'exit_code', 'env_fingerprint', 'issued_at'];
    const cact = Object.keys(core);
    for (const k of creq) if (!(k in core)) throw { code: CODES.SCHEMA_MISSING_REQUIRED_FIELD, message: 'Missing core: ' + k };
    // OEP-1: Ignore unknown core fields

    if (core.protocol_version !== 'oep-1') throw { code: CODES.SCHEMA_WRONG_TYPE, message: 'Unsupported protocol version' };
    if (!Array.isArray(core.command)) throw { code: CODES.SCHEMA_WRONG_TYPE, message: 'command must be list' };
    if (!Number.isInteger(core.exit_code)) throw { code: CODES.SCHEMA_WRONG_TYPE, message: 'exit_code must be integer' };
    if (typeof core.exit_code !== 'number') throw { code: CODES.SCHEMA_WRONG_TYPE, message: 'exit_code must be numeric' };
}

async function verifyProof(json) {
    let proof;
    try {
        if (!json) throw new Error("Empty proof payload");
        proof = strictParse(json);
    } catch (e) {
        return { decision: "INVALID", failure_class: "schema_error", message: "Parse failure: " + e.message };
    }

    try {
        validateSchema(proof);
    } catch (e) {
        return { decision: "INVALID", failure_class: "schema_error", message: "Schema failure: " + e.message };
    }

    let coreBytes;
    try {
        coreBytes = new TextEncoder().encode(jcsCanonicalize(proof.execution_core));
    } catch (e) {
        return { decision: "INVALID", failure_class: "identity_mismatch", message: 'JCS failure: ' + e.message };
    }

    const idBytes = await sha256(coreBytes);
    const recomputedId = bytesToHex(idBytes).toLowerCase();

    if (recomputedId !== (proof.execution_id || "").toLowerCase()) {
        return { decision: "INVALID", failure_class: "identity_mismatch", message: 'Execution ID mismatch: recomputed ' + recomputedId + ' but got ' + proof.execution_id };
    }

    try {
        const pub = b64urlToBytes(proof.signer.pubkey);
        const sig = b64urlToBytes(proof.signature);
        const key = await crypto.subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
        
        const scopeBytes = new TextEncoder().encode(recomputedId);
        const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, sig, scopeBytes);
        
        if (!ok) return { decision: "INVALID", failure_class: "signature_invalid", message: "Cryptographic verify failed" };
    } catch (e) {
        return { decision: "INVALID", failure_class: "signature_invalid", message: 'Signature verification error: ' + (e.message || e.code || String(e)) };
    }

    return { decision: "VALID", failure_class: null, proof: proof, execution_id: recomputedId };
}

async function boot() {
    const hash = window.location.hash.slice(1);

    if (hash) {
        try {
            if (typeof resetUI === 'function') resetUI();
            const json = decodeFragment('#' + hash);
            const result = await verifyProof(json);
            if (result.decision === 'VALID') {
                renderSuccess(result.proof, result);
            } else {
                renderFail(result.message || result.failure_class);
            }
            return;
        } catch (e) {
            if (typeof renderFail === 'function') renderFail(e.message || String(e));
            return;
        }
    }

    const params = new URLSearchParams(window.location.search);
    const id = params.get('id');

    if (id) {
        try {
            if (typeof resetUI === 'function') resetUI();
            if (!/^[a-f0-9]{64}$/.test(id)) {
                throw new Error('Invalid proof id');
            }

            const proofUrl = `p/${id}.json`;
            const resp = await fetch(proofUrl);
            if (!resp.ok) throw new Error('Proof not found');

            const json = await resp.text();
            const result = await verifyProof(json);
            if (result.decision === 'VALID') {
                renderSuccess(result.proof, result);
            } else {
                renderFail(result.message || result.failure_class);
            }
            return;
        } catch (e) {
            if (typeof renderFail === 'function') renderFail(e.message || String(e));
            return;
        }
    }

    if (typeof renderNeutral === 'function') renderNeutral();
}

