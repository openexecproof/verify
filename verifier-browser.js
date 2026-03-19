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
    if (typeof o === "string") return JSON.stringify(o);
    if (typeof o === "number") {
        if (!Number.isInteger(o)) throw new Error("Float forbidden");
        return o.toString();
    }
    if (typeof o === "boolean") throw new Error("Boolean forbidden in core");
    if (Array.isArray(o)) return "[" + o.map(jcsCanonicalize).join(",") + "]";
    if (typeof o === "object") {
        const k = Object.keys(o).sort();
        return "{" + k.map(k => JSON.stringify(k) + ":" + jcsCanonicalize(o[k])).join(",") + "}";
    }
    throw new Error("Unsupported type");
}

function b64urlToBytes(s) {
    if (typeof s !== "string" || s.length === 0) {
        throw new Error("Strict Base64url violation");
    }

    // STRICT: No padding, no invalid chars
    if (s.includes("=") || /[^A-Za-z0-9_-]/.test(s)) {
        throw new Error("Strict Base64url violation");
    }

    let m = s.replace(/-/g, "+").replace(/_/g, "/");
    const p = m.length % 4;
    if (p === 1) throw new Error("Invalid base64 length");
    if (p > 0) m += "=".repeat(4 - p);

    const b = atob(m);
    return Uint8Array.from(b, c => c.charCodeAt(0));
}

async function sha256(d) {
    const b = typeof d === "string" ? new TextEncoder().encode(d) : d;
    return new Uint8Array(await crypto.subtle.digest("SHA-256", b));
}

function bytesToHex(b) {
    return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
}

function decodeFragment(hash) {
    const raw = typeof hash === "string"
        ? (hash.startsWith("#") ? hash.slice(1) : hash)
        : "";

    if (!raw) {
        throw { code: "EMPTY", message: "No proof in URL fragment" };
    }

    if (raw.length > MAX_FRAGMENT_SIZE) {
        throw { code: CODES.FRAGMENT_TOO_LARGE, message: "Fragment exceeds 256KB" };
    }

    try {
        const bin = b64urlToBytes(raw);
        return new TextDecoder("utf-8", { fatal: true }).decode(bin);
    } catch (_e) {
        throw { code: CODES.DECODE_FAILED_INVALID_BASE64URL, message: "Invalid base64url" };
    }
}

function strictParse(json) {
    if (typeof json !== "string" || json.length === 0) {
        throw new Error("Empty JSON payload");
    }

    const keys = [];
    JSON.parse(json, (k, v) => {
        if (k !== "" && keys.includes(k)) throw new Error("Duplicate key: " + k);
        if (k !== "") keys.push(k);
        return v;
    });

    const parsed = JSON.parse(json);

    const walk = (o) => {
        if (o === null) throw new Error("Null values forbidden");
        if (typeof o === "object") Object.values(o).forEach(walk);
    };
    walk(parsed);

    return parsed;
}

function validateSchema(p) {
    if (!p || typeof p !== "object" || Array.isArray(p)) {
        throw { code: CODES.SCHEMA_WRONG_TYPE, message: "Proof must be object" };
    }

    const req = ["execution_core", "execution_id", "signer", "signature", "proof_class"];
    for (const k of req) {
        if (!(k in p)) {
            throw { code: CODES.SCHEMA_MISSING_REQUIRED_FIELD, message: "Missing: " + k };
        }
    }

    if (p.proof_class !== "portable") {
        throw { code: CODES.SCHEMA_WRONG_TYPE, message: "proof_class must be portable" };
    }

    if (!p.execution_core || typeof p.execution_core !== "object" || Array.isArray(p.execution_core)) {
        throw { code: CODES.SCHEMA_WRONG_TYPE, message: "execution_core must be object" };
    }

    if (!p.signer || typeof p.signer !== "object" || Array.isArray(p.signer)) {
        throw { code: CODES.SCHEMA_WRONG_TYPE, message: "signer must be object" };
    }

    const core = p.execution_core;
    const creq = ["protocol_version", "command", "stdout_hash", "stderr_hash", "exit_code", "env_fingerprint", "issued_at"];
    for (const k of creq) {
        if (!(k in core)) {
            throw { code: CODES.SCHEMA_MISSING_REQUIRED_FIELD, message: "Missing core: " + k };
        }
    }

    if (core.protocol_version !== "oep-1") {
        throw { code: CODES.SCHEMA_WRONG_TYPE, message: "Unsupported protocol version" };
    }

    if (!Array.isArray(core.command)) {
        throw { code: CODES.SCHEMA_WRONG_TYPE, message: "command must be list" };
    }

    if (!core.command.every(x => typeof x === "string")) {
        throw { code: CODES.SCHEMA_WRONG_TYPE, message: "command entries must be strings" };
    }

    if (typeof core.exit_code !== "number" || !Number.isInteger(core.exit_code)) {
        throw { code: CODES.SCHEMA_WRONG_TYPE, message: "exit_code must be integer" };
    }

    const requiredStringFields = ["stdout_hash", "stderr_hash", "env_fingerprint", "issued_at"];
    for (const k of requiredStringFields) {
        if (typeof core[k] !== "string" || core[k].length === 0) {
            throw { code: CODES.SCHEMA_WRONG_TYPE, message: "Invalid core field: " + k };
        }
    }

    if (typeof p.execution_id !== "string" || p.execution_id.length === 0) {
        throw { code: CODES.SCHEMA_WRONG_TYPE, message: "execution_id must be string" };
    }

    if (typeof p.signature !== "string") {
        throw { code: CODES.SCHEMA_WRONG_TYPE, message: "signature must be string" };
    }
}

async function verifyProof(json) {
    let proof;
    try {
        if (!json) throw new Error("Empty proof payload");
        proof = strictParse(json);
    } catch (e) {
        return {
            decision: "INVALID",
            failure_class: "schema_error",
            message: "Parse failure: " + (e.message || String(e))
        };
    }

    try {
        validateSchema(proof);
    } catch (e) {
        return {
            decision: "INVALID",
            failure_class: "schema_error",
            message: "Schema failure: " + (e.message || String(e))
        };
    }

    let coreBytes;
    try {
        coreBytes = new TextEncoder().encode(jcsCanonicalize(proof.execution_core));
    } catch (e) {
        return {
            decision: "INVALID",
            failure_class: "identity_mismatch",
            message: "JCS failure: " + (e.message || String(e))
        };
    }

    const idBytes = await sha256(coreBytes);
    const recomputedId = bytesToHex(idBytes).toLowerCase();

    if (recomputedId !== (proof.execution_id || "").toLowerCase()) {
        return {
            decision: "INVALID",
            failure_class: "identity_mismatch",
            message: "Execution ID mismatch: recomputed " + recomputedId + " but got " + proof.execution_id
        };
    }

    const signer = proof.signer;
    if (!signer || typeof signer !== "object" || Array.isArray(signer)) {
        return {
            decision: "INVALID",
            failure_class: "schema_error",
            message: "Schema failure: signer must be object"
        };
    }

    if (!proof.signature) {
        return {
            decision: "INVALID",
            failure_class: "signature_missing",
            message: "Signature verification failed"
        };
    }

    if (signer.alg !== "Ed25519") {
        return {
            decision: "INVALID",
            failure_class: "signer_unsupported",
            message: "Unsupported signer algorithm"
        };
    }

    if (typeof signer.pubkey !== "string" || signer.pubkey.length === 0) {
        return {
            decision: "INVALID",
            failure_class: "signature_invalid",
            message: "Signature verification failed"
        };
    }

    try {
        const pub = b64urlToBytes(signer.pubkey);
        const sig = b64urlToBytes(proof.signature);
        const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);

        const scopeBytes = new TextEncoder().encode(recomputedId);
        const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, scopeBytes);

        if (!ok) {
            return {
                decision: "INVALID",
                failure_class: "signature_invalid",
                message: "Signature verification failed"
            };
        }
    } catch (_e) {
        return {
            decision: "INVALID",
            failure_class: "signature_invalid",
            message: "Signature verification failed"
        };
    }

    return { decision: "VALID", failure_class: null, proof: proof, execution_id: recomputedId };
}

async function boot() {
    const rawHash = typeof window.location.hash === "string" ? window.location.hash : "";
    const hash = rawHash.startsWith("#") ? rawHash.slice(1) : rawHash;

    if (hash) {
        try {
            if (typeof resetUI === "function") resetUI();
            const json = decodeFragment(hash);
            const result = await verifyProof(json);

            if (result.decision === "VALID") {
                renderSuccess(result.proof, result);
            } else {
                renderFail(result.message || result.failure_class);
            }
            return;
        } catch (e) {
            if (typeof renderFail === "function") renderFail(e.message || String(e));
            return;
        }
    }

    const params = new URLSearchParams(window.location.search);
    const id = params.get("id");

    if (id) {
        try {
            if (typeof resetUI === "function") resetUI();

            if (!/^[a-f0-9]{64}$/.test(id)) {
                throw new Error("Invalid proof id");
            }

            const proofUrl = `p/${id}.json`;
            const resp = await fetch(proofUrl);
            if (!resp.ok) throw new Error("Proof not found");

            const json = await resp.text();
            const result = await verifyProof(json);

            if (result.decision === "VALID") {
                renderSuccess(result.proof, result);
            } else {
                renderFail(result.message || result.failure_class);
            }
            return;
        } catch (e) {
            if (typeof renderFail === "function") renderFail(e.message || String(e));
            return;
        }
    }

    if (typeof renderNeutral === "function") renderNeutral();
}