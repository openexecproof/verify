const CODES = {
    MALFORMED_INPUT: "malformed_input",
    SCHEMA_INVALID: "schema_invalid",
    UNSUPPORTED_PROTOCOL_VERSION: "unsupported_protocol_version",
    INVALID_EXECUTION_ID: "invalid_execution_id",
    IDENTITY_MISMATCH: "identity_mismatch",
    SIGNATURE_INVALID: "signature_invalid",
    PROOF_NOT_FOUND: "proof_not_found",
    NETWORK_FETCH_FAILED: "network_fetch_failed",
    ORIGIN_MISMATCH: "origin_mismatch",
    SOURCE_UNTRUSTED: "source_untrusted",
    RESOLUTION_EXHAUSTED: "resolution_exhausted",
    INTERNAL_VERIFIER_ERROR: "internal_verifier_error"
};

const MAX_FRAGMENT_SIZE = 256 * 1024;

const DESCRIPTORS = {
    EMBEDDED: "embedded_fragment",
    EXPLICIT_URL: "explicit_url",
    CANONICAL_MIRROR: "canonical_mirror",
    MANUAL: "manual_import",
    LOCAL: "local_known_source"
};

const PUBLIC_CANONICAL_ORIGIN = "https://openexecproof.github.io";
const PUBLIC_CANONICAL_MIRROR_PATH = "/verify/p";
const PUBLIC_VERIFIER_PATH = "/verify";

// TRUTH HARNESS GLOBALS
window.__GUBAZ_TRACE__ = [];
window.__GUBAZ_RESULT__ = null;

let stepCounter = 0;

function resetHarnessState() {
    window.__GUBAZ_TRACE__ = [];
    window.__GUBAZ_RESULT__ = null;
    stepCounter = 0;
}

function logTrace(entry) {
    window.__GUBAZ_TRACE__.push({
        step_index: stepCounter++,
        attempt_index: entry.attempt_index || 0,
        source_tier: entry.source_tier !== undefined ? entry.source_tier : null,
        source_descriptor: entry.source_descriptor || null,
        source_origin: entry.source_origin || null,
        candidate_reference: entry.candidate_reference || entry.source_origin || null,
        outcome: entry.outcome || "failed",
        error_class: entry.error_class || null,
        selected_final: !!entry.selected_final
    });
}

function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(input) {
    const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function b64urlToBytes(value) {
    const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

// Deterministic JSON canonicalization sufficient for OEP execution_core.
function jcsCanonicalize(value) {
    if (value === null || typeof value !== "object") {
        return JSON.stringify(value);
    }

    if (Array.isArray(value)) {
        return "[" + value.map(jcsCanonicalize).join(",") + "]";
    }

    const keys = Object.keys(value).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + jcsCanonicalize(value[k])).join(",") + "}";
}

// Duplicate-key detection must happen on raw text before JSON.parse.
function detectDuplicateKeys(jsonText) {
    const keyRegex = /"([^"\\]*(?:\\.[^"\\]*)*)"\s*:/g;
    const seen = new Set();
    let match;

    while ((match = keyRegex.exec(jsonText)) !== null) {
        const key = JSON.parse('"' + match[1].replace(/"/g, '\\"') + '"');
        if (seen.has(key)) return true;
        seen.add(key);
    }

    return false;
}

function strictParse(json) {
    if (detectDuplicateKeys(json)) {
        throw { code: CODES.MALFORMED_INPUT, message: "Duplicate keys detected" };
    }
    return JSON.parse(json);
}

function canonicalMirrorUrl(executionId) {
    return `${PUBLIC_CANONICAL_ORIGIN}${PUBLIC_CANONICAL_MIRROR_PATH}/${executionId}.json`;
}

function assertCanonicalMirrorUrl(urlString) {
    let u;
    try {
        u = new URL(urlString);
    } catch (_e) {
        throw new Error("Canonical URL malformed");
    }

    if (u.origin !== PUBLIC_CANONICAL_ORIGIN) {
        throw new Error("Canonical origin mismatch");
    }

    if (!u.pathname.startsWith(PUBLIC_CANONICAL_MIRROR_PATH + "/")) {
        throw new Error("Canonical mirror path mismatch");
    }
}

/**
 * RESOLUTION MODULE
 */
class ResolutionModule {
    static parseInputs() {
        const params = new URLSearchParams(window.location.search);
        const rawHash = typeof window.location.hash === "string" ? window.location.hash : "";
        const hash = rawHash.startsWith("#") ? rawHash.slice(1) : rawHash;

        let embedded = null;
        if (typeof hash === "string" && hash.startsWith("proof=")) {
            embedded = hash.slice(6);
        } else if (typeof hash === "string" && hash.length > 0 && !hash.includes("=")) {
            embedded = hash;
        }

        return {
            embedded_proof: embedded,
            proof_url: params.get("proof_url"),
            execution_id: params.get("id"),
            manual_proof: null
        };
    }

    static evaluatePrecedence(req) {
        if (req.embedded_proof) return 0;
        if (req.proof_url) return 1;
        if (req.execution_id) return 2;
        if (req.manual_proof) return 3;
        return -1;
    }

    static normalizeResult(res) {
        const normalized = {
            status: res.status || "resolution_failed",
            source_tier: res.source_tier !== undefined ? res.source_tier : null,
            source_descriptor: res.source_descriptor || null,
            source_origin: res.source_origin || null,
            proof_bytes: res.proof_bytes || null,
            parsed_proof: res.parsed_proof || null,
            error_class: res.error_class || null,
            error_detail: res.error_detail || null,
            trace: [...window.__GUBAZ_TRACE__]
        };

        if (normalized.status === "proof_resolved") {
            if (normalized.source_tier === null) throw new Error("Tier missing in successful resolution");
            if (!normalized.source_descriptor) throw new Error("Descriptor missing in successful resolution");
            if (!normalized.source_origin) throw new Error("Source origin missing in successful resolution");
        }

        if (normalized.status === "proof_resolved" && normalized.source_tier === 2) {
            assertCanonicalMirrorUrl(normalized.source_origin);
        }

        return normalized;
    }

    static async resolveEmbedded(req) {
        if (!req.embedded_proof) return null;

        if (req.embedded_proof.length > MAX_FRAGMENT_SIZE) {
            const fail = {
                status: "resolution_failed",
                source_tier: 0,
                source_descriptor: DESCRIPTORS.EMBEDDED,
                source_origin: "direct_input",
                error_class: CODES.MALFORMED_INPUT,
                error_detail: "Fragment exceeds 256KB"
            };
            logTrace({ ...fail, outcome: "failed", selected_final: true });
            return this.normalizeResult(fail);
        }

        try {
            const bin = b64urlToBytes(req.embedded_proof);
            const json = new TextDecoder("utf-8", { fatal: true }).decode(bin);
            const parsed = strictParse(json);

            const ok = {
                status: "proof_resolved",
                source_tier: 0,
                source_descriptor: DESCRIPTORS.EMBEDDED,
                source_origin: "direct_input",
                proof_bytes: json,
                parsed_proof: parsed
            };
            logTrace({ ...ok, outcome: "proof_resolved", selected_final: true });
            return this.normalizeResult(ok);
        } catch (e) {
            const fail = {
                status: "resolution_failed",
                source_tier: 0,
                source_descriptor: DESCRIPTORS.EMBEDDED,
                source_origin: "direct_input",
                error_class: e.code || CODES.MALFORMED_INPUT,
                error_detail: e.message || String(e)
            };
            logTrace({ ...fail, outcome: "failed", selected_final: true });
            return this.normalizeResult(fail);
        }
    }

    static async resolveExplicitUrl(req) {
        if (!req.proof_url) return null;

        try {
            let url;
            try {
                url = new URL(req.proof_url);
            } catch (_e) {
                const fail = {
                    status: "resolution_failed",
                    source_tier: 1,
                    source_descriptor: DESCRIPTORS.EXPLICIT_URL,
                    source_origin: req.proof_url,
                    error_class: CODES.MALFORMED_INPUT,
                    error_detail: "Malformed URL format"
                };
                logTrace({ ...fail, outcome: "failed", selected_final: true });
                return this.normalizeResult(fail);
            }

            const resp = await fetch(url.href);
            if (!resp.ok) {
                throw {
                    code: resp.status === 404 ? CODES.PROOF_NOT_FOUND : CODES.NETWORK_FETCH_FAILED,
                    message: `HTTP ${resp.status}`
                };
            }

            const json = await resp.text();
            const parsed = strictParse(json);

            const ok = {
                status: "proof_resolved",
                source_tier: 1,
                source_descriptor: DESCRIPTORS.EXPLICIT_URL,
                source_origin: url.href,
                proof_bytes: json,
                parsed_proof: parsed
            };
            logTrace({ ...ok, outcome: "proof_resolved", selected_final: true });
            return this.normalizeResult(ok);
        } catch (e) {
            const fail = {
                status: "resolution_failed",
                source_tier: 1,
                source_descriptor: DESCRIPTORS.EXPLICIT_URL,
                source_origin: req.proof_url,
                error_class: e.code || CODES.NETWORK_FETCH_FAILED,
                error_detail: e.message || String(e)
            };
            logTrace({ ...fail, outcome: "failed", selected_final: true });
            return this.normalizeResult(fail);
        }
    }

    static async resolveExecutionId(req) {
        if (!req.execution_id) return null;

        if (!/^[a-f0-9]{64}$/i.test(req.execution_id)) {
            const fail = {
                status: "resolution_failed",
                source_tier: 2,
                source_descriptor: DESCRIPTORS.CANONICAL_MIRROR,
                source_origin: "direct_input",
                error_class: CODES.INVALID_EXECUTION_ID,
                error_detail: "Invalid execution ID format (expected 64-char hex)"
            };
            logTrace({ ...fail, outcome: "failed", selected_final: true });
            return this.normalizeResult(fail);
        }

        const canonicalUrl = canonicalMirrorUrl(req.execution_id);

        try {
            assertCanonicalMirrorUrl(canonicalUrl);
        } catch (e) {
            const fail = {
                status: "resolution_failed",
                source_tier: 2,
                source_descriptor: DESCRIPTORS.CANONICAL_MIRROR,
                source_origin: canonicalUrl,
                error_class: CODES.ORIGIN_MISMATCH,
                error_detail: e.message || String(e)
            };
            logTrace({ ...fail, outcome: "failed", selected_final: true });
            return this.normalizeResult(fail);
        }

        const entry = {
            attempt_index: 1,
            source_tier: 2,
            source_descriptor: DESCRIPTORS.CANONICAL_MIRROR,
            source_origin: canonicalUrl,
            outcome: "failed",
            error_class: null
        };

        try {
            const resp = await fetch(canonicalUrl);

            if (!resp.ok) {
                entry.error_class = resp.status === 404 ? CODES.PROOF_NOT_FOUND : CODES.NETWORK_FETCH_FAILED;
                logTrace(entry);

                const fail = {
                    status: "resolution_failed",
                    source_tier: 2,
                    source_descriptor: DESCRIPTORS.CANONICAL_MIRROR,
                    source_origin: canonicalUrl,
                    error_class: entry.error_class,
                    error_detail: `HTTP ${resp.status}`
                };
                logTrace({ ...fail, outcome: "failed", selected_final: true });
                return this.normalizeResult(fail);
            }

            const json = await resp.text();
            const parsed = strictParse(json);

            entry.outcome = "proof_resolved";
            entry.selected_final = true;
            logTrace(entry);

            const ok = {
                status: "proof_resolved",
                source_tier: 2,
                source_descriptor: DESCRIPTORS.CANONICAL_MIRROR,
                source_origin: canonicalUrl,
                proof_bytes: json,
                parsed_proof: parsed
            };
            return this.normalizeResult(ok);
        } catch (e) {
            entry.error_class = e.code || ((e instanceof TypeError) ? CODES.NETWORK_FETCH_FAILED : CODES.MALFORMED_INPUT);
            logTrace(entry);

            const fail = {
                status: "resolution_failed",
                source_tier: 2,
                source_descriptor: DESCRIPTORS.CANONICAL_MIRROR,
                source_origin: canonicalUrl,
                error_class: entry.error_class,
                error_detail: e.message || String(e)
            };
            logTrace({ ...fail, outcome: "failed", selected_final: true });
            return this.normalizeResult(fail);
        }
    }

    static async resolveManualImport(req) {
        if (!req.manual_proof) return null;

        try {
            const parsed = strictParse(req.manual_proof);
            const ok = {
                status: "proof_resolved",
                source_tier: 3,
                source_descriptor: DESCRIPTORS.MANUAL,
                source_origin: "direct_input",
                proof_bytes: req.manual_proof,
                parsed_proof: parsed
            };
            logTrace({ ...ok, outcome: "proof_resolved", selected_final: true });
            return this.normalizeResult(ok);
        } catch (e) {
            const fail = {
                status: "resolution_failed",
                source_tier: 3,
                source_descriptor: DESCRIPTORS.MANUAL,
                source_origin: "direct_input",
                error_class: e.code || CODES.MALFORMED_INPUT,
                error_detail: e.message || String(e)
            };
            logTrace({ ...fail, outcome: "failed", selected_final: true });
            return this.normalizeResult(fail);
        }
    }
}

/**
 * VERIFICATION STAGE
 */
function validateSchema(p) {
    if (!p || typeof p !== "object" || Array.isArray(p)) {
        throw { code: CODES.SCHEMA_INVALID, message: "Proof must be object" };
    }

    const req = ["execution_core", "execution_id", "signer", "signature", "proof_class"];
    for (const k of req) {
        if (!(k in p)) throw { code: CODES.SCHEMA_INVALID, message: "Missing: " + k };
    }

    if (p.proof_class !== "portable") {
        throw { code: CODES.SCHEMA_INVALID, message: "proof_class must be portable" };
    }

    if (!p.execution_core || typeof p.execution_core !== "object" || Array.isArray(p.execution_core)) {
        throw { code: CODES.SCHEMA_INVALID, message: "execution_core must be object" };
    }

    if (!p.signer || typeof p.signer !== "object" || Array.isArray(p.signer)) {
        throw { code: CODES.SCHEMA_INVALID, message: "signer must be object" };
    }

    if (typeof p.signature !== "string" || p.signature.length === 0) {
        throw { code: CODES.SCHEMA_INVALID, message: "signature must be non-empty string" };
    }

    if (typeof p.signer.pubkey !== "string" || p.signer.pubkey.length === 0) {
        throw { code: CODES.SCHEMA_INVALID, message: "signer.pubkey must be non-empty string" };
    }

    const core = p.execution_core;
    const creq = ["protocol_version", "command", "stdout_hash", "stderr_hash", "exit_code", "env_fingerprint", "issued_at"];

    if (Object.keys(core).length !== creq.length) {
        throw { code: CODES.SCHEMA_INVALID, message: "Execution Core must have exactly 7 fields" };
    }

    for (const k of creq) {
        if (!(k in core)) throw { code: CODES.SCHEMA_INVALID, message: "Missing core: " + k };
    }

    if (core.protocol_version !== "oep-1") {
        throw { code: CODES.UNSUPPORTED_PROTOCOL_VERSION, message: "Unsupported protocol version" };
    }

    if (!Array.isArray(core.command)) {
        throw { code: CODES.SCHEMA_INVALID, message: "command must be list" };
    }

    if (!core.command.every(x => typeof x === "string")) {
        throw { code: CODES.SCHEMA_INVALID, message: "command entries must be strings" };
    }

    if (!Number.isInteger(core.exit_code)) {
        throw { code: CODES.SCHEMA_INVALID, message: "exit_code must be numeric integer" };
    }

    const requiredStringFields = ["protocol_version", "stdout_hash", "stderr_hash", "env_fingerprint", "issued_at"];
    for (const k of requiredStringFields) {
        if (typeof core[k] !== "string" || core[k].length === 0) {
            throw { code: CODES.SCHEMA_INVALID, message: "Invalid core field: " + k };
        }
    }
}

async function verifyProof(proof) {
    try {
        validateSchema(proof);
    } catch (e) {
        return {
            decision: "INVALID",
            failure_class: e.code || CODES.SCHEMA_INVALID,
            message: e.message || String(e)
        };
    }

    let coreBytes;
    try {
        coreBytes = new TextEncoder().encode(jcsCanonicalize(proof.execution_core));
    } catch (e) {
        return {
            decision: "INVALID",
            failure_class: CODES.IDENTITY_MISMATCH,
            message: "JCS failure: " + (e.message || String(e))
        };
    }

    const idBytes = await sha256(coreBytes);
    const recomputedId = bytesToHex(idBytes).toLowerCase();

    if (!/^[0-9a-f]{64}$/.test(proof.execution_id || "")) {
        return {
            decision: "INVALID",
            failure_class: CODES.INVALID_EXECUTION_ID,
            message: "Malformed execution ID"
        };
    }

    if (recomputedId !== (proof.execution_id || "").toLowerCase()) {
        return {
            decision: "INVALID",
            failure_class: CODES.IDENTITY_MISMATCH,
            message: "Execution ID mismatch"
        };
    }

    try {
        const pub = b64urlToBytes(proof.signer.pubkey);
        const sig = b64urlToBytes(proof.signature);
        const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
        const scopeBytes = new TextEncoder().encode(recomputedId);
        const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, scopeBytes);

        if (!ok) {
            return {
                decision: "INVALID",
                failure_class: CODES.SIGNATURE_INVALID,
                message: "Cryptographic verify failed"
            };
        }
    } catch (_e) {
        return {
            decision: "INVALID",
            failure_class: CODES.SIGNATURE_INVALID,
            message: "Signature verification failed"
        };
    }

    return { decision: "VALID", proof: proof, execution_id: recomputedId };
}

/**
 * BOOTSTRAP
 */
async function boot() {
    resetHarnessState();
    if (typeof resetUI === "function") resetUI();

    const request = ResolutionModule.parseInputs();
    const tier = ResolutionModule.evaluatePrecedence(request);

    if (tier === -1) {
        if (typeof renderState === "function") renderState("idle");
        return;
    }

    if (typeof renderState === "function") renderState("resolving");

    let result = null;
    if (tier === 0) result = await ResolutionModule.resolveEmbedded(request);
    else if (tier === 1) result = await ResolutionModule.resolveExplicitUrl(request);
    else if (tier === 2) result = await ResolutionModule.resolveExecutionId(request);
    else if (tier === 3) result = await ResolutionModule.resolveManualImport(request);

    if (!result) {
        window.__GUBAZ_RESULT__ = {
            status: "resolution_failed",
            source_tier: null,
            source_descriptor: null,
            source_origin: null,
            proof_bytes: null,
            parsed_proof: null,
            error_class: CODES.INTERNAL_VERIFIER_ERROR,
            error_detail: "Resolution returned null",
            trace: [...window.__GUBAZ_TRACE__]
        };
        if (typeof renderResolutionFail === "function") renderResolutionFail(window.__GUBAZ_RESULT__);
        return;
    }

    if (result.status !== "proof_resolved") {
        window.__GUBAZ_RESULT__ = result;

        if (window.location.search.includes("selftest=1")) {
            console.log("SELFTEST MODE");
            console.error("SELFTEST FAIL: resolution failed", result);
        }

        if (typeof renderResolutionFail === "function") renderResolutionFail(result);
        return;
    }

    if (typeof renderState === "function") renderState("proof_loaded", result);

    const verdict = await verifyProof(result.parsed_proof);
    window.__GUBAZ_RESULT__ = { ...result, verification: verdict };

    if (window.location.search.includes("selftest=1")) {
        console.log("SELFTEST MODE");

        if (!window.__GUBAZ_RESULT__) {
            console.error("SELFTEST FAIL: missing result");
        } else if (window.__GUBAZ_RESULT__.status !== "proof_resolved") {
            console.error("SELFTEST FAIL: resolution failed", window.__GUBAZ_RESULT__);
        } else if (window.__GUBAZ_RESULT__.source_tier === 2) {
            try {
                assertCanonicalMirrorUrl(window.__GUBAZ_RESULT__.source_origin);
                console.log("SELFTEST PASS:", window.__GUBAZ_RESULT__.source_origin);
            } catch (e) {
                console.error("SELFTEST FAIL: canonical invariant broken", e.message || String(e), window.__GUBAZ_RESULT__.source_origin);
            }
        } else {
            console.log("SELFTEST PASS: non-canonical tier", window.__GUBAZ_RESULT__.source_descriptor);
        }
    }

    if (verdict.decision === "VALID") {
        if (typeof renderSuccess === "function") renderSuccess(verdict.proof, result);
    } else {
        if (typeof renderVerifyFail === "function") renderVerifyFail(verdict);
    }
}

window.resolveManual = async (json) => {
    resetHarnessState();
    const res = await ResolutionModule.resolveManualImport({ manual_proof: json });

    if (!res) {
        window.__GUBAZ_RESULT__ = {
            status: "resolution_failed",
            source_tier: 3,
            source_descriptor: DESCRIPTORS.MANUAL,
            source_origin: "direct_input",
            proof_bytes: null,
            parsed_proof: null,
            error_class: CODES.INTERNAL_VERIFIER_ERROR,
            error_detail: "Manual resolution returned null",
            trace: [...window.__GUBAZ_TRACE__]
        };
        if (typeof renderResolutionFail === "function") renderResolutionFail(window.__GUBAZ_RESULT__);
        return;
    }

    if (res.status === "proof_resolved") {
        if (typeof renderState === "function") renderState("proof_loaded", res);
        const verdict = await verifyProof(res.parsed_proof);
        window.__GUBAZ_RESULT__ = { ...res, verification: verdict };

        if (verdict.decision === "VALID") {
            if (typeof renderSuccess === "function") renderSuccess(verdict.proof, res);
        } else {
            if (typeof renderVerifyFail === "function") renderVerifyFail(verdict);
        }
    } else {
        window.__GUBAZ_RESULT__ = res;
        if (typeof renderResolutionFail === "function") renderResolutionFail(res);
    }
};

document.addEventListener("DOMContentLoaded", boot);
window.onhashchange = boot;