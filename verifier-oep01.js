/**
 * Strict Base64/Base64URL validation and decoding.
 * Rejects illegal characters, whitespace, and handles unpadded Base64Url transport.
 */
function decodeBase64Strict(s) {
    if (typeof s !== 'string') throw new VerificationError("invalid_payload_type");
    
    // 1. Reject whitespace
    if (/\s/.test(s)) throw new VerificationError("illegal_whitespace");

    // 2. Detect style and reject mixed styles before normalization
    const hasStandard = /[+/]/.test(s);
    const hasUrlSafe = /[-_]/.test(s);
    if (hasStandard && hasUrlSafe) {
        throw new VerificationError("mixed_base64_styles");
    }

    // 3. Normalize URL-safe characters to standard Base64
    let normalized = s.replace(/-/g, '+').replace(/_/g, '/');

    // 4. Padding restoration and structural length check
    // Base64Url (RFC 7515) omits padding. We restore it for the browser's atob().
    const remainder = normalized.length % 4;
    if (remainder === 1) {
        throw new VerificationError("invalid_base64url_length");
    } else if (remainder === 2) {
        normalized += "==";
    } else if (remainder === 3) {
        normalized += "=";
    }

    // 5. Strict character check (only valid Base64 chars and padding allowed now)
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
        throw new VerificationError("illegal_characters");
    }

    // 6. Decode to bytes
    try {
        const binaryString = atob(normalized);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
    } catch (e) {
        throw new VerificationError("base64_decode_failed");
    }
}

class VerificationError extends Error {
    constructor(reasonCode) {
        super(reasonCode);
        this.reasonCode = reasonCode;
        this.name = "VerificationError";
    }
}

/**
 * Port of duplicate_check_hook logic.
 * Detects duplicate keys in raw JSON string before normal parsing.
 * Uses a manual scan to avoid regex edge cases with nested objects.
 */
function checkDuplicateKeys(jsonStr) {
    const keysStack = [new Set()];
    let inString = false;
    let escaped = false;
    
    let pos = 0;
    while (pos < jsonStr.length) {
        const char = jsonStr[pos];
        if (escaped) {
            escaped = false;
            pos++;
            continue;
        }
        if (char === '\\') {
            escaped = true;
            pos++;
            continue;
        }
        if (char === '"') {
            inString = !inString;
            if (inString) {
                let endPos = pos + 1;
                while (endPos < jsonStr.length) {
                    if (jsonStr[endPos] === '\\') { endPos += 2; continue; }
                    if (jsonStr[endPos] === '"') break;
                    endPos++;
                }
                const strContent = jsonStr.substring(pos + 1, endPos);
                pos = endPos + 1;
                inString = false;
                
                let peek = pos;
                while (peek < jsonStr.length && /\s/.test(jsonStr[peek])) peek++;
                if (jsonStr[peek] === ':') {
                    const currentSet = keysStack[keysStack.length - 1];
                    if (currentSet.has(strContent)) {
                        throw new VerificationError("duplicate_key");
                    }
                    currentSet.add(strContent);
                }
                pos = peek; 
                continue;
            }
        }
        
        if (!inString) {
            if (char === '{') {
                keysStack.push(new Set());
            } else if (char === '}') {
                keysStack.pop();
            }
        }
        pos++;
    }
}

function validateDigest(digest) {
    if (typeof digest !== 'string' || !digest.startsWith("sha256:")) {
        throw new VerificationError("invalid_digest_prefix");
    }
    const payload = digest.substring(7);
    if (payload.length !== 64) {
        throw new VerificationError("invalid_digest_length");
    }
    if (!/^[0-9a-f]{64}$/.test(payload)) {
        throw new VerificationError("invalid_digest_hex");
    }
}

function strictTypeCheck(v, fieldName = "") {
    if (fieldName === "exit_code" && typeof v === 'boolean') {
        throw new VerificationError("invalid_exit_code_type");
    }
    if (typeof v === 'number' && !Number.isInteger(v)) {
        throw new VerificationError("float_not_allowed");
    }
    if (v === null) {
        throw new VerificationError("null_required_field");
    }
    if (typeof v === 'object' && !Array.isArray(v)) {
        for (const k in v) {
            strictTypeCheck(v[k], k);
        }
    } else if (Array.isArray(v)) {
        for (const item of v) {
            strictTypeCheck(item);
        }
    }
}

/**
 * Exact canonicalization and hashing semantics of the Python reference verifier.
 */
async function computeProofId(receipt) {
    const identityInput = {
        "source": receipt.source,
        "protocol_version": receipt.protocol_version,
        "receipt_core": receipt.receipt_core
    };
    
    function sortObject(obj) {
        if (obj === null || typeof obj !== 'object') return obj;
        if (Array.isArray(obj)) return obj.map(sortObject);
        const sortedKeys = Object.keys(obj).sort();
        const result = {};
        sortedKeys.forEach(key => { result[key] = sortObject(obj[key]); });
        return result;
    }

    const sorted = sortObject(identityInput);
    
    function canonicalStringify(val) {
        if (val === null) return "null";
        if (typeof val === 'string') return JSON.stringify(val);
        if (typeof val === 'number') return val.toString();
        if (typeof val === 'boolean') return val.toString();
        if (Array.isArray(val)) {
            return "[" + val.map(canonicalStringify).join(",") + "]";
        }
        if (typeof val === 'object') {
            const keys = Object.keys(val).sort();
            return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalStringify(val[k])).join(",") + "}";
        }
        return "";
    }

    const canonStr = canonicalStringify(sorted);
    const bytes = new TextEncoder().encode(canonStr);
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return `sha256:${hashHex}`;
}

async function verifyOEP01(dataBytes) {
    try {
        const rawStr = new TextDecoder('utf-8', { fatal: true }).decode(dataBytes);
        
        checkDuplicateKeys(rawStr);

        let cleanStr = "";
        let inStr = false;
        let escaped = false;
        for (let i = 0; i < rawStr.length; i++) {
            const c = rawStr[i];
            if (escaped) {
                cleanStr += "X";
                escaped = false;
            } else if (c === "\\") {
                cleanStr += "X";
                escaped = true;
            } else if (c === '"') {
                inStr = !inStr;
                cleanStr += '"';
            } else if (inStr) {
                cleanStr += "X";
            } else {
                cleanStr += c;
            }
        }

        const numPattern = /-?\d+(\.\d+)?([eE][+-]?\d+)?/g;
        let numMatch;
        while ((numMatch = numPattern.exec(cleanStr)) !== null) {
            const numStr = numMatch[0];
            if (numStr.includes(".")) {
                throw new VerificationError("float_not_allowed");
            }
            if (numStr.toLowerCase().includes("e")) {
                 throw new VerificationError("invalid_numeric_format");
            }
        }

        const obj = JSON.parse(rawStr);

        const allowed = new Set(["source", "protocol_version", "receipt_core", "receipt_meta", "proof_id", "execution_core"]);
        for (const k in obj) {
            if (!allowed.has(k)) {
                return { status: "REJECT", reason_code: "unknown_field_top_level" };
            }
        }

        const required = ["source", "protocol_version", "receipt_core"];
        for (const f of required) {
            if (!(f in obj)) {
                if (f === "receipt_core") return { status: "REJECT", reason_code: "missing_receipt_core" };
                if (f === "source") return { status: "REJECT", reason_code: "missing_source" };
                if (f === "protocol_version") return { status: "REJECT", reason_code: "missing_protocol_version" };
            }
        }

        strictTypeCheck(obj);

        const receipt_core = obj.receipt_core;
        if (typeof receipt_core !== 'object' || Array.isArray(receipt_core)) {
            return { status: "REJECT", reason_code: "missing_receipt_core" };
        }

        if ("exit_code" in receipt_core) {
            if (typeof receipt_core.exit_code !== 'number' || !Number.isInteger(receipt_core.exit_code)) {
                return { status: "REJECT", reason_code: "invalid_exit_code_type" };
            }
        }

        const digestsToCheck = ["stdout_digest", "stderr_digest", "stdin_digest", "execution_digest"];
        for (const f of digestsToCheck) {
            if (f in receipt_core) {
                validateDigest(receipt_core[f]);
            }
        }

        if ("execution_core" in obj) {
            const execCore = obj.execution_core;
            const allowedExec = new Set(["command_argv", "exit_code", "stdout_digest", "stderr_digest"]);
            for (const k in execCore) {
                if (!allowedExec.has(k)) {
                    return { status: "REJECT", reason_code: "unknown_field_execution_core" };
                }
            }
            
            if (execCore.exit_code !== receipt_core.exit_code) {
                return { status: "REJECT", reason_code: "exit_code_inconsistency" };
            }
        }

        if ("command" in receipt_core) {
            const cmd = receipt_core.command;
            if (!Array.isArray(cmd)) {
                return { status: "REJECT", reason_code: "invalid_argv_type" };
            }
            if (cmd.length === 0) {
                return { status: "REJECT", reason_code: "empty_command" };
            }
            for (const item of cmd) {
                if (typeof item !== 'string') {
                    return { status: "REJECT", reason_code: "invalid_argv_type" };
                }
            }
        }

        const actualProofId = await computeProofId(obj);

        if ("proof_id" in obj) {
            const claimedId = obj.proof_id;
            try {
                validateDigest(claimedId);
            } catch (e) {
                return { status: "REJECT", reason_code: "invalid_proof_id_format" };
            }
            
            if (claimedId !== actualProofId) {
                return { status: "REJECT", reason_code: "proof_id_mismatch" };
            }
        }

        return { status: "ACCEPT", proof_id: actualProofId };

    } catch (e) {
        if (e instanceof VerificationError) {
            return { status: "REJECT", reason_code: e.reasonCode };
        }
        if (e instanceof SyntaxError) {
            return { status: "REJECT", reason_code: "invalid_json" };
        }
        return { status: "ERROR", message: e.message };
    }
}

// Export for browser use
if (typeof window !== 'undefined') {
    window.verifyOEP01 = verifyOEP01;
    window.decodeBase64Strict = decodeBase64Strict;
    window.VerificationError = VerificationError;
}