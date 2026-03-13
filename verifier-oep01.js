/**
 * Strict Base64/Base64URL validation and decoding.
 * Rejects illegal characters, whitespace, and malformed padding.
 */
function decodeBase64Strict(s) {
    if (typeof s !== 'string') throw new VerificationError("invalid_payload_type");
    
    // 1. Reject whitespace
    if (/\s/.test(s)) throw new VerificationError("illegal_whitespace");

    // 2. Reject illegal characters
    if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(s)) {
        throw new VerificationError("illegal_characters");
    }

    // 3. Detect style and normalize
    const hasStandard = /[+/]/.test(s);
    const hasUrlSafe = /[-_]/.test(s);
    if (hasStandard && hasUrlSafe) {
        throw new VerificationError("mixed_base64_styles");
    }

    let normalized = s.replace(/-/g, '+').replace(/_/g, '/');

    // 4. Strict padding check
    // Base64 length must be multiple of 4.
    // If not, it's missing padding.
    const expectedPadding = (4 - (normalized.length % 4)) % 4;
    const actualPaddingMatch = normalized.match(/=*$/);
    const actualPaddingCount = actualPaddingMatch ? actualPaddingMatch[0].length : 0;
    
    // If it has padding, it must be the correct amount
    if (actualPaddingCount > 0) {
        if (normalized.length % 4 !== 0) {
            throw new VerificationError("malformed_padding");
        }
    } else {
        // No padding provided, add it for atob if needed, 
        // but strictly speaking OEP-01 might require it.
        // Python's b64decode fails without padding usually.
        if (expectedPadding > 0) {
            // If we want to be strict like Python:
            throw new VerificationError("missing_padding");
        }
    }

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
    // We use a simplified scanner that tracks keys at the current level.
    // Given the constraints and OEP-01 structure, we can also use a regex
    // but we must ensure it doesn't match keys inside values.
    
    // A more robust way to do this in JS without a full-blown parser:
    const keysStack = [new Set()];
    let currentKey = null;
    let inString = false;
    let escaped = false;
    let expectation = 'key_or_value'; // simplify

    // Actually, for OEP-01, we can just use a simple regex approach if we are careful,
    // or a lightweight parser that tracks duplicates.
    // Let's use a manual scanner for "Boringly Deterministic" results.
    
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
                // Start of a string, could be a key or a value
                let endPos = pos + 1;
                while (endPos < jsonStr.length) {
                    if (jsonStr[endPos] === '\\') { endPos += 2; continue; }
                    if (jsonStr[endPos] === '"') break;
                    endPos++;
                }
                const strContent = jsonStr.substring(pos + 1, endPos);
                pos = endPos + 1;
                inString = false;
                
                // Peek ahead to see if it's a key
                let peek = pos;
                while (peek < jsonStr.length && /\s/.test(jsonStr[peek])) peek++;
                if (jsonStr[peek] === ':') {
                    // It's a key
                    const currentSet = keysStack[keysStack.length - 1];
                    if (currentSet.has(strContent)) {
                        throw new VerificationError("duplicate_key");
                    }
                    currentSet.add(strContent);
                }
                pos = peek; // skip to colon or next
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
    // 1. No booleans where integers expected (exit_code)
    if (fieldName === "exit_code" && typeof v === 'boolean') {
        throw new VerificationError("invalid_exit_code_type");
    }
    
    // 2. No floats
    if (typeof v === 'number' && !Number.isInteger(v)) {
        throw new VerificationError("float_not_allowed");
    }
    
    // 3. No nulls in required fields
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
 * json.dumps(identity_input, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
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

    // separators=(',', ':') means no spaces after comma or colon
    // ensure_ascii=False means output UTF-8 directly
    const sorted = sortObject(identityInput);
    const jsonString = JSON.stringify(sorted, (key, value) => {
        // Ensure no spaces in the output by using NO replacer and NO space argument
        return value;
    }, 0).replace(/\s/g, (match, offset, string) => {
        // Wait, JSON.stringify(obj, null, 0) might still have spaces in strings.
        // We only want to remove structural whitespace.
        // Actually JSON.stringify(obj) in modern JS is already compact (no spaces).
        return match; 
    });
    
    // But JSON.stringify(obj) is not guaranteed to matches Python's compactness perfectly if there are edge cases.
    // Let's use a manual serializer for total control.
    function canonicalStringify(val) {
        if (val === null) return "null";
        if (typeof val === 'string') return JSON.stringify(val); // Handles escaping
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
        
        // 0. Base64/Encoding validation (handled by caller before calling this normally, 
        // but we ensure rawStr is valid UTF-8).
        
        // 1. Duplicate Key Detection on raw string
        checkDuplicateKeys(rawStr);

        // Robust string stripping for validation
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

        // 2. Top-level Allowlist
        const allowed = new Set(["source", "protocol_version", "receipt_core", "receipt_meta", "proof_id", "execution_core"]);
        for (const k in obj) {
            if (!allowed.has(k)) {
                return { status: "REJECT", reason_code: "unknown_field_top_level" };
            }
        }

        // 3. Missing required fields
        const required = ["source", "protocol_version", "receipt_core"];
        for (const f of required) {
            if (!(f in obj)) {
                if (f === "receipt_core") return { status: "REJECT", reason_code: "missing_receipt_core" };
                if (f === "source") return { status: "REJECT", reason_code: "missing_source" };
                if (f === "protocol_version") return { status: "REJECT", reason_code: "missing_protocol_version" };
            }
        }

        // 4. Schema & Type Validation
        strictTypeCheck(obj);

        const receipt_core = obj.receipt_core;
        if (typeof receipt_core !== 'object' || Array.isArray(receipt_core)) {
            return { status: "REJECT", reason_code: "missing_receipt_core" };
        }

        // Exit code type and value
        if ("exit_code" in receipt_core) {
            if (typeof receipt_core.exit_code !== 'number' || !Number.isInteger(receipt_core.exit_code)) {
                return { status: "REJECT", reason_code: "invalid_exit_code_type" };
            }
        }

        // Digest validation
        const digestsToCheck = ["stdout_digest", "stderr_digest", "stdin_digest", "execution_digest"];
        for (const f of digestsToCheck) {
            if (f in receipt_core) {
                validateDigest(receipt_core[f]);
            }
        }

        // Execution Core validation (OEP-02)
        if ("execution_core" in obj) {
            const execCore = obj.execution_core;
            const allowedExec = new Set(["command_argv", "exit_code", "stdout_digest", "stderr_digest"]);
            for (const k in execCore) {
                if (!allowedExec.has(k)) {
                    return { status: "REJECT", reason_code: "unknown_field_execution_core" };
                }
            }
            
            // Consistency check
            if (execCore.exit_code !== receipt_core.exit_code) {
                return { status: "REJECT", reason_code: "exit_code_inconsistency" };
            }
        }

        // Argv validation
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

        // 5. Proof ID Calculation
        const actualProofId = await computeProofId(obj);

        // proof_id format validation if claimed
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
