(function () {
    let cachedModule = null;
    let loadingPromise = null;

    async function loadNobleEd25519() {
        if (cachedModule) return cachedModule;
        if (loadingPromise) return loadingPromise;

        loadingPromise = (async () => {
            const candidates = [
                "https://esm.sh/@noble/ed25519?bundle",
                "https://esm.run/@noble/ed25519",
                "https://cdn.jsdelivr.net/npm/@noble/ed25519/+esm"
            ];

            let lastError = null;

            for (const url of candidates) {
                try {
                    const mod = await import(url);
                    if (!mod || typeof mod.verifyAsync !== "function") {
                        throw new Error("Loaded module does not expose verifyAsync");
                    }
                    cachedModule = mod;
                    return mod;
                } catch (e) {
                    lastError = e;
                    try {
                        console.warn("[ED25519_FALLBACK] load failed:", url, e);
                    } catch (_ignore) {}
                }
            }

            throw lastError || new Error("Unable to load @noble/ed25519 from CDN");
        })();

        return loadingPromise;
    }

    function ensureUint8Array(v, name) {
        if (!(v instanceof Uint8Array)) {
            throw new Error(name + " must be Uint8Array");
        }
    }

    window.ED25519_FALLBACK = {
        async verify(sig, msg, pubkey) {
            ensureUint8Array(sig, "sig");
            ensureUint8Array(msg, "msg");
            ensureUint8Array(pubkey, "pubkey");

            if (sig.length !== 64) {
                throw new Error("Invalid Ed25519 signature length");
            }

            if (pubkey.length !== 32) {
                throw new Error("Invalid Ed25519 public key length");
            }

            const noble = await loadNobleEd25519();

            try {
                const ok = await noble.verifyAsync(sig, msg, pubkey);
                return !!ok;
            } catch (e) {
                throw new Error("Fallback verify failed: " + (e && e.message ? e.message : String(e)));
            }
        },

        async selftest() {
            const noble = await loadNobleEd25519();
            return {
                loaded: true,
                hasVerifyAsync: !!(noble && typeof noble.verifyAsync === "function")
            };
        }
    };
})();