(function () {
    const STATE = {
        stage: "boot",
        loaded: false,
        module_url: null,
        hasVerifyAsync: false,
        last_error: null,
        attempts: []
    };

    let cachedModule = null;
    let loadingPromise = null;

    function setState(patch) {
        Object.assign(STATE, patch);
        window.__ED25519_FALLBACK_STATE__ = {
            stage: STATE.stage,
            loaded: STATE.loaded,
            module_url: STATE.module_url,
            hasVerifyAsync: STATE.hasVerifyAsync,
            last_error: STATE.last_error,
            attempts: [...STATE.attempts]
        };
    }

    function errToString(e) {
        if (!e) return "unknown error";
        if (typeof e === "string") return e;
        if (e && e.message) return e.message;
        try {
            return String(e);
        } catch (_e) {
            return "unstringifiable error";
        }
    }

    async function loadNobleEd25519() {
        if (cachedModule) return cachedModule;
        if (loadingPromise) return loadingPromise;

        setState({ stage: "loading_local_module" });

        loadingPromise = (async () => {
            const url = "./vendor/noble-ed25519.bundle.mjs?v=20260321localvendor1";

            try {
                const mod = await import(url);

                if (!mod || typeof mod.verifyAsync !== "function") {
                    throw new Error("Local module does not expose verifyAsync");
                }

                cachedModule = mod;
                setState({
                    stage: "ready",
                    loaded: true,
                    module_url: url,
                    hasVerifyAsync: true,
                    last_error: null
                });

                return mod;
            } catch (e) {
                const msg = errToString(e);
                STATE.attempts.push({ url, error: msg });
                setState({
                    stage: "load_failed",
                    loaded: false,
                    hasVerifyAsync: false,
                    module_url: url,
                    last_error: msg
                });
                throw e;
            }
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
            setState({ stage: "verify_called" });

            ensureUint8Array(sig, "sig");
            ensureUint8Array(msg, "msg");
            ensureUint8Array(pubkey, "pubkey");

            if (sig.length !== 64) {
                const e = "Invalid Ed25519 signature length";
                setState({ stage: "verify_rejected", last_error: e });
                throw new Error(e);
            }

            if (pubkey.length !== 32) {
                const e = "Invalid Ed25519 public key length";
                setState({ stage: "verify_rejected", last_error: e });
                throw new Error(e);
            }

            const noble = await loadNobleEd25519();

            try {
                const ok = await noble.verifyAsync(sig, msg, pubkey);
                setState({
                    stage: ok ? "verify_true" : "verify_false",
                    last_error: null
                });
                return !!ok;
            } catch (e) {
                const msgText = "Fallback verify failed: " + errToString(e);
                setState({
                    stage: "verify_failed",
                    last_error: msgText
                });
                throw new Error(msgText);
            }
        },

        async selftest() {
            try {
                const noble = await loadNobleEd25519();
                return {
                    ok: true,
                    loaded: true,
                    module_url: STATE.module_url,
                    hasVerifyAsync: !!(noble && typeof noble.verifyAsync === "function"),
                    state: window.__ED25519_FALLBACK_STATE__
                };
            } catch (e) {
                return {
                    ok: false,
                    loaded: false,
                    module_url: STATE.module_url,
                    hasVerifyAsync: false,
                    error: errToString(e),
                    state: window.__ED25519_FALLBACK_STATE__
                };
            }
        }
    };

    setState({ stage: "booted" });
})();