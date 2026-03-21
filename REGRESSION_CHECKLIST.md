\# VERIFIER REGRESSION CHECKLIST



\## Resolution

\- \[ ] ?id= canonical mirror resolves proof

\- \[ ] 404 case classified as proof\_not\_found

\- \[ ] network failure classified separately



\## Verification

\- \[ ] Desktop native verification returns Verified Proof

\- \[ ] Mobile fallback verification returns Verified Proof

\- \[ ] Unsupported environment does not show Invalid Proof

\- \[ ] Signature mismatch shows Invalid Proof



\## Fallback

\- \[ ] fallback-selftest loads local vendor bundle

\- \[ ] module\_url points to ./vendor/noble-ed25519.bundle.mjs

\- \[ ] hasVerifyAsync is true



\## Canonical closure proof

\- \[ ] execution\_id 32ed4478b43f6a695803ad1beca45640383b59cf2e639debf31884bc4265194c verifies on desktop

\- \[ ] same execution\_id verifies on mobile

