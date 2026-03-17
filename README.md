# OEP Verifier

Public browser verifier for **Open Execution Proof (OEP-1)** execution proofs.

The verifier independently validates:

- execution identity  
- proof structure  
- Ed25519 signature  

---

## Live Verifier

https://openexecproof.github.io/verify/

---

## Verification Model

The verifier validates a signature over the UTF-8 bytes of the lowercase hexadecimal `execution_id`.

If the execution identity changes, the signature becomes invalid.

---

## Proof Transport

Two transport modes are supported.

### Fragment transport
https://openexecproof.github.io/verify/#
<proof_fragment>


### Hosted proof transport


https://openexecproof.github.io/verify/?id=
<execution_id>

Both modes pass through the same canonical validation corridor.

---

## Example Proof

https://openexecproof.github.io/verify/?id=5a6c7a254d5cc40cf0a5ff7394fb1801dd989ce63e32044a5fd2c4674ebdeba7

---

## Repository Structure
index.html
verifier-browser.js
p/


---

## License

MIT
