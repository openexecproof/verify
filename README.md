# OEP Verifier

Public browser verifier for **Open Execution Proof (OEP-1)** receipts.

The verifier independently validates:

- execution identity
- proof structure
- Ed25519 signature

It supports two proof transports:

1. Fragment transport
2. Hosted proof transport

---

## Live verifier

https://openexecproof.github.io/verify/

---

## Verification model

The verifier validates a signature over the **UTF-8 bytes of the lowercase hexadecimal `execution_id`**.

This ensures that the execution identity cannot be altered without invalidating the proof.

---

## Proof transports

### Fragment transport

```text
https://openexecproof.github.io/verify/#<proof_fragment>
```

### Hosted proof transport

```text
https://openexecproof.github.io/verify/?id=<execution_id>
```

Both transport modes are verified through the same canonical validation corridor.

---

## Example

Hosted proof URL:

```text
https://openexecproof.github.io/verify/?id=5a6c7a254d5cc40cf0a5ff7394fb1801dd989ce63e32044a5fd2c4674ebdeba7
```

---

## Repository structure

```text
index.html
verifier-browser.js
p/
```

---

## License

MIT
