# QuantumShield: Path from Prototype to Product

## What works now

The Secure Channel page performs actual client-side ML-KEM-768 key establishment and AES-256-GCM message encryption. It creates an encrypted packet containing only:

- ML-KEM ciphertext
- AES-GCM initialization vector
- AES-GCM ciphertext

Bob's private ML-KEM key and the shared AES key stay in browser memory.

The File Protection panel uses the same hybrid-encryption pattern for one local file at a time. It models a sender-to-recipient exchange:

1. A recipient creates an ML-KEM-768 key pair and downloads a shareable `.qpk` public key plus a private `.qsk` recovery key.
2. A sender encrypts a local file using only the recipient's `.qpk` key and receives a `.qshield` package.
3. The recipient uploads the package and matching `.qsk` key to recover the original file.

The `.qshield` package contains ML-KEM ciphertext, an AES-GCM IV, encrypted file data, and non-secret metadata. It contains neither the recipient private key nor the one-time AES key. A built-in integrity test alters one ciphertext byte and demonstrates that AES-GCM authentication rejects it.

This is a single-recipient local prototype, not a key-management solution. The public `.qpk` is intended to be shared; the private `.qsk` must remain with the recipient. Anyone holding a matching private key can decrypt the protected package.

## What a production system needs

1. **Client applications**: Browser, desktop, or mobile apps generate and protect private keys using the platform keystore where possible.
2. **Identity and authentication**: Users verify each other through authenticated accounts, device registration, certificates, or passkeys. ML-KEM alone does not authenticate a sender.
3. **Ciphertext-only relay**: HTTPS/WebSocket service relays and stores encrypted packets but never receives private keys or plaintext.
4. **Standardised hybrid protocols**: Transition systems combine established classical cryptography with PQC in a reviewed protocol until migration completes.
5. **Key lifecycle**: Device recovery, rotation, revocation, backups, forward secrecy, and multi-device management.
6. **Security review**: Threat modelling, independent review, penetration testing, monitoring, and incident response.

## Product positioning

QuantumShield can become a **post-quantum secure communication layer** for organisations with long-lived confidential data. It helps them replace quantum-vulnerable key establishment while preserving existing encrypted-data workflows.

## Synthetic medical-record integrity lab

The Q-MedGuard page models a related risk: a medical image can be visually convincing while no longer being the hospital's original record. It displays the project-supplied MRI reference asset with fictional, non-diagnostic metadata. After the reference record is signed locally, the page visualises a Q-GAN workflow prototype: a simulated quantum latent state drives a generator-style synthetic candidate, and a transparent discriminator-prototype score labels the candidate as likely synthetic. This is not a trained Q-GAN or a medical-image classifier; the demo makes the Generator → Discriminator concept visible while preserving an honest technical boundary. The final security decision is made by a real browser ECDSA verification check over the exact image pixels and metadata, which rejects the changed manifest. ECDSA is used solely because it is available in browser Web Crypto for a locally runnable integrity demonstration; the production architecture should replace it with ML-DSA for post-quantum origin and integrity verification, while ML-KEM + AES-GCM protects data in transit.

## BankGuard privacy-preserving sharing lab

The BankGuard page separates secure transport from minimum-necessary disclosure. A fictional bank first classifies direct identifiers, quasi-identifiers, and sensitive attributes. It removes names and account numbers, generalises age, location, income, and loan amounts, and produces four groups of three records (`k = 3`). The customer-level defaulter status is excluded from the partner payload. The permitted group view is then actually encrypted using ML-KEM-768 plus AES-256-GCM to a locally generated partner key pair. After local recipient decryption, the partner may request a bank-side differentially private aggregate. An identity-revealing request is blocked by an explicit policy rule. This is a browser-only illustration of privacy engineering, not a regulated banking, access-control, consent, or compliance system.
