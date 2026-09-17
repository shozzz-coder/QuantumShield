# QuantumShield — Encryption Visualizer

This is the first section of a hackathon project about quantum readiness. It teaches the basic journey from plaintext to ciphertext and back again.

## Run it

The simplest option is to open `index.html` in a web browser.

For the best editing experience, install the **Live Server** extension in VS Code. Open this folder in VS Code, right-click `index.html`, then select **Open with Live Server**.

## Important accuracy note

This demo uses the browser's real AES-256-GCM encryption through the Web Crypto API. It creates a new random key and initialization vector for each message. The key stays in the active browser tab and is not shared, stored, or protected by user authentication, so this is a genuine encryption demonstration—not a complete secure messaging system.

## Post-quantum encryption demonstration

`solution.html` also includes a real local ML-KEM-768 plus AES-256-GCM demonstration. ML-KEM-768 is a NIST FIPS 203 post-quantum key-encapsulation mechanism. It establishes a shared secret locally, which is then imported as the AES-256 key to encrypt the entered message.

The same page now includes a browser-only sender-to-recipient file workflow. A recipient creates an ML-KEM-768 key pair and downloads a shareable public `.qpk` key plus a private `.qsk` recovery key. A sender uses only the `.qpk` key and a file to make a `.qshield` package containing the ML-KEM ciphertext, AES-GCM initialization vector, encrypted file data, and non-secret metadata. The recipient uploads the matching `.qsk` key to recover the original file. The page also includes a one-byte tamper test: AES-GCM rejects an altered ciphertext instead of releasing a modified file, and the page can download that altered `.qshield` package so the rejection can be demonstrated through the normal recipient-decryption panel. The interface intentionally limits files to 10 MB because the package is a simple JSON envelope held in browser memory.

The RSA/Shor page is deliberately a safe, tiny-number concept simulator. It explains why a future fault-tolerant quantum computer threatens RSA and ECC key exchange; it does not claim to break real RSA, ML-KEM, or AES. The file package replaces the old RSA-style exchange with ML-KEM-768 and uses AES-256-GCM for file confidentiality and integrity.

The implementation is the bundled `@noble/post-quantum` ML-KEM module (version 0.7.0) in `vendor/ml-kem.classic.js`. This is an educational prototype, not a complete authenticated production protocol. A real deployment needs identity authentication, protected key storage, careful protocol design, and professional review.

`inspector.html` provides a technical, live trace. It displays public values and SHA-256 fingerprints, but never exposes the secret key or shared secret. The comparison page correctly describes the advantage as quantum resistance in the key-establishment layer; it does not claim a misleading numeric “times safer” score.

`impact.html` turns the prototype into an adoption strategy: sector risks, a software-first migration plan, and an interactive rollout planner for banks, governments, healthcare, telecom, and critical infrastructure.

`medical.html` is the Q-MedGuard integrity lab. It displays the project-supplied MRI reference image from `assets/professor-supplied-mri-reference.png` and binds it to fictional, non-diagnostic demo metadata. The interactive Q-GAN workflow prototype has a generator step that samples a **simulated** quantum latent state and composes a visibly synthetic candidate, followed by a discriminator-prototype step that scores the candidate using a transparent pixel-difference feature. It does not train or execute a quantum GAN, and the discriminator score is not a clinical classifier, deepfake detector, or final security decision. The page then uses a real local browser ECDSA signature check to reject the changed record. Its live ECDSA signing layer is a runnable prototype of the integrity workflow—not a post-quantum signature. A deployment should use ML-DSA (NIST FIPS 204) for the hospital-signature layer and the existing ML-KEM + AES-GCM workflow for protected transfer. Confirm that the supplied MRI image is cleared for public deployment before publishing the site.

`bank.html` is the BankGuard privacy-preserving data-sharing lab. A fictional bank classifies data fields, removes direct identifiers, generalises quasi-identifiers into groups that satisfy `k = 3`, and withholds customer-level defaulter status. It then uses real local ML-KEM-768 plus AES-256-GCM to encrypt only that permitted partner view. The authorised partner can ask a safe aggregate question; the bank-side privacy service releases a differentially private count with Laplace noise. A request for account numbers linked to defaulter status is visibly blocked by the policy engine.
