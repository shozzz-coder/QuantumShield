(() => {
  const mlKem = globalThis.QuantumShieldMLKEM?.ml_kem768;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const $ = (selector) => document.querySelector(selector);
  const generateKeysButton = $('#govGenerateKeysButton');
  const policyButton = $('#govPolicyButton');
  const encryptButton = $('#govEncryptButton');
  const openButton = $('#govOpenButton');
  const safeQueryButton = $('#govSafeQueryButton');
  const unsafeQueryButton = $('#govUnsafeQueryButton');
  const tamperButton = $('#govTamperButton');

  const keyCard = $('#govKeyCard');
  const policyCard = $('#govPolicyCard');
  const packageCard = $('#govPackageCard');
  const recipientCard = $('#govRecipientCard');
  const traceKey = $('#govTraceKey');
  const tracePolicy = $('#govTracePolicy');
  const tracePackage = $('#govTracePackage');
  const traceVerify = $('#govTraceVerify');
  const traceTamper = $('#govTraceTamper');
  const consoleOutput = $('#govConsole');

  const journeyState = $('#govJourneyState');
  const journeyPolicy = $('#govJourneyPolicy');
  const journeyPackage = $('#govJourneyPackage');
  const journeyRecipient = $('#govJourneyRecipient');
  const journeyPolicyOutput = $('#govJourneyPolicyOutput');
  const journeyGroups = $('#govJourneyGroups');
  const journeyKem = $('#govJourneyKem');
  const journeyAes = $('#govJourneyAes');
  const journeySignature = $('#govJourneySignature');
  const journeyPackageOutput = $('#govJourneyPackageOutput');
  const journeyOpen = $('#govJourneyOpen');
  const journeyVerify = $('#govJourneyVerify');
  const journeyQuery = $('#govJourneyQuery');
  const journeyTamper = $('#govJourneyTamper');
  const journeyRecipientOutput = $('#govJourneyRecipientOutput');

  const keyPanel = $('#govKeyPanel');
  const publicKeyFingerprint = $('#govPublicKeyFingerprint');
  const policyPanel = $('#govPolicyPanel');
  const policyList = $('#govPolicyList');
  const policyState = $('#govPolicyState');
  const groupsPanel = $('#govGroupsPanel');
  const groupsTableBody = $('#govGroupsTable tbody');
  const kStatus = $('#govKStatus');
  const packagePanel = $('#govPackagePanel');
  const packagePayload = $('#govPackagePayload');
  const packageKem = $('#govPackageKem');
  const packageIv = $('#govPackageIv');
  const packageSignature = $('#govPackageSignature');
  const recipientPanel = $('#govRecipientPanel');
  const verificationState = $('#govVerificationState');
  const decryptOutcome = $('#govDecryptOutcome');
  const signatureOutcome = $('#govSignatureOutcome');
  const queryPanel = $('#govQueryPanel');
  const queryResult = $('#govQueryResult');
  const tamperPanel = $('#govTamperPanel');

  const rawApplications = [
    { reference: 'SYN-GOV-1001', name: 'Riya Sharma', age: 19, pincode: '560034', cluster: 'Bengaluru Metro', income: 210000, programme: 'Education Support', decision: 'Approved' },
    { reference: 'SYN-GOV-1002', name: 'Kavya Nair', age: 22, pincode: '560038', cluster: 'Bengaluru Metro', income: 230000, programme: 'Education Support', decision: 'Approved' },
    { reference: 'SYN-GOV-1003', name: 'Imran Khan', age: 23, pincode: '560040', cluster: 'Bengaluru Metro', income: 180000, programme: 'Education Support', decision: 'Pending' },
    { reference: 'SYN-GOV-1011', name: 'Meera Joshi', age: 20, pincode: '411004', cluster: 'Pune Metro', income: 220000, programme: 'Education Support', decision: 'Approved' },
    { reference: 'SYN-GOV-1012', name: 'Arjun Patil', age: 23, pincode: '411007', cluster: 'Pune Metro', income: 180000, programme: 'Education Support', decision: 'Pending' },
    { reference: 'SYN-GOV-1013', name: 'Sana Sheikh', age: 24, pincode: '411014', cluster: 'Pune Metro', income: 290000, programme: 'Education Support', decision: 'Approved' },
    { reference: 'SYN-GOV-1021', name: 'Aditi Verma', age: 26, pincode: '226010', cluster: 'Lucknow Urban', income: 340000, programme: 'Education Support', decision: 'Approved' },
    { reference: 'SYN-GOV-1022', name: 'Rohan Gupta', age: 29, pincode: '226016', cluster: 'Lucknow Urban', income: 310000, programme: 'Education Support', decision: 'Pending' },
    { reference: 'SYN-GOV-1023', name: 'Farah Ali', age: 32, pincode: '226021', cluster: 'Lucknow Urban', income: 380000, programme: 'Education Support', decision: 'Approved' },
  ];

  const fieldPolicy = [
    ['Citizen name', 'Direct identifier', 'Never include in a planning release'],
    ['Service reference', 'Direct identifier', 'Never include in a planning release'],
    ['Exact age / date of birth', 'Quasi-identifier', 'Convert to a broad age band'],
    ['PIN code / address', 'Quasi-identifier', 'Convert to a district cluster'],
    ['Income proof', 'Sensitive attribute', 'Convert to a broad income band'],
    ['Individual benefit decision', 'Sensitive attribute', 'Keep inside gateway; aggregate only'],
    ['Purpose ID + policy version', 'Release control', 'Sign and include with the authorised release'],
  ];

  let stateOfficeKeys;
  let approvedGroups;
  let protectedRelease;
  let gatewaySigningKeys;
  let openedRelease;
  let releaseOpened = false;

  function pause(milliseconds) {
    return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  async function sha256(bytes) {
    const digest = await window.crypto.subtle.digest('SHA-256', bytes);
    return bytesToHex(new Uint8Array(digest));
  }

  function shortFingerprint(value) {
    return value.match(/.{1,8}/g).slice(0, 4).join(' · ');
  }

  function formatBytes(bytes) {
    return bytes < 1024 ? `${bytes} bytes` : `${(bytes / 1024).toFixed(1)} KB`;
  }

  function ageBand(age) {
    if (age <= 24) return '18–24';
    return '25–34';
  }

  function incomeBand(income) {
    return income < 300000 ? '₹0–3L' : '₹3–5L';
  }

  function laplaceNoise(epsilon) {
    const uniform = Math.random() - 0.5;
    return -(1 / epsilon) * Math.sign(uniform) * Math.log(1 - (2 * Math.abs(uniform)));
  }

  function ensureCryptoSupport() {
    if (!mlKem) throw new Error('The ML-KEM library did not load. Refresh the page and try again.');
    if (!window.crypto?.subtle) throw new Error('Web Crypto is unavailable. Use the deployed HTTPS site in Chrome.');
  }

  function setState(card, state) {
    card.classList.remove('active', 'complete', 'failed', 'blocked');
    if (state) card.classList.add(state);
  }

  function setTrace(card, state, value) {
    setState(card, state);
    card.querySelector('code').textContent = value;
  }

  function buildGroups() {
    const grouped = new Map();
    for (const record of rawApplications) {
      const key = `${record.cluster}|${ageBand(record.age)}|${incomeBand(record.income)}|${record.programme}`;
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key).push(record);
    }
    return Array.from(grouped.values()).map((records) => ({
      districtCluster: records[0].cluster,
      ageBand: ageBand(records[0].age),
      incomeBand: incomeBand(records[0].income),
      programme: records[0].programme,
      applicationCount: records.length,
    }));
  }

  function renderPolicy() {
    policyList.innerHTML = fieldPolicy.map(([field, kind, action]) => `<article><span>${kind}</span><strong>${field}</strong><p>${action}</p></article>`).join('');
  }

  function renderGroups() {
    groupsTableBody.innerHTML = approvedGroups.map((group) => `<tr><td>${group.districtCluster}</td><td>${group.ageBand}</td><td>${group.incomeBand}</td><td>${group.programme}</td><td>${group.applicationCount}</td><td>Not shared — aggregate only</td></tr>`).join('');
  }

  async function createStateKeySet() {
    try {
      ensureCryptoSupport();
      generateKeysButton.disabled = true;
      setState(keyCard, 'active');
      setTrace(traceKey, 'active', 'Generating an ML-KEM-768 state-office key pair locally…');
      journeyState.textContent = 'CREATING STATE-OFFICE KEY';
      consoleOutput.textContent = 'STATE EDUCATION OFFICE: generating an ML-KEM-768 key pair. The public key can travel to the gateway; the private key remains in this browser.';

      const keyPair = mlKem.keygen();
      const fingerprint = await sha256(keyPair.publicKey);
      stateOfficeKeys = { publicKey: keyPair.publicKey, secretKey: keyPair.secretKey, fingerprint };
      publicKeyFingerprint.textContent = shortFingerprint(fingerprint);
      keyPanel.hidden = false;
      setState(keyCard, 'complete');
      setState(policyCard, 'active');
      setTrace(traceKey, 'complete', `Public-key fingerprint: ${shortFingerprint(fingerprint)} · private key remains local`);
      journeyState.textContent = 'GATEWAY RECEIVED AUTHORISED PUBLIC KEY';
      setState(journeyPolicy, 'active');
      journeyPolicyOutput.textContent = `Recipient public key accepted · ${shortFingerprint(fingerprint)}`;
      policyButton.disabled = false;
      consoleOutput.textContent = `STATE PUBLIC KEY READY ✓\nFingerprint sent to National Civic Services Gateway: ${shortFingerprint(fingerprint)}\n\nThe gateway can encrypt an approved release to this public key, but it cannot decrypt the package.`;
    } catch (error) {
      generateKeysButton.disabled = false;
      setState(keyCard, 'failed');
      setTrace(traceKey, 'failed', `Key setup failed: ${error.message}`);
      consoleOutput.textContent = `STATE KEY SETUP FAILED: ${error.message}`;
    }
  }

  async function applyReleasePolicy() {
    try {
      if (!stateOfficeKeys) throw new Error('Create the state-office key set first.');
      policyButton.disabled = true;
      setState(policyCard, 'active');
      setState(journeyPolicy, 'active');
      setTrace(tracePolicy, 'active', 'Classifying fields against the district-planning release purpose…');
      journeyState.textContent = 'APPLYING PURPOSE & PRIVACY POLICY';
      journeyPolicyOutput.textContent = 'Checking every field before any encryption begins…';
      consoleOutput.textContent = 'NATIONAL CIVIC SERVICES GATEWAY: applying the purpose-bound release policy for district-level education planning…';
      await pause(180);

      approvedGroups = buildGroups();
      const smallestGroup = Math.min(...approvedGroups.map((group) => group.applicationCount));
      if (smallestGroup < 3) throw new Error('The synthetic planning groups did not meet the k = 3 threshold.');
      renderPolicy();
      renderGroups();
      policyPanel.hidden = false;
      groupsPanel.hidden = false;
      policyState.textContent = 'POLICY APPLIED';
      kStatus.textContent = `k = ${smallestGroup} ✓`;
      setState(policyCard, 'complete');
      setState(journeyPolicy, 'complete');
      setState(packageCard, 'active');
      setState(journeyPackage, 'active');
      setTrace(tracePolicy, 'complete', `Removed 2 direct identifiers · generalised 3 quasi-identifiers · ${approvedGroups.length} groups satisfy k = ${smallestGroup}`);
      journeyState.textContent = `POLICY COMPLETE · ${approvedGroups.length} APPROVED PLANNING GROUPS`;
      journeyPolicyOutput.textContent = `Removed identity fields · generalised age/PIN/income · withheld individual decisions · k = ${smallestGroup}`;
      journeyGroups.textContent = `${approvedGroups.length} groups`;
      journeyPackageOutput.textContent = 'Only the approved planning groups may now be signed and encrypted.';
      encryptButton.disabled = false;
      consoleOutput.textContent = `RELEASE POLICY APPLIED ✓\nNames and service references: removed\nAge, PIN code and income: generalised\nIndividual benefit decisions: withheld\n\n${approvedGroups.length} anonymous planning groups satisfy k = ${smallestGroup}.`;
    } catch (error) {
      policyButton.disabled = false;
      policyState.textContent = 'POLICY FAILED';
      setState(policyCard, 'failed');
      setTrace(tracePolicy, 'failed', `Policy failed: ${error.message}`);
      consoleOutput.textContent = `RELEASE POLICY FAILED: ${error.message}`;
    }
  }

  async function signAndEncryptRelease() {
    let sharedSecret;
    try {
      ensureCryptoSupport();
      if (!stateOfficeKeys || !approvedGroups) throw new Error('Apply the purpose and privacy policy before creating a release.');
      encryptButton.disabled = true;
      setState(packageCard, 'active');
      setState(journeyPackage, 'active');
      setTrace(tracePackage, 'active', 'Signing the authorised manifest and encapsulating a one-time ML-KEM secret…');
      journeyState.textContent = 'SIGNING AND ENCRYPTING APPROVED RELEASE';
      journeyKem.textContent = 'Encapsulating…';
      journeyAes.textContent = 'Waiting';
      journeySignature.textContent = 'Signing…';
      journeyPackageOutput.textContent = 'The gateway is binding purpose, policy, and groups into a signed manifest…';
      consoleOutput.textContent = 'GATEWAY: signing the exact approved planning manifest, then encrypting it to the authorised state office.';

      gatewaySigningKeys = await window.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      const manifest = {
        format: 'GovGuard-Release-1',
        issuedBy: 'National Civic Services Gateway (fictional demo)',
        recipient: 'State Education Office (fictional demo)',
        purposeId: 'EDU-PLAN-2026',
        purpose: 'District-level education-support capacity planning',
        policyVersion: 'minimum-necessary-v1',
        groups: approvedGroups,
      };
      const manifestBytes = encoder.encode(JSON.stringify(manifest));
      const signature = new Uint8Array(await window.crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, gatewaySigningKeys.privateKey, manifestBytes));
      const encapsulated = mlKem.encapsulate(stateOfficeKeys.publicKey);
      sharedSecret = encapsulated.sharedSecret;
      const aesKey = await window.crypto.subtle.importKey('raw', sharedSecret, { name: 'AES-GCM' }, false, ['encrypt']);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const releaseEnvelope = { manifest, signature: Array.from(signature) };
      const payload = encoder.encode(JSON.stringify(releaseEnvelope));
      await pause(180);
      const ciphertext = new Uint8Array(await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, payload));
      protectedRelease = { kemCiphertext: encapsulated.cipherText.slice(), iv, ciphertext };

      packagePayload.textContent = `${approvedGroups.length} approved groups · ${formatBytes(payload.length)}`;
      packageKem.textContent = `${formatBytes(protectedRelease.kemCiphertext.length)} public encapsulation data`;
      packageIv.textContent = `${protectedRelease.iv.length} bytes`;
      packageSignature.textContent = `ECDSA P-256 · ${formatBytes(signature.length)}`;
      packagePanel.hidden = false;
      setState(packageCard, 'complete');
      setState(journeyPackage, 'complete');
      setState(recipientCard, 'active');
      setState(journeyRecipient, 'active');
      setTrace(tracePackage, 'complete', `Manifest signature: ${formatBytes(signature.length)} · ML-KEM ciphertext: ${formatBytes(protectedRelease.kemCiphertext.length)} · AES-GCM payload: ${formatBytes(ciphertext.length)}`);
      journeyState.textContent = 'PROTECTED, SIGNED RELEASE TRAVELLING TO STATE OFFICE';
      journeyKem.textContent = `${formatBytes(protectedRelease.kemCiphertext.length)} capsule`;
      journeyAes.textContent = `${formatBytes(ciphertext.length)} encrypted`;
      journeySignature.textContent = 'Included';
      journeyPackageOutput.textContent = 'The signature and permitted view are now inside authenticated AES-GCM ciphertext.';
      journeyRecipientOutput.textContent = 'Package received. The state office needs its matching private ML-KEM key to open it.';
      openButton.disabled = false;
      consoleOutput.textContent = 'PROTECTED RELEASE READY ✓\nContents: approved anonymous planning groups only\nSignature: gateway ECDSA P-256 manifest signature\nProtection: ML-KEM-768 secret establishment + AES-256-GCM encryption\n\nNo citizen names, service references, exact PIN codes, or individual decisions are present.';
    } catch (error) {
      encryptButton.disabled = false;
      setState(packageCard, 'failed');
      setTrace(tracePackage, 'failed', `Release creation failed: ${error.message}`);
      consoleOutput.textContent = `RELEASE CREATION FAILED: ${error.message}`;
    } finally {
      sharedSecret?.fill(0);
    }
  }

  async function openAndVerifyRelease() {
    let sharedSecret;
    try {
      ensureCryptoSupport();
      if (!protectedRelease || !stateOfficeKeys || !gatewaySigningKeys) throw new Error('Create the protected release first.');
      openButton.disabled = true;
      setState(recipientCard, 'active');
      setState(journeyRecipient, 'active');
      setTrace(traceVerify, 'active', 'State office is decapsulating the secret, decrypting the release, and checking the gateway signature…');
      journeyState.textContent = 'STATE OFFICE DECRYPTING AND VERIFYING RELEASE';
      journeyRecipientOutput.textContent = 'Private ML-KEM key recovers the one-time secret; AES-GCM authenticates the package; ECDSA verifies origin…';
      consoleOutput.textContent = 'STATE EDUCATION OFFICE: recovering the one-time secret with its private ML-KEM key and verifying the signed release manifest…';

      sharedSecret = mlKem.decapsulate(protectedRelease.kemCiphertext, stateOfficeKeys.secretKey);
      const aesKey = await window.crypto.subtle.importKey('raw', sharedSecret, { name: 'AES-GCM' }, false, ['decrypt']);
      const plaintext = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: protectedRelease.iv }, aesKey, protectedRelease.ciphertext);
      const envelope = JSON.parse(decoder.decode(plaintext));
      const signatureValid = await window.crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        gatewaySigningKeys.publicKey,
        new Uint8Array(envelope.signature),
        encoder.encode(JSON.stringify(envelope.manifest)),
      );
      if (!signatureValid) throw new Error('The gateway signature did not verify.');
      const safeText = JSON.stringify(envelope.manifest);
      if (/SYN-GOV-|Riya Sharma|\"decision\"|\"name\"/i.test(safeText)) throw new Error('Policy violation: identity or individual decision data appeared in the release.');

      openedRelease = envelope;
      releaseOpened = true;
      recipientPanel.hidden = false;
      queryPanel.hidden = false;
      tamperPanel.hidden = false;
      verificationState.textContent = 'SIGNATURE VALID ✓';
      decryptOutcome.textContent = `${envelope.manifest.groups.length} approved planning groups opened`;
      signatureOutcome.textContent = 'Gateway signature valid ✓';
      setState(recipientCard, 'complete');
      setState(journeyRecipient, 'complete');
      setTrace(traceVerify, 'complete', `AES-GCM decrypted ${envelope.manifest.groups.length} approved groups · ECDSA signature valid · identity fields absent`);
      journeyState.textContent = 'STATE OFFICE RECEIVED VERIFIED MINIMUM-NECESSARY VIEW';
      journeyOpen.textContent = `${envelope.manifest.groups.length} groups opened`;
      journeyVerify.textContent = 'Valid ✓';
      journeyRecipientOutput.textContent = 'Verified release opened ✓ Identity fields and individual decisions are absent.';
      consoleOutput.textContent = 'STATE OFFICE VERIFICATION SUCCESSFUL ✓\nAES-GCM authentication: valid\nGateway ECDSA signature: valid\nAuthorised purpose: EDU-PLAN-2026\n\nOpened planning groups only. No citizen identity or individual benefit decision was released.';
    } catch (error) {
      openButton.disabled = false;
      setState(recipientCard, 'failed');
      setTrace(traceVerify, 'failed', `Verification failed: ${error.message}`);
      verificationState.textContent = 'VERIFICATION FAILED';
      consoleOutput.textContent = `STATE-OFFICE VERIFICATION FAILED: ${error.message}`;
    } finally {
      sharedSecret?.fill(0);
    }
  }

  function runSafeQuery() {
    if (!releaseOpened) return;
    const exactCount = rawApplications.filter((record) => record.cluster === 'Bengaluru Metro' && record.programme === 'Education Support').length;
    const noise = laplaceNoise(1);
    const protectedCount = Math.max(0, Math.round(exactCount + noise));
    setTrace(traceVerify, 'complete', 'Verified partner view remains open · approved aggregate query sent to the gateway privacy service');
    journeyState.textContent = 'APPROVED PRIVACY-PROTECTED AGGREGATE RELEASED';
    journeyQuery.textContent = `Aggregate: ${protectedCount}`;
    queryResult.innerHTML = `<strong>APPROVED · PRIVACY-PROTECTED AGGREGATE ✓</strong><p>Education-support applications in Bengaluru Metro cluster: <b>${protectedCount}</b></p><small>The exact count is calculated inside the fictional gateway service. Laplace noise (ε = 1.0) is added before the aggregate is released. No citizen reference or individual benefit decision is returned.</small>`;
    consoleOutput.textContent = `SAFE QUERY APPROVED ✓\nQuestion: “How many Education Support applications are in Bengaluru Metro cluster?”\nPrivacy mechanism: Laplace noise with ε = 1.0\nReleased value: ${protectedCount}\n\nNo citizen-level record is released.`;
  }

  function blockUnsafeQuery() {
    if (!releaseOpened) return;
    setState(recipientCard, 'blocked');
    journeyState.textContent = 'IDENTITY-REVEALING REQUEST BLOCKED';
    journeyQuery.textContent = 'Blocked ✕';
    queryResult.innerHTML = '<strong>BLOCKED BY RELEASE POLICY ✕</strong><p>The request links citizen references with individual approval status.</p><small>Reason: direct identifiers are never included in the state-office package, and individual benefit decisions are kept inside the source gateway. Differential privacy cannot make an identity lookup permissible.</small>';
    consoleOutput.textContent = 'UNSAFE QUERY BLOCKED ✕\nRequested fields: citizen service reference + individual approval status\nPolicy decision: deny. This would expose a sensitive citizen-level decision.';
  }

  async function testModifiedManifest() {
    try {
      if (!releaseOpened || !openedRelease || !gatewaySigningKeys) throw new Error('Open and verify the approved release first.');
      tamperButton.disabled = true;
      setTrace(traceTamper, 'active', 'Changing a local copy of the signed manifest and verifying it against the original signature…');
      journeyTamper.textContent = 'Testing…';
      consoleOutput.textContent = 'INTEGRITY TEST: modifying a local copy of the approved manifest. The original gateway signature must reject it.';
      await pause(160);

      const modifiedManifest = JSON.parse(JSON.stringify(openedRelease.manifest));
      modifiedManifest.purpose = 'Unapproved citizen-level lookup';
      modifiedManifest.groups[0].applicationCount += 1;
      const signatureValid = await window.crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        gatewaySigningKeys.publicKey,
        new Uint8Array(openedRelease.signature),
        encoder.encode(JSON.stringify(modifiedManifest)),
      );
      if (signatureValid) throw new Error('Modified data unexpectedly verified.');

      setTrace(traceTamper, 'failed', 'Modified purpose + count → original gateway signature rejected ✓');
      journeyTamper.textContent = 'Rejected ✓';
      journeyRecipientOutput.textContent = 'Integrity test passed ✓ A modified manifest cannot validate against the original signature.';
      consoleOutput.textContent = 'MODIFIED MANIFEST REJECTED ✓\nChanged fields: purpose and one group count\nSignature result: invalid, as expected\n\nSecurity decision: do not accept the altered release.';
    } catch (error) {
      setTrace(traceTamper, 'failed', `Integrity test failed: ${error.message}`);
      consoleOutput.textContent = `INTEGRITY TEST FAILED: ${error.message}`;
    } finally {
      tamperButton.disabled = false;
    }
  }

  generateKeysButton.addEventListener('click', createStateKeySet);
  policyButton.addEventListener('click', applyReleasePolicy);
  encryptButton.addEventListener('click', signAndEncryptRelease);
  openButton.addEventListener('click', openAndVerifyRelease);
  safeQueryButton.addEventListener('click', runSafeQuery);
  unsafeQueryButton.addEventListener('click', blockUnsafeQuery);
  tamperButton.addEventListener('click', testModifiedManifest);
})();
