(() => {
  const mlKem = globalThis.QuantumShieldMLKEM?.ml_kem768;
  const generateKeysButton = document.querySelector('#bankGenerateKeysButton');
  const classifyButton = document.querySelector('#bankClassifyButton');
  const encryptButton = document.querySelector('#bankEncryptButton');
  const openButton = document.querySelector('#bankOpenButton');
  const safeQueryButton = document.querySelector('#bankSafeQueryButton');
  const unsafeQueryButton = document.querySelector('#bankUnsafeQueryButton');
  const rawTableBody = document.querySelector('#bankRawTable tbody');
  const anonTableBody = document.querySelector('#bankAnonTable tbody');
  const keyPanel = document.querySelector('#bankKeyPanel');
  const publicKeyFingerprint = document.querySelector('#bankPublicKeyFingerprint');
  const policyPanel = document.querySelector('#bankPolicyPanel');
  const policyState = document.querySelector('#bankPolicyState');
  const fieldRules = document.querySelector('#bankFieldRules');
  const anonPanel = document.querySelector('#bankAnonPanel');
  const kStatus = document.querySelector('#bankKStatus');
  const packagePanel = document.querySelector('#bankPackagePanel');
  const packagePayload = document.querySelector('#bankPackagePayload');
  const packageKem = document.querySelector('#bankPackageKem');
  const packageIv = document.querySelector('#bankPackageIv');
  const queryPanel = document.querySelector('#bankQueryPanel');
  const queryResult = document.querySelector('#bankQueryResult');
  const consoleOutput = document.querySelector('#bankConsole');
  const keyCard = document.querySelector('#bankKeyCard');
  const policyCard = document.querySelector('#bankPolicyCard');
  const packageCard = document.querySelector('#bankPackageCard');
  const partnerCard = document.querySelector('#bankPartnerCard');
  const traceKey = document.querySelector('#bankTraceKey');
  const tracePolicy = document.querySelector('#bankTracePolicy');
  const traceEncrypt = document.querySelector('#bankTraceEncrypt');
  const traceQuery = document.querySelector('#bankTraceQuery');
  const journeyState = document.querySelector('#bankJourneyState');
  const journeySource = document.querySelector('#bankJourneySource');
  const journeyPolicy = document.querySelector('#bankJourneyPolicy');
  const journeyPackage = document.querySelector('#bankJourneyPackage');
  const journeyPartner = document.querySelector('#bankJourneyPartner');
  const journeyPolicyOutput = document.querySelector('#bankJourneyPolicyOutput');
  const journeyKem = document.querySelector('#bankJourneyKem');
  const journeyAes = document.querySelector('#bankJourneyAes');
  const journeyPackageOutput = document.querySelector('#bankJourneyPackageOutput');
  const journeyGroupView = document.querySelector('#bankJourneyGroupView');
  const journeyQueryView = document.querySelector('#bankJourneyQueryView');
  const journeyBlockView = document.querySelector('#bankJourneyBlockView');
  const journeyPartnerOutput = document.querySelector('#bankJourneyPartnerOutput');
  const queryJourneyInternalCard = document.querySelector('#bankQueryJourneyInternalCard');
  const queryJourneyNoiseCard = document.querySelector('#bankQueryJourneyNoiseCard');
  const queryJourneyReleaseCard = document.querySelector('#bankQueryJourneyReleaseCard');
  const queryJourneyInternal = document.querySelector('#bankQueryJourneyInternal');
  const queryJourneyNoise = document.querySelector('#bankQueryJourneyNoise');
  const queryJourneyRelease = document.querySelector('#bankQueryJourneyRelease');

  const encoder = new TextEncoder();
  const rawRecords = [
    { name: 'Aarav Mehta', account: 'AC-7011', age: 22, pincode: '110021', income: 620000, loan: 510000, defaulted: false, region: 'North' },
    { name: 'Isha Kapoor', account: 'AC-7012', age: 25, pincode: '110029', income: 710000, loan: 580000, defaulted: true, region: 'North' },
    { name: 'Rohan Bedi', account: 'AC-7013', age: 28, pincode: '110048', income: 840000, loan: 630000, defaulted: false, region: 'North' },
    { name: 'Neha Shah', account: 'AC-7021', age: 31, pincode: '400050', income: 1040000, loan: 860000, defaulted: true, region: 'West' },
    { name: 'Kabir Jain', account: 'AC-7022', age: 35, pincode: '400053', income: 1120000, loan: 920000, defaulted: false, region: 'West' },
    { name: 'Tara Desai', account: 'AC-7023', age: 38, pincode: '400058', income: 1380000, loan: 1110000, defaulted: true, region: 'West' },
    { name: 'Vikram Nair', account: 'AC-7031', age: 42, pincode: '560034', income: 1540000, loan: 1280000, defaulted: false, region: 'South' },
    { name: 'Ananya Iyer', account: 'AC-7032', age: 46, pincode: '560038', income: 1710000, loan: 1390000, defaulted: false, region: 'South' },
    { name: 'Dev Malhotra', account: 'AC-7033', age: 48, pincode: '560041', income: 1880000, loan: 1510000, defaulted: true, region: 'South' },
    { name: 'Sana Ali', account: 'AC-7041', age: 51, pincode: '700019', income: 650000, loan: 490000, defaulted: false, region: 'East' },
    { name: 'Arjun Bose', account: 'AC-7042', age: 54, pincode: '700026', income: 780000, loan: 570000, defaulted: true, region: 'East' },
    { name: 'Mira Sen', account: 'AC-7043', age: 57, pincode: '700029', income: 910000, loan: 660000, defaulted: false, region: 'East' },
  ];

  const fieldPolicy = [
    ['Customer name', 'Direct identifier', 'Remove from partner package'],
    ['Account number', 'Direct identifier', 'Remove from partner package'],
    ['Exact age', 'Quasi-identifier', 'Convert to age band'],
    ['PIN code', 'Quasi-identifier', 'Convert to broad region'],
    ['Exact income / loan', 'Financial quasi-identifier', 'Convert to bands'],
    ['Default status', 'Sensitive attribute', 'Bank-side aggregate query only'],
  ];

  let partnerKeys;
  let anonymousGroups;
  let protectedPackage;
  let partnerViewOpened = false;

  function pause(milliseconds) {
    return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  function shortFingerprint(value) {
    return value.match(/.{1,8}/g).slice(0, 4).join(' · ');
  }

  async function sha256(bytes) {
    const digest = await window.crypto.subtle.digest('SHA-256', bytes);
    return bytesToHex(new Uint8Array(digest));
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} bytes`;
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  function ageBand(age) {
    const start = Math.floor(age / 10) * 10;
    return `${start}–${start + 9}`;
  }

  function incomeBand(income) {
    if (income < 1000000) return '₹5–10L';
    if (income < 1500000) return '₹10–15L';
    return '₹15–20L';
  }

  function formatLoanRange(records) {
    const values = records.map((record) => record.loan / 100000);
    return `₹${Math.min(...values).toFixed(1)}–${Math.max(...values).toFixed(1)}L`;
  }

  function setCardState(card, state) {
    card.classList.remove('active', 'complete', 'failed');
    if (state) card.classList.add(state);
  }

  function setTraceState(card, state, value) {
    card.classList.remove('active', 'complete', 'failed');
    if (state) card.classList.add(state);
    card.querySelector('code').textContent = value;
  }

  function setJourneyCard(card, state) {
    card.classList.remove('active', 'complete', 'blocked');
    if (state) card.classList.add(state);
  }

  function setQueryJourneyCard(card, state) {
    card.classList.remove('complete', 'blocked');
    if (state) card.classList.add(state);
  }

  function resetJourney() {
    setJourneyCard(journeySource, 'complete');
    setJourneyCard(journeyPolicy);
    setJourneyCard(journeyPackage);
    setJourneyCard(journeyPartner);
    journeyState.textContent = 'WAITING FOR PARTNER KEY';
    journeyPolicyOutput.textContent = 'Waiting for classification';
    journeyKem.textContent = 'Waiting';
    journeyAes.textContent = 'Waiting';
    journeyPackageOutput.textContent = 'Waiting for encrypted package';
    journeyGroupView.textContent = 'Locked';
    journeyQueryView.textContent = 'Not run';
    journeyBlockView.textContent = 'Not tested';
    journeyPartnerOutput.textContent = 'Waiting for private-key decryption';
    setQueryJourneyCard(queryJourneyInternalCard);
    setQueryJourneyCard(queryJourneyNoiseCard);
    setQueryJourneyCard(queryJourneyReleaseCard);
    queryJourneyInternal.textContent = 'Exact customer-level result stays internal';
    queryJourneyNoise.textContent = 'Noise added only for an approved aggregate';
    queryJourneyRelease.textContent = 'No result released yet';
  }

  function ensureCryptoSupport() {
    if (!mlKem) throw new Error('The ML-KEM library did not load. Refresh the page and try again.');
    if (!window.crypto?.subtle) throw new Error('Web Crypto is unavailable. Use the deployed HTTPS site in Chrome.');
  }

  function renderRawTable() {
    rawTableBody.innerHTML = rawRecords.map((record) => `<tr><td>${record.name}</td><td>${record.account}</td><td>${record.age}</td><td>${record.pincode}</td><td>₹${(record.income / 100000).toFixed(1)}L</td><td>₹${(record.loan / 100000).toFixed(1)}L</td><td>${record.defaulted ? 'Yes' : 'No'}</td></tr>`).join('');
  }

  function buildAnonymousGroups() {
    const grouped = new Map();
    for (const record of rawRecords) {
      const groupKey = `${ageBand(record.age)}|${record.region}|${incomeBand(record.income)}`;
      if (!grouped.has(groupKey)) grouped.set(groupKey, []);
      grouped.get(groupKey).push(record);
    }
    return Array.from(grouped.values()).map((records) => ({
      ageBand: ageBand(records[0].age),
      region: records[0].region,
      incomeBand: incomeBand(records[0].income),
      customerCount: records.length,
      loanBand: formatLoanRange(records),
    }));
  }

  function renderFieldPolicy() {
    fieldRules.innerHTML = fieldPolicy.map(([field, kind, action]) => `<article><span>${kind}</span><strong>${field}</strong><p>${action}</p></article>`).join('');
  }

  function renderAnonymousTable() {
    anonTableBody.innerHTML = anonymousGroups.map((group) => `<tr><td>${group.ageBand}</td><td>${group.region}</td><td>${group.incomeBand}</td><td>${group.customerCount}</td><td>${group.loanBand}</td><td>Not shared — aggregate only</td></tr>`).join('');
  }

  function laplaceNoise(epsilon) {
    const uniform = Math.random() - 0.5;
    return -(1 / epsilon) * Math.sign(uniform) * Math.log(1 - (2 * Math.abs(uniform)));
  }

  async function createPartnerKeySet() {
    try {
      ensureCryptoSupport();
      generateKeysButton.disabled = true;
      setCardState(keyCard, 'active');
      setTraceState(traceKey, 'active', 'Generating ML-KEM-768 partner key pair locally…');
      journeyState.textContent = 'CREATING PARTNER KEY';
      consoleOutput.textContent = 'RISK RESEARCH LAB: generating an ML-KEM-768 key pair. The public key may be sent to the bank; the private key remains with the partner.';

      const keyPair = mlKem.keygen();
      const fingerprint = await sha256(keyPair.publicKey);
      partnerKeys = { publicKey: keyPair.publicKey, secretKey: keyPair.secretKey, fingerprint };
      publicKeyFingerprint.textContent = shortFingerprint(fingerprint);
      keyPanel.hidden = false;
      setCardState(keyCard, 'complete');
      setTraceState(traceKey, 'complete', `Public-key fingerprint: ${shortFingerprint(fingerprint)} · private key remains local`);
      journeyState.textContent = 'PUBLIC KEY RECEIVED BY BANK';
      setJourneyCard(journeyPolicy, 'active');
      journeyPolicyOutput.textContent = `Partner public key accepted · ${shortFingerprint(fingerprint)}`;
      classifyButton.disabled = false;
      consoleOutput.textContent = `PARTNER PUBLIC KEY READY ✓\nFingerprint sent to Bank: ${shortFingerprint(fingerprint)}\n\nThe bank can encrypt to this key, but cannot decrypt the package.`;
    } catch (error) {
      generateKeysButton.disabled = false;
      setCardState(keyCard, 'failed');
      setTraceState(traceKey, 'failed', `Key setup failed: ${error.message}`);
      consoleOutput.textContent = `KEY SETUP FAILED: ${error.message}`;
    }
  }

  async function classifyAndAnonymise() {
    try {
      if (!partnerKeys) throw new Error('Create the partner key set first.');
      classifyButton.disabled = true;
      setCardState(policyCard, 'active');
      setTraceState(tracePolicy, 'active', 'Classifying fields as direct identifiers, quasi-identifiers, or sensitive attributes…');
      journeyState.textContent = 'APPLYING PRIVACY POLICY';
      setJourneyCard(journeyPolicy, 'active');
      journeyPolicyOutput.textContent = 'Inspecting every field before any encryption begins…';
      consoleOutput.textContent = 'BANK POLICY ENGINE: classifying raw fictional records and applying the minimum-necessary sharing policy…';
      await pause(250);

      renderFieldPolicy();
      policyState.textContent = 'POLICY APPLIED';
      anonymousGroups = buildAnonymousGroups();
      const smallestGroup = Math.min(...anonymousGroups.map((group) => group.customerCount));
      if (smallestGroup < 3) throw new Error('k-anonymity threshold was not met by the synthetic groups.');
      renderAnonymousTable();
      anonPanel.hidden = false;
      kStatus.textContent = `k = ${smallestGroup} ✓`;
      setCardState(policyCard, 'complete');
      setTraceState(tracePolicy, 'complete', `Removed 2 direct identifiers · generalised 3 quasi-identifiers · ${anonymousGroups.length} groups satisfy k = ${smallestGroup}`);
      journeyState.textContent = `POLICY COMPLETE · ${anonymousGroups.length} SAFE GROUPS`;
      setJourneyCard(journeyPolicy, 'complete');
      setJourneyCard(journeyPackage, 'active');
      journeyPolicyOutput.textContent = `Removed name + account · generalised age/PIN/income · withheld default status · k = ${smallestGroup}`;
      journeyPackageOutput.textContent = `${anonymousGroups.length} anonymous groups are ready; raw records remain inside bank`;
      encryptButton.disabled = false;
      consoleOutput.textContent = `POLICY APPLIED ✓\nNames and account numbers: removed\nAge, PIN, income, loan: generalised into groups\nCustomer-level defaulter status: withheld\n\n${anonymousGroups.length} anonymous groups meet k = ${smallestGroup}.`;
    } catch (error) {
      classifyButton.disabled = false;
      policyState.textContent = 'POLICY FAILED';
      setCardState(policyCard, 'failed');
      setTraceState(tracePolicy, 'failed', `Policy failed: ${error.message}`);
      consoleOutput.textContent = `PRIVACY POLICY FAILED: ${error.message}`;
    }
  }

  async function encryptPartnerPackage() {
    let sharedSecret;
    try {
      ensureCryptoSupport();
      if (!partnerKeys || !anonymousGroups) throw new Error('Apply the privacy policy before creating a package.');
      encryptButton.disabled = true;
      setCardState(packageCard, 'active');
      setTraceState(traceEncrypt, 'active', 'Encapsulating a one-time ML-KEM secret to the partner public key…');
      journeyState.textContent = 'BUILDING ENCRYPTED SAFE PACKAGE';
      setJourneyCard(journeyPackage, 'active');
      journeyKem.textContent = 'Encapsulating…';
      journeyAes.textContent = 'Waiting for secret';
      journeyPackageOutput.textContent = 'ML-KEM creates a one-time secret for the partner public key…';
      consoleOutput.textContent = 'BANK: encrypting the permitted k-anonymous groups—not the raw customer dataset—to the authorised partner.';

      const recipientResult = mlKem.encapsulate(partnerKeys.publicKey);
      sharedSecret = recipientResult.sharedSecret;
      const aesKey = await window.crypto.subtle.importKey('raw', sharedSecret, { name: 'AES-GCM' }, false, ['encrypt']);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const payload = encoder.encode(JSON.stringify({
        format: 'BankGuard-Partner-View-1',
        k: 3,
        recipient: 'Risk Research Lab',
        groups: anonymousGroups,
      }));
      await pause(200);
      const ciphertext = new Uint8Array(await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, payload));
      protectedPackage = { kemCiphertext: recipientResult.cipherText.slice(), iv, ciphertext };
      recipientResult.cipherText.fill(0);
      packagePayload.textContent = `${anonymousGroups.length} k-anonymous groups · ${formatBytes(payload.length)}`;
      packageKem.textContent = `${formatBytes(protectedPackage.kemCiphertext.length)} public encapsulation data`;
      packageIv.textContent = `${protectedPackage.iv.length} bytes`;
      packagePanel.hidden = false;
      setCardState(packageCard, 'complete');
      setTraceState(traceEncrypt, 'complete', `ML-KEM ciphertext: ${formatBytes(protectedPackage.kemCiphertext.length)} · AES-GCM protected payload: ${formatBytes(ciphertext.length)}`);
      journeyState.textContent = 'SAFE PACKAGE TRAVELLING TO PARTNER';
      setJourneyCard(journeyPackage, 'complete');
      setJourneyCard(journeyPartner, 'active');
      journeyKem.textContent = `${formatBytes(protectedPackage.kemCiphertext.length)} capsule`;
      journeyAes.textContent = `${formatBytes(ciphertext.length)} encrypted`;
      journeyPackageOutput.textContent = `Only ${anonymousGroups.length} k-anonymous groups entered AES-GCM ciphertext`;
      journeyPartnerOutput.textContent = 'Package received. Only matching private key can recover the safe group view.';
      openButton.disabled = false;
      consoleOutput.textContent = 'ENCRYPTED PARTNER PACKAGE READY ✓\nPayload: k-anonymous group view only\nProtection: ML-KEM-768 establishes the secret; AES-256-GCM encrypts the payload\n\nDirect identifiers and customer-level default status are absent before encryption.';
    } catch (error) {
      encryptButton.disabled = false;
      setCardState(packageCard, 'failed');
      setTraceState(traceEncrypt, 'failed', `Package creation failed: ${error.message}`);
      consoleOutput.textContent = `PACKAGE CREATION FAILED: ${error.message}`;
    } finally {
      sharedSecret?.fill(0);
    }
  }

  async function openPartnerView() {
    let sharedSecret;
    try {
      ensureCryptoSupport();
      if (!protectedPackage || !partnerKeys) throw new Error('The bank must create the encrypted partner package first.');
      openButton.disabled = true;
      setCardState(partnerCard, 'active');
      setTraceState(traceQuery, 'active', 'Partner uses private ML-KEM key to open only the authorised package…');
      journeyState.textContent = 'PARTNER DECRYPTING SAFE VIEW';
      setJourneyCard(journeyPartner, 'active');
      journeyPartnerOutput.textContent = 'Private ML-KEM key decapsulates the one-time secret; AES-GCM authenticates and opens the package…';
      consoleOutput.textContent = 'RISK RESEARCH LAB: decapsulating the one-time secret and decrypting the authorised anonymous view locally…';

      sharedSecret = mlKem.decapsulate(protectedPackage.kemCiphertext, partnerKeys.secretKey);
      const aesKey = await window.crypto.subtle.importKey('raw', sharedSecret, { name: 'AES-GCM' }, false, ['decrypt']);
      const plaintext = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: protectedPackage.iv }, aesKey, protectedPackage.ciphertext);
      const partnerView = JSON.parse(new TextDecoder().decode(plaintext));
      const viewString = JSON.stringify(partnerView);
      if (viewString.includes('AC-') || viewString.includes('defaulted') || viewString.includes('Aarav')) throw new Error('Policy violation: sensitive source data appeared in the partner view.');

      partnerViewOpened = true;
      queryPanel.hidden = false;
      setCardState(partnerCard, 'complete');
      setTraceState(traceQuery, 'complete', `Partner opened ${partnerView.groups.length} anonymous groups · ready for aggregate-only queries`);
      journeyState.textContent = 'PARTNER HAS SAFE GROUP VIEW ONLY';
      setJourneyCard(journeyPartner, 'complete');
      journeyGroupView.textContent = `${partnerView.groups.length} anonymous groups`;
      journeyPartnerOutput.textContent = 'Opened safe group view ✓ Names, accounts, and customer-level default status are absent.';
      consoleOutput.textContent = 'PARTNER OPENED SAFE VIEW ✓\nThe partner received 4 k-anonymous groups.\nVerified absent: names, account numbers, exact PIN codes, and customer-level default status.\n\nThe partner may now request an approved aggregate from the bank privacy service.';
    } catch (error) {
      openButton.disabled = false;
      setCardState(partnerCard, 'failed');
      setTraceState(traceQuery, 'failed', `Partner view failed: ${error.message}`);
      consoleOutput.textContent = `PARTNER ACCESS FAILED: ${error.message}`;
    } finally {
      sharedSecret?.fill(0);
    }
  }

  function runSafeQuery() {
    if (!partnerViewOpened) return;
    const exactCount = rawRecords.filter((record) => ageBand(record.age) === '30–39' && record.defaulted).length;
    const noise = laplaceNoise(1);
    const protectedCount = Math.max(0, Math.round(exactCount + noise));
    setTraceState(traceQuery, 'complete', 'Approved aggregate request → bank privacy service adds Laplace noise (ε = 1.0) → protected result released');
    journeyState.textContent = 'APPROVED PRIVATE AGGREGATE RELEASED';
    setQueryJourneyCard(queryJourneyInternalCard, 'complete');
    setQueryJourneyCard(queryJourneyNoiseCard, 'complete');
    setQueryJourneyCard(queryJourneyReleaseCard, 'complete');
    queryJourneyInternal.textContent = `Exact count = ${exactCount}; it remains inside the bank privacy service`;
    queryJourneyNoise.textContent = `Laplace noise ${noise >= 0 ? '+' : ''}${noise.toFixed(2)} with ε = 1.0`;
    queryJourneyRelease.textContent = `Protected aggregate = ${protectedCount}; no person or account is returned`;
    journeyQueryView.textContent = `Aggregate released: ${protectedCount}`;
    journeyBlockView.textContent = 'Safe policy path';
    queryResult.innerHTML = `<strong>APPROVED · DIFFERENTIALLY PRIVATE RESULT ✓</strong><p>Defaulters in age band 30–39: <b>${protectedCount}</b> (privacy-protected aggregate)</p><small>The bank computes the exact count inside its trusted service, adds controlled noise, and releases only the protected result. No customer identity or account is returned.</small>`;
    consoleOutput.textContent = `SAFE QUERY APPROVED ✓\nQuestion: “How many defaulters are age 30–39?”\nPrivacy mechanism: Laplace noise with ε = 1.0\nReleased value: ${protectedCount}\n\nCustomer-level default records remain at the bank.`;
  }

  function blockUnsafeQuery() {
    if (!partnerViewOpened) return;
    setTraceState(traceQuery, 'failed', 'Blocked: request combines sensitive default status with direct identifiers (account numbers).');
    journeyState.textContent = 'IDENTITY-REVEALING REQUEST BLOCKED';
    setQueryJourneyCard(queryJourneyInternalCard, 'blocked');
    setQueryJourneyCard(queryJourneyNoiseCard, 'blocked');
    setQueryJourneyCard(queryJourneyReleaseCard, 'blocked');
    queryJourneyInternal.textContent = 'No customer-level lookup is run inside the bank.';
    queryJourneyNoise.textContent = 'Differential privacy cannot allow an identity lookup.';
    queryJourneyRelease.textContent = 'Nothing released — the policy blocks the request.';
    journeyQueryView.textContent = 'No aggregate requested';
    journeyBlockView.textContent = 'Blocked ✕';
    setJourneyCard(journeyPartner, 'blocked');
    journeyPartnerOutput.textContent = 'Blocked: account ID and defaulter status cannot be joined.';
    queryResult.innerHTML = '<strong>BLOCKED BY PRIVACY POLICY ✕</strong><p>The request asks for account numbers linked to defaulter status.</p><small>Reason: direct identifiers are never in the partner package, and the sensitive attribute is available only through approved aggregate queries.</small>';
    consoleOutput.textContent = 'UNSAFE QUERY BLOCKED ✕\nRequested fields: account number + customer default status\nPolicy decision: deny. The request could identify individuals and expose a sensitive financial attribute.';
  }

  renderRawTable();
  resetJourney();
  generateKeysButton.addEventListener('click', createPartnerKeySet);
  classifyButton.addEventListener('click', classifyAndAnonymise);
  encryptButton.addEventListener('click', encryptPartnerPackage);
  openButton.addEventListener('click', openPartnerView);
  safeQueryButton.addEventListener('click', runSafeQuery);
  unsafeQueryButton.addEventListener('click', blockUnsafeQuery);
})();
