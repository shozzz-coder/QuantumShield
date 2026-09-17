(() => {
  const originalCanvas = document.querySelector('#medicalOriginalCanvas');
  const attackCanvas = document.querySelector('#medicalAttackCanvas');
  const originalState = document.querySelector('#medicalOriginalState');
  const attackState = document.querySelector('#medicalAttackState');
  const originalHashOutput = document.querySelector('#medicalOriginalHash');
  const attackHashOutput = document.querySelector('#medicalAttackHash');
  const originalNote = document.querySelector('#medicalOriginalNote');
  const attackNote = document.querySelector('#medicalAttackNote');
  const latentStateOutput = document.querySelector('#medicalLatentState');
  const discriminatorScoreOutput = document.querySelector('#medicalDiscriminatorScore');
  const signButton = document.querySelector('#medicalSignButton');
  const generatorButton = document.querySelector('#medicalGeneratorButton');
  const discriminatorButton = document.querySelector('#medicalDiscriminatorButton');
  const verifyButton = document.querySelector('#medicalVerifyButton');
  const resetButton = document.querySelector('#medicalResetButton');
  const consoleOutput = document.querySelector('#medicalConsole');
  const signCard = document.querySelector('#medicalSignCard');
  const generatorCard = document.querySelector('#medicalGeneratorCard');
  const discriminatorCard = document.querySelector('#medicalDiscriminatorCard');
  const verifyCard = document.querySelector('#medicalVerifyCard');
  const attackRecord = document.querySelector('#medicalAttackRecord');
  const traceHash = document.querySelector('#medicalTraceHash');
  const traceSignature = document.querySelector('#medicalTraceSignature');
  const traceGenerator = document.querySelector('#medicalTraceGenerator');
  const traceDiscriminator = document.querySelector('#medicalTraceDiscriminator');
  const traceVerify = document.querySelector('#medicalTraceVerify');
  const traceHashValue = document.querySelector('#medicalTraceHashValue');
  const traceSignatureValue = document.querySelector('#medicalTraceSignatureValue');
  const traceGeneratorValue = document.querySelector('#medicalTraceGeneratorValue');
  const traceDiscriminatorValue = document.querySelector('#medicalTraceDiscriminatorValue');
  const traceVerifyValue = document.querySelector('#medicalTraceVerifyValue');

  const encoder = new TextEncoder();
  const REFERENCE_IMAGE_PATH = 'assets/professor-supplied-mri-reference.png';
  // SHA-256 of the supplied MRI asset. Keeping this canonical value avoids
  // Chrome's file:// canvas-security restriction while still binding the
  // signed manifest to this exact reference asset.
  const REFERENCE_ASSET_SHA256 = 'd12f3871028577b987dea7aef9d63811ba8a04b480d6df3661c2c36094387d9c';
  const ORIGINAL_NOTE = 'Demo review: pending';
  const ALTERED_NOTE = 'Demo review: cleared';
  let signingKeyPair;
  let originalSignature;
  let generatedManifest;
  let generatorState;
  let discriminatorResult;
  let referenceImage;
  let referenceImageReady = typeof Image === 'undefined';
  let referenceImageStatus = referenceImageReady ? 'fallback' : 'loading';

  function toHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  function shortFingerprint(value) {
    return value.match(/.{1,8}/g).slice(0, 4).join(' · ');
  }

  async function sha256(bytes) {
    const digest = await window.crypto.subtle.digest('SHA-256', bytes);
    return toHex(new Uint8Array(digest));
  }

  function pause(milliseconds) {
    return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
  }

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    if (window.crypto?.getRandomValues) window.crypto.getRandomValues(bytes);
    else for (let index = 0; index < length; index += 1) bytes[index] = (index * 53 + 71) % 256;
    return bytes;
  }

  function drawFallbackReference(canvas) {
    const context = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    context.clearRect(0, 0, width, height);
    context.fillStyle = '#030914';
    context.fillRect(0, 0, width, height);
    const haze = context.createRadialGradient(width / 2, height / 2, 22, width / 2, height / 2, 240);
    haze.addColorStop(0, '#d7e2e8');
    haze.addColorStop(0.36, '#91a3b0');
    haze.addColorStop(0.72, '#3f5264');
    haze.addColorStop(1, '#101d2c');
    context.fillStyle = haze;
    context.beginPath();
    context.ellipse(width / 2, height / 2, 174, 146, 0, 0, Math.PI * 2);
    context.fill();
    context.strokeStyle = 'rgba(4, 15, 28, 0.52)';
    context.lineWidth = 7;
    context.beginPath();
    context.ellipse(width / 2, height / 2, 142, 118, 0, 0, Math.PI * 2);
    context.stroke();
    context.lineWidth = 3;
    context.beginPath();
    context.moveTo(width / 2, 76);
    context.bezierCurveTo(width / 2 - 28, 140, width / 2 - 22, 236, width / 2, 308);
    context.bezierCurveTo(width / 2 + 22, 236, width / 2 + 28, 140, width / 2, 76);
    context.stroke();
  }

  function drawMRIHeader(context, canvas, label) {
    context.fillStyle = 'rgba(108, 231, 242, 0.88)';
    context.font = '600 14px DM Mono, monospace';
    context.fillText(label, 20, 30);
    context.fillStyle = 'rgba(212, 226, 239, 0.68)';
    context.font = '500 11px DM Mono, monospace';
    context.fillText('MED-DEMO-2048  |  Hospital North  |  NOT DIAGNOSTIC', 20, canvas.height - 18);
  }

  function drawReferenceMRI(canvas) {
    const context = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    context.clearRect(0, 0, width, height);
    context.fillStyle = '#030914';
    context.fillRect(0, 0, width, height);
    if (referenceImageReady && referenceImage && typeof context.drawImage === 'function') {
      const paddingX = 115;
      const paddingY = 20;
      const scale = Math.min((width - paddingX * 2) / referenceImage.width, (height - paddingY * 2) / referenceImage.height);
      const imageWidth = referenceImage.width * scale;
      const imageHeight = referenceImage.height * scale;
      const x = (width - imageWidth) / 2;
      const y = (height - imageHeight) / 2;
      context.drawImage(referenceImage, x, y, imageWidth, imageHeight);
      context.strokeStyle = 'rgba(159, 207, 226, 0.22)';
      context.lineWidth = 1;
      context.strokeRect(x, y, imageWidth, imageHeight);
    } else {
      drawFallbackReference(canvas);
    }
    drawMRIHeader(context, canvas, 'REFERENCE MRI · PROJECT-SUPPLIED');
  }

  function createGeneratorState() {
    const seed = randomBytes(7);
    const components = Array.from(seed.slice(0, 4), (byte) => ((byte / 127.5) - 1).toFixed(2));
    return {
      seed,
      latentLabel: '|ψ⟩ = [' + components.join(', ') + ']',
      x: 360 + (seed[0] % 120),
      y: 145 + (seed[1] % 115),
      radiusX: 29 + (seed[2] % 18),
      radiusY: 22 + (seed[3] % 16),
      rotation: ((seed[4] % 70) - 35) * (Math.PI / 180),
      intensity: 0.74 + ((seed[5] % 20) / 100),
      seedHint: seed[6].toString(16).padStart(2, '0'),
    };
  }

  function drawSyntheticCandidate(canvas, state) {
    drawReferenceMRI(canvas);
    const context = canvas.getContext('2d');
    const glow = context.createRadialGradient(state.x, state.y, 3, state.x, state.y, state.radiusX + 14);
    glow.addColorStop(0, 'rgba(255, 246, 248, ' + state.intensity + ')');
    glow.addColorStop(0.34, 'rgba(239, 114, 142, ' + state.intensity + ')');
    glow.addColorStop(0.72, 'rgba(137, 34, 68, 0.32)');
    glow.addColorStop(1, 'rgba(137, 34, 68, 0)');
    context.fillStyle = glow;
    context.beginPath();
    context.ellipse(state.x, state.y, state.radiusX + 13, state.radiusY + 13, state.rotation, 0, Math.PI * 2);
    context.fill();
    context.fillStyle = 'rgba(255, 170, 183, 0.4)';
    context.beginPath();
    context.ellipse(state.x, state.y, state.radiusX, state.radiusY, state.rotation, 0, Math.PI * 2);
    context.fill();
    context.strokeStyle = '#ff9cac';
    context.setLineDash([6, 5]);
    context.lineWidth = 2;
    context.strokeRect(state.x - state.radiusX - 12, state.y - state.radiusY - 12, (state.radiusX + 12) * 2, (state.radiusY + 12) * 2);
    context.setLineDash([]);
    context.fillStyle = '#ffc1c9';
    context.font = '600 12px DM Mono, monospace';
    context.fillText('G(|ψ⟩) · SYNTHETIC REGION', Math.max(22, state.x - state.radiusX - 18), Math.min(canvas.height - 40, state.y + state.radiusY + 35));
    context.fillStyle = 'rgba(222, 181, 255, 0.96)';
    context.font = '600 14px DM Mono, monospace';
    context.fillText('Q-GAN CANDIDATE · SIMULATED', 20, 30);
  }

  async function createManifest(careNote, candidateState) {
    const imageHash = candidateState
      ? await sha256(encoder.encode(JSON.stringify({
        referenceAssetSha256: REFERENCE_ASSET_SHA256,
        generatorSeed: Array.from(candidateState.seed),
        region: [candidateState.x, candidateState.y, candidateState.radiusX, candidateState.radiusY, candidateState.rotation, candidateState.intensity],
        careNote,
      })))
      : REFERENCE_ASSET_SHA256;
    const manifest = {
      recordId: 'MED-DEMO-2048',
      patient: 'Demo subject — non-diagnostic',
      organisation: 'Hospital North',
      modality: 'Project-supplied MRI reference image — not for clinical use',
      careNote,
      imageSha256: imageHash,
    };
    return { bytes: encoder.encode(JSON.stringify(manifest)), imageHash };
  }

  function setCardState(card, state) {
    card.classList.remove('active', 'complete', 'failed');
    if (state) card.classList.add(state);
  }

  function setTraceState(card, valueOutput, state, value) {
    card.classList.remove('active', 'complete', 'failed');
    if (state) card.classList.add(state);
    valueOutput.textContent = value;
  }

  function scoreCandidate() {
    const changedArea = generatorState
      ? (Math.PI * generatorState.radiusX * generatorState.radiusY) / (attackCanvas.width * attackCanvas.height)
      : 0.01;
    const latentContribution = generatorState ? (generatorState.seed[0] % 12) / 100 : 0.05;
    const visualChangeIndex = generatorState
      ? Math.min(1, changedArea * generatorState.intensity * 12)
      : 0.01;
    const score = Math.min(0.97, 0.70 + Math.min(0.17, visualChangeIndex) + latentContribution);
    return { probability: score, visualChangeIndex };
  }

  function resetLab() {
    signingKeyPair = undefined;
    originalSignature = undefined;
    generatedManifest = undefined;
    generatorState = undefined;
    discriminatorResult = undefined;
    drawReferenceMRI(originalCanvas);
    drawReferenceMRI(attackCanvas);
    originalState.textContent = referenceImageReady ? 'READY' : 'LOADING';
    originalState.className = 'record-state';
    attackState.textContent = 'WAITING';
    attackState.className = 'record-state danger-state';
    originalHashOutput.textContent = 'Waiting for signature';
    attackHashOutput.textContent = 'Waiting for generator';
    originalNote.textContent = ORIGINAL_NOTE;
    attackNote.textContent = 'No generated candidate';
    latentStateOutput.textContent = 'Waiting for generator';
    discriminatorScoreOutput.textContent = 'Not evaluated';
    signButton.disabled = !referenceImageReady;
    generatorButton.disabled = true;
    discriminatorButton.disabled = true;
    verifyButton.disabled = true;
    setCardState(signCard);
    setCardState(generatorCard);
    setCardState(discriminatorCard);
    setCardState(verifyCard);
    attackRecord.classList.remove('attack-active');
    setTraceState(traceHash, traceHashValue, '', 'Waiting for original record');
    setTraceState(traceSignature, traceSignatureValue, '', 'Waiting for hospital signature');
    setTraceState(traceGenerator, traceGeneratorValue, '', 'Waiting for generator');
    setTraceState(traceDiscriminator, traceDiscriminatorValue, '', 'Waiting for discriminator');
    setTraceState(traceVerify, traceVerifyValue, '', 'Waiting for received record');
    consoleOutput.textContent = referenceImageReady
      ? 'Ready. Sign the project-supplied reference MRI record to begin.'
      : 'Loading the project-supplied MRI reference image…';
  }

  async function signOriginalRecord() {
    try {
      if (!window.crypto?.subtle) throw new Error('Web Crypto is unavailable. Open the deployed HTTPS site in Chrome.');
      if (!referenceImageReady) throw new Error('The MRI reference image is still loading. Please wait a moment and try again.');
      signButton.disabled = true;
      setCardState(signCard, 'active');
      setTraceState(traceHash, traceHashValue, 'active', 'Loading the canonical supplied-MRI fingerprint + demo metadata → SHA-256…');
      consoleOutput.textContent = 'HOSPITAL NORTH: calculating the reference MRI fingerprint and signing its exact record manifest…';
      const originalManifest = await createManifest(ORIGINAL_NOTE);
      setTraceState(traceHash, traceHashValue, 'complete', 'SHA-256: ' + shortFingerprint(originalManifest.imageHash));
      setTraceState(traceSignature, traceSignatureValue, 'active', 'Signing the exact original manifest with hospital demo key…');
      await pause(180);
      signingKeyPair = await window.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      originalSignature = await window.crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKeyPair.privateKey, originalManifest.bytes);
      const publicKeyBytes = await window.crypto.subtle.exportKey('spki', signingKeyPair.publicKey);
      const signerFingerprint = await sha256(publicKeyBytes);
      originalHashOutput.textContent = shortFingerprint(originalManifest.imageHash);
      originalState.textContent = 'SIGNED ✓';
      originalState.className = 'record-state verified-state';
      setCardState(signCard, 'complete');
      setTraceState(traceSignature, traceSignatureValue, 'complete', 'Signature locked to original hash · signer key: ' + shortFingerprint(signerFingerprint));
      generatorButton.disabled = false;
      consoleOutput.textContent = 'SIGNATURE CREATED ✓\nReference asset SHA-256: ' + shortFingerprint(originalManifest.imageHash) + '\nHospital demo signing-key fingerprint: ' + shortFingerprint(signerFingerprint) + '\n\nThe signed manifest binds the supplied MRI asset fingerprint and demo metadata together.';
    } catch (error) {
      signButton.disabled = false;
      setCardState(signCard, 'failed');
      consoleOutput.textContent = 'SIGNING FAILED: ' + error.message;
    }
  }

  async function runGeneratorPrototype() {
    try {
      if (!originalSignature || !signingKeyPair) throw new Error('Sign the reference record first.');
      generatorButton.disabled = true;
      setCardState(generatorCard, 'active');
      setTraceState(traceGenerator, traceGeneratorValue, 'active', '1/3 Sampling a simulated quantum latent state |ψ⟩…');
      consoleOutput.textContent = 'Q-GAN GENERATOR PROTOTYPE: sampling a simulated latent state and composing a synthetic candidate…';
      await pause(180);
      generatorState = createGeneratorState();
      latentStateOutput.textContent = generatorState.latentLabel;
      setTraceState(traceGenerator, traceGeneratorValue, 'active', '2/3 Latent sample: ' + generatorState.latentLabel + ' · seed ' + generatorState.seedHint);
      await pause(180);
      drawSyntheticCandidate(attackCanvas, generatorState);
      generatedManifest = await createManifest(ALTERED_NOTE, generatorState);
      attackHashOutput.textContent = shortFingerprint(generatedManifest.imageHash);
      attackNote.textContent = ALTERED_NOTE;
      attackState.textContent = 'GENERATED ⚠';
      attackState.className = 'record-state danger-state altered-state';
      attackRecord.classList.add('attack-active');
      setCardState(generatorCard, 'complete');
      setTraceState(traceGenerator, traceGeneratorValue, 'complete', '3/3 G(|ψ⟩) composed candidate pixels · SHA-256: ' + shortFingerprint(generatedManifest.imageHash));
      discriminatorButton.disabled = false;
      consoleOutput.textContent = 'GENERATOR OUTPUT CREATED ⚠\nLatent state: ' + generatorState.latentLabel + '\nCandidate SHA-256: ' + shortFingerprint(generatedManifest.imageHash) + '\n\nThis is a visual Q-GAN workflow prototype, not the output of a trained medical Q-GAN.';
    } catch (error) {
      generatorButton.disabled = false;
      setCardState(generatorCard, 'failed');
      consoleOutput.textContent = 'GENERATOR FAILED: ' + error.message;
    }
  }

  async function runDiscriminatorPrototype() {
    try {
      if (!generatedManifest || !generatorState) throw new Error('Run the generator first.');
      discriminatorButton.disabled = true;
      setCardState(discriminatorCard, 'active');
      setTraceState(traceDiscriminator, traceDiscriminatorValue, 'active', 'Scoring the generator-controlled changed region and latent sample…');
      consoleOutput.textContent = 'DISCRIMINATOR PROTOTYPE: scoring the Q-GAN candidate against the signed reference image…';
      await pause(220);
      discriminatorResult = scoreCandidate();
      const percentage = Math.round(discriminatorResult.probability * 100);
      discriminatorScoreOutput.textContent = percentage + '% likely synthetic';
      attackState.textContent = 'LIKELY SYNTHETIC';
      attackState.className = 'record-state danger-state altered-state';
      setCardState(discriminatorCard, 'complete');
      setTraceState(traceDiscriminator, traceDiscriminatorValue, 'complete', 'D(candidate) = ' + percentage + '% synthetic likelihood · visual change index ' + discriminatorResult.visualChangeIndex.toFixed(3));
      verifyButton.disabled = false;
      consoleOutput.textContent = 'DISCRIMINATOR RESULT: LIKELY SYNTHETIC (' + percentage + '%)\nPrototype feature: generator-controlled visual-change index = ' + discriminatorResult.visualChangeIndex.toFixed(3) + '\n\nThis score illustrates the discriminator role. It is not a trained clinical classifier and is not the final security decision.';
    } catch (error) {
      discriminatorButton.disabled = false;
      setCardState(discriminatorCard, 'failed');
      consoleOutput.textContent = 'DISCRIMINATOR FAILED: ' + error.message;
    }
  }

  async function verifyGeneratedRecord() {
    try {
      if (!generatedManifest || !originalSignature || !signingKeyPair || !discriminatorResult) throw new Error('Create and score the generated candidate first.');
      verifyButton.disabled = true;
      setCardState(verifyCard, 'active');
      setTraceState(traceVerify, traceVerifyValue, 'active', 'Verifying original hospital signature against the candidate record manifest…');
      consoleOutput.textContent = 'VERIFYING: checking Hospital North’s original signature against the generated record candidate…';
      await pause(220);
      const valid = await window.crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, signingKeyPair.publicKey, originalSignature, generatedManifest.bytes);
      if (valid) {
        setCardState(verifyCard, 'failed');
        setTraceState(traceVerify, traceVerifyValue, 'failed', 'Unexpected verification success — reset the lab.');
        consoleOutput.textContent = 'UNEXPECTED RESULT: the generated candidate verified. Reset the lab and try again.';
        return;
      }
      setCardState(verifyCard, 'complete');
      setTraceState(traceVerify, traceVerifyValue, 'complete', 'REJECTED: candidate hash ' + shortFingerprint(generatedManifest.imageHash) + ' does not match signed reference');
      consoleOutput.textContent = 'RECORD REJECTED ✓\nThe Q-GAN candidate failed signature verification because its image fingerprint and demo metadata no longer match Hospital North’s original signed manifest.\n\nSecurity decision: do not display, file, or act on this candidate. The cryptographic signature—not visual appearance or the discriminator score—makes this final decision.';
    } catch (error) {
      setCardState(verifyCard, 'failed');
      consoleOutput.textContent = 'VERIFICATION FAILED: ' + error.message;
    } finally {
      verifyButton.disabled = false;
    }
  }

  function preloadReferenceMRI() {
    if (typeof Image === 'undefined') return Promise.resolve();
    return new Promise((resolve) => {
      referenceImage = new Image();
      referenceImage.onload = () => {
        referenceImageReady = true;
        referenceImageStatus = 'loaded';
        resolve();
      };
      referenceImage.onerror = () => {
        referenceImageReady = true;
        referenceImageStatus = 'fallback';
        resolve();
      };
      referenceImage.src = REFERENCE_IMAGE_PATH;
    });
  }

  signButton.addEventListener('click', signOriginalRecord);
  generatorButton.addEventListener('click', runGeneratorPrototype);
  discriminatorButton.addEventListener('click', runDiscriminatorPrototype);
  verifyButton.addEventListener('click', verifyGeneratedRecord);
  resetButton.addEventListener('click', resetLab);
  resetLab();
  preloadReferenceMRI().then(() => {
    resetLab();
    if (referenceImageStatus === 'fallback' && typeof Image !== 'undefined') {
      consoleOutput.textContent = 'The supplied MRI could not be loaded, so the lab is using a visual fallback. Check the assets folder before deployment.';
    }
  });
})();
