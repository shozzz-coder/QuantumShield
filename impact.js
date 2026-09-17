const sectorSelect = document.querySelector('#sector-select');
const scaleSelect = document.querySelector('#scale-select');
const lifetimeSelect = document.querySelector('#lifetime-select');
const buildPlanButton = document.querySelector('#build-plan');
const planResult = document.querySelector('#plan-result');

const sectors = {
  bank: { name: 'banking and payments', assets: 'public payment endpoints, remote access, transaction APIs, and long-retention records', pilot: 'one non-critical customer or partner API path' },
  government: { name: 'government and public services', assets: 'identity systems, archived records, government-to-government links, and supplier access', pilot: 'one inter-agency service with a controlled set of users' },
  health: { name: 'healthcare and research', assets: 'patient archives, research-transfer channels, and medical-device update services', pilot: 'one research-transfer or internal clinical application' },
  infra: { name: 'telecom and critical infrastructure', assets: 'VPN gateways, management networks, firmware signing, and supplier connections', pilot: 'one managed gateway or staging network' }
};

const scales = {
  team: 'Name one accountable owner, create a single inventory template, and use the pilot to establish a repeatable playbook.',
  national: 'Set a shared baseline for agencies, fund a central inventory service, and require PQC readiness in new procurement contracts.',
  network: 'Publish a supplier transition profile, test interoperability with a small partner cohort, and make compliance measurable at renewal time.'
};

function buildPlan() {
  const sector = sectors[sectorSelect.value];
  const lifetime = lifetimeSelect.value;
  const urgency = lifetime === 'long' ? 'High priority: data captured now may still be valuable when future quantum capability becomes relevant.' : lifetime === 'medium' ? 'Elevated priority: schedule the transition alongside the next planned platform upgrades.' : 'Planning priority: begin the inventory now, then align migration with regular upgrade cycles.';

  planResult.innerHTML = `
    <p class="plan-label">YOUR STARTING PLAN</p>
    <h3>${sector.name.charAt(0).toUpperCase() + sector.name.slice(1)}</h3>
    <p class="plan-risk">${urgency}</p>
    <ol>
      <li><strong>First 30 days:</strong> inventory ${sector.assets}. Record the algorithm, certificate, owner, vendor, data lifetime, and upgrade dependency—never the secret keys.</li>
      <li><strong>Days 31–60:</strong> choose ${sector.pilot}. Test a standards-based hybrid post-quantum key-establishment configuration alongside your existing setup.</li>
      <li><strong>Days 61–90:</strong> measure performance, document operational changes, and turn the pilot into a centrally approved migration pattern.</li>
      <li><strong>Scale affordably:</strong> ${scales[scaleSelect.value]}</li>
    </ol>
    <p class="plan-footnote">Recommendation: make ML-KEM-based post-quantum cryptography the software baseline. Reserve QKD for exceptional dedicated links with a clear physical-security case.</p>`;
  planResult.classList.add('is-visible');
}

buildPlanButton.addEventListener('click', buildPlan);
