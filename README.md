# BlindAudit

**Verifying dataset properties without exposing dataset contents.**

BlindAudit is a protocol for proving that training datasets meet compliance requirements (no PII, no unlicensed copyrighted content, no unsafe material) without revealing the actual data to auditors.

## The Problem

AI labs training frontier models face a dilemma:

- **Regulators and insurers** want proof that training data is clean — free of PII, copyrighted content, CSAM, biased data, or other problematic material
- **Labs** can't reveal their datasets — they contain proprietary data, trade secrets, or are simply too large to share

Current options are unsatisfying: either trust the lab's self-attestation, or require full dataset disclosure. BlindAudit enables a middle path.

## Our Approach

BlindAudit combines two mechanisms for different portions of the dataset:

### For data from public/approved sources

**Zero-knowledge set membership proofs** demonstrate that data items come from pre-approved source datasets without revealing *which* approved sources were used or in what proportions.

```
Lab proves: "Every item in our dataset exists in at least one approved source"
Lab hides: Which sources, which items, what proportions
```

### For proprietary/private data

**Challenge-based auditing in a trusted execution environment (TEE)** allows auditors to run detection scripts on the data without seeing it directly.

```
1. Auditor submits a detection script (e.g., PII detector, CSAM hash matcher)
2. Script runs inside TEE on the committed dataset
3. TEE attests to the results without revealing data contents
4. If script flags potential violations, controlled reveal process begins
```

## Protocol Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     SETUP PHASE                             │
├─────────────────────────────────────────────────────────────┤
│ 1. Lab commits to dataset (Merkle root)                     │
│ 2. Lab declares: "X% from approved sources, Y% proprietary" │
│ 3. Approved source registries publish commitments           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  VERIFICATION PHASE                         │
├─────────────────────────────────────────────────────────────┤
│ Public portion:                                             │
│   → ZK proof of membership in approved sources              │
│                                                             │
│ Private portion:                                            │
│   → Auditor submits detection script                        │
│   → TEE executes script on committed data                   │
│   → TEE returns attestation of results                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 CHALLENGE/REVEAL PHASE                      │
├─────────────────────────────────────────────────────────────┤
│ If detection script flags items:                            │
│   → Random subset selected for reveal                       │
│   → Neutral arbiter reviews revealed items                  │
│   → Ruling: violation confirmed or false positive           │
└─────────────────────────────────────────────────────────────┘
```

## Repository Structure

```
blindaudit/
├── commitment/        # Merkle tree and dataset commitment schemes
├── zk-membership/     # Zero-knowledge proofs for approved source membership
├── tee-runner/        # TEE execution environment for challenge scripts
├── challenge/         # Challenge protocol and script sandboxing
├── arbiter/           # Reveal and adjudication process
├── demo/              # Example scenarios and walkthrough
└── docs/              # Protocol specification and threat model
```

## Threat Model

BlindAudit protects against:

- **Labs hiding bad data:** Challenge scripts can detect violations without lab cooperation
- **Auditors stealing secrets:** Auditors never see raw data; only TEE-attested results
- **Labs faking compliance:** Commitments bind the lab to a specific dataset; can't swap after the fact

BlindAudit does NOT protect against:

- **Compromised TEE:** We trust the TEE implementation (Intel SGX, AMD SEV, or similar)
- **Colluding arbiter:** The reveal/adjudication process requires a trusted neutral party
- **Adversarial classifier evasion:** If bad content is transformed to evade all detection scripts, it won't be caught

See [THREAT_MODEL.md](docs/THREAT_MODEL.md) for detailed analysis.

## Current Status

🚧 **Hackathon prototype** — built for the Technical AI Governance Hackathon.

This is a proof-of-concept demonstrating the protocol design. It includes:

- [ ] Merkle commitment scheme for datasets
- [ ] Mock ZK membership proofs (real ZK implementation is a stretch goal)
- [ ] Simulated TEE environment for running challenge scripts
- [ ] Example detection scripts (PII, blocklist matching)
- [ ] Basic arbiter interface

Not yet production-ready. See [ROADMAP.md](docs/ROADMAP.md) for what full implementation would require.

## Getting Started

```bash
# Clone the repository
git clone https://github.com/edkins/blind-audit.git
cd blind-audit

# Install dependencies
uv run -m demo.walkthrough
```

## Contributing

We welcome contributions! This project emerged from a hackathon but aims to be a serious prototype for AI governance infrastructure.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT

## Acknowledgments

Built at the [Technical AI Governance Hackathon](https://apartresearch.com) organized by Apart Research.