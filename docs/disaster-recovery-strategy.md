# Disaster Recovery and Backup Strategy: Identity & Payment Systems

This document establishes the authoritative Disaster Recovery (DR) and Backup Strategy for the core infrastructure architecture, covering both decentralized on-chain assets (Stellar Network/Soroban smart contracts) and centralized off-chain support components (Nest.js backend APIs, PostgreSQL relational storage, Redis caching matrices).

---

## 1. System DR Classification Matrix (RTO / RPO)

We define target Recovery Time Objectives (**RTO**) and Recovery Point Objectives (**RPO**) per system architecture module:

| Component | Backup Frequency | Target RTO | Target RPO | Primary DR Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **On-Chain Contract State** | Continuous (Ledger Sync) | < 30 Mins | 0 (Ledger Bound) | Multi-Node RPC Fallback & Event Re-indexing |
| **Off-Chain Database (PostgreSQL)** | Continuous Write-Ahead + Daily Snapshot | < 1 Hour | < 5 Mins | Multi-AZ Streaming Replication + S3 Cross-Region Cross-Account |
| **Caching Layer (Redis)** | Ephemeral / Snapshot Cache | < 15 Mins | Cache Miss | Auto-rebuilding cluster cache instances |
| **Identity / Gateway API** | Stateless Deployment | < 5 Mins | 0 (Stateless) | DNS Failover Routing (Route53) + Multi-Region Blue/Green |

---

## 2. Data Backup Procedures

### A. On-Chain Smart Contract State
Because smart contract execution lives natively on the decentralized Stellar ledger, states cannot be altered or deleted via standard structural faults. However, transaction execution and ingestion can fail if private network RPC nodes drop.
* **Procedure:** Maintain a live primary-secondary cluster connection loop spanning two independent public RPC nodes (e.g., SDF and custom infrastructure mirrors).
* **Archive Method:** An automated background synchronization worker executes a daily sweep of event matrices emitted by the contract registry, storing historical transaction logs into immutable AWS S3 Glacier buckets.

### B. Off-Chain Database (PostgreSQL)
* **Continuous WAL Archiving:** Stream Write-Ahead Logs (WAL) continuously to an encrypted AWS S3 repository bucket using `pgBackRest` or native AWS RDS transaction pipelines.
* **Daily Snapshots:** Execute full database snapshots automatically at `02:00 UTC` every night. Maintain a strict **30-day retention loop policy**.
* **Cross-Region Vaulting:** Encrypt all snapshot exports using custom AWS KMS keys and mirror them instantly to an isolated fallback storage region (`us-west-2` assuming primary operation is inside `us-east-1`).

---

## 3. High-Availability & Automated Failover Architecture



### Network Infrastructure Routing
* **Application Gateway Layer:** Utilize AWS Route53 latency-based failover routing with configured health check sweeps. If health probes on the primary compute cluster time out for 3 consecutive check intervals (30 seconds total), edge traffic automatically shifts to the backup secondary regional cluster.
* **Database Master Failover:** Run active hot standby replicas across distinct availability zones (Multi-AZ mapping). Upon primary database node degradation, the clustering coordinator promotes the secondary node to master write status within 60 seconds without application interruption.

---

## 4. Disaster Recovery Runbook & Checklists

### Incident Scenario: Primary Database Layer Unreachable or Corrupted

#### Phase 1: Triage and Verification
- [ ] Confirm outage scope via centralized tracking metrics (Datadog/Grafana) indicating sustained > 5xx state codes or depleted pool connection metrics.
- [ ] Verify if automated infrastructure failover failed to initialize natively within 90 seconds.
- [ ] Notify on-call engineering squads and declare a Sev-1 incident communication bridge channel.

#### Phase 2: Manual Recovery & Ingestion Re-alignment
- [ ] **Step 1:** Freeze ingress gateway pipelines to block incoming mutated writes and prevent split-brain conflicts during database master modifications:
  ```bash
  aws route53 change-resource-record-sets --hosted-zone-id Z12345 --change-batch file://infra/stop-traffic.json