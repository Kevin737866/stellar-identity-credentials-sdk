export interface RevocationRegistry {
  id: string;
  issuer: string;
  name: string;
  credentialCount: number;
  revokedCount: number;
  active: boolean;
  created: number;
  updated: number;
  metadata?: Record<string, string>;
}

export interface RevocationProof {
  registryId: string;
  credentialId: string;
  revokedAt: number;
  reason?: string;
  signature: string;
  issuer: string;
}

export interface BatchRevocationRecord {
  batchId: string;
  registryId: string;
  credentialIds: string[];
  revokedCount: number;
  failedCount: number;
  failedCredentials: Array<{ credentialId: string; error: string }>;
  reason?: string;
  revokedAt: number;
  issuer: string;
}
