export interface DidResolutionMeta {
  contentType: 'application/did+ld+json';
  error?: 'invalidDid' | 'notFound' | 'unsupportedDidMethod';
}

export interface DidDocumentMeta {
  created?: string;
  updated?: string;
  deactivated?: boolean;
}

export interface DidVerificationMethod {
  id: string;
  type: 'Ed25519VerificationKey2020' | 'X25519KeyAgreementKey2020';
  controller: string;
  publicKeyMultibase?: string;
}

export interface DidDocument {
  '@context': string[];
  id: string;
  verificationMethod: DidVerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
}

export interface UniversalResolverResponse {
  didResolutionMetadata: DidResolutionMeta;
  didDocument: DidDocument | null;
  didDocumentMetadata: DidDocumentMeta;
}