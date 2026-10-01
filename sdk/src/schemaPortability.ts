import CryptoJS from 'crypto-js';
import { CredentialSchema, PortableSchema } from './types';

function canonicalSchema(schema: CredentialSchema): string {
  return JSON.stringify({
    id: schema.id,
    issuer: schema.issuer,
    version: schema.version,
    definition: schema.definition,
    created: schema.created,
    updated: schema.updated,
  });
}

export function createPortableSchema(schema: CredentialSchema): PortableSchema {
  if (!schema.id || !schema.issuer || !schema.definition || !Number.isInteger(schema.version) || schema.version < 1) {
    throw new Error('Schema metadata is incomplete or invalid');
  }
  try {
    JSON.parse(schema.definition);
  } catch {
    throw new Error('Schema definition must contain valid JSON');
  }
  return {
    format: 'stellar-identity-schema',
    formatVersion: 1,
    schema: { ...schema },
    checksum: CryptoJS.SHA256(canonicalSchema(schema)).toString(),
  };
}

export function verifyPortableSchema(bundle: PortableSchema): boolean {
  if (!bundle || bundle.format !== 'stellar-identity-schema' || bundle.formatVersion !== 1 || !bundle.schema) return false;
  try {
    return createPortableSchema(bundle.schema).checksum === bundle.checksum;
  } catch {
    return false;
  }
}
