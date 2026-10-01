import { createPortableSchema, verifyPortableSchema } from '../schemaPortability';
import { CredentialSchema } from '../types';

const schema: CredentialSchema = {
  id: 'kyc-v1',
  issuer: 'GISSUER',
  version: 1,
  definition: '{"type":"object","required":["name"]}',
  created: 100,
  updated: 200,
};

describe('portable schema bundles', () => {
  it('exports complete metadata and verifies its checksum', () => {
    const bundle = createPortableSchema(schema);
    expect(bundle.schema).toEqual(schema);
    expect(verifyPortableSchema(bundle)).toBe(true);
  });

  it('rejects tampered metadata and malformed schema definitions', () => {
    const bundle = createPortableSchema(schema);
    expect(verifyPortableSchema({ ...bundle, schema: { ...schema, definition: '{"type":"string"}' } })).toBe(false);
    expect(() => createPortableSchema({ ...schema, definition: '{' })).toThrow('valid JSON');
  });
});
