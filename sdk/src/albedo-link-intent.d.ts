declare module '@albedo-link/intent' {
  interface AlbedoIntent {
    publicKey(options?: Record<string, unknown>): Promise<{ pubkey: string }>;
    tx(options: { xdr: string; network: string }): Promise<{ signed_envelope_xdr: string }>;
  }
  const albedo: AlbedoIntent;
  export default albedo;
}
