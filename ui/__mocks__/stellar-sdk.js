// Mock for stellar-sdk
const Keypair = {
  random: jest.fn(() => ({
    publicKey: () => 'GABC123456789TESTPUBLICKEY',
    secret: () => 'SABC123456789TESTSECRETKEY',
  })),
  fromSecret: jest.fn((secret) => ({
    publicKey: () => 'GABC123456789TESTPUBLICKEY',
    secret: () => secret,
  })),
};

module.exports = { Keypair };
