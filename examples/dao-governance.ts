import { Keypair } from 'stellar-sdk';
import { ReputationClient, StellarIdentityConfig } from '../sdk/src';

const config: StellarIdentityConfig = {
  network: 'testnet',
  contracts: {
    didRegistry: 'CDIDREGISTRYEXAMPLE',
    credentialIssuer: 'CCREDENTIALISSUEREXAMPLE',
    reputationScore: 'CREPUTATIONENGINEEXAMPLE',
    zkAttestation: 'CZKATTESTATIONEXAMPLE',
    complianceFilter: 'CCOMPLIANCEFILTEREXAMPLE',
  },
};

async function run() {
  const reputation = new ReputationClient(config);
  const delegates = [Keypair.random(), Keypair.random(), Keypair.random()];

  for (const delegate of delegates) {
    await reputation.initializeReputation(delegate);
    await reputation.updateCredentialReputation(delegate, delegate.publicKey(), true, 'KYC');
  }

  await reputation.updateReputation(delegates[0], delegates[0].publicKey(), 'contract', { count: 6 });
  await reputation.updateReputation(delegates[1], delegates[1].publicKey(), 'contract', { count: 3 });
  await reputation.updateReputation(delegates[2], delegates[2].publicKey(), 'dispute', { count: 1 });

  await reputation.attestTrust(delegates[0], delegates[1].publicKey(), 840, 'Trusted governance operator');
  await reputation.attestTrust(delegates[1], delegates[0].publicKey(), 760, 'Strong participation and high-quality proposals');

  const proposalWeightTable = await Promise.all(
    delegates.map(async delegate => {
      const snapshot = await reputation.getReputationScore(delegate.publicKey());
      return {
        delegate: delegate.publicKey(),
        tier: snapshot.tier,
        reputationScore: snapshot.score,
        votingWeight: Number((1 + snapshot.score / 1000).toFixed(3)),
      };
    }),
  );

  const totalWeight = proposalWeightTable.reduce((sum, item) => sum + item.votingWeight, 0);
  const yesWeight = proposalWeightTable[0].votingWeight + proposalWeightTable[1].votingWeight;
  const approvalRatio = Number((yesWeight / totalWeight).toFixed(3));

  console.log('Reputation-weighted governance vote');
  console.log({
    proposal: 'Increase builder grants by 8%',
    delegates: proposalWeightTable,
    approvalRatio,
    passed: approvalRatio >= 0.6,
  });
}

run().catch(error => {
  console.error('dao-governance example failed');
  console.error(error);
  process.exitCode = 1;
});
