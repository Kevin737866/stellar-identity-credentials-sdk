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
  const lender = Keypair.random();
  const borrower = Keypair.random();
  const reputation = new ReputationClient(config);

  await reputation.initializeReputation(borrower);
  await reputation.updateTransactionReputation(borrower, borrower.publicKey(), true, 4_500);
  await reputation.updateCredentialReputation(borrower, borrower.publicKey(), true, 'KYC');
  await reputation.updateReputation(borrower, borrower.publicKey(), 'contract', { count: 3 });

  await reputation.attestTrust(lender, borrower.publicKey(), 780, 'Reliable repayment history across prior pools');

  const snapshot = await reputation.getReputationScore(borrower.publicKey());
  const score = snapshot.score;
  const interestRateBps = score >= 850 ? 650 : score >= 700 ? 900 : score >= 550 ? 1250 : 1850;
  const collateralRatio = score >= 800 ? 0 : score >= 650 ? 10 : 25;
  const approved = score >= 550 && snapshot.penalties.sanctionsMatches === 0;

  console.log('Collateral-free lending decision');
  console.log({
    borrower: borrower.publicKey(),
    score,
    tier: snapshot.tier,
    approved,
    interestRateBps,
    collateralRatio,
    driverBreakdown: snapshot.factors,
  });
}

run().catch(error => {
  console.error('reputation-lending example failed');
  console.error(error);
  process.exitCode = 1;
});
