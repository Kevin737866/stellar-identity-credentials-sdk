pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsa.circom";
include "circomlib/circuits/bitify.circom";

/**
 * Credential Ownership Proof Circuit
 * Proves possession of a valid credential without revealing the credential itself
 * 
 * Public Inputs:
 * - credential_hash: hash of the credential metadata
 * - issuer_public_key: public key of the credential issuer
 * - subject_address: blockchain address of the credential subject
 * - expiration_timestamp: when the credential expires
 * 
 * Private Inputs:
 * - credential_id: unique identifier of the credential
 * - subject_private_key: private key of the credential subject
 * - issuance_timestamp: when the credential was issued
 * - credential_attributes: encoded credential attributes
 */
template CredentialOwnership() {
    signal input credential_hash;
    signal input issuer_public_key[2];
    signal input subject_address;
    signal input expiration_timestamp;
    
    signal input credential_id;
    signal input subject_private_key;
    signal input issuance_timestamp;
    signal input credential_attributes;
    
    signal output is_valid;
    signal output is_not_expired;
    
    // Verify credential hash matches
    component credHasher = Poseidon(4);
    credHasher.inputs[0] <== credential_id;
    credHasher.inputs[1] <== issuance_timestamp;
    credHasher.inputs[2] <== credential_attributes;
    credHasher.inputs[3] <== subject_address;
    
    signal computed_hash;
    computed_hash <== credHasher.out;
    computed_hash === credential_hash;
    
    // Verify subject owns the private key corresponding to the address
    component addrFromPriv = EddsaPrivToPubKey();
    addrFromPriv.private_key <== subject_private_key;
    
    signal derived_address;
    derived_address <== addrFromPriv.public_key[0]; // Simplified address derivation
    
    derived_address === subject_address;
    
    // Check if credential is not expired
    signal current_time;
    component timeChecker = GreaterEqThan(64);
    timeChecker.in[0] <== expiration_timestamp;
    timeChecker.in[1] <== current_time;
    is_not_expired <== timeChecker.out;
    
    // Overall validity
    is_valid <== is_not_expired;
}

/**
 * KYC Credential Proof
 * Specialized for KYC credentials with specific attributes
 */
template KYCCredentialProof() {
    signal input credential_hash;
    signal input issuer_public_key[2];
    signal input subject_address;
    signal input expiration_timestamp;
    signal input kyc_level;
    
    signal input credential_id;
    signal input subject_private_key;
    signal input issuance_timestamp;
    signal input personal_info_hash;
    signal input verification_score;
    
    signal output is_valid;
    signal output kyc_level_valid;
    signal output verification_passed;
    
    // Basic credential ownership verification
    component credOwnership = CredentialOwnership();
    credOwnership.credential_hash <== credential_hash;
    credOwnership.issuer_public_key[0] <== issuer_public_key[0];
    credOwnership.issuer_public_key[1] <== issuer_public_key[1];
    credOwnership.subject_address <== subject_address;
    credOwnership.expiration_timestamp <== expiration_timestamp;
    
    credOwnership.credential_id <== credential_id;
    credOwnership.subject_private_key <== subject_private_key;
    credOwnership.issuance_timestamp <== issuance_timestamp;
    credOwnership.credential_attributes <== personal_info_hash;
    
    is_valid <== credOwnership.is_valid;
    
    // Verify KYC level meets requirements
    component kycChecker = GreaterEqThan(8);
    kycChecker.in[0] <== kyc_level;
    kycChecker.in[1] <== 2; // Minimum KYC level 2
    kyc_level_valid <== kycChecker.out;
    
    // Verify verification score is sufficient
    component scoreChecker = GreaterEqThan(8);
    scoreChecker.in[0] <== verification_score;
    scoreChecker.in[1] <== 80; // Minimum score of 80
    verification_passed <== scoreChecker.out;
}

/**
 * Accreditation Credential Proof
 * For professional accreditations and certifications
 */
template AccreditationCredentialProof() {
    signal input credential_hash;
    signal input issuer_public_key[2];
    signal input subject_address;
    signal input expiration_timestamp;
    signal input accreditation_type;
    
    signal input credential_id;
    signal input subject_private_key;
    signal input issuance_timestamp;
    signal input accreditation_details;
    signal input renewal_count;
    
    signal output is_valid;
    signal output is_accredited;
    signal output renewal_status;
    
    // Basic credential ownership verification
    component credOwnership = CredentialOwnership();
    credOwnership.credential_hash <== credential_hash;
    credOwnership.issuer_public_key[0] <== issuer_public_key[0];
    credOwnership.issuer_public_key[1] <== issuer_public_key[1];
    credOwnership.subject_address <== subject_address;
    credOwnership.expiration_timestamp <== expiration_timestamp;
    
    credOwnership.credential_id <== credential_id;
    credOwnership.subject_private_key <== subject_private_key;
    credOwnership.issuance_timestamp <== issuance_timestamp;
    credOwnership.credential_attributes <== accreditation_details;
    
    is_valid <== credOwnership.is_valid;
    
    // Verify accreditation type is valid (non-zero)
    is_accredited <== accreditation_type > 0 ? 1 : 0;
    
    // Check renewal status (has been renewed at least once)
    renewal_status <== renewal_count > 0 ? 1 : 0;
}

/**
 * Age Credential Proof
 * Specialized for age verification credentials
 */
template AgeCredentialProof() {
    signal input credential_hash;
    signal input issuer_public_key[2];
    signal input subject_address;
    signal input expiration_timestamp;
    
    signal input credential_id;
    signal input subject_private_key;
    signal input issuance_timestamp;
    signal input birth_date;
    signal input age_commitment[2];
    
    signal output is_valid;
    signal output age_commitment_valid;
    
    // Basic credential ownership verification
    component credOwnership = CredentialOwnership();
    credOwnership.credential_hash <== credential_hash;
    credOwnership.issuer_public_key[0] <== issuer_public_key[0];
    credOwnership.issuer_public_key[1] <== issuer_public_key[1];
    credOwnership.subject_address <== subject_address;
    credOwnership.expiration_timestamp <== expiration_timestamp;
    
    credOwnership.credential_id <== credential_id;
    credOwnership.subject_private_key <== subject_private_key;
    credOwnership.issuance_timestamp <== issuance_timestamp;
    credOwnership.credential_attributes <== birth_date;
    
    is_valid <== credOwnership.is_valid;
    
    // Verify age commitment is properly formed
    component ageCommitChecker = Poseidon(1);
    ageCommitChecker.inputs[0] <== birth_date;
    signal computed_commitment;
    computed_commitment <== ageCommitChecker.out;
    
    age_commitment_valid <== computed_commitment === age_commitment[0] ? 1 : 0;
}

/**
 * Batch Credential Verification
 * Verify multiple credentials simultaneously
 */
template BatchCredentialVerification(num_credentials) {
    signal input credential_hashes[num_credentials];
    signal input issuer_public_keys[num_credentials][2];
    signal input subject_addresses[num_credentials];
    signal input expiration_timestamps[num_credentials];
    
    signal input credential_ids[num_credentials];
    signal input subject_private_key; // Same private key for all credentials
    signal input issuance_timestamps[num_credentials];
    signal input credential_attributes[num_credentials];
    
    signal output validity_results[num_credentials];
    signal output overall_valid;
    
    for (var i = 0; i < num_credentials; i++) {
        component credOwnership = CredentialOwnership();
        credOwnership.credential_hash <== credential_hashes[i];
        credOwnership.issuer_public_key[0] <== issuer_public_keys[i][0];
        credOwnership.issuer_public_key[1] <== issuer_public_keys[i][1];
        credOwnership.subject_address <== subject_addresses[i];
        credOwnership.expiration_timestamp <== expiration_timestamps[i];
        
        credOwnership.credential_id <== credential_ids[i];
        credOwnership.subject_private_key <== subject_private_key;
        credOwnership.issuance_timestamp <== issuance_timestamps[i];
        credOwnership.credential_attributes <== credential_attributes[i];
        
        validity_results[i] <== credOwnership.is_valid;
    }
    
    // Compute overall validity (all credentials must be valid)
    signal accumulated;
    accumulated <== 0;
    for (var i = 0; i < num_credentials; i++) {
        accumulated <== accumulated + validity_results[i];
    }
    overall_valid <== accumulated === num_credentials ? 1 : 0;
}

// Main circuit components
component main = CredentialOwnership();
component kycProof = KYCCredentialProof();
component accreditationProof = AccreditationCredentialProof();
component ageProof = AgeCredentialProof();

component batch3 = BatchCredentialVerification(3);
component batch5 = BatchCredentialVerification(5);
component batch10 = BatchCredentialVerification(10);
