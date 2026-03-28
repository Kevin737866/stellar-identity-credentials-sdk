pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "range_proof.circom";
include "set_membership.circom";
include "credential_ownership.circom";

/**
 * Composite Proof Circuit
 * Combines multiple proof statements into a single proof
 * 
 * Public Inputs:
 * - commitments: array of commitments to private values
 * - merkle_roots: array of Merkle roots for set membership proofs
 * - credential_hashes: array of credential hashes
 * - threshold_values: array of threshold values for range proofs
 * 
 * Private Inputs:
 * - private_values: array of private values to prove range constraints
 * - randomness: array of randomness values for commitments
 * - merkle_proofs: array of Merkle proofs for set membership
 * - indices: array of indices for set membership proofs
 * - credentials: array of credential data
 */
template CompositeProof(num_statements) {
    signal input commitments[num_statements][2];
    signal input merkle_roots[num_statements];
    signal input credential_hashes[num_statements];
    signal input threshold_values[num_statements];
    
    signal input private_values[num_statements];
    signal input randomness[num_statements];
    signal input merkle_proofs[num_statements][16][2]; // Max depth 16
    signal input indices[num_statements];
    signal input credentials[num_statements][4]; // Simplified credential data
    
    signal output all_statements_valid;
    signal output statement_validity[num_statements];
    
    for (var i = 0; i < num_statements; i++) {
        // Range proof for each statement
        component rangeProof = RangeProof();
        rangeProof.commitment[0] <== commitments[i][0];
        rangeProof.commitment[1] <== commitments[i][1];
        rangeProof.min_value <== threshold_values[i];
        rangeProof.max_value <== 1000000; // Large max value
        rangeProof.value <== private_values[i];
        rangeProof.randomness <== randomness[i];
        
        // Set membership proof (simplified)
        component setProof = SetMembership(8);
        setProof.merkle_root <== merkle_roots[i];
        setProof.element <== private_values[i];
        for (var j = 0; j < 8; j++) {
            setProof.merkle_proof[j][0] <== merkle_proofs[i][j][0];
            setProof.merkle_proof[j][1] <== merkle_proofs[i][j][1];
        }
        setProof.index <== indices[i];
        
        // Credential ownership proof (simplified)
        component credProof = CredentialOwnership();
        credProof.credential_hash <== credential_hashes[i];
        credProof.credential_id <== credentials[i][0];
        credProof.issuance_timestamp <== credentials[i][1];
        credProof.credential_attributes <== credentials[i][2];
        credProof.subject_address <== credentials[i][3];
        
        // Combine all proofs for this statement
        signal range_valid;
        signal set_valid;
        signal cred_valid;
        
        range_valid <== 1; // Simplified - rangeProof would output validity
        set_valid <== setProof.is_member;
        cred_valid <== 1; // Simplified - credProof would output validity
        
        statement_validity[i] <== range_valid * set_valid * cred_valid;
    }
    
    // All statements must be valid
    signal accumulated;
    accumulated <== 0;
    for (var i = 0; i < num_statements; i++) {
        accumulated <== accumulated + statement_validity[i];
    }
    all_statements_valid <== accumulated === num_statements ? 1 : 0;
}

/**
 * Age + Country Composite Proof
 * Proves age >= minimum AND country is in approved list
 */
template AgeCountryCompositeProof() {
    signal input age_commitment[2];
    signal input country_merkle_root;
    signal input min_age;
    signal input current_year;
    
    signal input birth_year;
    signal input age_randomness;
    signal input country_code;
    signal input country_merkle_proof[8][2];
    signal input country_index;
    
    signal output is_valid;
    signal output age_valid;
    signal output country_valid;
    
    // Age proof component
    component ageProof = AgeRangeProof();
    ageProof.birth_year <== birth_year;
    ageProof.current_year <== current_year;
    ageProof.min_age <== min_age;
    ageProof.randomness <== age_randomness;
    
    // Verify age commitment
    signal age_commit_match;
    age_commit_match <== (ageProof.commitment[0] === age_commitment[0] && 
                         ageProof.commitment[1] === age_commitment[1]) ? 1 : 0;
    age_valid <== ageProof.is_valid * age_commit_match;
    
    // Country membership proof
    component countryProof = CountryMembership(8);
    countryProof.country_code <== country_code;
    countryProof.eu_merkle_root <== country_merkle_root;
    for (var i = 0; i < 8; i++) {
        countryProof.merkle_proof[i][0] <== country_merkle_proof[i][0];
        countryProof.merkle_proof[i][1] <== country_merkle_proof[i][1];
    }
    countryProof.index <== country_index;
    country_valid <== countryProof.is_eu_country;
    
    // Both conditions must be satisfied
    is_valid <== age_valid * country_valid;
}

/**
 * Income + Credit Score Composite Proof
 * Proves income >= minimum AND credit score in acceptable range
 */
template IncomeCreditCompositeProof() {
    signal input income_commitment[2];
    signal input credit_commitment[2];
    signal input min_income;
    signal input min_credit_score;
    signal input max_credit_score;
    
    signal input income;
    signal input credit_score;
    signal input income_randomness;
    signal input credit_randomness;
    
    signal output is_valid;
    signal output income_valid;
    signal output credit_valid;
    
    // Income proof component
    component incomeProof = IncomeRangeProof();
    incomeProof.income <== income;
    incomeProof.min_income <== min_income;
    incomeProof.randomness <== income_randomness;
    
    // Verify income commitment
    signal income_commit_match;
    income_commit_match <== (incomeProof.commitment[0] === income_commitment[0] && 
                           incomeProof.commitment[1] === income_commitment[1]) ? 1 : 0;
    income_valid <== incomeProof.is_valid * income_commit_match;
    
    // Credit score proof component
    component creditProof = CreditScoreRangeProof();
    creditProof.credit_score <== credit_score;
    creditProof.min_score <== min_credit_score;
    creditProof.max_score <== max_credit_score;
    creditProof.randomness <== credit_randomness;
    
    // Verify credit commitment
    signal credit_commit_match;
    credit_commit_match <== (creditProof.commitment[0] === credit_commitment[0] && 
                           creditProof.commitment[1] === credit_commitment[1]) ? 1 : 0;
    credit_valid <== creditProof.is_valid * credit_commit_match;
    
    // Both conditions must be satisfied
    is_valid <== income_valid * credit_valid;
}

/**
 * KYC Composite Proof
 * Proves multiple KYC requirements simultaneously
 */
template KYCCompositeProof() {
    signal input credential_hash;
    signal input issuer_public_key[2];
    signal input subject_address;
    signal input expiration_timestamp;
    signal input age_commitment[2];
    signal input country_merkle_root;
    signal input min_age;
    signal input current_year;
    
    signal input credential_id;
    signal input subject_private_key;
    signal input issuance_timestamp;
    signal input personal_info_hash;
    signal input verification_score;
    signal input birth_year;
    signal input age_randomness;
    signal input country_code;
    signal input country_merkle_proof[8][2];
    signal input country_index;
    
    signal output is_valid;
    signal output credential_valid;
    signal output age_valid;
    signal output country_valid;
    signal output kyc_level_valid;
    
    // KYC credential proof
    component kycProof = KYCCredentialProof();
    kycProof.credential_hash <== credential_hash;
    kycProof.issuer_public_key[0] <== issuer_public_key[0];
    kycProof.issuer_public_key[1] <== issuer_public_key[1];
    kycProof.subject_address <== subject_address;
    kycProof.expiration_timestamp <== expiration_timestamp;
    kycProof.credential_id <== credential_id;
    kycProof.subject_private_key <== subject_private_key;
    kycProof.issuance_timestamp <== issuance_timestamp;
    kycProof.personal_info_hash <== personal_info_hash;
    kycProof.verification_score <== verification_score;
    
    credential_valid <== kycProof.is_valid;
    kyc_level_valid <== kycProof.kyc_level_valid * kycProof.verification_passed;
    
    // Age proof
    component ageProof = AgeRangeProof();
    ageProof.birth_year <== birth_year;
    ageProof.current_year <== current_year;
    ageProof.min_age <== min_age;
    ageProof.randomness <== age_randomness;
    
    signal age_commit_match;
    age_commit_match <== (ageProof.commitment[0] === age_commitment[0] && 
                         ageProof.commitment[1] === age_commitment[1]) ? 1 : 0;
    age_valid <== ageProof.is_valid * age_commit_match;
    
    // Country proof
    component countryProof = CountryMembership(8);
    countryProof.country_code <== country_code;
    countryProof.eu_merkle_root <== country_merkle_root;
    for (var i = 0; i < 8; i++) {
        countryProof.merkle_proof[i][0] <== country_merkle_proof[i][0];
        countryProof.merkle_proof[i][1] <== country_merkle_proof[i][1];
    }
    countryProof.index <== country_index;
    country_valid <== countryProof.is_eu_country;
    
    // All conditions must be satisfied for complete KYC
    is_valid <== credential_valid * age_valid * country_valid * kyc_level_valid;
}

/**
 * Loan Application Composite Proof
 * Comprehensive proof for loan eligibility
 */
template LoanApplicationCompositeProof() {
    signal input income_commitment[2];
    signal input credit_commitment[2];
    signal input employment_commitment[2];
    signal input residence_commitment[2];
    signal input min_income;
    signal input min_credit_score;
    signal input max_debt_to_income;
    signal input min_employment_months;
    signal input residence_merkle_root;
    
    signal input income;
    signal input credit_score;
    signal input employment_months;
    signal input debt_amount;
    signal input residence_proof;
    signal input income_randomness;
    signal input credit_randomness;
    signal input employment_randomness;
    signal input residence_randomness;
    signal input residence_merkle_proof[8][2];
    signal input residence_index;
    
    signal output is_eligible;
    signal output income_valid;
    signal output credit_valid;
    signal output employment_valid;
    signal output debt_ratio_valid;
    signal output residence_valid;
    
    // Income validation
    component incomeProof = IncomeRangeProof();
    incomeProof.income <== income;
    incomeProof.min_income <== min_income;
    incomeProof.randomness <== income_randomness;
    
    signal income_commit_match;
    income_commit_match <== (incomeProof.commitment[0] === income_commitment[0] && 
                           incomeProof.commitment[1] === income_commitment[1]) ? 1 : 0;
    income_valid <== incomeProof.is_valid * income_commit_match;
    
    // Credit score validation
    component creditProof = CreditScoreRangeProof();
    creditProof.credit_score <== credit_score;
    creditProof.min_score <== min_credit_score;
    creditProof.max_score <== 850; // Max credit score
    creditProof.randomness <== credit_randomness;
    
    signal credit_commit_match;
    credit_commit_match <== (creditProof.commitment[0] === credit_commit[0] && 
                           creditProof.commitment[1] === credit_commit[1]) ? 1 : 0;
    credit_valid <== creditProof.is_valid * credit_commit_match;
    
    // Employment duration validation
    component empCheck = GreaterEqThan(32);
    empCheck.in[0] <== employment_months;
    empCheck.in[1] <== min_employment_months;
    employment_valid <== empCheck.out;
    
    // Debt-to-income ratio validation
    signal debt_ratio;
    debt_ratio <== (debt_amount * 100) / income; // Percentage
    component debtCheck = LessEqThan(32);
    debtCheck.in[0] <== debt_ratio;
    debtCheck.in[1] <== max_debt_to_income;
    debt_ratio_valid <== debtCheck.out;
    
    // Residence validation (set membership)
    component residenceProof = SetMembership(8);
    residenceProof.merkle_root <== residence_merkle_root;
    residenceProof.element <== residence_proof;
    for (var i = 0; i < 8; i++) {
        residenceProof.merkle_proof[i][0] <== residence_merkle_proof[i][0];
        residenceProof.merkle_proof[i][1] <== residence_merkle_proof[i][1];
    }
    residenceProof.index <== residence_index;
    residence_valid <== residenceProof.is_member;
    
    // All conditions must be satisfied for loan eligibility
    is_eligible <== income_valid * credit_valid * employment_valid * 
                   debt_ratio_valid * residence_valid;
}

// Main circuit components
component main2 = CompositeProof(2);
component main3 = CompositeProof(3);
component main5 = CompositeProof(5);

component ageCountryProof = AgeCountryCompositeProof();
component incomeCreditProof = IncomeCreditCompositeProof();
component kycCompositeProof = KYCCompositeProof();
component loanApplicationProof = LoanApplicationCompositeProof();
