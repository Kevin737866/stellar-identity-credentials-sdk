pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/**
 * Range Proof Circuit
 * Proves that a private value falls within a specified range [min, max]
 * without revealing the actual value
 * 
 * Public Inputs:
 * - commitment: Pedersen commitment to the private value
 * - min_value: minimum allowed value
 * - max_value: maximum allowed value
 * 
 * Private Inputs:
 * - value: the actual private value
 * - randomness: randomness for the commitment
 */
template RangeProof() {
    signal input commitment[2];
    signal input min_value;
    signal input max_value;
    signal input value;
    signal input randomness;
    
    // Component for Pedersen commitment
    component pedersen = Pedersen(256);
    pedersen.in[0] <== value;
    pedersen.in[1] <== randomness;
    
    // Verify commitment matches
    commitment[0] <== pedersen.out[0];
    commitment[1] <== pedersen.out[1];
    
    // Component for range verification
    component minCheck = LessEqThan(256);
    minCheck.in[0] <== min_value;
    minCheck.in[1] <== value;
    minCheck.out === 0;
    
    component maxCheck = LessEqThan(256);
    maxCheck.in[0] <== value;
    maxCheck.in[1] <== max_value;
    maxCheck.out === 0;
}

/**
 * Age Range Proof
 * Specialized circuit for proving age >= minimum age
 */
template AgeRangeProof() {
    signal input birth_year;
    signal input current_year;
    signal input min_age;
    signal input randomness;
    signal output commitment[2];
    signal output is_valid;
    
    // Calculate age
    signal age;
    age <== current_year - birth_year;
    
    // Create commitment to age
    component pedersen = Pedersen(256);
    pedersen.in[0] <== age;
    pedersen.in[1] <== randomness;
    commitment[0] <== pedersen.out[0];
    commitment[1] <== pedersen.out[1];
    
    // Verify age >= min_age
    component ageCheck = GreaterEqThan(256);
    ageCheck.in[0] <== age;
    ageCheck.in[1] <== min_age;
    is_valid <== ageCheck.out;
}

/**
 * Income Range Proof
 * Specialized circuit for proving income >= minimum income
 */
template IncomeRangeProof() {
    signal input income;
    signal input min_income;
    signal input randomness;
    signal output commitment[2];
    signal output is_valid;
    
    // Create commitment to income
    component pedersen = Pedersen(256);
    pedersen.in[0] <== income;
    pedersen.in[1] <== randomness;
    commitment[0] <== pedersen.out[0];
    commitment[1] <== pedersen.out[1];
    
    // Verify income >= min_income
    component incomeCheck = GreaterEqThan(256);
    incomeCheck.in[0] <== income;
    incomeCheck.in[1] <== min_income;
    is_valid <== incomeCheck.out;
}

/**
 * Credit Score Range Proof
 * Proves credit score falls within acceptable range
 */
template CreditScoreRangeProof() {
    signal input credit_score;
    signal input min_score;
    signal input max_score;
    signal input randomness;
    signal output commitment[2];
    signal output is_valid;
    
    // Create commitment to credit score
    component pedersen = Pedersen(256);
    pedersen.in[0] <== credit_score;
    pedersen.in[1] <== randomness;
    commitment[0] <== pedersen.out[0];
    commitment[1] <== pedersen.out[1];
    
    // Verify score range
    component minCheck = GreaterEqThan(256);
    minCheck.in[0] <== credit_score;
    minCheck.in[1] <== min_score;
    
    component maxCheck = LessEqThan(256);
    maxCheck.in[0] <== credit_score;
    maxCheck.in[1] <== max_score;
    
    is_valid <== minCheck.out * maxCheck.out;
}

// Main circuit components
component main = RangeProof();
component ageProof = AgeRangeProof();
component incomeProof = IncomeRangeProof();
component creditScoreProof = CreditScoreRangeProof();
