pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

template AgeVerification() {
    signal input minAge;
    signal input age;
    signal input salt;
    signal output commitment;
    
    // Validate inputs
    signal agePositive;
    agePositive <== age > 0 ? 1 : 0;
    agePositive === 1;
    
    signal minAgePositive;
    minAgePositive <== minAge > 0 ? 1 : 0;
    minAgePositive === 1;
    
    // Check age >= minAge
    component ageCheck = GreaterEqThan(32);
    ageCheck.in[0] <== age;
    ageCheck.in[1] <== minAge;
    ageCheck.out === 1;
    
    // Create Poseidon hash commitment
    component hasher = Poseidon(2);
    hasher.inputs[0] <== age;
    hasher.inputs[1] <== salt;
    commitment <== hasher.out;
}

component main = AgeVerification();
