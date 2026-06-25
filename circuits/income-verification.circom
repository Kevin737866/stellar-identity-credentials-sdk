pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

template IncomeVerification() {
    signal input minIncome;
    signal input income;
    signal input salt;
    signal output commitment;
    
    // Validate positive values
    signal incomePositive;
    incomePositive <== income > 0 ? 1 : 0;
    incomePositive === 1;
    
    signal minIncomePositive;
    minIncomePositive <== minIncome > 0 ? 1 : 0;
    minIncomePositive === 1;
    
    // Check income >= minIncome
    component incomeCheck = GreaterEqThan(64);
    incomeCheck.in[0] <== income;
    incomeCheck.in[1] <== minIncome;
    incomeCheck.out === 1;
    
    // Poseidon hash commitment
    component hasher = Poseidon(2);
    hasher.inputs[0] <== income;
    hasher.inputs[1] <== salt;
    commitment <== hasher.out;
}

component main = IncomeVerification();
