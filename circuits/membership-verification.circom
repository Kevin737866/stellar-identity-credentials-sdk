pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

template MembershipVerification(depth) {
    signal input root;
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    
    // Compute leaf hash using Poseidon
    component leafHasher = Poseidon(1);
    leafHasher.inputs[0] <== leaf;
    signal computedHash;
    computedHash <== leafHasher.out;
    
    // Verify Merkle path
    for (var i = 0; i < depth; i++) {
        component hasher = Poseidon(2);
        
        // If pathIndices[i] == 0, computedHash is left child
        // If pathIndices[i] == 1, computedHash is right child
        signal isLeft;
        isLeft <== 1 - pathIndices[i];
        
        hasher.inputs[0] <== isLeft * computedHash + pathIndices[i] * pathElements[i];
        hasher.inputs[1] <== isLeft * pathElements[i] + pathIndices[i] * computedHash;
        computedHash <== hasher.out;
    }
    
    // Verify computed root matches public root
    computedHash === root;
}

component main = MembershipVerification(20);
