pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mimc.circom";
include "circomlib/circuits/bitify.circom";

/**
 * Set Membership Proof Circuit
 * Proves that a private element is a member of a Merkle tree set
 * without revealing which element
 * 
 * Public Inputs:
 * - merkle_root: root of the Merkle tree
 * - set_hash: hash of the entire set
 * 
 * Private Inputs:
 * - element: the private element to prove membership
 * - merkle_proof: Merkle proof path
 * - index: index of the element in the set
 */
template SetMembership(tree_depth) {
    signal input merkle_root;
    signal input element;
    signal input merkle_proof[tree_depth][2];
    signal input index;
    signal output is_member;
    
    // Calculate leaf hash from element
    component leafHasher = Poseidon(1);
    leafHasher.inputs[0] <== element;
    signal leaf_hash;
    leaf_hash <== leafHasher.out;
    
    // Verify Merkle proof
    signal current_hash;
    current_hash <== leaf_hash;
    
    for (var i = 0; i < tree_depth; i++) {
        component hasher = Poseidon(2);
        signal current_bit = (index >> i) & 1;
        
        // Choose left or right based on path bit
        hasher.inputs[0] <== current_bit == 0 ? current_hash : merkle_proof[i][0];
        hasher.inputs[1] <== current_bit == 0 ? merkle_proof[i][0] : current_hash;
        current_hash <== hasher.out;
    }
    
    // Verify final hash matches merkle root
    is_member <== current_hash === merkle_root ? 1 : 0;
}

/**
 * Country Membership Proof
 * Proves that a country is in the approved EU list
 */
template CountryMembership(tree_depth) {
    signal input country_code;
    signal input eu_merkle_root;
    signal input merkle_proof[tree_depth][2];
    signal input index;
    signal output is_eu_country;
    
    component setProof = SetMembership(tree_depth);
    setProof.merkle_root <== eu_merkle_root;
    setProof.element <== country_code;
    
    for (var i = 0; i < tree_depth; i++) {
        setProof.merkle_proof[i][0] <== merkle_proof[i][0];
        setProof.merkle_proof[i][1] <== merkle_proof[i][1];
    }
    setProof.index <== index;
    
    is_eu_country <== setProof.is_member;
}

/**
 * Whitelist Membership Proof
 * Proves an address is whitelisted
 */
template WhitelistMembership(tree_depth) {
    signal input address;
    signal input whitelist_root;
    signal input merkle_proof[tree_depth][2];
    signal input index;
    signal output is_whitelisted;
    
    component setProof = SetMembership(tree_depth);
    setProof.merkle_root <== whitelist_root;
    setProof.element <== address;
    
    for (var i = 0; i < tree_depth; i++) {
        setProof.merkle_proof[i][0] <== merkle_proof[i][0];
        setProof.merkle_proof[i][1] <== merkle_proof[i][1];
    }
    setProof.index <== index;
    
    is_whitelisted <== setProof.is_member;
}

/**
 * Blacklist Non-Membership Proof
 * Proves an element is NOT in a blacklist set
 */
template BlacklistNonMembership(tree_depth) {
    signal input element;
    signal input blacklist_root;
    signal input merkle_proof[tree_depth][2];
    signal input index;
    signal output is_not_blacklisted;
    
    component setProof = SetMembership(tree_depth);
    setProof.merkle_root <== blacklist_root;
    setProof.element <== element;
    
    for (var i = 0; i < tree_depth; i++) {
        setProof.merkle_proof[i][0] <== merkle_proof[i][0];
        setProof.merkle_proof[i][1] <== merkle_proof[i][1];
    }
    setProof.index <== index;
    
    // Return negation of membership
    is_not_blacklisted <== 1 - setProof.is_member;
}

/**
 * Multi-Set Membership Proof
 * Proves membership in multiple sets simultaneously
 */
template MultiSetMembership(tree_depth, num_sets) {
    signal input element;
    signal input merkle_roots[num_sets];
    signal input merkle_proofs[num_sets][tree_depth][2];
    signal input indices[num_sets];
    signal output membership_results[num_sets];
    
    for (var i = 0; i < num_sets; i++) {
        component setProof = SetMembership(tree_depth);
        setProof.merkle_root <== merkle_roots[i];
        setProof.element <== element;
        setProof.index <== indices[i];
        
        for (var j = 0; j < tree_depth; j++) {
            setProof.merkle_proof[j][0] <== merkle_proofs[i][j][0];
            setProof.merkle_proof[j][1] <== merkle_proofs[i][j][1];
        }
        
        membership_results[i] <== setProof.is_member;
    }
}

// Main circuit components for common depths
component main8 = SetMembership(8);    // For small sets (256 elements)
component main12 = SetMembership(12);  // For medium sets (4096 elements)
component main16 = SetMembership(16);  // For large sets (65536 elements)

component countryProof8 = CountryMembership(8);
component countryProof12 = CountryMembership(12);
component countryProof16 = CountryMembership(16);

component whitelistProof8 = WhitelistMembership(8);
component whitelistProof12 = WhitelistMembership(12);
component whitelistProof16 = WhitelistMembership(16);

component blacklistProof8 = BlacklistNonMembership(8);
component blacklistProof12 = BlacklistNonMembership(12);
component blacklistProof16 = BlacklistNonMembership(16);
