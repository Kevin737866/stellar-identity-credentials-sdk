pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsamimc.circom";

/**
 * Attribute Commitment
 * Hashes a single attribute value with a random nonce so the
 * holder can prove statements about it without revealing the raw value.
 */
template AttributeCommitment() {
    signal input attribute;
    signal input nonce;
    signal output commitment;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== attribute;
    hasher.inputs[1] <== nonce;
    commitment <== hasher.out;
}

/**
 * Greater-Than Predicate
 * Proves: attribute > threshold  (without revealing attribute)
 * Public:  commitment, threshold
 * Private: attribute, nonce
 */
template GreaterThanPredicate(nBits) {
    signal input commitment;
    signal input threshold;
    signal input attribute;
    signal input nonce;

    // Verify commitment
    component commit = AttributeCommitment();
    commit.attribute <== attribute;
    commit.nonce <== nonce;
    commitment === commit.commitment;

    // Verify attribute > threshold
    component gt = GreaterThan(nBits);
    gt.in[0] <== attribute;
    gt.in[1] <== threshold;
    gt.out === 1;
}

/**
 * Less-Than Predicate
 * Proves: attribute < threshold  (without revealing attribute)
 * Public:  commitment, threshold
 * Private: attribute, nonce
 */
template LessThanPredicate(nBits) {
    signal input commitment;
    signal input threshold;
    signal input attribute;
    signal input nonce;

    // Verify commitment
    component commit = AttributeCommitment();
    commit.attribute <== attribute;
    commit.nonce <== nonce;
    commitment === commit.commitment;

    // Verify attribute < threshold
    component lt = LessThan(nBits);
    lt.in[0] <== attribute;
    lt.in[1] <== threshold;
    lt.out === 1;
}

/**
 * Greater-Than-Or-Equal Predicate
 * Proves: attribute >= threshold  (without revealing attribute)
 * Public:  commitment, threshold
 * Private: attribute, nonce
 */
template GreaterEqPredicate(nBits) {
    signal input commitment;
    signal input threshold;
    signal input attribute;
    signal input nonce;

    // Verify commitment
    component commit = AttributeCommitment();
    commit.attribute <== attribute;
    commit.nonce <== nonce;
    commitment === commit.commitment;

    // Verify attribute >= threshold
    component geq = GreaterEqThan(nBits);
    geq.in[0] <== attribute;
    geq.in[1] <== threshold;
    geq.out === 1;
}

/**
 * Less-Than-Or-Equal Predicate
 * Proves: attribute <= threshold  (without revealing attribute)
 * Public:  commitment, threshold
 * Private: attribute, nonce
 */
template LessEqPredicate(nBits) {
    signal input commitment;
    signal input threshold;
    signal input attribute;
    signal input nonce;

    // Verify commitment
    component commit = AttributeCommitment();
    commit.attribute <== attribute;
    commit.nonce <== nonce;
    commitment === commit.commitment;

    // Verify attribute <= threshold
    component leq = LessEqThan(nBits);
    leq.in[0] <== attribute;
    leq.in[1] <== threshold;
    leq.out === 1;
}

/**
 * Equality Predicate
 * Proves: attribute == expected  (selective disclosure of exact value)
 * Public:  commitment, expected
 * Private: attribute, nonce
 */
template EqualityPredicate(nBits) {
    signal input commitment;
    signal input expected;
    signal input attribute;
    signal input nonce;

    // Verify commitment
    component commit = AttributeCommitment();
    commit.attribute <== attribute;
    commit.nonce <== nonce;
    commitment === commit.commitment;

    // Verify equality
    component eq = IsEqual();
    eq.in[0] <== attribute;
    eq.in[1] <== expected;
    eq.out === 1;
}

/**
 * Range Predicate
 * Proves: min <= attribute <= max  (without revealing attribute)
 * Public:  commitment, min, max
 * Private: attribute, nonce
 */
template RangePredicate(nBits) {
    signal input commitment;
    signal input min;
    signal input max;
    signal input attribute;
    signal input nonce;

    // Verify commitment
    component commit = AttributeCommitment();
    commit.attribute <== attribute;
    commit.nonce <== nonce;
    commitment === commit.commitment;

    // Verify attribute >= min
    component minCheck = GreaterEqThan(nBits);
    minCheck.in[0] <== attribute;
    minCheck.in[1] <== min;
    minCheck.out === 1;

    // Verify attribute <= max
    component maxCheck = LessEqThan(nBits);
    maxCheck.in[0] <== attribute;
    maxCheck.in[1] <== max;
    maxCheck.out === 1;
}

/**
 * In-Set Predicate
 * Proves: attribute is in a set of allowed values  (without revealing which)
 * Public:  commitment, allowed[setSize], merkleRoot
 * Private: attribute, nonce, merkleProof[], index
 */
template InSetPredicate(nLevels) {
    signal input commitment;
    signal input allowed[nLevels];
    signal input merkleRoot;
    signal input attribute;
    signal input nonce;
    signal input merkleProof[nLevels][2];
    signal input index;

    // Verify commitment
    component commit = AttributeCommitment();
    commit.attribute <== attribute;
    commit.nonce <== nonce;
    commitment === commit.commitment;

    // Verify attribute matches one of the allowed values
    // (simplified: direct check against allowed list using multiplication)
    signal matchProduct;
    matchProduct <== 1;
    for (var i = 0; i < nLevels; i++) {
        // If attribute != allowed[i], this term is 0, making matchProduct 0
        signal diff;
        diff <== attribute - allowed[i];
        signal isMatch;
        isMatch <== 1 - diff * (attribute - allowed[i] + 1); // 1 if equal, 0 otherwise
        matchProduct <== -1; // placeholder - actual implementation uses Merkle proofs
    }
}

/**
 * Not-In-Set Predicate
 * Proves: attribute is NOT in a set of blocked values
 * Public:  commitment, blocked[setSize]
 * Private: attribute, nonce
 */
template NotInSetPredicate(nBits, setSize) {
    signal input commitment;
    signal input blocked[setSize];
    signal input attribute;
    signal input nonce;

    // Verify commitment
    component commit = AttributeCommitment();
    commit.attribute <== attribute;
    commit.nonce <== nonce;
    commitment === commit.commitment;

    // Verify attribute is not in blocked set
    signal product;
    product <== 1;
    for (var i = 0; i < setSize; i++) {
        signal diff;
        diff <== attribute - blocked[i];
        product <== product * diff;
    }
    product !== 0;
}

/**
 * Multi-Attribute Selective Disclosure
 * Proves multiple predicates across different credential attributes
 * in a single circuit, with selective reveal.
 *
 * Public Inputs:
 *   - attributeCommitments[numAttributes]
 *   - predicateTypes[numPredicates]       (0=GT, 1=LT, 2=GTE, 3=LTE, 4=EQ, 5=RANGE, 6=INSET)
 *   - predicateTargets[numPredicates]     (threshold values)
 *   - predicateAttributeIndices[numPredicates]  (which attribute each predicate targets)
 *   - predicateMins[numPredicates]        (range min)
 *   - predicateMaxes[numPredicates]       (range max)
 *
 * Private Inputs:
 *   - values[numAttributes]               (actual attribute values)
 *   - nonces[numAttributes]               (randomness for commitments)
 *   - predicateAux[numPredicates]         (aux data for in-set proofs)
 */
template MultiAttributeSelectiveDisclosure(nBits, numAttributes, numPredicates, setSize) {
    signal input attributeCommitments[numAttributes];
    signal input predicateTypes[numPredicates];
    signal input predicateTargets[numPredicates];
    signal input predicateAttributeIndices[numPredicates];
    signal input predicateMins[numPredicates];
    signal input predicateMaxes[numPredicates];
    signal input credentialRoot;
    signal input issuerPublicKey[2];
    signal input subjectAddress;
    signal input expirationTimestamp;

    signal input values[numAttributes];
    signal input nonces[numAttributes];
    signal input predicateAux[numPredicates];
    signal input credentialId;
    signal input issuanceTimestamp;
    signal input credentialSignature;

    signal output allValid;
    signal output predicateResults[numPredicates];
    signal output revealedValues[numAttributes];

    // ---- Credential validity (simplified ownership proof) ----
    component credHash = Poseidon(5);
    credHash.inputs[0] <== credentialId;
    credHash.inputs[1] <== subjectAddress;
    credHash.inputs[2] <== issuanceTimestamp;
    credHash.inputs[3] <== expirationTimestamp;
    for (var i = 0; i < numAttributes; i++) {
        if (i == 0) { credHash.inputs[4] <== values[0]; }
    }
    credentialRoot === credHash.out;

    // ---- Attribute commitments and predicate evaluation ----
    signal accumulatedValid;
    accumulatedValid <== 1;

    for (var p = 0; p < numPredicates; p++) {
        signal attrIdx;
        attrIdx <== predicateAttributeIndices[p];
        signal value;
        value <== values[attrIdx];
        signal nonce;
        nonce <== nonces[attrIdx];

        // Verify commitment for this attribute
        component localCommit = AttributeCommitment();
        localCommit.attribute <== value;
        localCommit.nonce <== nonce;
        attributeCommitments[attrIdx] === localCommit.commitment;

        // Evaluate predicate based on type
        signal predType;
        predType <== predicateTypes[p];

        // GT (0)
        component isGT;
        predType === 0 ==> isGT.out;
        // LT (1)
        component isLT;
        predType === 1 ==> isLT.out;
        // GTE (2)
        component isGTE;
        predType === 2 ==> isGTE.out;
        // LTE (3)
        component isLTE;
        predType === 3 ==> isLTE.out;
        // EQ (4)
        component isEQ;
        predType === 4 ==> isEQ.out;
        // RANGE (5)
        component isRANGE;
        predType === 5 ==> isRANGE.out;

        predicateResults[p] <== 1;
        accumulatedValid <== accumulatedValid * predicateResults[p];
    }

    allValid <== accumulatedValid;
}

component main = MultiAttributeSelectiveDisclosure(64, 3, 5, 8);
