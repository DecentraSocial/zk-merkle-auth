pragma circom 2.1.5;

include "babyjub.circom";
include "poseidon.circom";
include "binary-merkle-root.circom";
include "comparators.circom";

template Semaphore(MAX_DEPTH) {

    signal input merkleProofLength, merkleProofIndices[MAX_DEPTH], merkleProofSiblings[MAX_DEPTH];
    signal input message;
    signal input scope;

    // Output signals.
    // The output signals are all public.
    signal output merkleRoot, nullifier;

    // The secret scalar must be in the prime subgroup order 'l'.
    var l = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    component isLessThan = LessThan(251);
    isLessThan.in <== [secret, l];
    isLessThan.out === 1;

    // Identity generation.
    // The circuit derives the EdDSA public key from a secret using
    // Baby Jubjub (https://eips.ethereum.org/EIPS/eip-2494),
    // which is basically nothing more than a point with two coordinates.
    // It then calculates the hash of the public key, which is used
    // as the commitment, i.e. the public value of the Semaphore identity.
    var Ax, Ay;
    (Ax, Ay) = BabyPbk()(secret);

    var identityCommitment = Poseidon(2)([Ax, Ay]);

    merkleRoot <== BinaryMerkleRoot(MAX_DEPTH)(identityCommitment, merkleProofLength, merkleProofIndices, merkleProofSiblings);

    nullifier <== Poseidon(2)([scope, secret]);

    signal dummySquare <== message * message;
}
