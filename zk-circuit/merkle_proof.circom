pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

template MerkleTreeInclusionProof(nLevels) {
    signal input leaf;
    signal input path_elements[nLevels];
    signal input path_index[nLevels];
    signal output root;

    component hashers[nLevels];
    component muxers[nLevels];

    signal levelHashes[nLevels + 1];
    levelHashes[0] <== leaf;

    signal left[nLevels];
    signal right[nLevels];

    for (var i = 0; i < nLevels; i++) {
        // Muxer to select order based on path_index
        // path_index == 0 => Left=levelHashes[i], Right=path_elements[i]
        // path_index == 1 => Left=path_elements[i], Right=levelHashes[i]
        
        // We can use a simple if-logic or a DualMux.
        // Left = levelHashes[i] + path_index * (path_elements[i] - levelHashes[i])
        // Right = path_elements[i] - path_index * (path_elements[i] - levelHashes[i])
        
        left[i] <== levelHashes[i] + path_index[i] * (path_elements[i] - levelHashes[i]);
        right[i] <== path_elements[i] - path_index[i] * (path_elements[i] - levelHashes[i]);

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[nLevels];
}

component main {public [leaf]} = MerkleTreeInclusionProof(10);
