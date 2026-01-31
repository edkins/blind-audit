const fs = require('fs');
const path = require('path');
const { buildPoseidon } = require('circomlibjs');
const snarkjs = require('snarkjs');

async function main() {
    const command = process.argv[2];
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    if (command === 'compute-root') {
        const inputDir = process.argv[3];
        const files = fs.readdirSync(inputDir).sort();
        const leaves = [];
        
        for (const file of files) {
            const content = fs.readFileSync(path.join(inputDir, file));
            // Hash content: mimicking the circuit logic if possible
            // For simplicity, let's assume content hash is calculated elsewhere or pass file names?
            // Wait, the circuit usually takes a leaf. 
            // In our python code, we hash the content with SHA256 then convert to Field Element?
            // Or use Poseidon on chunks?
            // Let's use SHA256 hex -> BigInt -> Poseidon(BigInt) as leaf for compatibility?
            // Or simpler: The "file hash" from Python (SHA256) is passed as input.
        }
        // Actually, Python passes a list of hashes.
        
        // Let's change design: input is a JSON file with pre-computed SHA256 hashes converted to strings.
        const headerFile = process.argv[3];
        const data = JSON.parse(fs.readFileSync(headerFile, 'utf8')); 
        // data.leaves: array of hex strings (SHA256)
        
        // Convert to BigInts compatible with BN254
        const leafBigInts = data.leaves.map(h => BigInt('0x' + h) % F.p);
        
        // Build Tree (Naive)
        // Pad with zeros to next power of 2 (or match circuit size, e.g. 10 levels = 1024 leaves)
        let level = leafBigInts;
        while (level.length < 1024) { level.push(BigInt(0)); }
        
        // Compute root
        let currentLevel = level;
        while (currentLevel.length > 1) {
            const nextLevel = [];
            for (let i = 0; i < currentLevel.length; i += 2) {
                const hash = poseidon([currentLevel[i], currentLevel[i+1]]);
                nextLevel.push(F.toObject(hash));
            }
            currentLevel = nextLevel;
        }
        
        console.log(currentLevel[0].toString());
    
    } else if (command === 'generate-proof') {
        const headerFile = process.argv[3];
        const index = parseInt(process.argv[4]);
        const wasmPath = process.argv[5];
        const zkeyPath = process.argv[6];
        
        const data = JSON.parse(fs.readFileSync(headerFile, 'utf8'));
        const leafBigInts = data.leaves.map(h => BigInt('0x' + h) % F.p);
        
        // Pad
        while (leafBigInts.length < 1024) { leafBigInts.push(BigInt(0)); }
        
        // Collect Path
        const pathElements = [];
        const pathIndices = [];
        let curr = index;
        let currentLevel = leafBigInts;
        
        for (let i = 0; i < 10; i++) {
            const isRight = curr % 2;
            const siblingIndex = isRight ? curr - 1 : curr + 1;
            pathElements.push(currentLevel[siblingIndex]);
            pathIndices.push(isRight);
            
            // Next level
            const nextLevel = [];
            for (let j = 0; j < currentLevel.length; j += 2) {
                const hash = poseidon([currentLevel[j], currentLevel[j+1]]);
                nextLevel.push(F.toObject(hash));
            }
            currentLevel = nextLevel;
            curr = Math.floor(curr / 2);
        }
        
        const input = {
            leaf: leafBigInts[index],
            path_elements: pathElements,
            path_index: pathIndices
        };
        
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
        
        console.log(JSON.stringify({ proof, publicSignals }));
    }
}

main().catch(console.error);
