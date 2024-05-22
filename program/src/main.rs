use sha2::{Sha384, Digest};
use alloy_primitives::FixedBytes;
use bls_signatures::{PublicKey, Signature, verify_messages, Serialize};

use alloy_sol_types::{sol, SolValue};

sol! {
    struct PublicInputs {
        bytes merkle_root;
        bytes leaf;
        bytes bls_pubkey;
        bytes bls_signature;
    }
}

use serde::Deserialize;

// Function to verify a Merkle proof
fn compute_merkle_root(leaf: FixedBytes<48>, merkle_path: [[u8; 48]; 256]) -> [u8; 48] {
    let mut hash = Sha384::digest(leaf.as_slice());
    
    for sibling in merkle_path {
        let sibling_slice = sibling.as_slice();
        let mut combined = Vec::with_capacity(96);
        if hash.as_slice() < sibling_slice {
            combined.extend_from_slice(&hash);
            combined.extend_from_slice(&sibling_slice);
        } else {
            combined.extend_from_slice(&sibling_slice);
            combined.extend_from_slice(&hash);
        }
        hash = Sha384::digest(&combined);
    }
    
    let mut result = [0u8; 48];
    result.copy_from_slice(hash.as_slice());
    result
}

#[derive(Debug, Deserialize)]
struct PrivateInputs {
    pub merkle_root: FixedBytes<48>,
    pub leaf: FixedBytes<48>,
    pub bls_pubkey: FixedBytes<48>, // BLS public key size will always be 48 bytes
    pub bls_signature: FixedBytes<96>, // BLS signature size will always be 96 bytes
    pub serialized_path: FixedBytes<12288> // 48 * 256 length
}

#[no_main]
sp1_zkvm::entrypoint!(main);
pub fn main() {

    let private_inputs = sp1_zkvm::io::read::<PrivateInputs>();
    // let leaf: FixedBytes<48>= env::read();
    // let bls_pubkey: FixedBytes<48> = env::read(); // BLS public key size will always be 48 bytes
    // let bls_signature: FixedBytes<96> = env::read(); // BLS public key size will always be 96 bytes
    // let serialized_path: FixedBytes<12288> = env::read(); // 48 * 256 length

    let merkle_path: [[u8; 48]; 256] = private_inputs.serialized_path.chunks_exact(48).map(|chunk| {
        let mut arr = [0u8; 48];
        arr.copy_from_slice(chunk);
        arr
    }).collect::<Vec<[u8; 48]>>().try_into().unwrap();


    println!("private inputs: {:?}", private_inputs);


    let computed_root: [u8; 48] = compute_merkle_root(private_inputs.leaf, merkle_path);
    
    println!("computed_root: {:?}", computed_root);

    assert_eq!(computed_root, private_inputs.merkle_root.as_slice());

    // Verify the BLS signature
    let pubkey = PublicKey::from_bytes(&private_inputs.bls_pubkey.as_slice()).expect("Invalid public key");
    let signature = Signature::from_bytes(&private_inputs.bls_signature.as_slice()).expect("Invalid signature");

    println!("PublicKey: {:?}", private_inputs.bls_pubkey);
    println!("Signature: {:?}", private_inputs.bls_signature);
    
    assert!(verify_messages(&signature, &[computed_root.as_slice()], &[pubkey]), "Invalid verification");

    // Encocde the public values of the program.
    let public_inputs: PublicInputs = PublicInputs {
        merkle_root: computed_root.to_vec().into(),
        leaf: private_inputs.leaf.to_vec().into(),
        bls_pubkey: private_inputs.bls_pubkey.to_vec().into(),
        bls_signature: private_inputs.bls_signature.to_vec().into()
    };
    // Commit to the public values of the program.
    sp1_zkvm::io::commit_slice(&(public_inputs.abi_encode()));

}