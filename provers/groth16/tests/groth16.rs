use lambdaworks_groth16::{common::*, setup, test_circuits::*, verify, Proof, Prover};

#[test]
fn vitalik_1() {
    let qap = vitalik_qap(); // x^3 + x + 5 = 35

    let (pk, vk) = setup(&qap);

    let w = ["0x1", "0x3", "0x23", "0x9", "0x1b", "0x1e"] // x = 3
        .map(FrElement::from_hex_unchecked)
        .to_vec();

    let serialized_proof = Prover::prove(&w, &qap, &pk).serialize();
    let deserialized_proof = Proof::deserialize(&serialized_proof).unwrap();

    let accept = verify(&vk, &deserialized_proof, &w[..qap.num_of_public_inputs]);
    assert!(accept);
}

#[test]
fn vitalik_2() {
    let qap = vitalik_qap(); // x^3 + x + 5 = 35

    let (pk, vk) = setup(&qap);

    let w = ["0x1", "0x1", "0x7", "0x1", "0x1", "0x2"] // x = 1
        .map(FrElement::from_hex_unchecked)
        .to_vec();

    let serialized_proof = Prover::prove(&w, &qap, &pk).serialize();
    let deserialized_proof = Proof::deserialize(&serialized_proof).unwrap();

    let accept = verify(&vk, &deserialized_proof, &w[..qap.num_of_public_inputs]);
    assert!(accept);
}

#[test]
fn qap_2() {
    let qap = test_qap_2();
    let (pk, vk) = setup(&qap);

    // 1, x, y, ~out, sym_1, sym_2, sym_3, sym_4
    let w = ["0x1", "0x5", "0x3", "0x0", "0x19", "0x9", "0x0", "0x0"] // x = 3
        .map(FrElement::from_hex_unchecked)
        .to_vec();

    let serialized_proof = Prover::prove(&w, &qap, &pk).serialize();
    let deserialized_proof = Proof::deserialize(&serialized_proof).unwrap();

    let accept = verify(&vk, &deserialized_proof, &w[..qap.num_of_public_inputs]);
    assert!(accept);
}
