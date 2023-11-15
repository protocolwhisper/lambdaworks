use lambdaworks_math::{
    cyclic_group::IsGroup,
    elliptic_curve::short_weierstrass::{
        curves::bls12_381::{
            curve::BLS12381Curve, pairing::BLS12381AtePairing, twist::BLS12381TwistCurve,
        },
        point::ShortWeierstrassProjectivePoint,
    },
    elliptic_curve::traits::{IsEllipticCurve, IsPairing},
    field::{
        element::FieldElement,
        fields::montgomery_backed_prime_fields::{IsModulus, U384PrimeField},
    },
    unsigned_integer::element::{UnsignedInteger, U384},
};
use num_bigint::{BigUint, RandBigInt};
use num_traits::Num;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

pub type G2Point = <BLS12381TwistCurve as IsEllipticCurve>::PointRepresentation;

#[derive(Clone, Debug)]
pub struct U384ModulusP;

impl IsModulus<U384> for U384ModulusP {
    const MODULUS: U384 = U384::from_hex_unchecked("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
}

type U384FP = U384PrimeField<U384ModulusP>;
type U384FPElement = FieldElement<U384FP>;

fn generate_privatekey() -> U384FPElement {
    let max_value_str = "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787"; // Base field r
    let max_value = BigUint::from_str_radix(max_value_str, 10).unwrap();

    let mut rng = rand::thread_rng();

    // Calculate the number of bits in the maximum value
    let max_bits = max_value.bits(); //381
    let mut random_biguint;

    loop {
        // Generate a random BigUint with a number of bits up to max_bits
        random_biguint = rng.gen_biguint(max_bits);

        // Check if the generated number is within the desired range
        if random_biguint <= max_value {
            break;
        }
    }
    let sk: U384FPElement = U384FPElement::new(UnsignedInteger::from_hex_unchecked(
        &random_biguint.to_str_radix(16),
    )); // // It must be fixed
    sk
}

pub fn publickey_g1(secret: U384FPElement) -> ShortWeierstrassProjectivePoint<BLS12381Curve> {
    let _g_1: ShortWeierstrassProjectivePoint<BLS12381Curve> = BLS12381Curve::generator();

    // Public Key:
    let pk: ShortWeierstrassProjectivePoint<BLS12381Curve> =
        _g_1.operate_with_self(secret.representative());
    pk
}

pub fn hash(msg: &str) -> ShortWeierstrassProjectivePoint<BLS12381TwistCurve> {
    // This function must be fixed
    let _g_2: ShortWeierstrassProjectivePoint<BLS12381TwistCurve> = BLS12381TwistCurve::generator();

    // Message:
    let mut hasher = Shake128::default();
    hasher.update(msg.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut res1 = [0u8; 10];
    reader.read(&mut res1);

    let mut final_hash: u128 = 0;
    for byte in &res1 {
        final_hash <<= 8;
        final_hash |= *byte as u128;
    }

    let hash: ShortWeierstrassProjectivePoint<BLS12381TwistCurve> =
        _g_2.operate_with_self(final_hash);
    hash
}

pub fn signer_bls(
    hash: ShortWeierstrassProjectivePoint<BLS12381TwistCurve>,
    sk: U384FPElement,
) -> ShortWeierstrassProjectivePoint<BLS12381TwistCurve> {
    // Signature:
    let _signature: ShortWeierstrassProjectivePoint<BLS12381TwistCurve> =
        hash.operate_with_self(sk.representative());
    _signature
}

pub fn verifying_bls(
    _signature: ShortWeierstrassProjectivePoint<BLS12381TwistCurve>,
    pk: ShortWeierstrassProjectivePoint<BLS12381Curve>,
    hash: ShortWeierstrassProjectivePoint<BLS12381TwistCurve>,
) -> bool {
    let _g_1: ShortWeierstrassProjectivePoint<BLS12381Curve> = BLS12381Curve::generator();
    let p_1 = <BLS12381AtePairing as IsPairing>::compute(&_g_1, &_signature);
    let p_2 = <BLS12381AtePairing as IsPairing>::compute(&pk, &hash);
    p_1 == p_2
}

#[cfg(test)]
mod tests {

    use crate::generate_privatekey;
    use crate::hash;
    use crate::publickey_g1;
    use crate::signer_bls;
    use crate::verifying_bls;

    #[test]
    fn verify_test_1() {
        let msg = "abc";
        let secret = generate_privatekey();
        let public = publickey_g1(secret.clone());
        let hash = hash(msg);
        let signer = signer_bls(hash.clone(), secret);
        let result = verifying_bls(signer, public, hash);
        assert_eq!(result, true);
    }

    #[test]
    fn verify_test_2() {
        let msg = "HelloWorld!";
        let secret = generate_privatekey();
        let public = publickey_g1(secret.clone());
        let hash = hash(msg);
        let signer = signer_bls(hash.clone(), secret);
        let result = verifying_bls(signer, public, hash);
        assert_eq!(result, true);
    }
}
