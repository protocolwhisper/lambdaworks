use lambdaworks_math::{
    elliptic_curve::
        traits::{IsEllipticCurve, IsPairing},
    cyclic_group::IsGroup,
    elliptic_curve::
        short_weierstrass::{
            curves::bls12_381::{
                pairing::BLS12381AtePairing,
                curve::BLS12381Curve,
                twist::BLS12381TwistCurve},
                point::ShortWeierstrassProjectivePoint},
    field::{
        fields::montgomery_backed_prime_fields::{U384PrimeField, IsModulus},
        element::FieldElement},
    unsigned_integer::element::{UnsignedInteger, U384},
    };

use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};

pub type G2Point = <BLS12381TwistCurve as IsEllipticCurve>::PointRepresentation;

#[derive(Clone, Debug)]
pub struct U384ModulusP;

impl IsModulus<U384> for U384ModulusP {
    const MODULUS: U384 = U384::from_hex_unchecked("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
}

type U384FP = U384PrimeField<U384ModulusP>;
type U384FPElement = FieldElement<U384FP>;

pub fn secretkey_g1 () -> U384FPElement {

    // Private Key:
    let sk: U384FPElement = U384FPElement::new(UnsignedInteger::from_hex_unchecked("45")); // It must be fixed
    sk
}

pub fn publickey_g1 (secret: U384FPElement) -> ShortWeierstrassProjectivePoint<BLS12381Curve> {

    let _g_1: ShortWeierstrassProjectivePoint<BLS12381Curve> = BLS12381Curve::generator();

    // Public Key:
    let pk: ShortWeierstrassProjectivePoint<BLS12381Curve> = _g_1.operate_with_self(secret.representative());
    pk
}

pub fn hash(msg: &str) -> ShortWeierstrassProjectivePoint<BLS12381TwistCurve> { // This function must be fixed
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

    let hash: ShortWeierstrassProjectivePoint<BLS12381TwistCurve> = _g_2.operate_with_self(final_hash);
    hash
}

pub fn signer_bls (hash: ShortWeierstrassProjectivePoint<BLS12381TwistCurve>, sk: U384FPElement) -> ShortWeierstrassProjectivePoint<BLS12381TwistCurve> {    

    // Signature:
    let _signature: ShortWeierstrassProjectivePoint<BLS12381TwistCurve> = hash.operate_with_self(sk.representative());
    _signature
}

pub fn verifying_bls (_signature: ShortWeierstrassProjectivePoint<BLS12381TwistCurve>, pk: ShortWeierstrassProjectivePoint<BLS12381Curve>, hash: ShortWeierstrassProjectivePoint<BLS12381TwistCurve>) -> bool {
    let _g_1: ShortWeierstrassProjectivePoint<BLS12381Curve> = BLS12381Curve::generator();
    let p_1 = <BLS12381AtePairing as IsPairing>::compute(&_g_1, &_signature);
    let p_2 = <BLS12381AtePairing as IsPairing>::compute(&pk, &hash);
    p_1 == p_2
}

#[cfg(test)]
mod tests {
    
    use crate::secretkey_g1;
    use crate::publickey_g1;
    use crate::hash;
    use crate::signer_bls;
    use crate::verifying_bls;

    #[test]
    fn verify_test_1() {
        let msg = "abc";
        let secret = secretkey_g1();
        let public = publickey_g1(secret.clone());
        let hash = hash(msg);
        let signer = signer_bls(hash.clone(), secret);
        let result = verifying_bls(signer, public, hash);
        assert_eq!(result, true);
    }

    #[test]
    fn verify_test_2() {
        let msg = "HelloWorld!";
        let secret = secretkey_g1();
        let public = publickey_g1(secret.clone());
        let hash = hash(msg);
        let signer = signer_bls(hash.clone(), secret);
        let result = verifying_bls(signer, public, hash);
        assert_eq!(result, true);
    }
}
