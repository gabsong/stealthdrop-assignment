global CANDIDATES: Field = 2;

use dep::std;
use dep::ecrecover;

fn main(
  pub_key: [u8; 64],
  signature: [u8; 64],
  hashed_message: pub [u8; 32],
  polynomial: [Field; CANDIDATES + 1],
  polynomial_commitment: pub Field,
  nullifier: pub [u8; 32],
) {
  // #1. The validity of an ECDSA signature's origin from a particular public key
  // https://github.com/colinnielsen/ecrecover-noir/tree/main
  let key = ecrecover::secp256k1::PubKey::from_unified(pub_key);

  // Combines verify_sig and to_eth_address, so we can verify the validity of the signature,
  // and also obtain the eth address
  let eth_address = key.ecrecover(signature, hashed_message);

  // #2. The inclusion of the public key in the polynomial
  // Verify that the public polynomial_commitment is in fact the hash of the polynomial
  // Note: polynomial is already an array, insert directly as input to pedersen
  assert(std::hash::pedersen(polynomial)[0] == polynomial_commitment);

  // Check if eth_address is a root of the polynomial for eligibility
  assert(evaluate_polynomial(polynomial, eth_address) == 0x);

  // #3. The hash of the signature (also called nullifier) is derived from the signature, it helps in preventing double-claiming
  // Verify that the public nullifier is in fact the hash of the signature
  let sig_hash = std::hash::blake2s(signature);
  assert(sig_hash == nullifier);

  // Questions: 
  // - Where in the repo do we prevent double claiming?
  // - What else can I run other than the steps below?

  // Results:
  // - nargo check - OK
  // - nargo test - OK
  // - nargo prove circuits - OK, generates circuits/proofs/circuits.proof
  // - nargo verify circuits - OK, no errors
}

fn evaluate_polynomial(polynomial: [Field; CANDIDATES + 1], x: Field) -> Field {
  // input polynomial is an array of Fields, length is 3; means it's a 2nd degree
  // the value of `x` that satisfies the polynomial should result in a zero sum
  // i.e. A*x^2 + B*x^1 + C*x^0 = 0
  let mut sum: Field = 0;
  for i in 0..polynomial.len() {
    sum += polynomial[i] * x.pow_32(i);
  }
  sum
}

#[test]
fn test_main() {
  let pub_key = [131,  24,  83,  91,  84,  16,  93,  74,  122,  174,  96,  192,  143,  196,  95,  150,  135,  24,  27,  79,  223,  198,  37,  189,  26,  117,  63,  167,  57,  127,  237,  117,  53,  71,  241,  28,  168,  105,  102,  70,  242,  243,  172,  176,  142,  49,  1,  106,  250,  194,  62,  99,  12,  93,  17,  245,  159,  97,  254,  245,  123,  13,  42,  165];
  let signature = [1,  83,  82,  167,  184,  77,  226,  104,  5,  27,  151,  91,  202,  127,  17,  183,  75,  31,  190,  253,  159,  116,  155,  13,  24,  178,  40,  165,  129,  90,  103,  204,  42,  164,  230,  62,  73,  181,  169,  61,  251,  221,  128,  221,  14,  19,  179,  25,  107,  132,  10,  188,  149,  0,  197,  52,  151,  239,  244,  103,  215,  224,  56,  242];

  let hashed_message = [3,  57, 199, 96, 145, 58, 183, 241, 206, 140, 36, 34, 165, 163, 17, 210, 97, 254, 154, 79, 91, 223, 149, 18, 3, 210, 111, 56, 246, 219, 19, 104];

  let polynomial = [
    0x0832c9fedf291cc3adf56eefd21ac09630c66ad67747329385c9fcfc7cbf8d38,
    0x30644e72e131a029b85045b51d480807486e4c754ae9f95bbfba6db6d86a63d3,
    0x01
  ];

  let polynomial_commitment = 0x1eceef64088bbbeb280bee01b3f4e611137e8d0ac5a868f538e4617df5c62ec2;
  let nullifier = [142,  197,  227,  35,  35,  142,  255,  176,  38,  63,  247,  168,  33,  178,  55,  202,  46,  76,  167,  202,  130,  208,  59,  14,  151,  19,  144,  228,  58,  37,  10,  101];

  main(pub_key, signature, hashed_message, polynomial, polynomial_commitment, nullifier);
}

