global MAX_SHARE: u32 = 3;
global SECRET_SHARE_T: u32 = 3;
global MAX_DATA_LENGTH: u32 = 900;
global MAX_ISSUER_LENGTH: u32 = 100;
global MAX_AUDIENCE_LENGTH: u32 = 100;

fn main(
   x_coords: [Field; MAX_SHARE],
   y_coords: [Field; MAX_SHARE],
   share: pub [Field; 2],
   data: BoundedVec<u8, MAX_DATA_LENGTH>,  // Encoded JWT token
   b64_offset: u32,                        // Base64 offset for signature
   pubkey_modulus_limbs: pub [Field; 18],  // RSA modulus
   redc_params_limbs: pub [Field; 18],         // RSA reduction parameters
   signature_limbs: pub [Field; 18],           // RSA signature
   domain: BoundedVec<u8, MAX_AUDIENCE_LENGTH>, // Expected audience
   issuer: BoundedVec<u8, MAX_ISSUER_LENGTH>,  // Expected issuer
   current_time: u64                     // Current timestamp
) {
    let sub = id_token::verify(
        data,
        b64_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
        domain,
        issuer,
        current_time
    );

    // verify secret share
    let mut share_exists = false;
    for i in 0..MAX_SHARE {
        if (x_coords[i] == share[0]) & (y_coords[i] == share[1]) {
            share_exists = true;
        }
    }

    assert(share_exists, "share is exist in share array");

    let reconstructed_secret = shamir_secret_sharing::shamir_reconstruct::<SECRET_SHARE_T>(x_coords, y_coords);

    let arrSub = sub.storage();
    let bts: [u8; 32] = reconstructed_secret.to_le_bytes();

    let subPtr: u32 = sub.len() + 32;
    let mut mtch = true;
    for i in 0..32 {
        if (subPtr - i -1 >= 32 ) & mtch {
            mtch = arrSub[subPtr - i - 33] == bts[i];
        }
    }

    assert(mtch, "share not match");
}
