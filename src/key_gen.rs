use XorName;
use id::FullId;
use rust_sodium::crypto::sign;

const MAX_KEY_TRIES: usize = 10_000_000_000;

/// Generate a new signing key pair and return the old one.
pub fn generate_key((start, end): (XorName, XorName),
                    full_id: &mut FullId)
                    -> Result<(sign::PublicKey, sign::SecretKey), ()> {
    let original_keys = full_id.replace_signing_keys(sign::gen_keypair());

    for _ in 0..MAX_KEY_TRIES {
        let name = *full_id.public_id().name();
        if name.between(&start, &end) {
            return Ok(original_keys);
        }
        drop(full_id.replace_signing_keys(sign::gen_keypair()));
    }

    error!("Timed out generating a key to match [{:?},{:?}]",
           start,
           end);
    Err(())
}
