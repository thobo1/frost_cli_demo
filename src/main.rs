mod args;
mod errors;
mod keygen;
mod sign;
mod utils;

use args::parse_args;
use frost_dalek::signature::compute_message_hash;
use keygen::generate_threshold_keypair;
use sign::sign_with_threshold;
use std::error::Error;
use utils::{save_participant_keys, save_to_file};

fn main() -> Result<(), Box<dyn Error>> {
    println!("Starting secret sharing scheme initialization.");

    // Parse command-line arguments
    let (message, output_key, output_signature, participants, threshold) = match parse_args() {
        Ok(values) => values,
        Err(e) => {
            eprintln!("Erreur de parsing des arguments : {}", e);
            return Err(e.into());
        }
    };

    // Validate message and setup parameters for the threshold scheme
    if message.is_empty() {
        return Err("Message cannot be empty.".into());
    }
    let params = frost_dalek::Parameters {
        t: threshold,
        n: participants,
    };

    // Generate keys for threshold signing
    let (group_key, participants_with_key) = generate_threshold_keypair(params)?;

    // Compute message hash
    let context = b"context";
    let message_hash = compute_message_hash(context, &message.as_bytes());

    // Perform threshold signing
    let signing_result = sign_with_threshold(
        context,
        &message.as_bytes(),
        params,
        &participants_with_key,
        group_key,
    );
    assert!(signing_result.is_ok());
    let threshold_signature = signing_result.unwrap();

    // Verify the generated threshold signature
    let verification_result = threshold_signature.verify(&group_key, &message_hash);
    assert!(verification_result.is_ok());
    // Save the group key, participant key, and threshold signature to disk
    save_participant_keys(&participants_with_key);
    save_to_file(&output_key, &group_key)?;
    save_to_file(&output_signature, &threshold_signature)?;

    println!("Signature validated and saved!");
    Ok(())
}
