use crate::keygen::ParticipantWithKey;
use frost_dalek::keygen::GroupKey;
use frost_dalek::precomputation::{generate_commitment_share_lists, SecretCommitmentShareList};
use frost_dalek::signature::{compute_message_hash, ThresholdSignature};
use frost_dalek::{Parameters, SignatureAggregator};
use rand::rngs::OsRng;
use std::collections::HashMap;

// Perform signing with the specified threshold and participan
pub fn sign_with_threshold(
    context: &[u8],
    message: &[u8],
    params: Parameters,
    participants_with_key: &Vec<ParticipantWithKey>,
    group_key: GroupKey,
) -> Result<ThresholdSignature, HashMap<u32, &'static str>> {
    let message_hash = compute_message_hash(context, message);
    let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);
    let mut secret_comshares_map: HashMap<u32, SecretCommitmentShareList> = HashMap::new();
    for participant in participants_with_key.iter() {
        let (public_comshares, secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, participant.participant.index, 1);
        aggregator.include_signer(
            participant.participant.index,
            public_comshares.commitments[0],
            participant.public_key.clone(),
        );
        secret_comshares_map.insert(participant.participant.index, secret_comshares);
    }
    let signers = aggregator.get_signers();
    let mut partial_signatures = Vec::new();
    for participant in participants_with_key {
        if let Some(secret_comshares) = secret_comshares_map.get_mut(&participant.participant.index)
        {
            let partial_signature = participant
                .private_key
                .sign(&message_hash, &group_key, secret_comshares, 0, signers)
                .unwrap();

            partial_signatures.push(partial_signature);
        } else {
            eprintln!(
                "No secret commitment shares found for participant {}",
                participant.participant.index
            );
        }
    }
    for signature in partial_signatures {
        aggregator.include_partial_signature(signature);
    }
    let aggregator = aggregator.finalize().unwrap();
    aggregator.aggregate()
}
