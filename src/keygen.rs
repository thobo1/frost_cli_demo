use crate::errors::KeyGenError;
use frost_dalek::keygen::{GroupKey, RoundOne, SecretKey, SecretShare};
use frost_dalek::{DistributedKeyGeneration, IndividualPublicKey, Parameters, Participant};

#[derive(Debug)]
pub struct ParticipantWithKey {
    pub participant: Participant,
    pub public_key: IndividualPublicKey,
    pub private_key: SecretKey,
}

pub fn generate_threshold_keypair(
    params: Parameters,
) -> Result<(GroupKey, Vec<ParticipantWithKey>), KeyGenError> {
    let num_participants = params.n;
    let mut participants = Vec::with_capacity(num_participants as usize);
    let mut coeffs = Vec::with_capacity(num_participants as usize);

    for i in 1..=num_participants {
        let (participant, participant_coeffs) = Participant::new(&params, i);
        participants.push(participant);
        coeffs.push(participant_coeffs);
    }

    verify_proofs(&mut participants)?;

    let mut dkg_states = Vec::with_capacity(num_participants as usize);
    for (i, participant) in participants.iter().enumerate() {
        let other_participants: Vec<Participant> = participants
            .iter()
            .filter(|p| p.index != participant.index)
            .cloned()
            .collect();
        let dkg = DistributedKeyGeneration::new(
            &params,
            &participant.index,
            &coeffs[i],
            &mut other_participants.clone(),
        )
        .map_err(|_| KeyGenError::PublicKeyDerivationFailed)?;
        dkg_states.push(dkg);
    }

    let secret_shares = collect_secret_shares_for_round_one(&mut dkg_states);
    let mut final_states = Vec::with_capacity(num_participants as usize);

    for (i, dkg_state) in dkg_states.into_iter().enumerate() {
        let participant_shares = secret_shares[i].clone();
        final_states.push(
            dkg_state
                .to_round_two(participant_shares)
                .map_err(|_| KeyGenError::VerificationFailed)?,
        );
    }

    let mut group_public_key: Option<GroupKey> = None;
    let mut participants_with_key = Vec::with_capacity(num_participants as usize);

    for (i, final_state) in final_states.into_iter().enumerate() {
        let (group_key, secret_key) = final_state
            .finish(
                participants[i]
                    .public_key()
                    .ok_or(KeyGenError::PublicKeyDerivationFailed)?,
            )
            .map_err(|_| KeyGenError::PublicKeyDerivationFailed)?;

        participants_with_key.push(ParticipantWithKey {
            participant: participants[i].clone(),
            public_key: secret_key.to_public(),
            private_key: secret_key,
        });

        if group_public_key.is_none() {
            group_public_key = Some(group_key.clone());
        } else if group_key != group_public_key.unwrap() {
            return Err(KeyGenError::GroupPublicKeyMismatch);
        }
    }

    Ok((
        group_public_key.ok_or(KeyGenError::PublicKeyDerivationFailed)?,
        participants_with_key,
    ))
}

fn verify_proofs(participants: &mut Vec<Participant>) -> Result<(), KeyGenError> {
    for p in participants.iter() {
        let public_key = p.commitments.get(0).ok_or(KeyGenError::ProofError)?;
        if p.proof_of_secret_key.verify(&p.index, &public_key).is_err() {
            return Err(KeyGenError::ProofError);
        }
    }
    Ok(())
}

fn collect_secret_shares_for_round_one(
    dkg_states: &mut Vec<DistributedKeyGeneration<RoundOne>>,
) -> Vec<Vec<SecretShare>> {
    let mut all_secret_shares: Vec<Vec<SecretShare>> = vec![vec![]; dkg_states.len()];
    for dkg_state in dkg_states.iter_mut() {
        let participant_shares = dkg_state.their_secret_shares().unwrap();
        for share in participant_shares.iter() {
            all_secret_shares[(share.index - 1) as usize].push(share.clone());
        }
    }
    all_secret_shares
}
