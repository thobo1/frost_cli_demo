use crate::keygen::ParticipantWithKey;
use std::fmt::Debug;
use std::fs::File;
use std::io::{self, Write};

pub fn save_to_file(filename: &str, data: &impl Debug) -> io::Result<()> {
    let mut file = File::create(filename)?;
    writeln!(file, "{:?}", data)?;
    Ok(())
}

// Save each participant's private key to a separate file
pub fn save_participant_keys(participant_keys: &Vec<ParticipantWithKey>) {
    for (i, participant_key) in participant_keys.iter().enumerate() {
        let filename: String = format!("participant_{}_private_key.txt", i + 1);
        let _ = save_to_file(&filename, &participant_key.private_key).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("Error saving participant {}'s private key: {}", i + 1, e),
            )
        });
    }
}
