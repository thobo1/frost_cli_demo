use clap::{Arg, Command};

pub fn parse_args() -> Result<(String, String, String, u32, u32), String> {
    let matches = Command::new("FROST Threshold Signature CLI")
        .version("1.0")
        .author("Anthony")
        .about(
            "Generates a public key, shares private keys, and signs a message using FROST protocol",
        )
        .arg(
            Arg::new("message")
                .help("The message to sign")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("output_key")
                .short('k')
                .long("output-key")
                .help("Output file for the group public key")
                .default_value("public_key.txt"),
        )
        .arg(
            Arg::new("output_signature")
                .short('s')
                .long("output-signature")
                .help("Output file for the threshold signature")
                .default_value("signature.txt"),
        )
        .arg(
            Arg::new("participants")
                .short('p')
                .long("participants")
                .help("The number of participants in the threshold scheme (minimum 3)")
                .default_value("3"),
        )
        .arg(
            Arg::new("threshold")
                .short('t')
                .long("threshold")
                .help("The number of participants required for a successful signature")
                .default_value("2"),
        )
        .get_matches();

    let message = matches
        .get_one::<String>("message")
        .expect("Message required")
        .clone();
    let output_key = matches.get_one::<String>("output_key").unwrap().clone();
    let output_signature = matches
        .get_one::<String>("output_signature")
        .unwrap()
        .clone();
    let participants: u32 = matches
        .get_one::<String>("participants")
        .unwrap()
        .parse()
        .expect("Invalid number of participants");
    let threshold: u32 = matches
        .get_one::<String>("threshold")
        .unwrap()
        .parse()
        .expect("Invalid threshold value");

    // Validate participant and threshold counts
    if participants < 3 {
        return Err("The number of participants must be at least 3.".into());
    }
    if threshold < 2 || threshold > participants {
        return Err(
            "Threshold must be at least 2 and less than or equal to the number of participants."
                .into(),
        );
    }
    if message.is_empty() {
        return Err("Message cannot be empty.".into());
    }
    Ok((
        message,
        output_key,
        output_signature,
        participants,
        threshold,
    ))
}
