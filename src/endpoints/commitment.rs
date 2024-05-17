struct Commitment {
    commitment: todo!(),
    spec: Spec,
    spec_signature: Signature
}

struct Challenge {
    challenge: todo!(),
    challenge_signature: Signature
}

enum CommitmentError {
    InvalidSignature
}

async fn commitment(commitment: Commitment) -> Result<Challenge, CommitmentError> {
    todo!()
}