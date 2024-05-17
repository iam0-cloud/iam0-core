struct ChallangeVerify {
    spec: Spec,
    spec_signature: Signature,
    challenge: todo!(),
    challenge_signature: Signature,
    commitment: todo!(),
    proof: Proof
}

enum ChallengeError {
    InvalidSignature,
    FailedChallenge
}

async fn challenge() -> Result<(), ChallengeError> {
    todo!()
} 