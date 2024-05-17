enum Spec {
    RSA(RSASpec),
    EllipticCurve(EllipticCurveSpec)
}

enum RSASpec {
    Standard(String),
    Custom(EllipticCurvePoint)
}

enum EllipticCurve {
    Standard(String),
    Custom {
        a: BigUint,
        b: BigUint,
        p: BigUint,
        g: EllipticCurvePoint 
    }
}

struct ClientSpec {
    available: Vec<Spec>
}

#[derive(Debug, Error)]
enum SelectionError {
    #[error("no valid method available")]
    NoValidMethod
}

struct SelectedSpec {
    spec: Spec,
    spec_signature: Signature
}

/// Select from the available methods the best one and return it with a signature that the
/// next endpoint will be able to use 
async fn spec(config: Arc<Config>, specs: ClientSpec) -> result<SelcetedSpec, SelectionError> {
    todo!()
}