use bls_signature_aggregator::{Error, Proof, ProofShare, SignatureAggregator};

#[derive(Default)]
pub(crate) struct MessageAccumulator(SignatureAggregator);

impl MessageAccumulator {
    pub fn add(&mut self, payload: &[u8], proof_share: ProofShare) -> Result<Proof, Error> {
        self.0.add(payload, proof_share)
    }
}
