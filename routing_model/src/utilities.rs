// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// This is used two ways: inline tests, and integration tests (with mock).
// There's no point configuring each item which is only used in one of these.

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
pub struct Name(pub i32);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
pub struct Age(i32);

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Attributes {
    pub age: i32,
    pub name: i32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Candidate(pub Attributes);

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Node(pub Attributes);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NodeChange {
    AddResourceProofing(Node),
    Online(Node),
    Relocating(Node),
    Remove(Node),
    Elder(Node, bool),
}

impl NodeChange {
    fn node(&self) -> Node {
        match &self {
            NodeChange::AddResourceProofing(node)
            | NodeChange::Online(node)
            | NodeChange::Relocating(node)
            | NodeChange::Remove(node)
            | NodeChange::Elder(node, _) => *node,
        }
    }

    fn relocating(&self) -> bool {
        match &self {
            NodeChange::Relocating(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct NodeState {
    pub node: Node,
    pub is_elder: bool,
    pub is_relocating: bool,
    pub need_relocate: bool,
    pub is_resource_proofing: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, PartialOrd, Ord, Eq)]
pub struct Section(pub i32);

#[derive(Debug, Clone, Copy, Default, PartialEq, PartialOrd, Ord, Eq)]
pub struct SectionInfo(pub Section, pub i32 /*contain full membership */);

#[derive(Debug, Clone, Copy, Default, PartialEq, PartialOrd, Ord, Eq)]
pub struct GenesisPfxInfo(pub SectionInfo);

#[derive(Debug, Clone, PartialEq)]
pub struct ChangeElder {
    pub changes: Vec<(Node, bool)>,
    pub new_section: SectionInfo,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProofRequest {
    pub value: i32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Proof {
    ValidPart,
    ValidEnd,
    Invalid,
}

impl Proof {
    pub fn is_valid(&self) -> bool {
        match self {
            Proof::ValidPart | Proof::ValidEnd => true,
            Proof::Invalid => false,
        }
    }
}

#[derive(Debug, PartialEq, Default, Copy, Clone)]
pub struct ProofSource(pub i32);

impl ProofSource {
    pub fn next_part(&mut self) -> Proof {
        if self.0 > -1 {
            self.0 -= 1;
        }

        self.resend()
    }

    fn resend(&self) -> Proof {
        if self.0 > 0 {
            Proof::ValidPart
        } else if self.0 == 0 {
            Proof::ValidEnd
        } else {
            Proof::Invalid
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Event {
    Rpc(Rpc),
    ParsecConsensus(ParsecVote),
    LocalEvent(LocalEvent),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Rpc {
    RefuseCandidate(Candidate),
    RelocateResponse(Candidate, SectionInfo),
    RelocatedInfo(Candidate, SectionInfo),

    ExpectCandidate(Candidate),
    ResendExpectCandidate(Section, Candidate),

    ResourceProof {
        candidate: Candidate,
        source: Name,
        proof: ProofRequest,
    },
    ResourceProofReceipt {
        candidate: Candidate,
        source: Name,
    },
    NodeApproval(Candidate, GenesisPfxInfo),

    ResourceProofResponse {
        candidate: Candidate,
        destination: Name,
        proof: Proof,
    },
    CandidateInfo {
        candidate: Candidate,
        destination: Name,
        valid: bool,
    },

    ConnectionInfoRequest {
        source: Name,
        destination: Name,
        connection_info: i32,
    },
    ConnectionInfoResponse {
        source: Name,
        destination: Name,
        connection_info: i32,
    },
}

impl Rpc {
    pub fn to_event(&self) -> Event {
        Event::Rpc(*self)
    }

    pub fn candidate(&self) -> Option<Candidate> {
        match self {
            Rpc::RefuseCandidate(candidate)
            | Rpc::RelocateResponse(candidate, _)
            | Rpc::RelocatedInfo(candidate, _)
            | Rpc::ExpectCandidate(candidate)
            | Rpc::ResendExpectCandidate(_, candidate)
            | Rpc::ResourceProof { candidate, .. }
            | Rpc::ResourceProofReceipt { candidate, .. }
            | Rpc::NodeApproval(candidate, _)
            | Rpc::ResourceProofResponse { candidate, .. }
            | Rpc::CandidateInfo { candidate, .. } => Some(*candidate),

            Rpc::ConnectionInfoRequest { .. } | Rpc::ConnectionInfoResponse { .. } => None,
        }
    }

    pub fn destination(&self) -> Option<Name> {
        match self {
            Rpc::RefuseCandidate(_)
            | Rpc::RelocateResponse(_, _)
            | Rpc::RelocatedInfo(_, _)
            | Rpc::ExpectCandidate(_)
            | Rpc::ResendExpectCandidate(_, _)
            | Rpc::NodeApproval(_, _) => None,

            Rpc::ResourceProof { candidate, .. } | Rpc::ResourceProofReceipt { candidate, .. } => {
                Some(Name(candidate.0.name))
            }

            Rpc::ResourceProofResponse { destination, .. }
            | Rpc::CandidateInfo { destination, .. }
            | Rpc::ConnectionInfoRequest { destination, .. }
            | Rpc::ConnectionInfoResponse { destination, .. } => Some(*destination),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ParsecVote {
    ExpectCandidate(Candidate),
    Online(Candidate),
    PurgeCandidate(Candidate),
    AddElderNode(Node),
    RemoveElderNode(Node),
    NewSectionInfo(SectionInfo),

    RelocationTrigger,
    RefuseCandidate(Candidate),
    RelocateResponse(Candidate, SectionInfo),

    CheckElder,
}

impl ParsecVote {
    pub fn to_event(&self) -> Event {
        Event::ParsecConsensus(*self)
    }

    pub fn candidate(&self) -> Option<Candidate> {
        match self {
            ParsecVote::ExpectCandidate(candidate)
            | ParsecVote::Online(candidate)
            | ParsecVote::PurgeCandidate(candidate)
            | ParsecVote::RefuseCandidate(candidate)
            | ParsecVote::RelocateResponse(candidate, _) => Some(*candidate),

            ParsecVote::AddElderNode(_)
            | ParsecVote::RemoveElderNode(_)
            | ParsecVote::NewSectionInfo(_)
            | ParsecVote::RelocationTrigger
            | ParsecVote::CheckElder => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LocalEvent {
    TimeoutAccept,
    RelocationTrigger,
    TimeoutCheckElder,
    JoiningTimeoutResendCandidateInfo,
    JoiningTimeoutRefused,
    ComputeResourceProofForElder(Name, ProofSource),
}

impl LocalEvent {
    pub fn to_event(&self) -> Event {
        Event::LocalEvent(*self)
    }
}

