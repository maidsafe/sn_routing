# Flow for routing add node(Draft)

This describe the flow for adding a Node to a section.

Notes:
- All event loops are common.
  So with `Wait For 0` and `Wait for 1`, first `1` will be processed, and if it did not process an event, `0` will attempt processing. The top most, `0`, will have to process remaining events (could discard them as needed).
- Condition can be split in multiple condition event:
  If a branch not provided, consider the condition never met.

Todo:
- WIP: Destination section flow
- WIP: Source section flow
- **Make Add/Remove Flow symetrical to avoid reaching a point where node is elder in 2 sections and other similar weirdness.**
- Run both source and destination event loops (Remove conflict between Add/Remove)
- Merge/Split

Unanswered Questions:
- Should ParsecExpectCandidate/ParsecRefuseCandidate/ParsecRelocateResponse be a quorum that we are looking for or a single observation?
- How do we ensure that we never forward a request twice? - Quorum?
- What do we do with ParsecExpectCandidate/ParsecRefuseCandidate/ParsecRelocateResponse that never reached quorum? (Is that a bug?)
- Many unknown unknown...


Note:
- ParsecPurgeCandidate/ParsecRefuseCandidate/ParsecRelocateResponse need payload (could be candidate+nonce) so previous candidate not affect current.

# Destination Section Flow
## Top Level Flow

```mermaid
graph TB

    Start --> LoopStart
    LoopEnd --> LoopStart

    style Start fill:#f9f,stroke:#333,stroke-width:4px
    style End fill:#f9f,stroke:#333,stroke-width:4px

    LoopStart --> WaitFor

    WaitFor((Wait for 0:))
    WaitFor --Exit--> End
    WaitFor --RPC--> RPC
    WaitFor --Parsec<br/>consensus--> ParsecConsensus

    RPC((RPC))
    DiscardRPC[Discard RPC]
    RPC --ExpectCandidate--> VoteParsecExpectCandidate
    RPC --ResourceProofResponse<br/>CandidateInfo--> DiscardRPC
    DiscardRPC --> LoopEnd

    ParsecConsensus((Parsec<br/>consensus))
    DiscardParsec["Discard<br/>Parsec<br/>event"]
    ParsecConsensus --ParsecExpectCandidate--> Balanced
    ParsecConsensus --ParsecOnline<br/>ParsecPurgeCandidate<br/>--> DiscardParsec
    DiscardParsec --> LoopEnd

    VoteParsecExpectCandidate[Vote for<br/>ParsecExpectCandidate<br/>to handle the RPC consistently]
    VoteParsecExpectCandidate --> LoopEnd

    Balanced(("Check Candidate?<br/>(shared state)"))
    Balanced -- Not shortest prefix --> Resend
    Balanced -- "Shortest prefix<br/>ProcessingCandidate=yes" --> SendRefuse
    Balanced -- "Shortest prefix<br/>ProcessingCandidate=No" --> SetCandidateYes

    Resend["Resend RPC <br/>ExpectCandidate<br/>to a shorter prefix section"]
    Resend --> LoopEnd

    SendRefuse["Send RPC<br/>RefuseCandidate<br/>to source section"]
    SendRefuse --> LoopEnd

    SetCandidateYes["ProcessingCandidate=yes<br/>(shared state)"]
    SetCandidateYes-->Concurrent0

    Concurrent0{"Concurrent<br/>paths"}
    Concurrent0 --> AcceptAsCandidate
    Concurrent0 --> LoopEnd


    AcceptAsCandidate["AcceptAsCandidate<br/>Sub Routine<br/>(shared state)"]
    style AcceptAsCandidate fill:#f9f,stroke:#333,stroke-width:4px
    AcceptAsCandidate --> ProcessCandidateConsensus

    ProcessCandidateConsensus["ProcessCandidateConsensus<br/>Sub Routine<br/>(shared state)"]
    style ProcessCandidateConsensus fill:#f9f,stroke:#333,stroke-width:4px
    ProcessCandidateConsensus--> SetCandidateNo

    SetCandidateNo["ProcessingCandidate=no<br/>(shared state)"]
    SetCandidateNo-->LoopEnd

```

## AcceptAsCandidate Sub-routine

```mermaid
graph TB
    AcceptAsCandidate["Accept As Candidate<br/> Shared state all peers proceed"]
    EndRoutine["End of AcceptAsCandidate<br/>(shared state)"]
    style AcceptAsCandidate fill:#f9f,stroke:#333,stroke-width:4px
    style EndRoutine fill:#f9f,stroke:#333,stroke-width:4px

    AcceptAsCandidate --> SendRelocateResponse

    SendRelocateResponse["Send RelocateResponse to source section<br/>Start TimeoutAccept"]
    WaitFor(("Wait for 1:<br/><br/>Only current<br/>candidate<br/>events"))
    VoteParsecPurgeCandidate[Vote for<br/>ParsecPurgeCandidate]
    VoteParsecOnline["Vote for<br/>NetworkEvent<br/>::Online<br/><br/>VotedOnline=yes"]
    RequestRP["Send ResourceProof<br/>RPC to candidate<br/><br/>GotCandidateInfo=yes"]
    SendProofReceit["Send receipt<br/>for proof"]

    SendRelocateResponse --> LoopStart
    LoopStart-->WaitFor


    WaitFor -- Consensus any<br/><br/>ParsecOnline<br/>ParsecPurgeCandidate--> EndRoutine

    WaitFor -- ResourceProofResponse<br/><br/>GotCandidateInfo=yes<br/>VotedOnline=no --> ProofResponse((Proof))
    ProofResponse -- Valid Part --> SendProofReceit
    ProofResponse -- Valid End --> VoteParsecOnline

    WaitFor -- CandidateInfo<br/><br/>GotCandidateInfo=no --> Info((Info))
    Info -- Valid<br/>CandidateInfo --> RequestRP
    Info -- Invalid<br/>CandidateInfo --> VoteParsecPurgeCandidate
    WaitFor -- TimeoutAccept<br/>expire --> VoteParsecPurgeCandidate

    RequestRP --> LoopEnd
    SendProofReceit-->LoopEnd
    VoteParsecOnline --> LoopEnd
    VoteParsecPurgeCandidate --> LoopEnd
    LoopEnd --> LoopStart


```


## ProcessCandidateConsensus Sub-routine

```mermaid
graph TB
    ProcessCandidateConsensus["ProcessCandidateConsensus<br/>Sub Routine<br/>(shared state)"]
    EndRoutine["End of ProcessCandidateConsensus<br/>(shared state)"]
    style ProcessCandidateConsensus fill:#f9f,stroke:#333,stroke-width:4px
    style EndRoutine fill:#f9f,stroke:#333,stroke-width:4px

    ProcessCandidateConsensus --> Consensus

    Consensus((Consensus))
    CheckElderChange((Elder<br/>need<br/>Change?))
    VoteSwapNewElder["Vote Add new node<br/>Vote Remove yougest elder<br/>Vote for new section"]
    WaitFor(("Wait for 1:"))
    Consensus -- ParsecPurgeCandidate<br/>consensused --> EndRoutine
    Consensus -- ParsecOnline<br/>consensused --> AddNode
    AddNode --> CheckElderChange
    CheckElderChange -- No --> EndRoutine
    CheckElderChange -- Yes --> VoteSwapNewElder
    VoteSwapNewElder --> LoopStart
    LoopStart --> WaitFor

    WaitFor--"one of the event<br/>consensused in Parsec"--> LoopStart
    WaitFor--"the 3 events <br/>consensused in Parsec"-->EndRoutine


```


# Source Section Flow
## Top Level Flow

```mermaid
graph TB

    Start --> LoopStart
    LoopEnd --> LoopStart

    style Start fill:#f9f,stroke:#333,stroke-width:4px
    style End fill:#f9f,stroke:#333,stroke-width:4px

    LoopStart --> WaitFor

    WaitFor((Wait for 0:))
    WaitFor --Exit--> End
    WaitFor --Event--> Event
    WaitFor --RPC--> RPC
    WaitFor --Parsec<br/>consensus--> ParsecConsensus

    Event((Event))
    Event -- Detect<br/>Relocation<br/>Trigger --> VoteParsecRelocationTrigger
    VoteParsecRelocationTrigger["Vote for<br/>ParsecRelocationTrigger"]
    VoteParsecRelocationTrigger --> LoopEnd

    RPC((RPC))
    RPC --RefuseCandidate<br/>RelocateResponse--> DiscardRPC
    DiscardRPC --> LoopEnd

    ParsecConsensus((Parsec<br/>consensus))
    DiscardParsec["Discard<br/>Parsec<br/>event"]
    Bug["BUG:<br/><br/>Section can only send either<br/>one of these RPC, and only for<br/>the candidate we are Relocating"]

    ParsecConsensus --"ParsecRelocationTrigger<br/>Relocating.is_none()"--> SetRelocating
    ParsecConsensus --"ParsecRelocationTrigger<br/>Relocating.is_some()"--> DiscardParsec
    ParsecConsensus --"Any:<br/><br/>ParsecRefuseCandidate<br/><br/>ParsecRelocateResponse"--> Bug
    Bug
    DiscardParsec --> LoopEnd

    SetRelocating["Relocating=Some(Candidate)<br/>RelocatingState is best<br/>(shared state)"]
    SetRelocating --> Concurrent0

    Concurrent0{"Concurrent<br/>paths"}
    Concurrent0 --> ProcessRelocationConsensus
    Concurrent0 --> LoopEnd

    ProcessRelocationConsensus["ProcessRelocationConsensus<br/>Sub Routine<br/>(shared state)"]
    style ProcessRelocationConsensus fill:#f9f,stroke:#333,stroke-width:4px
    ProcessRelocationConsensus --> TryRelocating

    TryRelocating["TryRelocating<br/>Sub Routine<br/>(shared state)"]
    style TryRelocating fill:#f9f,stroke:#333,stroke-width:4px
    TryRelocating-->ResetRelocating

    ResetRelocating["Relocating=None<br/>(shared state)"]
    ResetRelocating --> LoopEnd
```



## TryRelocating sub-routine

```mermaid
graph TB

    TryRelocating["TryRelocating<br/> Shared state all peers proceed"]
    EndRoutine["End of TryRelocating<br/>(shared state)"]
    style TryRelocating fill:#f9f,stroke:#333,stroke-width:4px
    style EndRoutine fill:#f9f,stroke:#333,stroke-width:4px

    TryRelocating --> SendExpectCandidate

    SendExpectCandidate["Send RPC <br/>ExpectCandidate"]
    SendExpectCandidate --> LoopStart
    LoopStart --> WaitFor
    LoopEnd --> LoopStart

    WaitFor((Wait for 1:<br/><br/>Only current<br/>candidate<br/>events))
    WaitFor --RPC--> RPC
    WaitFor --Parsec consensus<br/><br/>ParsecRefuseCandidate<br/>ParsecRelocateResponse--> Consensus

    Consensus((Consensus))
    Consensus --"ParsecRefuseCandidate"--> EndRoutine
    Consensus --"ParsecRelocateResponse"--> PurgeNodeInfos

    PurgeNodeInfos["Purge Candidate Node info"]
    PurgeNodeInfos--> EndRoutine

    RPC((RPC))
    RPC --RefuseCandidate--> VoteParsecRefuseCandidate
    RPC --RelocateResponse--> VoteParsecRelocateResponse

    VoteParsecRefuseCandidate[Vote for<br/>ParsecRefuseCandidate<br/>to handle the RPC consistently]
    VoteParsecRefuseCandidate --> LoopEnd

    VoteParsecRelocateResponse[Vote for<br/>ParsecRelocateResponse<br/>to handle the RPC consistently]
    VoteParsecRelocateResponse --> LoopEnd

```




## ProcessRelocationConsensus Sub-routine

```mermaid
graph TB
    ProcessRelocationConsensus["ProcessRelocationConsensus<br/>Sub Routine<br/>(shared state)"]
    EndRoutine["End of ProcessRelocationConsensus<br/>(shared state)"]
    style ProcessRelocationConsensus fill:#f9f,stroke:#333,stroke-width:4px
    style EndRoutine fill:#f9f,stroke:#333,stroke-width:4px

    ProcessRelocationConsensus --> CheckCandidate

    CheckCandidate((Check<br/>Candidate?))
    CheckCandidate-- Node=RelocatingState --> EndRoutine
    CheckCandidate-- Not Node=RelocatingState --> MarkAsRelocating

    MarkAsRelocating["Node=RelocatingState"]
    CheckElderChange((Elder<br/>need<br/>Change?))
    VoteSwapNewElder["Vote Remove relocated node<br/>Vote Add oldest Adult<br/>Vote for new section"]
    WaitFor(("Wait for 1:"))
    MarkAsRelocating --> CheckElderChange
    CheckElderChange -- No --> EndRoutine
    CheckElderChange -- Yes --> VoteSwapNewElder
    VoteSwapNewElder --> LoopStart
    LoopStart --> WaitFor

    WaitFor--"one of the event<br/>consensused in Parsec"--> LoopStart
    WaitFor--"the 3 events <br/>consensused in Parsec"-->EndRoutine
```
