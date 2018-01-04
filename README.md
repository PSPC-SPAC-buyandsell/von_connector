# von_connector
As part of the technology demonstrator project using Hyperledger indy to explore the use of the distributed ledger with PSPC Supplier Registration Information (SRI), the design specifies agents with service wrapper APIs to facilitate interoperability. This package uses django to implement the service wrapper API code implenting VON connector layer.

The current state of the project aims to fulfil a demonstration use case enabling collaboration between the SRI and the British Columbia government's The Org Book project, underpinning its Verified Organization Network (VON).

The demonstration defines several agents:
  - the Trust Anchor as:
    - schema originator
    - agent registrar on the distributed ledger
  - the SRI agent as:
    - a verifier of claims that the BC Registrar issues and the Org Book proves
    - an issuer for its own claims of SRI registration.
  - the PSPC Org Book as:
    - a verifier of claims that the BC Registrar issues and the Org Book proves
    - a W3C claims holder and indy-sdk prover for SRI claims of SRI registration.
  - the BC Registrar as an issuer
  - the BC Org Book as a W3C claims holder and indy-sdk prover for BC Registrar-issued claims

## Documentation
The design document is available from the `von_base` repository (<https://github.com/PSPC-SPAC-buyandsell/von_base.git>) at `doc/agent-design.doc`. It discusses in detail the packages comprising the technology demonstrator project:
  - `von_base`
  - `von_agent`
  - `von_connector`

including instructions for installation, configuration, and operation.
