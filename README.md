# von_connector
As part of the technology demonstrator project using Hyperledger indy to explore the use of the distributed ledger with PSPC Supplier Registration Information (SRI), the design specifies agents with service wrapper APIs to facilitate interoperability. This package uses django to implement the service wrapper API code implenting VON connector layer.

The current state of the project aims to fulfil a demonstration use case enabling collaboration between the SRI and the British Columbia government's The Org Book project, underpinning its Verified Organization Network (VON).

The demonstration defines four agents:
  - the Trust Anchor as:
    - schema originator
    - agent registrar on the distributed ledger
  - the BC Registrar as an issuer
  - the BC Org Book as, for BC Registrar-issued claims, both
    - a W3C claims holder
    - an indy-sdk prover
  - the PSPC-SRI as:
    - a verifier of claims that the BC Registrar issues and the Org Book proves
    - an issuer holder, and porver for its own claims of SRI registration.

# Prerequisites
Use the directions at `https://github.com/hyperledger/indy-sdk/blob/master/doc/ubuntu-build.md` to:
  - set up the docker `indy_pool` container and the docker `indy_pool_network` network.
  - create a virtual environment on python 3.5

# Installation
To install the package, activate the virtual environment on python 3.5, change to the parent of the installation directory, and then issue:
```
(py35) $ git clone https://github.com/PSPC-SPAC-buyandsell/von_connector.git
(py35) $ cd von_connector
(py35) $ sudo ./configure
(py35) $ pip install -Ur service_wrapper_project/requirements.txt
```

The `configure` script completes the configuration file, wiring the genesis transaction file into the application configuration from the current installation directory, then uncompresses and copies the `libindy.so` binary into `/usr/lib`.

# Using the Agents
The pytest code exercises the four service wrapper APIs above, each delegating to its respective von_agent. To complete the demonstration, a front end may wire the service wrappers to its user interface, providing an accessible view.

To run the test code, activate the virtual environment on python 3.5, then from the installation directory issue:
```
(py35) $ cd service_wrapper_project/wrapper_api/tests
(py35) $ pytest -s test_wrapper.py
```
