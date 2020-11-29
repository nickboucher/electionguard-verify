# ElectionGuard Verify
An ElectionGuard Verifier, in Python

This repository contains an independent verifier for elections conducted using Microsoft's [ElectionGuard](https://github.com/microsoft/electionguard) system.

:exclamation: | The official [ElectionGuard Python implementation](https://github.com/microsoft/electionguard-python) contains inconsistencies with the ElectionGuard cryptographic specification. Until these are resolved, the ElectionGuard Python implementation should be considered insecure.
:---: | :---

## Overview

ElectionGuard Verify is a Python package and corresponding command line utility which cryptographically verifies the results of election's conducted using Microsoft's [ElectionGuard](https://github.com/microsoft/electionguard) system. This package takes as input the artifacts published as the results of an ElectionGuard election.

This code can be consumed as a Python package used within other applications or as a standalone command line utility.

## Installation

After cloning the repository, ElectionGuard Verify can be installed via:
```bash
# Should be run within the root directory of the cloned repository
pip install .
```

The installation requires Python 3.8+. This requirement is, unfortunately, set by the official `electionguard` Microsoft package which is consumed for useful data structure definitions.

The installation depends on the `gmpy2` Python package, which is a high-performance [library](https://github.com/aleaxit/gmpy) for general multi-precision arithmetic commonly used in cryptographic applications. Many OSs do not ship with the binaries required for this package to work. For example, if you experience installation issues with this dependency on MacOS, you can use the `brew` [package manager](https://brew.sh) to install the missing system dependencies via `brew install libmpc mpfr`. For other platforms, you can find various tutorials on installing this package's dependencies through your search engine of choice.

## Usage

ElectionGuard Verify can be consumed as either a command line utility or a standard Python package.

### Command Line Utility

The command line utility `egverify` is automatically installed and added to the PATH of your current Python environment during installation. This command line utility is the easiest way to use this verifier, as no additional code is required.

To begin verification of an election, simply run the following command:

```bash
egverify RESULTS_DIR
```

where `RESULTS_DIR` is the directory containing the artifacts published as the result of any ElectionGuard election. If no value is provided, the tool will run against the current working directory.

There are a variety of other options that can be specified, although most won't be necessary for standard elections. The key options are:
- `-v`, `--verbose`: This flag configures the verifier to output information about the verification steps while running.
- `-n`, `--no-warn`: This flag will silence all warnings that the verifier outputs. You probably don't want to specify this flag.

Additional options exist to override the default naming conventions of the files in `RESULTS_DIR`. It is very unlikely that these options will need to be specified. To view a full list of options, run `egverify --help`.

### Python

ElectionGuard Verify can also be consumed as a standard Python package, thus allowing ElectionGuard elections to be verified programmatically as part of a larger software pipeline.

There is a single function called `verify` which will perform all steps required to cryptographically verify an ElectionGuard election. It can be imported as:

```python
from electionguard_verify import verify
```

In order to invoke this function, though, you will need to supply it with a deserialized version of the election results. You will likely want to use the official Microsoft `electionguard` package to import the correct data structures and deserialization functions. An example of this can be found in `electionguard_verify/command_line.py`.

The typed function signature of `verify` is:

```python
def verify(
    description: ElectionDescription,
    context: CiphertextElectionContext,
    constants: ElectionConstants,
    devices: Iterable[EncryptionDevice],
    ciphertext_ballots: Iterable[CiphertextAcceptedBallot],
    spoiled_ballots: Iterable[CiphertextAcceptedBallot],
    ciphertext_tally: PublishedCiphertextTally,
    plaintext_tally: PlaintextTally,
    coefficient_validation_sets: Iterable[CoefficientValidationSet] = None
) -> bool
```

The function returns `True` for a valid election and `False` for an invalid election. Logging verbosity level can be set using the Python standard library `logging` [package](https://docs.python.org/3/library/logging.html).

## Feedback

The author of this package invites anyone to review the code for implementation errors. Such a pursuit is likely performed most fruitfully in consultation with the ElectionGuard formal specification, which can be downloaded as human-readable document from the [releases section](https://github.com/microsoft/electionguard/releases) of the primary Microsoft ElectionGuard repository. Knowledge of [modular arithmetic](https://en.wikipedia.org/wiki/Modular_arithmetic) and [zero-knowledge proofs](https://en.wikipedia.org/wiki/Zero-knowledge_proof) will also be helpful. Please open [issues](https://github.com/nickboucher/electionguard-verify/issues) on GitHub for any discovered bugs.

## Disclaimers

This codebase was developed independently of Microsoft. The original author, however, has a Microsoft affiliation as a full-time employee in a non-ElectionGuard organization within Microsoft.
