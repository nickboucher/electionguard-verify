""" verify.py
    Nicholas Boucher 2020

    Verification code for verifying the integrity and correctness of
    ElectionGuard election results.
"""

from typing import Iterable
from logging import info
from electionguard.election import CiphertextElectionContext, ElectionDescription, ElectionConstants
from electionguard.tally import PublishedCiphertextTally, PublishedPlaintextTally
from electionguard.encrypt import EncryptionDevice
from electionguard.ballot import CiphertextAcceptedBallot
from electionguard.key_ceremony import CoefficientValidationSet

def verify(
    description: ElectionDescription,
    context: CiphertextElectionContext,
    constants: ElectionConstants,
    devices: Iterable[EncryptionDevice],
    ciphertext_ballots: Iterable[CiphertextAcceptedBallot],
    spoiled_ballots: Iterable[CiphertextAcceptedBallot],
    ciphertext_tally: PublishedCiphertextTally,
    plaintext_tally: PublishedPlaintextTally,
    coefficient_validation_sets: Iterable[CoefficientValidationSet] = None
) -> bool:
    """ Returns whether the election results provided as arguments represent
        a valid ElectionGuard election. Verification details can be
        emitted by setting the logging level."""
    info('Validation not implemented.')