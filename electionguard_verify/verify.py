""" verify.py
    Nicholas Boucher 2020

    Verification code for verifying the integrity and correctness of
    ElectionGuard election results.
"""

from typing import Iterable
from logging import info, warning, error
from electionguard.election import CiphertextElectionContext, ElectionDescription, ElectionConstants
from electionguard.tally import PublishedCiphertextTally, PublishedPlaintextTally
from electionguard.encrypt import EncryptionDevice
from electionguard.ballot import CiphertextAcceptedBallot
from electionguard.key_ceremony import CoefficientValidationSet
from electionguard.hash import hash_elems
from electionguard_verify.constants import P, Q, R, G

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

    # Warn users that this implementation is currently incomplete
    error("Verifier implementation is not yet complete. Do not use for testing production elections.")
    
    # Verify election paramter cryptographic values
    if (
            constants.large_prime == P and
            constants.small_prime == Q and
            constants.cofactor == R and
            constants.generator == G and
            context.quorum >= 1 and
            context.number_of_guardians >= context.quorum and
            context.crypto_base_hash == hash_elems(P, Q, G, context.number_of_guardians, context.quorum, description.crypto_hash())
        ):
        info("Election parameters are valid.")
    else:
        warning("Election parameters are invalid.")
        return False
    
    # All verification steps have succeeded
    return True