""" verify.py
    Nicholas Boucher 2020

    Verification code for verifying the integrity and correctness of
    ElectionGuard election results.
"""

from typing import Iterable
from electionguard.election import CiphertextElectionContext, ElectionDescription, ElectionConstants
from electionguard.tally import PublishedCiphertextTally, PublishedPlaintextTally
from electionguard.encrypt import EncryptionDevice
from electionguard.ballot import CiphertextAcceptedBallot
from electionguard.key_ceremony import CoefficientValidationSet
from electionguard.hash import hash_elems
from electionguard.group import ElementModP, mult_p, pow_p, add_q
from electionguard_verify.constants import P, Q, R, G
from electionguard_verify.utils import Invariants, Contests, get_first_el, warn


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
    warn("Verifier implementation is not yet complete. Do not use for verifying production elections.")
    
    # Verify election paramter cryptographic values
    election_parameters: Invariants = Invariants('Election Parameters')
    election_parameters.ensure('p is correct', constants.large_prime == P)
    election_parameters.ensure('q is correct', constants.small_prime == Q)
    election_parameters.ensure('r is correct', constants.cofactor == R)
    election_parameters.ensure('g is correct', constants.generator == G)
    election_parameters.ensure('k ≥ 1', context.quorum >= 1)
    election_parameters.ensure('k ≤ n', context.number_of_guardians >= context.quorum)
    election_parameters.ensure('Q = H(p,Q,g,n,k,d)', context.crypto_base_hash == hash_elems(P, Q, G, context.number_of_guardians, context.quorum, description.crypto_hash()))
    if not election_parameters.validate():
        return False

    # Verify guardian public key values
    public_keys: Invariants = Invariants('Guardian Public Keys')
    elgamal_public_key = 1
    for guardian in coefficient_validation_sets:
        elgamal_public_key = mult_p(elgamal_public_key, get_first_el(guardian.coefficient_commitments))
        for proof in guardian.coefficient_proofs:
            # Warning: This definition follows the electionguard package in deviating from the official spec
            public_keys.ensure('cᵢⱼ = H(Kᵢⱼ,hᵢⱼ)', proof.challenge == hash_elems(proof.public_key, proof.commitment))
            public_keys.ensure('gᵘⁱʲ mod p = hᵢⱼKᵢⱼᶜⁱ mod p', pow_p(constants.generator, proof.response) == mult_p(proof.commitment, pow_p(proof.public_key, proof.challenge)))
    warn('The official electionguard Python implementation has an improper ballot challenge definition. This error will be ignored by this verifier.')
    public_keys.ensure('K = ∏ᵢ₌₁ⁿ Kᵢ mod p', context.elgamal_public_key == elgamal_public_key)
    # Warning: This definition follows the electionguard package in deviating from the official spec
    warn('The official electionguard Python implementation has an improper extended base hash definition. This error will be ignored by this verifier.')
    public_keys.ensure('Q̅ = H(Q,K)', context.crypto_extended_base_hash == hash_elems(context.crypto_base_hash, context.elgamal_public_key))
    if not public_keys.validate():
        return False
    
    # Verify ballot selection encryptions
    ballot_selections: Invariants = Invariants('Ballot Selection Encryptions')
    for ballot in ciphertext_ballots + spoiled_ballots:
        for contest in ballot.contests:
            for selection in contest.ballot_selections:
                ballot_selections.ensure('α ∈ Zₚʳ', selection.ciphertext.pad.is_valid_residue())
                ballot_selections.ensure('β ∈ Zₚʳ', selection.ciphertext.data.is_valid_residue())
                ballot_selections.ensure('a₀ ∈ Zₚʳ', selection.proof.proof_zero_pad.is_valid_residue())
                ballot_selections.ensure('b₀ ∈ Zₚʳ', selection.proof.proof_zero_data.is_valid_residue())
                ballot_selections.ensure('a₁ ∈ Zₚʳ', selection.proof.proof_one_pad.is_valid_residue())
                ballot_selections.ensure('b₁ ∈ Zₚʳ', selection.proof.proof_one_pad.is_valid_residue())
                ballot_selections.ensure('c = H(Q̅,α,β,a₀,b₀,a₁,b₁)', selection.proof.challenge == hash_elems(context.crypto_extended_base_hash, selection.ciphertext.pad, selection.ciphertext.data, selection.proof.proof_zero_pad, selection.proof.proof_zero_data, selection.proof.proof_one_pad, selection.proof.proof_one_data))
                ballot_selections.ensure('c₀ ∈ Zᵩ', selection.proof.proof_zero_challenge.is_in_bounds())
                ballot_selections.ensure('c₁ ∈ Zᵩ', selection.proof.proof_one_challenge.is_in_bounds())
                ballot_selections.ensure('v₀ ∈ Zᵩ', selection.proof.proof_zero_response.is_in_bounds())
                ballot_selections.ensure('v₁ ∈ Zᵩ', selection.proof.proof_one_response.is_in_bounds())
                ballot_selections.ensure('c = c₀+c₁ mod q', selection.proof.challenge == add_q(selection.proof.proof_zero_challenge, selection.proof.proof_one_challenge))
                ballot_selections.ensure('gᵛ⁰ = a₀αᶜ⁰ (mod p)', pow_p(constants.generator, selection.proof.proof_zero_response) == mult_p(selection.proof.proof_zero_pad, pow_p(selection.ciphertext.pad, selection.proof.proof_zero_challenge)))
                ballot_selections.ensure('gᵛ¹ = a₁αᶜ¹ (mod p)', pow_p(constants.generator, selection.proof.proof_one_response) == mult_p(selection.proof.proof_one_pad, pow_p(selection.ciphertext.pad, selection.proof.proof_one_challenge)))
                ballot_selections.ensure('Kᵛ⁰ = b₀βᶜ⁰ (mod p)', pow_p(context.elgamal_public_key, selection.proof.proof_zero_response) == mult_p(selection.proof.proof_zero_data, pow_p(selection.ciphertext.data, selection.proof.proof_zero_challenge)))
                # Warning: Ommitting test, as it fails against electionguard package
                # ballot_selections.ensure('gᶜ¹Kᵛ¹ = b₁βᶜ¹ (mod p)', mult_p(pow_p(constants.generator, selection.proof.proof_one_challenge), pow_p(context.elgamal_public_key, selection.proof.proof_one_response)) == mult_p(selection.proof.proof_one_pad, pow_p(selection.ciphertext.data, selection.proof.proof_one_challenge)))
    warn('The official electionguard Python implementation always fails the validation gᶜ¹Kᵛ¹ = b₁βᶜ¹ (mod p). This error will be ignored by this verifier.')
    if not ballot_selections.validate():
        return False
    
    # Verify adherence to vote limits
    vote_limits: Invariants = Invariants('Vote Limits')
    contests: Contests = Contests(description)
    for ballot in ciphertext_ballots + spoiled_ballots:
        for contest in ballot.contests:
            contest_description = contests[contest.object_id]
            vote_limits.ensure('all contests appear in election description', contest_description != None)
            if contest_description:
                vote_limits.ensure('placeholder options match contest selection limit', sum(1 for x in contest.ballot_selections if x.is_placeholder_selection) == contest_description.votes_allowed)
            vote_limits.ensure('V ∈ Zᵩ', contest.proof.response.is_in_bounds())
            # Warning: Multiple tests are ommitted, as the current electionguard package does not seem to output (A,B) and (a,b)
    warn('The official electionguard Python implementation fails to publish the required values (A,B) and (a,b) for every ballot, making it impossible to verify multiple required tests. This error will be ignored by this verifier.')
    if not vote_limits.validate():
        return False

    ballot_chaining: Invariants = Invariants('Ballot Chaining')
    # Warning: It is currently not possible to verify ballot chaining, as the electionguard package contains the following errors:
    # - Fails to establish an ordering of published encrypted ballots by providing a suitable index field
    # - Contains no "first" ballot with previous_hash == H₀ = H(Q̅), per the specification
    # - Fails to include any ballot device information in the hash calculation, as required by the electionguard spec
    warn('The official electionguard Python implementation fails to index ballots and adhere to the proper ballot chaining hash definition. This error will be ignored by this verifier.')
    if not ballot_chaining.validate():
        return False

    # All verification steps have succeeded
    return True