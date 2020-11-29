""" command_line.py
    Nicholas Boucher 2020

    Command line utility for reading ElectionGuard election results from files
    and invoking verification utility on the deserialized data.
"""

from os import getcwd
from os.path import join, split
from glob import glob
from typing import Iterable
from argparse import ArgumentParser
from logging import basicConfig, INFO, ERROR
from electionguard.serializable import read_json
from electionguard.election import CiphertextElectionContext, ElectionDescription, ElectionConstants
from electionguard.tally import PublishedCiphertextTally, PlaintextTally
from electionguard.encrypt import EncryptionDevice
from electionguard.ballot import CiphertextAcceptedBallot
from electionguard.key_ceremony import CoefficientValidationSet
from electionguard_verify.verify import verify
from electionguard.publish import (DESCRIPTION_FILE_NAME, CONTEXT_FILE_NAME, CONSTANTS_FILE_NAME, ENCRYPTED_TALLY_FILE_NAME,
                                  TALLY_FILE_NAME, DEVICES_DIR, DEVICE_PREFIX, BALLOTS_DIR, BALLOT_PREFIX, SPOILED_DIR,
                                  COEFFICIENTS_DIR, COEFFICIENT_PREFIX)

# Define constants
EXIT_SUCCESS: int = 0
EXIT_FAILURE: int = 1
READ: str = 'r'
JSON_EXT = '.json'


def main() -> int:
    """Function which reads and deserializes election results into memory via command line arguments
       and then invokes verification function. Primary target of command line utility."""

    # Parse argument from command line
    parser = ArgumentParser(description='ElectionGuard Verifier.')
    parser.add_argument('directory', default=getcwd(), nargs='?', help='Directory containing election files.')
    parser.add_argument('-c', '--context', help='File containing election context JSON, overriding files found in election directory.')
    parser.add_argument('-d', '--description', help='File containing election description JSON, overriding files found in election directory.')
    parser.add_argument('-e', '--encrypted-tally', help='File containing election encrypted tally JSON, overriding files found in election directory.')
    parser.add_argument('-k', '--constants', help='File containing election constants JSON, overriding files found in election directory.')
    parser.add_argument('-t', '--tally', help='File containing election tally JSON, overriding files found in election directory.')
    parser.add_argument('-x', '--devices-prefix', help="Prefix for device JSON file names, overriding default prefix.")
    parser.add_argument('-X', '--devices-dir', help="Directory containing device JSON, overriding election subdirectory.")
    parser.add_argument('-b', '--encrypted-ballots-prefix', help="Prefix for encrypted ballot JSON file names, overriding default prefix.")
    parser.add_argument('-B', '--encrypted-ballots-dir', help="Directory containing encrypted ballots JSON, overriding election subdirectory.")
    parser.add_argument('-s', '--spoiled-ballots-prefix', help="Prefix for spoiled ballot JSON file names, overriding default prefix.")
    parser.add_argument('-S', '--spoiled-ballots-dir', help="Directory containing spoiled ballots JSON, overriding election subdirectory.")
    parser.add_argument('-f', '--coefficients-prefix', help="Prefix for coefficient validation set JSON file names, overriding default prefix.")
    parser.add_argument('-F', '--coefficients-dir', help="Directory containing coefficient validation set JSON, overriding election subdirectory.")
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help='Output vaildation details.')
    parser.add_argument('-n', '--no-warn', default=False, action='store_true', help='Silence all warnings. Has no effect in verbose mode.')
    args = parser.parse_args()

    # Deserialize election results
    context_path: str = args.context or join(args.directory, CONTEXT_FILE_NAME + JSON_EXT)
    with open(context_path, READ) as f:
        context: CiphertextElectionContext = read_json(f.read(), CiphertextElectionContext)

    description_path: str = args.description or join(args.directory, DESCRIPTION_FILE_NAME + JSON_EXT)
    with open(description_path, READ) as f:
        description: ElectionDescription = read_json(f.read(), ElectionDescription)

    ciphertext_tally_path: str = args.encrypted_tally or join(args.directory, ENCRYPTED_TALLY_FILE_NAME + JSON_EXT)
    with open(ciphertext_tally_path, READ) as f:
        ciphertext_tally: PublishedCiphertextTally = read_json(f.read(), PublishedCiphertextTally)

    constants_path: str = args.constants or join(args.directory, CONSTANTS_FILE_NAME + JSON_EXT)
    with open(constants_path, READ) as f:
        constants: ElectionConstants = read_json(f.read(), ElectionConstants)

    plaintext_tally_path: str = args.tally or join(args.directory, TALLY_FILE_NAME + JSON_EXT)
    with open(plaintext_tally_path, READ) as f:
        plaintext_tally: PlaintextTally = read_json(f.read(), PlaintextTally)

    devices_dir: str = args.devices_dir or join(args.directory, split(DEVICES_DIR)[-1])
    devices_prefix: str = args.devices_prefix or DEVICE_PREFIX
    device_files: list[str] = glob(join(devices_dir, f'{devices_prefix}*{JSON_EXT}'))
    devices: list[EncryptionDevice] = []
    for device_file in device_files:
        with open(device_file, READ) as f:
            devices.append(read_json(f.read(), EncryptionDevice))

    enc_ballots_dir: str = args.encrypted_ballots_dir or join(args.directory, split(BALLOTS_DIR)[-1])
    enc_ballots_prefix: str = args.encrypted_ballots_prefix or BALLOT_PREFIX
    enc_ballot_files: list[str] = glob(join(enc_ballots_dir, f'{enc_ballots_prefix}*{JSON_EXT}'))
    ciphertext_ballots: list[CiphertextAcceptedBallot] = []
    for enc_ballot in enc_ballot_files:
        with open(enc_ballot, READ) as f:
            ciphertext_ballots.append(read_json(f.read(), CiphertextAcceptedBallot))

    spoiled_ballots_dir: str = args.spoiled_ballots_dir or join(args.directory, split(SPOILED_DIR)[-1])
    spoiled_ballots_prefix: str = args.spoiled_ballots_prefix or BALLOT_PREFIX
    spoiled_ballot_files: list[str] = glob(join(spoiled_ballots_dir, f'{spoiled_ballots_prefix}*{JSON_EXT}'))
    spoiled_ballots: list[CiphertextAcceptedBallot] = []
    for spoiled_ballot in spoiled_ballot_files:
        with open(spoiled_ballot, READ) as f:
            spoiled_ballots.append(read_json(f.read(), CiphertextAcceptedBallot))

    coefficients_dir: str = args.coefficients_dir or join(args.directory, split(COEFFICIENTS_DIR)[-1])
    coefficients_prefix: str = args.coefficients_prefix or COEFFICIENT_PREFIX
    coefficients_files: list[str] = glob(join(coefficients_dir, f'{coefficients_prefix}*{JSON_EXT}'))
    coefficient_validation_sets: list[CoefficientValidationSet] = []
    for coefficient in coefficients_files:
        with open(coefficient, READ) as f:
            coefficient_validation_sets.append(read_json(f.read(), CoefficientValidationSet))

    # Set logging verbosity
    if (args.verbose):
        basicConfig(level=INFO, format='%(message)s')
    elif (args.no_warn):
        basicConfig(level=ERROR, format='%(message)s')
    else:
        basicConfig(format='%(message)s')

    # Verify election
    is_valid: bool = verify(
        description,
        context,
        constants,
        devices,
        ciphertext_ballots,
        spoiled_ballots,
        ciphertext_tally,
        plaintext_tally,
        coefficient_validation_sets
    )

    # Exit with result
    if (is_valid):
        print("Election valid.")
        return EXIT_SUCCESS
    else:
        print("Election invalid.")
        return EXIT_FAILURE
