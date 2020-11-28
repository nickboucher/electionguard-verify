""" utils.py
    Nicholas Boucher 2020

    Utility functions for assisting in election verification
    calculations.
"""

from typing import TypeVar, Iterable
from logging import info, warning
from electionguard.group import ElementModP, int_to_p
from electionguard.election import ElectionDescription, ContestDescription
from electionguard.ballot import CiphertextAcceptedBallot, CiphertextBallotContest, CiphertextBallotSelection
from electionguard.key_ceremony import CoefficientValidationSet


T: TypeVar = TypeVar('T')


class Invariants():
    """Represents a series of conditions that must all hold for the
       collection of invariants to remain valid."""

    title: str
    conditions: dict[str, bool]

    def __init__(self, title: str):
        """Instantiate a new set of invariants collectively labelled `title`."""
        self.title = title
        self.conditions = {}
    
    def ensure(self, invariant: str, condition: bool) -> bool:
        """Track the truthiness of `condition` for the invariant labelled `invariant`."""
        if invariant in self.conditions:
            self.conditions[invariant] = self.conditions[invariant] and condition
        else:
            self.conditions[invariant] = condition
        return condition
    
    def validate(self) -> bool:
        """Return whether all conditions are valid, logging the results."""
        validity: bool = True
        error_msg: str = ''
        for invariant, state in self.conditions.items():
            validity = validity and state
            if not state:
                error_msg += f'\t\tFailed to validate invariant {invariant}.\n'
        if validity:
            info(f'[VALID]: {self.title}')
        else:
            info(f'[INVALID]: {self.title}')
            info(error_msg)
        return validity

class Contests():
    """Speeds up access to contest descriptions through object_id indexing."""

    contests: dict[str,ContestDescription]

    def __init__(self, description: ElectionDescription):
        """Indexes contest descriptions by object_id for quick lookups."""
        self.contests = {}
        for contest in description.contests:
            self.contests[contest.object_id] = contest
    
    def __getitem__(self, contest: str) -> ContestDescription:
        """Returns the requested contest, or None if no such contest exists."""
        if contest in self.contests:
            return self.contests[contest]
        else:
            return None

class Guardians():
    """Speeds up access to guardians through owner_id indexing."""

    guardians: dict[str,CoefficientValidationSet]

    def __init__(self, guardians: Iterable[CoefficientValidationSet]):
        """Indexes guardians by owner_id for quick lookups."""
        self.guardians = {}
        for guardian in guardians:
            self.guardians[guardian.owner_id] = guardian
    
    def __getitem__(self, guardian: str) -> ContestDescription:
        """Returns the requested guardian, or None if no such guardian exists."""
        if guardian in self.guardians:
            return self.guardians[guardian]
        else:
            return None

def get_first_el(els: list[T]) -> T:
    """Returns the first element of `els`, or None if it is empty."""
    if len(els) > 0:
        return els[0]
    else:
        return None

def get_contest(ballot: CiphertextAcceptedBallot, contest_id: str) -> CiphertextBallotContest:
    """Given a ballot, gets the supplied contest. If the contest appears more than once,
       None is returned."""
    result: CiphertextBallotContest = None
    for contest in ballot.contests:
        if contest.object_id == contest_id:
            if result != None:
                warn('Ballot contains multiple entries for the same contest.')
                return None
            else:
                result = contest
    return result

def get_selection(ballot: CiphertextAcceptedBallot, contest_id: str, selection_id: str) -> CiphertextBallotSelection:
    """Given a ballot, gets the supplied selection from within the supplied contest.
       If the contest or selection appear more than once, None is returned."""
    result: CiphertextBallotSelection = None
    contest: CiphertextBallotContest = get_contest(ballot, contest_id)
    if contest:
        for selection in contest.ballot_selections:
            if selection.object_id == selection_id:
                if result != None:
                    warn('Ballot contains multiple entries for the same selection.')
                    return None
                else:
                    result = selection
    return result

def warn(msg: str) -> None:
    """Emits a warning message `msg` to the logs."""
    warning(f'[WARNING]: {msg}')