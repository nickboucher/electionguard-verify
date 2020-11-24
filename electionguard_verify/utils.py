""" utils.py
    Nicholas Boucher 2020

    Utility functions for assisting in election verification
    calculations.
"""

from typing import TypeVar
from logging import info
from electionguard.group import ElementModP, int_to_p


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


def get_first_el(els: list[T]) -> T:
    """Returns the first element of `els`, or None if it is empty."""
    if len(els) > 0:
        return els[0]
    else:
        return None
