""" utils.py
    Nicholas Boucher 2020

    Utility functions for assisting in election verification
    calculations.
"""

from typing import TypeVar

T: TypeVar = TypeVar('T')

def get_first_el(els: list[T]) -> T:
    if len(els) > 0:
        return els[0]
    else:
        return None