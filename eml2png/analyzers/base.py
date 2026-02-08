"""Base analyzer abstract class."""

from abc import ABC, abstractmethod


class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, parsed: dict) -> dict:
        ...
