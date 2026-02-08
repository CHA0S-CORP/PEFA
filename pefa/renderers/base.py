"""Base widget abstract class."""

from abc import ABC, abstractmethod


class Widget(ABC):
    nav_id: str = ""
    nav_label: str = ""
    nav_group: str = ""

    @abstractmethod
    def render(self, analysis: dict, parsed: dict) -> str:
        ...
