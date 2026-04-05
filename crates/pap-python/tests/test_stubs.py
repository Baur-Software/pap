"""
Validate that .pyi stub files are syntactically correct and complete.

These tests do NOT require ``maturin develop`` — they parse the stub source
directly with the ``ast`` module, so they run in any Python 3.8+ environment.
"""

from __future__ import annotations

import ast
import pathlib
from typing import List, Set

# Resolve paths relative to the test file location so pytest can be invoked
# from any working directory.
_PKG_DIR = pathlib.Path(__file__).resolve().parent.parent / "python" / "pap"

_PAP_PYI = _PKG_DIR / "_pap.pyi"
_INIT_PYI = _PKG_DIR / "__init__.pyi"
_PY_TYPED = _PKG_DIR / "py.typed"
_INIT_PY = _PKG_DIR / "__init__.py"


class TestStubSyntax:
    """Ensure .pyi files are parseable Python."""

    def test_pap_pyi_parses(self) -> None:
        source = _PAP_PYI.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(_PAP_PYI))
        assert isinstance(tree, ast.Module)

    def test_init_pyi_parses(self) -> None:
        source = _INIT_PYI.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(_INIT_PYI))
        assert isinstance(tree, ast.Module)


class TestPep561:
    """PEP 561 compliance checks."""

    def test_py_typed_marker_exists(self) -> None:
        assert _PY_TYPED.exists(), "py.typed marker file is missing"


class TestStubCompleteness:
    """Every name in __init__.py's __all__ must appear in _pap.pyi."""

    @staticmethod
    def _extract_all_names() -> List[str]:
        """Parse __init__.py and return the list of strings in __all__."""
        source = _INIT_PY.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(_INIT_PY))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "__all__":
                        if isinstance(node.value, ast.List):
                            return [
                                elt.value
                                for elt in node.value.elts
                                if isinstance(elt, ast.Constant)
                                and isinstance(elt.value, str)
                            ]
        return []

    @staticmethod
    def _extract_stub_names() -> Set[str]:
        """Return top-level class, function, and variable names from _pap.pyi."""
        source = _PAP_PYI.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(_PAP_PYI))
        names: Set[str] = set()
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
        return names

    @staticmethod
    def _extract_init_pyi_imports() -> Set[str]:
        """Return names re-exported by __init__.pyi."""
        source = _INIT_PYI.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(_INIT_PYI))
        names: Set[str] = set()
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    names.add(alias.asname or alias.name)
        return names

    def test_all_names_have_stubs(self) -> None:
        all_names = self._extract_all_names()
        assert len(all_names) >= 20, (
            f"__all__ has only {len(all_names)} names, expected >= 20"
        )
        stub_names = self._extract_stub_names()
        missing = [name for name in all_names if name not in stub_names]
        assert not missing, f"Names in __all__ missing from _pap.pyi: {missing}"

    def test_init_pyi_reexports_match_all(self) -> None:
        """__init__.pyi must re-export every name from __init__.py's __all__."""
        all_names = self._extract_all_names()
        pyi_imports = self._extract_init_pyi_imports()
        missing = [name for name in all_names if name not in pyi_imports]
        assert not missing, f"Names in __all__ missing from __init__.pyi: {missing}"
