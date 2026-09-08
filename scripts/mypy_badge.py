#!/usr/bin/env python3
"""Read the checked and total module counts, and write them into the badge.

The typing badge states a ratio: how many modules the checker reads out of how
many the package holds. Both halves are computed from the repository -- the
numerator by resolving `[tool.mypy] files`, the denominator by counting the
package -- so neither needs mypy to run, and neither should ever be typed by
hand. The gate that compares them has existed since the badge said `strict`
about a package with hundreds of errors in it; what did not exist was anything
that could set the ratio right once it moved.

It moves on ordinary work. Adding a module to the package changes the
denominator. Adding one to a directory already inside the scope changes both.
Neither edit looks like it touches a badge.

The pattern is written once here and used to read and to write. The reader it
replaces unquoted the label and matched a loose ratio, which was the right
shape for a badge nothing could write; a writer needs to know exactly where
the numbers sit, and two different ideas of where that is would be two
producers of one string.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import tomllib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
README = _ROOT / "README.md"
# The launch post states the same ratio for a reader who never opens the
# repository. It said the checker was clean on one named module while the
# scope resolved to ninety-five, because nothing wrote it and nothing read it.
# One pair of counters, two places the ratio is written.
POST = _ROOT / "blog" / "launch-post-draft.md"
_PYPROJECT = _ROOT / "pyproject.toml"
_PACKAGE = _ROOT / "cyberai"

_BADGE = re.compile(r"badge/mypy-strict%3A%20(\d+)%2F(\d+)%20modules")
# Matched across line breaks as well, so a reflowed paragraph does not
# silently stop being written to.
_POST = re.compile(r"clean over\s+(\d+)\s+of\s+(\d+)\s+modules")


def checked() -> int:
    """Modules `[tool.mypy] files` resolves to, directories expanded."""
    settings = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["tool"]["mypy"]
    resolved: set[pathlib.Path] = set()
    for entry in settings["files"]:
        path = _ROOT / entry
        resolved.update(path.rglob("*.py")) if path.is_dir() else resolved.add(path)
    return len(resolved)


def package() -> int:
    """Modules the package holds."""
    return len(list(_PACKAGE.rglob("*.py")))


def claimed(readme: pathlib.Path = README) -> tuple[int, int]:
    """The ratio the badge currently states."""
    match = _BADGE.search(readme.read_text(encoding="utf-8"))
    assert match, "the README carries no mypy badge in the expected shape"
    return int(match.group(1)), int(match.group(2))


def rewrite(counts: tuple[int, int], readme: pathlib.Path = README) -> bool:
    """Put the ratio into the badge. True when the file changed."""
    text = readme.read_text(encoding="utf-8")
    updated = _BADGE.sub(
        f"badge/mypy-strict%3A%20{counts[0]}%2F{counts[1]}%20modules", text, count=1
    )
    if updated == text:
        return False
    readme.write_text(updated, encoding="utf-8")
    return True


def claimed_in_post(post: pathlib.Path = POST) -> tuple[int, int]:
    """The ratio the launch post currently states."""
    match = _POST.search(post.read_text(encoding="utf-8"))
    assert match, "the launch post carries no typing ratio in the expected shape"
    return int(match.group(1)), int(match.group(2))


def rewrite_post(counts: tuple[int, int], post: pathlib.Path = POST) -> bool:
    """Put the ratio into the post. True when the file changed."""
    text = post.read_text(encoding="utf-8")
    updated = _POST.sub(f"clean over {counts[0]} of {counts[1]} modules", text, count=1)
    if updated == text:
        return False
    post.write_text(updated, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="report a stale badge without touching the README",
    )
    arguments = parser.parse_args(argv)
    counts = (checked(), package())
    if arguments.check:
        stale = [
            f"{label} says {states[0]}/{states[1]}"
            for label, states in (("badge", claimed()), ("post", claimed_in_post()))
            if states != counts
        ]
        if not stale:
            print(f"badge and post are current: {counts[0]}/{counts[1]}")
            return 0
        print(f"{', '.join(stale)}; the repository holds {counts[0]}/{counts[1]}")
        return 1
    for label, wrote in (("badge", rewrite(counts)), ("post", rewrite_post(counts))):
        verb = "set to" if wrote else "already said"
        print(f"{label} {verb} {counts[0]}/{counts[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
