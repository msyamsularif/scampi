"""Small domain helpers shared by extraction and the allowlist.

Leaf module: imports nothing from the rest of the plugin, so both the
extractor and the allowlist can depend on it without a cycle.
"""

from __future__ import annotations

#: Second-level labels under .id that mark a registrable domain at depth 3
#: (``bca.co.id``, not ``co.id``).
ID_SECOND_LEVELS = frozenset(
    {"co", "or", "go", "ac", "net", "sch", "web", "my", "biz", "ponpes", "desa", "id"}
)


def registrable_domain(host: str) -> str:
    """Approximate registrable domain: the last 2 labels, or 3 under ``.id``.

    No public-suffix list is consulted on purpose — the allowlist stores
    registrable domains already, and comparisons only ever happen between
    values produced by this same function.
    """
    host = (host or "").strip().lower().strip(".")
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return host
    if labels[-1] == "id" and labels[-2] in ID_SECOND_LEVELS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def levenshtein(a: str, b: str) -> int:
    """Edit distance. Bounded inputs (domains), so plain DP is fine."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            substitute = previous[j - 1] + (ca != cb)
            current.append(min(insert, delete, substitute))
        previous = current
    return previous[-1]
