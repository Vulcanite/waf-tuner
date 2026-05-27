"""
CRS Rule Index — Phase 1.5

Parses all OWASP CRS .conf files from CRS_RULES_DIR and builds an
in-memory dict keyed by rule ID. Called once at api-server startup.
"""
import os
import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Module-level singleton — imported by other services
CRS_INDEX: dict[str, "CRSRule"] = {}


@dataclass
class CRSRule:
    rule_id: str
    raw: str                    # Full raw SecRule directive as written in .conf
    targets: list[str]          # e.g. ["ARGS", "REQUEST_BODY"]
    operator: str               # e.g. "@detectSQLi", "@rx (?i:union)"
    message: str                # msg: value
    tags: list[str]             # all tag: values
    paranoia_level: int         # from paranoia-level/N tag, 0 if absent
    phase: int                  # phase:N from actions
    severity: str               # severity: value
    chain: bool                 # True if rule uses 'chain' action


def build_crs_index(rules_dir: str) -> dict[str, CRSRule]:
    """
    Parse all .conf files in rules_dir and return a dict of CRSRule objects
    keyed by rule ID string. Continuation lines (ending with \\) are joined.
    """
    index: dict[str, CRSRule] = {}
    files_parsed = 0

    if not os.path.isdir(rules_dir):
        logger.warning("CRS rules directory not found: %s", rules_dir)
        return index

    for filename in sorted(os.listdir(rules_dir)):
        if not filename.endswith(".conf"):
            continue
        filepath = os.path.join(rules_dir, filename)
        files_parsed += 1

        try:
            with open(filepath, "r", errors="replace") as f:
                content = f.read()
        except OSError as e:
            logger.warning("Could not read CRS file %s: %s", filepath, e)
            continue

        # Join continuation lines (line ending with \)
        content = re.sub(r"\\\n\s*", " ", content)

        # Extract all SecRule blocks: SecRule TARGETS "OPERATOR" "ACTIONS"
        # The operator string may contain escaped quotes so we handle that carefully.
        for match in re.finditer(
            r'SecRule\s+(\S+)\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"',
            content,
            re.MULTILINE,
        ):
            targets_raw, operator_raw, actions_raw = match.groups()
            raw = match.group(0)

            # Extract rule id
            id_match = re.search(r'\bid:(\d+)', actions_raw)
            if not id_match:
                continue
            rule_id = id_match.group(1)

            # Extract msg (single-quoted)
            msg_match = re.search(r"msg:'([^']*)'", actions_raw)
            message = msg_match.group(1) if msg_match else ""

            # Extract all tag values
            tags = re.findall(r"tag:'([^']*)'", actions_raw)

            # Paranoia level from tags
            pl = 0
            for tag in tags:
                pl_match = re.match(r"paranoia-level/(\d+)", tag)
                if pl_match:
                    pl = int(pl_match.group(1))
                    break

            # Phase
            phase_match = re.search(r'\bphase:(\d+)', actions_raw)
            phase = int(phase_match.group(1)) if phase_match else 2

            # Severity (quoted or unquoted)
            sev_match = re.search(r"\bseverity:'?(\w+)'?", actions_raw)
            severity = sev_match.group(1) if sev_match else ""

            chain = "chain" in actions_raw.split(",")

            targets = [t.strip() for t in targets_raw.split("|")]
            operator = operator_raw.strip()

            index[rule_id] = CRSRule(
                rule_id=rule_id,
                raw=raw,
                targets=targets,
                operator=operator,
                message=message,
                tags=tags,
                paranoia_level=pl,
                phase=phase,
                severity=severity,
                chain=chain,
            )

    logger.info("CRS index built: %d rules from %d files", len(index), files_parsed)
    return index


def get_rule(rule_id: str) -> CRSRule | None:
    """Look up a rule by ID from the module-level singleton."""
    return CRS_INDEX.get(str(rule_id))
