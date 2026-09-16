"""Classification levels and authorization policy for Aperture Systems."""

from __future__ import annotations

from enum import Enum
from typing import Iterable


class Classification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    HIGHLY_RESTRICTED = "highly_restricted"


CLASSIFICATION_RANK: dict[Classification, int] = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 2,
    Classification.RESTRICTED: 3,
    Classification.HIGHLY_RESTRICTED: 4,
}


class Department(str, Enum):
    ENGINEERING = "engineering"
    FINANCE = "finance"
    HR = "hr"
    SALES = "sales"
    SECURITY = "security"
    EXECUTIVE = "executive"
    GENERAL = "general"


class Role(str, Enum):
    ENGINEER = "engineer"
    HR = "hr"
    FINANCE = "finance"
    SALES = "sales"
    SECURITY = "security"
    EXECUTIVE = "executive"


# Max classification a role may access by default.
ROLE_CLEARANCE: dict[Role, Classification] = {
    Role.ENGINEER: Classification.INTERNAL,
    Role.SALES: Classification.CONFIDENTIAL,
    Role.HR: Classification.RESTRICTED,
    Role.FINANCE: Classification.RESTRICTED,
    Role.SECURITY: Classification.HIGHLY_RESTRICTED,
    Role.EXECUTIVE: Classification.HIGHLY_RESTRICTED,
}

# Departments a role may retrieve from (in addition to GENERAL/PUBLIC).
ROLE_DEPARTMENTS: dict[Role, set[Department]] = {
    Role.ENGINEER: {Department.ENGINEERING, Department.GENERAL},
    Role.SALES: {Department.SALES, Department.GENERAL},
    Role.HR: {Department.HR, Department.GENERAL},
    Role.FINANCE: {Department.FINANCE, Department.GENERAL},
    Role.SECURITY: {Department.SECURITY, Department.GENERAL, Department.ENGINEERING},
    Role.EXECUTIVE: set(Department),
}


def allowed_classifications(clearance: Classification) -> set[Classification]:
    rank = CLASSIFICATION_RANK[clearance]
    return {c for c, r in CLASSIFICATION_RANK.items() if r <= rank}


def can_access_document(
    *,
    role: Role,
    clearance: Classification,
    doc_classification: Classification,
    doc_department: Department,
    allowed_roles: Iterable[str] | None = None,
) -> bool:
    """Enforce clearance + department (+ optional explicit role ACL)."""
    if CLASSIFICATION_RANK[doc_classification] > CLASSIFICATION_RANK[clearance]:
        return False
    if doc_classification == Classification.PUBLIC:
        return True
    departments = ROLE_DEPARTMENTS.get(role, {Department.GENERAL})
    if doc_department not in departments and doc_department != Department.GENERAL:
        return False
    if allowed_roles is not None:
        allowed = {r.lower() for r in allowed_roles}
        if allowed and role.value not in allowed and "all" not in allowed:
            return False
    return True
