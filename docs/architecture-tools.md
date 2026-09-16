# Architecture notes (tool / DB boundary)

## Architecture A (anti-pattern — lab baseline only)

```text
LLM → raw SQL string → database
```

Enabled only when `HADES_ALLOW_UNSAFE_SQL=true` **and** defense level is below D5. At D5+, the PEP rejects raw SQL even if the flag is set.

## Architecture B (required secure path)

```text
LLM / caller → typed tool API → Policy Enforcement Point → parameterized query → SQLite
```

Authorization is decided by the PEP from the authenticated identity — **never** by model text.

Principle: *Never delegate authorization decisions to the model.*
