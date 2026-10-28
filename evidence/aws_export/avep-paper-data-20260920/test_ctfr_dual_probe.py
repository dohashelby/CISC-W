from __future__ import annotations

import hashlib
import json
import unittest

from ctfr_dual_probe import canonical_sha256, validate_manifest


def manifest_entry(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "ordinal": 0,
        "wave": 0,
        "principal": "attacker",
        "prompt": "한국어 고정 프롬프트",
        "max_tokens": 4,
        "seed": 1,
        "temperature": 0,
        "allowed_token_ids": [279],
    }
    entry.update(overrides)
    return entry


class CtfrDualProbeTest(unittest.TestCase):
    def test_canonical_hash_preserves_unicode_form(self) -> None:
        payload = {
            "schema": "ctfr-workload-manifest-v1",
            "entries": [manifest_entry()],
        }
        encoded = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        self.assertEqual(
            canonical_sha256(payload), hashlib.sha256(encoded).hexdigest()
        )

    def test_validate_manifest_rejects_boolean_integer_fields(self) -> None:
        for field in ("ordinal", "wave", "max_tokens", "seed"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_manifest(
                    {
                        "schema": "ctfr-workload-manifest-v1",
                        "entries": [manifest_entry(**{field: True})],
                    }
                )

    def test_validate_manifest_sorts_by_ordinal(self) -> None:
        payload = {
            "schema": "ctfr-workload-manifest-v1",
            "entries": [
                manifest_entry(ordinal=1, principal="victim"),
                manifest_entry(ordinal=0),
            ],
        }
        self.assertEqual(
            [entry["ordinal"] for entry in validate_manifest(payload)],
            [0, 1],
        )


if __name__ == "__main__":
    unittest.main()
