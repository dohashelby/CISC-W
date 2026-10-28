#!/usr/bin/env python
"""Unit tests for deterministic CTFR Stage D/E manifest generation."""

from __future__ import annotations

import json
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path

from generate_ctfr_manifests import (
    GENERATOR_SCHEMA,
    MANIFEST_SPECS,
    build_bundle,
    canonical_sha256,
    check_bundle,
    corpus_content_sha256,
    read_json,
    validate_corpus,
    write_bundle,
)


def valid_corpus() -> dict:
    payload = {
        "schema": "ctfr-frozen-corpus-v1",
        "corpus_id": "ctfr-test-v1",
        "request_defaults": {
            "base_seed": 20260920,
            "max_tokens": 16,
            "temperature": 0.0,
        },
        "repetitions": {
            "compile_warmup": 2,
            "baseline_adaptation": 2,
            "baseline_evaluation": 2,
            "shifted_adaptation": 2,
            "shifted_evaluation": 2,
            "stationary_adaptation": 2,
            "e1_one_identity": 2,
            "e2_disagreement": 2,
            "e3_two_credentials": 2,
        },
        "prompt_sets": {
            "compile_warmup": [
                {"prompt_id": "warm-0", "prompt": "warm zero"},
                {"prompt_id": "warm-1", "prompt": "warm one"},
            ],
            "baseline_benign_train": [
                {"prompt_id": "base-0", "prompt": "base zero"},
                {"prompt_id": "base-1", "prompt": "base one"},
            ],
            "adaptation_eval": [
                {"prompt_id": "eval-0", "prompt": "eval zero"},
                {"prompt_id": "eval-1", "prompt": "eval one"},
            ],
            "shifted_benign_train": [
                {"prompt_id": "shift-0", "prompt": "shift zero"},
                {"prompt_id": "shift-1", "prompt": "shift one"},
            ],
            "stationary_benign_train": [
                {"prompt_id": "stat-0", "prompt": "stat zero"},
                {"prompt_id": "stat-1", "prompt": "stat one"},
            ],
            "adversarial_train": [
                {
                    "prompt_id": "adv-0",
                    "prompt": "adversarial zero",
                    "allowed_token_ids": [279],
                },
                {
                    "prompt_id": "adv-1",
                    "prompt": "adversarial one",
                    "allowed_token_ids": [279],
                },
            ],
            "disagreement_benign_train": [
                {"prompt_id": "dis-0", "prompt": "disagree zero"},
                {"prompt_id": "dis-1", "prompt": "disagree one"},
            ],
        },
        "metadata": {"cohort": "unit-test"},
    }
    payload["frozen_sha256"] = corpus_content_sha256(payload)
    return payload


def by_wave(manifest: dict) -> dict[int, list[dict]]:
    grouped: dict[int, list[dict]] = defaultdict(list)
    for entry in manifest["entries"]:
        grouped[entry["wave"]].append(entry)
    return grouped


class CTFRManifestTests(unittest.TestCase):
    def test_required_files_and_hash_index_are_deterministic(self) -> None:
        corpus = valid_corpus()
        first = build_bundle(corpus)
        second = build_bundle(corpus)
        self.assertEqual(first, second)
        expected_files = {spec.file_name for spec in MANIFEST_SPECS}
        self.assertEqual(set(first["manifests"]), expected_files)
        descriptors = first["index"]["manifests"]
        self.assertEqual(
            [item["file"] for item in descriptors],
            [spec.file_name for spec in MANIFEST_SPECS],
        )
        for descriptor in descriptors:
            manifest = first["manifests"][descriptor["file"]]
            self.assertEqual(
                descriptor["canonical_sha256"],
                canonical_sha256(manifest),
            )
        bundle_material = {
            "corpus_id": corpus["corpus_id"],
            "corpus_sha256": corpus["frozen_sha256"],
            "generator_schema": GENERATOR_SCHEMA,
            "manifests": descriptors,
        }
        self.assertEqual(
            first["index"]["bundle_sha256"],
            canonical_sha256(bundle_material),
        )

    def test_dual_principals_are_interleaved_in_balanced_waves(self) -> None:
        manifests = build_bundle(valid_corpus())["manifests"]
        for file_name, manifest in manifests.items():
            waves = by_wave(manifest)
            self.assertEqual(sorted(waves), list(range(len(waves))))
            if file_name == "e1_one_identity.json":
                self.assertTrue(
                    all(
                        [entry["principal"] for entry in entries]
                        == ["attacker"]
                        for entries in waves.values()
                    )
                )
                continue
            for wave, entries in waves.items():
                expected = (
                    ["attacker", "victim"]
                    if wave % 2 == 0
                    else ["victim", "attacker"]
                )
                self.assertEqual(
                    [entry["principal"] for entry in entries], expected
                )
            self.assertEqual(
                [entry["ordinal"] for entry in manifest["entries"]],
                list(range(manifest["entry_count"])),
            )

    def test_evaluation_pair_reuses_held_out_prompts_and_seeds(self) -> None:
        manifests = build_bundle(valid_corpus())["manifests"]
        baseline = manifests["baseline_evaluation.json"]
        shifted = manifests["shifted_evaluation.json"]
        baseline_requests = [
            (
                entry["principal"],
                entry["prompt_id"],
                entry["repetition"],
                entry["seed"],
                entry["prompt"],
            )
            for entry in baseline["entries"]
        ]
        shifted_requests = [
            (
                entry["principal"],
                entry["prompt_id"],
                entry["repetition"],
                entry["seed"],
                entry["prompt"],
            )
            for entry in shifted["entries"]
        ]
        self.assertEqual(baseline_requests, shifted_requests)
        train_ids = {
            entry["prompt_id"]
            for name in (
                "baseline_adaptation.json",
                "shifted_adaptation.json",
                "stationary_adaptation.json",
            )
            for entry in manifests[name]["entries"]
        }
        eval_ids = {entry["prompt_id"] for entry in baseline["entries"]}
        self.assertFalse(train_ids & eval_ids)

    def test_sybil_manifests_hold_adversarial_requests_constant(self) -> None:
        manifests = build_bundle(valid_corpus())["manifests"]
        e1 = manifests["e1_one_identity.json"]
        e2 = manifests["e2_disagreement.json"]
        e3 = manifests["e3_two_credentials.json"]

        def attacker_requests(manifest: dict) -> list[tuple]:
            return [
                (
                    entry["prompt_id"],
                    entry["repetition"],
                    entry["seed"],
                    entry["allowed_token_ids"],
                )
                for entry in manifest["entries"]
                if entry["principal"] == "attacker"
            ]

        self.assertEqual(attacker_requests(e1), attacker_requests(e2))
        self.assertEqual(attacker_requests(e1), attacker_requests(e3))
        for entries in by_wave(e3).values():
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0]["prompt_id"], entries[1]["prompt_id"])
            self.assertEqual(entries[0]["seed"], entries[1]["seed"])
            self.assertEqual(
                {entry["workload_role"] for entry in entries},
                {"attacker-a", "attacker-b"},
            )
        for entries in by_wave(e2).values():
            roles = {entry["workload_role"] for entry in entries}
            self.assertEqual(roles, {"attacker-a", "benign-b"})

    def test_corpus_hash_mismatch_is_rejected(self) -> None:
        corpus = valid_corpus()
        corpus["request_defaults"]["max_tokens"] = 17
        with self.assertRaisesRegex(ValueError, "frozen_sha256 mismatch"):
            validate_corpus(corpus)

    def test_training_and_evaluation_prompt_id_overlap_is_rejected(self) -> None:
        corpus = valid_corpus()
        corpus["prompt_sets"]["adaptation_eval"][0]["prompt_id"] = "base-0"
        corpus["frozen_sha256"] = corpus_content_sha256(corpus)
        with self.assertRaisesRegex(ValueError, "appears in"):
            validate_corpus(corpus)

    def test_training_and_evaluation_text_alias_is_rejected(self) -> None:
        corpus = valid_corpus()
        corpus["prompt_sets"]["adaptation_eval"][0]["prompt"] = "base zero"
        corpus["frozen_sha256"] = corpus_content_sha256(corpus)
        with self.assertRaisesRegex(ValueError, "identical prompt text"):
            validate_corpus(corpus)

    def test_e2_requires_one_to_one_wave_pairing(self) -> None:
        corpus = valid_corpus()
        corpus["prompt_sets"]["disagreement_benign_train"].pop()
        corpus["frozen_sha256"] = corpus_content_sha256(corpus)
        with self.assertRaisesRegex(ValueError, "equal length"):
            validate_corpus(corpus)

    def test_paired_repetition_counts_are_required(self) -> None:
        corpus = valid_corpus()
        corpus["repetitions"]["shifted_evaluation"] = 3
        corpus["frozen_sha256"] = corpus_content_sha256(corpus)
        with self.assertRaisesRegex(ValueError, "evaluation repetitions"):
            validate_corpus(corpus)
        corpus = valid_corpus()
        corpus["repetitions"]["e3_two_credentials"] = 3
        corpus["frozen_sha256"] = corpus_content_sha256(corpus)
        with self.assertRaisesRegex(ValueError, "E1, E2, and E3"):
            validate_corpus(corpus)

    def test_manifest_entry_limit_is_enforced(self) -> None:
        corpus = valid_corpus()
        corpus["repetitions"]["shifted_adaptation"] = 4096
        corpus["frozen_sha256"] = corpus_content_sha256(corpus)
        with self.assertRaisesRegex(ValueError, "maximum is 8192"):
            build_bundle(corpus)

    def test_write_and_check_refuse_tampered_output(self) -> None:
        bundle = build_bundle(valid_corpus())
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory) / "manifests"
            write_bundle(bundle, output_dir)
            check_bundle(bundle, output_dir)
            path = output_dir / "shifted_adaptation.json"
            payload = json.loads(path.read_text())
            payload["entries"][0]["seed"] += 1
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            with self.assertRaisesRegex(ValueError, "differs"):
                check_bundle(bundle, output_dir)
            with self.assertRaisesRegex(
                FileExistsError, "refusing to overwrite"
            ):
                write_bundle(bundle, output_dir)

    def test_strict_reader_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema":"a","schema":"b"}\n')
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                read_json(path)


if __name__ == "__main__":
    unittest.main()
