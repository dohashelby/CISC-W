#!/usr/bin/env python
"""Find ordinary one-token strings for the pinned Qwen tokenizer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from transformers import AutoTokenizer


CANDIDATES = (
    " the",
    " and",
    " blue",
    " cat",
    " hello",
    " water",
    " seven",
    " Paris",
    ".",
    ",",
    "!",
    "?",
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="Qwen/Qwen3-4B")
    parser.add_argument(
        "--revision", default="1cfa9a7208912126459214e8b04321603b3df60c"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(
        args.model,
        revision=args.revision,
        trust_remote_code=True,
    )
    special_ids = set(tokenizer.all_special_ids)
    ordinary = []
    for text in CANDIDATES:
        token_ids = tokenizer.encode(text, add_special_tokens=False)
        if len(token_ids) != 1 or token_ids[0] in special_ids:
            continue
        token_id = int(token_ids[0])
        ordinary.append(
            {
                "text": text,
                "token_id": token_id,
                "token": tokenizer.convert_ids_to_tokens(token_id),
                "decoded": tokenizer.decode([token_id]),
            }
        )

    artifact = {
        "model": args.model,
        "revision": args.revision,
        "special_token_ids": sorted(special_ids),
        "ordinary_single_tokens": ordinary,
    }
    if len(ordinary) < 4:
        raise RuntimeError("Fewer than four ordinary one-token candidates found")
    args.output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    print(json.dumps(artifact, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
