"""Legacy module entry point for the noninteractive reference suite.
Run from api: python -m core.test.test [--case 18] [--direction receiving]
"""
import argparse
import json
from pathlib import Path
from core.reference import run_case


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=int)
    parser.add_argument('--direction', choices=['sending', 'receiving'])
    args = parser.parse_args()
    vectors = json.loads(Path(__file__).with_name('test_vectors.json').read_text())
    if args.case is not None and not 0 <= args.case < len(vectors):
        parser.error('Invalid case id')
    failed = 0
    for i, entry in enumerate(vectors):
        if args.case is not None and args.case != i:
            continue
        for direction in ([args.direction] if args.direction else ['sending', 'receiving']):
            for subcase in range(len(entry.get(direction, []))):
                passed = run_case(entry, direction, subcase, i)['test_passed']
                print(f'{i}/{direction}/{subcase}: {"PASS" if passed else "FAIL"}')
                failed += not passed
    return int(bool(failed))


if __name__ == '__main__':
    raise SystemExit(main())
