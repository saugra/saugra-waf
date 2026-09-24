#!/usr/bin/env python3
import sys
import os
import collections

def main():
    lcov_file = sys.argv[1] if len(sys.argv) > 1 else 'lcov.info'
    if not os.path.exists(lcov_file):
        print(f"Error: {lcov_file} not found.", file=sys.stderr)
        sys.exit(1)

    file_coverage = collections.defaultdict(lambda: [0, 0])
    current_file = None

    with open(lcov_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('SF:'):
                current_file = line[3:]
            elif line.startswith('DA:'):
                if current_file:
                    parts = line[3:].split(',')
                    hits = int(parts[1])
                    file_coverage[current_file][1] += 1
                    if hits > 0:
                        file_coverage[current_file][0] += 1

    modules = collections.defaultdict(lambda: [0, 0])
    total_hits = 0
    total_lines = 0

    for filepath, (hits, lines) in file_coverage.items():
        total_hits += hits
        total_lines += lines

        relpath = os.path.relpath(filepath)
        parts = relpath.split(os.sep)
        if len(parts) > 1 and parts[0] == 'src':
            mod = f"src/{parts[1]}"
        elif len(parts) > 0:
            mod = parts[0]
        else:
            mod = 'root'
        modules[mod][0] += hits
        modules[mod][1] += lines

    print("==========================================================")
    print("                SAUGRA WAF COVERAGE SUMMARY               ")
    print("==========================================================")
    print(f"{'Module / Path':<35} | {'Lines Hit':<10} | {'Coverage':<8}")
    print("----------------------------------------------------------")

    for mod, (hits, lines) in sorted(modules.items()):
        pct = (100.0 * hits / lines) if lines > 0 else 0.0
        print(f"{mod:<35} | {hits}/{lines:<8} | {pct:>6.2f}%")

    print("----------------------------------------------------------")
    overall_pct = (100.0 * total_hits / total_lines) if total_lines > 0 else 0.0
    print(f"{'TOTAL LINE COVERAGE':<35} | {total_hits}/{total_lines:<8} | {overall_pct:>6.2f}%")
    print("==========================================================")

if __name__ == '__main__':
    main()
