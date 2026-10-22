#!/usr/bin/env python3
import os
import sys

extensions = ('.go', '.md', '.proto', '.yaml', '.yml', '.json', '.toml', 'Makefile')
ignored_dirs = {'.git', 'vendor', 'bin', 'testdata'}
ignored_files = {'dagger.gen.go'}

non_ascii_files = []

for root, dirs, files in os.walk('.'):
    dirs[:] = [d for d in dirs if d not in ignored_dirs]
    for f in files:
        if f in ignored_files:
            continue
        if f.endswith(extensions) or f == 'Makefile':
            path = os.path.join(root, f)
            try:
                with open(path, 'rb') as fp:
                    data = fp.read()
                bad = [(i, b) for i, b in enumerate(data) if b > 127]
                if bad:
                    non_ascii_files.append((path, len(bad), bad[:5]))
            except Exception as e:
                print(f"Error reading {path}: {e}", file=sys.stderr)

if non_ascii_files:
    print(f"FAILED: Found {len(non_ascii_files)} file(s) with non-ASCII characters:")
    for path, count, samples in non_ascii_files:
        sample_str = ", ".join(f"0x{b:02X} at pos {pos}" for pos, b in samples)
        print(f"  {path}: {count} non-ASCII byte(s) ({sample_str})")
    sys.exit(1)

print("100% PURE ASCII across all codebase source and documentation!")
sys.exit(0)
