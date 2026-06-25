"""
Usage:
    python scripts/anonymize.py <input.log> <output.log> <config.txt>

Example config file (scripts/anonymize.conf):
    amranich.dev = example.com
"""

import sys


def load_replacements(config_path):
    """Read replacement pairs from a config file."""
    pairs = []

    with open(config_path, "r") as f:
        for line in f:
            line = line.strip()

            # skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            original, replacement = line.split("=", 1)
            pairs.append((original.strip(), replacement.strip()))

    return pairs


def anonymize_line(line, replacements):
    """Replace all identifiers in a single log line."""
    for original, replacement in replacements:
        line = line.replace(original, replacement)
    return line


def anonymize_file(input_path, output_path, config_path):
    """Read a log, anonymize every line, write the result."""
    replacements = load_replacements(config_path)
    count = 0

    with open(input_path, "r", errors="replace") as infile:
        with open(output_path, "w") as outfile:
            for line in infile:
                outfile.write(anonymize_line(line, replacements))
                count += 1

    print(f"Done: {count} lines, {len(replacements)} replacements applied")
    print(f"  Input:  {input_path}")
    print(f"  Output: {output_path}")
    print(f"  Config: {config_path}")


if __name__ == "__main__":
    anonymize_file(sys.argv[1], sys.argv[2], sys.argv[3])