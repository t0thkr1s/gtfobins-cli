#!/usr/bin/env python3
# coding=utf-8
import argparse
import json
import os
import sys
from difflib import SequenceMatcher
from pathlib import Path
from string import Template

from colorama import Fore, Style, init
from pygments import highlight, formatters, lexers

# Initialize colorama for Windows compatibility
init(autoreset=True)

banner = r'''
         __    ___        __    _
  ___ _ / /_  / _/ ___   / /   (_)  ___   ___
 / _ `// __/ / _/ / _ \ / _ \ / /  / _ \ (_-<
 \_, / \__/ /_/   \___//_.__//_/  /_//_//___/
/___/
'''

# Get the absolute path to the data directory
PACKAGE_DIR = Path(__file__).parent
data_dir = PACKAGE_DIR / "data"
json_ext = ".json"

EXPLOIT_TYPES = [
    'shell', 'command', 'reverse-shell', 'non-interactive-reverse-shell',
    'bind-shell', 'non-interactive-bind-shell', 'file-upload', 'file-download',
    'file-write', 'file-read', 'library-load', 'suid', 'sudo', 'capabilities',
    'limited-suid'
]

info = Template(Style.BRIGHT + '[ ' + Fore.GREEN + '*' + Fore.RESET + ' ] ' + Style.RESET_ALL + '$text')
fail = Template(Style.BRIGHT + '[ ' + Fore.RED + '-' + Fore.RESET + ' ] ' + Style.RESET_ALL + '$text')
title = Template(
    '\n' + Style.BRIGHT + '---------- [ ' + Fore.CYAN + '$title' + Fore.RESET + ' ] ----------' + Style.RESET_ALL + '\n'
)
description = Template(Style.DIM + '# ' + '$description' + Style.RESET_ALL)
divider = '\n' + Style.BRIGHT + ' - ' * 10 + Style.RESET_ALL + '\n'


def get_all_binaries():
    """Get list of all available binary names."""
    return sorted([f.stem for f in data_dir.glob('*.json')])


def fuzzy_match(query, choices, threshold=0.4):
    """Return choices that fuzzy match the query, sorted by relevance."""
    results = []
    query_lower = query.lower()
    for choice in choices:
        choice_lower = choice.lower()
        # Exact substring match gets highest priority
        if query_lower in choice_lower:
            score = 1.0 if query_lower == choice_lower else 0.9
        else:
            score = SequenceMatcher(None, query_lower, choice_lower).ratio()
        if score >= threshold:
            results.append((choice, score))
    return [r[0] for r in sorted(results, key=lambda x: (-x[1], x[0]))]


def get_binaries_with_type(exploit_type):
    """Get all binaries that have a specific exploitation type."""
    matching = []
    for json_file in data_dir.glob('*.json'):
        with open(json_file) as f:
            data = json.load(f)
        if exploit_type in data.get('functions', {}):
            matching.append(json_file.stem)
    return sorted(matching)


def parse_args():
    from . import __version__
    parser = argparse.ArgumentParser(
        prog="gtfo",
        description="Command-line tool for GTFOBins - helps you bypass system security restrictions."
    )
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('binary', metavar='binary', nargs='?', help='Unix binary to search for exploitation techniques')
    parser.add_argument('-s', '--search', metavar='TERM', help='Fuzzy search binaries by name')
    parser.add_argument('-f', '--filter', metavar='TYPE', dest='exploit_type',
                        help=f'Filter binaries by exploitation type: {", ".join(EXPLOIT_TYPES)}')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Interactive mode with autocomplete')
    parser.add_argument('-l', '--list', action='store_true', dest='list_all',
                        help='List all available binaries')
    return parser.parse_args()


def display_binary(binary, filter_type=None):
    """Display exploitation techniques for a binary."""
    file_path = data_dir / f"{binary}{json_ext}"
    if not file_path.exists():
        print(fail.safe_substitute(text="Sorry, couldn't find anything for " + binary))
        return False

    print(info.safe_substitute(text="Supplied binary: " + binary))
    with open(file_path) as source:
        json_data = json.load(source)

    if 'description' in json_data:
        print('\n' + description.safe_substitute(description=json_data['description']))

    vectors = json_data['functions']
    if filter_type:
        vectors = {k: v for k, v in vectors.items() if k == filter_type}
        if not vectors:
            print(fail.safe_substitute(text=f"No '{filter_type}' techniques for {binary}"))
            return False

    for vector in vectors:
        print(title.safe_substitute(title=str(vector).upper()))
        for idx, code in enumerate(vectors[vector]):
            if 'description' in code:
                print(description.safe_substitute(description=code['description']) + '\n')
            print(highlight(code['code'], lexers.BashLexer(),
                            formatters.TerminalTrueColorFormatter(style='igor')).strip())
            if idx != len(vectors[vector]) - 1:
                print(divider)

    print('\n' + info.safe_substitute(text="Goodbye, friend."))
    return True


def print_binary_list(binaries, columns=4):
    """Print binaries in columns."""
    if not binaries:
        print(fail.safe_substitute(text="No binaries found."))
        return
    max_len = max(len(b) for b in binaries) + 2
    per_row = columns
    for i in range(0, len(binaries), per_row):
        row = binaries[i:i + per_row]
        print('  ' + ''.join(b.ljust(max_len) for b in row))


def interactive_mode():
    """Interactive mode with autocomplete."""
    try:
        from prompt_toolkit import prompt
        from prompt_toolkit.completion import FuzzyWordCompleter
    except ImportError:
        print(fail.safe_substitute(text="Interactive mode requires 'prompt_toolkit'. Install with: pip install prompt_toolkit"))
        sys.exit(1)

    binaries = get_all_binaries()
    completer = FuzzyWordCompleter(binaries)

    print(info.safe_substitute(text=f"Interactive mode - {len(binaries)} binaries available"))
    print(info.safe_substitute(text="Type binary name (Tab for autocomplete, Ctrl+C to exit)"))
    print()

    while True:
        try:
            user_input = prompt('gtfo> ', completer=completer).strip()
            if not user_input:
                continue
            if user_input.lower() in ('exit', 'quit', 'q'):
                break
            display_binary(user_input)
            print()
        except KeyboardInterrupt:
            break
        except EOFError:
            break

    print('\n' + info.safe_substitute(text="Goodbye, friend."))


def run(binary=None):
    """Main function that can be called programmatically."""
    args = parse_args() if binary is None else None

    if args:
        if args.interactive:
            interactive_mode()
            return

        if args.list_all:
            binaries = get_all_binaries()
            print(info.safe_substitute(text=f"Available binaries ({len(binaries)}):"))
            print()
            print_binary_list(binaries)
            return

        if args.search:
            binaries = get_all_binaries()
            matches = fuzzy_match(args.search, binaries)
            if matches:
                print(info.safe_substitute(text=f"Search results for '{args.search}' ({len(matches)} matches):"))
                print()
                print_binary_list(matches)
            else:
                print(fail.safe_substitute(text=f"No binaries matching '{args.search}'"))
            return

        if args.exploit_type:
            if args.exploit_type not in EXPLOIT_TYPES:
                print(fail.safe_substitute(text=f"Unknown type '{args.exploit_type}'"))
                print(info.safe_substitute(text=f"Valid types: {', '.join(EXPLOIT_TYPES)}"))
                return
            binaries = get_binaries_with_type(args.exploit_type)
            if binaries:
                print(info.safe_substitute(text=f"Binaries with '{args.exploit_type}' ({len(binaries)}):"))
                print()
                print_binary_list(binaries)
            else:
                print(fail.safe_substitute(text=f"No binaries with '{args.exploit_type}'"))
            return

        binary = args.binary

    if not binary:
        print(fail.safe_substitute(text="No binary specified. Use -h for help."))
        return

    filter_type = args.exploit_type if args else None
    display_binary(binary, filter_type)


def main():
    """Console script entry point"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(banner)
    run()


if __name__ == '__main__':
    main()
