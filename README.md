<div align="center">

# 🚀 GTFOBins CLI

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-GPL%20v3-green?style=for-the-badge)](https://github.com/kasem545/gtfobins-cli/blob/master/LICENSE)
[![Stars](https://img.shields.io/github/stars/kasem545/gtfobins-cli?style=for-the-badge)](https://github.com/kasem545/gtfobins-cli/stargazers)

</div>

## Overview

**GTFOBins CLI** is a command-line interface for [GTFOBins](https://gtfobins.github.io/), providing instant access to Unix binary exploitation techniques. This tool helps security professionals and system administrators identify and understand how legitimate Unix binaries can be misused to bypass security restrictions.

### Key Features

- 🔍 **Quick Binary Lookup**: Search exploitation techniques for any Unix binary
- 🔎 **Fuzzy Search**: Find binaries with partial name matching
- 🏷️ **Filter by Type**: Filter binaries by exploitation type (shell, suid, sudo, etc.)
- 🖥️ **Interactive Mode**: fzf-style autocomplete for quick navigation
- 🎨 **Syntax Highlighting**: Color-coded output for better readability
- 📦 **Offline Database**: No internet connection required
- 🚀 **Instant Access**: Fast, local searches with zero latency
- 💻 **Cross-Platform**: Works on Linux, macOS, and Windows

## Installation

### From pipx (Recommended)

```bash
pipx install git+https://github.com/kasem545/gtfobins-cli
```

### From Source

```bash
git clone https://github.com/kasem545/gtfobins-cli
cd gtfobins-cli
pip install -e .
```

## Usage

### Basic Usage

```bash
gtfo <binary>
```

### Examples

```bash
# Search for sudo exploitation techniques
gtfo sudo

# Search for python exploitation techniques
gtfo python

# Fuzzy search binaries by name
gtfo -s pyth

# Filter binaries by exploitation type
gtfo -f shell
gtfo -f suid
gtfo -f sudo

# Show only specific technique for a binary
gtfo python -f sudo

# Interactive mode with autocomplete
gtfo -i

# List all available binaries
gtfo -l

# Check version
gtfo --version
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `binary` | Unix binary to search for exploitation techniques |
| `-s, --search TERM` | Fuzzy search binaries by name |
| `-f, --filter TYPE` | Filter binaries by exploitation type |
| `-i, --interactive` | Interactive mode with autocomplete |
| `-l, --list` | List all available binaries |
| `-v, --version` | Show version |
| `-h, --help` | Show help message |

## Exploitation Categories

The tool provides information about various exploitation techniques:

- **Shell**: Spawn an interactive shell
- **Command**: Execute system commands
- **Reverse Shell**: Establish a reverse shell connection
- **Non-interactive Reverse Shell**: Create a non-interactive reverse shell
- **Bind Shell**: Set up a bind shell
- **Non-interactive Bind Shell**: Create a non-interactive bind shell
- **File Upload**: Transfer files to the target system
- **File Download**: Extract files from the target system
- **File Write**: Write data to files
- **File Read**: Read file contents
- **Library Load**: Load shared libraries
- **SUID**: Exploit SUID permissions
- **Sudo**: Exploit sudo permissions
- **Capabilities**: Exploit Linux capabilities
- **Limited SUID**: Work with limited SUID permissions

## Screenshots

<p align="center">
  <img src="gtfo/images/sqlit3.png" width="45%">
  <img src="gtfo/images/search-interactive.png" width="45%">
</p>
<p align="center">
  <img src="gtfo/images/filter-with.png" width="45%">
  <img src="gtfo/images/search-for.png" width="45%">
</p>
<p align="center">
  <img src="gtfo/images/search-docker.png" width="45%">
</p>



## Development

### Setting up Development Environment

```bash
# Clone the repository
git clone https://github.com/kasem545/gtfobins-cli
cd gtfo

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Credits

- Binary exploitation data from [GTFOBins](https://gtfobins.github.io/)
- Original GTFOBins project contributors
- Created by [t0thkr1s](https://github.com/t0thkr1s) 
- maintained by [kasem545](https://github.com/kasem545)

## Security Notice

⚠️ **Important**: This tool is designed for authorized security testing and educational purposes only. Users must:

- Only use this tool on systems they own or have explicit permission to test
- Comply with all applicable laws and regulations
- Understand that misuse of this tool may result in criminal charges

The developers assume no liability and are not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have questions:

- Open an [issue](https://github.com/kasem545/gtfobins-cli/issues)
- Check existing issues for solutions
- Consult the [GTFOBins website](https://gtfobins.github.io/) for additional information
