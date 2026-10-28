# Security Policy

## Supported Versions

The following versions are currently supported with security updates:

| Version | Supported |
|---------|-----------|
| main    | yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

### What to report

- Vulnerabilities in Python dependencies (capstone, networkx, customtkinter, pandas, numpy)
- Path traversal or arbitrary file read/write via EX4 file loading
- Code execution risks in the code generation pipeline
- Information disclosure through logs or exported JSON

### How to report

Open a private issue on GitHub or email the project maintainer directly. Do not post vulnerability details in public issues, pull requests, or discussions.

Include:

- A description of the vulnerability
- Steps to reproduce
- The affected file(s) and line number(s)
- Suggested fix or mitigation (if you have one)

### Response timeline

- Acknowledgment within 5 business days
- Initial assessment within 10 business days
- Fix or workaround provided as soon as possible, depending on severity

## Disclosure

We follow coordinated disclosure. Please give us reasonable time to investigate and patch before public disclosure.

## Sample EX4 Files

The `EX4 file (indicator)/` directory contains sample `.ex4` files for testing. These are provided for analysis purposes only. Do not reverse engineer or distribute proprietary EX4 files you do not own or have rights to analyze.

## Dependencies

This project uses the following key dependencies:

- capstone - x86 disassembly engine
- networkx - control flow and call graph analysis
- customtkinter - GUI framework
- pandas, numpy - data analysis
- darkdetect - OS theme detection

Keep dependencies updated and review `pip audit` output regularly.
