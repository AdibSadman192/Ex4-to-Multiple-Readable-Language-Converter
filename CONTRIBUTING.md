# Contributing to EX4-to-Multiple-Readable-Language-Converter

Thank you for considering a contribution to this project. This is a Python tool that analyzes MetaTrader 4 (MT4) EX4 binary files and converts them into multiple readable programming languages (MQL4, MQL5, Python, C, R, Text).

## Getting Started

### Prerequisites

- Python 3.10 or higher
- pip package manager

### Setup

1. Fork the repository on GitHub.
2. Clone your fork locally:

   ```bash
   git clone https://github.com/<your-username>/Ex4-to-Multiple-Readable-Language-Converter.git
   cd Ex4-to-Multiple-Readable-Language-Converter
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Verify the GUI and CLI both launch:

   ```bash
   python ex4_gui_app.py
   python ex4_debug_decompiler.py --help
   ```

## Project Structure

| File | Purpose |
|------|---------|
| `ex4_gui_app.py` | CustomTkinter GUI (EX4 Studio) with six analysis tabs |
| `ex4_debug_decompiler.py` | CLI entry point plus MT4Analyzer core logic |
| `ex4_rea_engine.py` | REA reverse-engineering engine (PE parsing, MQL4 VM disassembly, CFG, call graph, data flow, string deobfuscation, API resolution, function boundaries) |
| `ex4_analyzer.py` | Legacy analyzer module |
| `mt4_file_manager.py` | MT4 file management utilities |
| `ex4_decompiler.py` | Alternate decompiler implementation |
| `ex4_full_decompiler.py` | Full decompiler implementation |

## How to Contribute

### 1. Report a Bug

Open an issue using the bug report template. Include:

- The EX4 file build version (if known)
- Steps to reproduce
- Expected vs actual behavior
- Error logs from the Log tab or CLI output

### 2. Suggest a Feature

Open an issue using the feature request template. Describe:

- What you want to add or change
- Why it helps EX4 analysis or code generation
- Example input/output if applicable

### 3. Submit a Pull Request

1. Create a new branch from `main`:

   ```bash
   git checkout -b your-feature-name
   ```

2. Make your changes.
3. Compile-check all modified Python files:

   ```bash
   python -m py_compile ex4_gui_app.py ex4_debug_decompiler.py ex4_rea_engine.py
   ```

4. Run a quick functional test against one of the sample EX4 files in `EX4 file (indicator)/`.
5. Commit with a clear message:

   ```bash
   git commit -m "Add feature: short description"
   ```

6. Push to your fork and open a pull request.

## Code Style

- Follow PEP 8 where practical.
- Match the existing style of the file you are editing (imports at top, class/method ordering, docstrings on public methods).
- Do not commit secrets, API keys, or sample EX4 files that contain proprietary logic.

## Testing

- Test against the sample `.ex4` files in `EX4 file (indicator)/`.
- Verify both GUI and CLI paths work after your change.
- For CLI changes, test with `--dump` and `--json` flags as well as plain analysis.

## Legal

By contributing, you agree that your contributions are licensed under the MIT License (see `LICENSE`). Do not submit code you do not have the right to contribute.
