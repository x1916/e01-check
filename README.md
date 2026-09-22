# e01-check

Verify EnCase/EWF (`.E01`) forensic image acquisition hashes (MD5).

Recursively scans a folder for `.E01` images, recalculates the MD5 of each
image's media data and compares it against the stored acquisition hash
embedded in the E01 file. Also reports the case/examiner metadata from the
image header and exports results to CSV.

## Requirements

- Python 3.10+
- Windows, Linux or macOS

## Install

```
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt
```

## Usage

```
python verify-e01.py [FOLDER ...]
```

- Scans the current folder if no path is given.
- Accepts individual `.E01` files or folders (scanned recursively).
- Multi-segment sets (`image.E01`, `image.E02`, ...) are discovered
  automatically and verified as one image.
- Prints one panel per image, a summary table, and writes
  `e01-verification-report.csv` (UTF-8 BOM, Excel-friendly).

Status codes:

| Symbol | Meaning                                     | Colour |
| ------ | ------------------------------------------- | ------ |
| `✓`    | Stored hash matches calculated hash         | green  |
| `✗`    | Stored hash differs from calculated hash    | red    |
| `⚠`    | Image contains no stored hash (not checked) | yellow |
| `✗`    | Image could not be read                    | red    |

Exit code is `0` when every image matches, `1` otherwise (mismatch or error),
so the tool can be used in CI pipelines.

Options:

```
--csv PATH       report file (default: e01-verification-report.csv)
--no-csv         do not write the report
--no-progress    disable per-image progress bars
--help           show help
```

## Notes

- Only MD5 is supported (the hash stored in `.E01` files is MD5).
- WALRUS/EW2 (`.Ex01`) variants are outside the current scope.
- Header date values in the E01 may be stored as epoch seconds or as a
  formatted string; both are normalized to `YYYY-MM-DD HH:MM:SS` when possible.

## Build a Windows EXE

A standalone, single-file `e01-check.exe` can be built on any Windows machine
with Python installed (no cross-compilation possible):

```
build-exe.bat
```

The script creates a `.venv-build` virtualenv, installs PyInstaller and the
project dependencies, then produces `dist\e01-check.exe`. The resulting binary
runs identically to the script:

```
e01-check.exe [FOLDER ...]
```

Notes:

- Build on the target architecture (32- vs 64-bit) or ship both if needed.
- The EXE is unsigned, so Windows SmartScreen/Defender may warn on first run.
- `--onefile` means the EXE extracts itself to a temp dir on startup, so the
  first launch takes a few seconds longer than the script.
- To rebuild after edits: re-run `build-exe.bat` (it reuses `.venv-build`).