#!/usr/bin/env python3
"""Verify EnCase/EWF (.E01) acquisition hashes.

Recursively scans a folder for .E01 forensic images, recalculates the MD5
of each image and compares it against the stored acquisition hash embedded
in the E01 file. Reports case/examiner metadata and writes a CSV report.

Exit code: 0 if every image hashed matches, otherwise 1.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import re
import sys
import zlib
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from dissect.evidence.ewf import EWF

FIELD_NAMES = {
    "c": "Case Number",
    "n": "Evidence Number",
    "a": "Description",
    "e": "Examiner Name",
    "t": "Notes",
    "md": "Media Model",
    "sn": "Serial Number",
    "av": "Acquisition Version",
    "ov": "Platform/OS",
    "m": "Acquisition Date",
    "u": "System Date",
    "dc": "Data Format",
}

# Display order for metadata shown in the panel
DISPLAY_KEYS = ["c", "n", "a", "e", "t", "md", "sn", "ov", "av", "m", "u"]

SEGMENT_RE = re.compile(r"^[Ee][0-9A-Za-z]{2,3}$")

STATUS_MATCH = "MATCH"
STATUS_MISMATCH = "MISMATCH"
STATUS_NO_HASH = "NO_HASH"
STATUS_ERROR = "ERROR"

STATUS_STYLE = {
    STATUS_MATCH: ("green", "✓"),
    STATUS_MISMATCH: ("red", "✗"),
    STATUS_NO_HASH: ("yellow", "⚠"),
    STATUS_ERROR: ("red", "✗"),
}


def find_segments(first: Path) -> list[Path]:
    """Find all segment files (image.E01, image.E02, ...) belonging to `first`."""
    segments = [p for p in first.parent.iterdir() if SEGMENT_RE.match(p.suffix[1:]) and p.stem == first.stem]
    return sorted(segments, key=lambda p: p.suffix)


def decode_header(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def parse_header_fields(raw: bytes) -> dict[str, str]:
    """Parse EWF header/header2 text into a {key: value} dict."""
    text = decode_header(raw)
    lines = [ln.rstrip("\r") for ln in text.split("\n")]
    fields: dict[str, str] = {}
    for i, line in enumerate(lines):
        if line.strip().isdigit() and i + 3 < len(lines):
            keys = lines[i + 2]
            if "\t" in keys:
                klist = [k.strip() for k in keys.split("\t")]
                vlist = [v.strip() for v in lines[i + 3].split("\t")]
                for k, v in zip(klist, vlist):
                    if k and v:
                        fields[k] = v
    return fields


def format_date(value: str) -> str:
    if value.isdigit() and len(value) in (9, 10):
        try:
            return datetime.datetime.fromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, ValueError):
            pass
    return value


def read_section_data(seg, section) -> bytes:
    seg.fh.seek(section.data_offset)
    buff = seg.fh.read(section.size)
    if section.type == b"hash":
        return buff
    try:
        return zlib.decompress(buff)
    except zlib.error:
        return buff


def verify_image(first: Path, progress: Progress, show_progress: bool) -> dict:
    """Verify a single .E01 image, returning a result dict."""
    result = {
        "first": first,
        "segments": [],
        "status": STATUS_ERROR,
        "stored_md5": None,
        "calculated_md5": None,
        "meta": {},
        "error": None,
        "media_size": 0,
    }

    ewf: EWF | None = None
    task: int | None = None
    try:
        segments = find_segments(first)
        result["segments"] = [str(p) for p in segments]

        ewf = EWF([str(p) for p in segments])
        result["media_size"] = ewf.size
        seg_objs = [ewf.segment(i) for i in range(len(segments))]

        if show_progress:
            task = progress.add_task(f"{first.parent.name}/{first.name}", total=ewf.size)

        # Stored hash + header metadata live in the segment sections
        for seg in seg_objs:
            for section in seg.sections:
                if section.type == b"hash" and result["stored_md5"] is None:
                    try:
                        result["stored_md5"] = read_section_data(seg, section)[:16].hex()
                    except Exception:
                        pass
                elif section.type in (b"header", b"header2"):
                    try:
                        parsed = parse_header_fields(read_section_data(seg, section))
                        # ASCII `header` (older, human dates) overrides header2
                        if section.type == b"header":
                            result["meta"].update(parsed)
                        else:
                            result["meta"] = {**parsed, **result["meta"]}
                    except Exception:
                        pass

        # Recalculate MD5 over every chunk of every segment
        md5 = hashlib.md5()
        done_bytes = 0
        for seg in seg_objs:
            for tbl in seg.tables:
                for c in range(tbl.num_entries):
                    data = tbl.read_chunk(c)
                    md5.update(data)
                    done_bytes += len(data)
                if task:
                    progress.update(task, completed=done_bytes)

        result["calculated_md5"] = md5.hexdigest()

        if result["stored_md5"] is None:
            result["status"] = STATUS_NO_HASH
        elif result["stored_md5"] == result["calculated_md5"]:
            result["status"] = STATUS_MATCH
        else:
            result["status"] = STATUS_MISMATCH

    except Exception as e:  # noqa: BLE001 - report any parse/hash failure per image
        result["error"] = str(e)
        result["status"] = STATUS_ERROR

    finally:
        if task is not None:
            progress.remove_task(task)
        if ewf is not None:
            try:
                ewf.close()
            except Exception:
                pass

    return result


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{n} B"


def build_panel(result: dict) -> Panel:
    style, icon = STATUS_STYLE[result["status"]]
    label = {
        STATUS_MATCH: "MATCH",
        STATUS_MISMATCH: "MISMATCH",
        STATUS_NO_HASH: "NO STORED HASH",
        STATUS_ERROR: "ERROR",
    }[result["status"]]

    title = f"[b]{result['first'].name}[/b]  [{style}]{icon} {label}[/{style}]"

    lines = []
    if result["status"] == STATUS_ERROR:
        lines.append(f"[red]{result['error'] or 'unknown error'}[/red]")
    else:
        meta = result["meta"]
        for key in DISPLAY_KEYS:
            if key in meta:
                value = format_date(meta[key]) if key in ("m", "u") else meta[key]
                lines.append(f"[cyan]{FIELD_NAMES[key]:<18}[/cyan] {value}")
        if "md" in meta:
            lines.append(f"[cyan]{FIELD_NAMES['md']:<18}[/cyan] {meta['md']}")
        if "sn" in meta:
            lines.append(f"[cyan]{FIELD_NAMES['sn']:<18}[/cyan] {meta['sn']}")
        lines.append(f"[cyan]{'Segments':<18}[/cyan] {len(result['segments'])} file(s)")
        lines.append(f"[cyan]{'Media size':<18}[/cyan] {human_bytes(result['media_size'])}")
        lines.append("")
        lines.append(f"[cyan]{'Stored MD5':<18}[/cyan] {result['stored_md5'] or '—'}")
        lines.append(
            f"[cyan]{'Calculated MD5':<18}[/cyan] {result['calculated_md5'] or '—'}"
        )
        lines.append("")
        status_color = {"MATCH": "green", "MISMATCH": "red", "NO STORED HASH": "yellow"}[label]
        lines.append(f"[{status_color}]  {icon} {label}[/{status_color}]")

    return Panel("\n".join(lines), title=title, border_style=style, padding=(0, 1))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify EnCase/EWF (.E01) acquisition hashes (MD5).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="file(s) or folder(s) to scan (recursively). Default: current folder",
    )
    parser.add_argument(
        "--csv",
        metavar="PATH",
        default="e01-verification-report.csv",
        help="write results to this CSV file",
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        help="do not write a CSV report",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="disable per-image progress bars",
    )
    return parser.parse_args(argv)


def collect_images(paths: list[str]) -> list[Path]:
    images: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_file() and p.suffix.lower() == ".e01":
            images.append(p)
        elif p.is_dir():
            images.extend(x for x in p.rglob("*.E01") if x.suffix.lower() == ".e01")
        elif p.exists():
            print(f"warning: not a file or directory: {p}", file=sys.stderr)
        else:
            print(f"warning: path not found: {p}", file=sys.stderr)
    # de-duplicate and keep stable order
    seen: set[str] = set()
    unique: list[Path] = []
    for img in images:
        key = str(img.resolve())
        if key not in seen:
            seen.add(key)
            unique.append(img)
    return unique


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    console = Console()
    show_progress = not args.no_progress and console.is_terminal

    images = collect_images(args.paths)
    if not images:
        console.print("No .E01 images found.")
        return 0

    progress = Progress(
        TextColumn("[bold]{task.description}[/bold]"),
        BarColumn(),
        MofNCompleteColumn(),
        "•",
        TimeElapsedColumn(),
        "<",
        TimeRemainingColumn(),
        console=console,
    )

    results: list[dict] = []
    if show_progress:
        with progress:
            _interactive_verify(images, progress, show_progress, results)
    else:
        _interactive_verify(images, progress, show_progress, results)

    for result in results:
        console.print(build_panel(result))
        console.print("")

    summary = Table(title="E01 Verification Summary", show_header=True)
    summary.add_column("Status", style="bold")
    summary.add_column("Count", justify="right")
    counts: dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    for status, label in (
        (STATUS_MATCH, "MATCH"),
        (STATUS_MISMATCH, "MISMATCH"),
        (STATUS_NO_HASH, "NO STORED HASH"),
        (STATUS_ERROR, "ERROR"),
    ):
        style = "green" if status == STATUS_MATCH else "red" if status in (STATUS_MISMATCH, STATUS_ERROR) else "yellow"
        summary.add_row(f"[{style}]{label}[/{style}]", str(counts.get(status, 0)))
    summary.add_row("[bold]Total images verified[/bold]", str(len(results)))
    console.print(summary)

    if not args.no_csv:
        if write_csv(args.csv, results):
            console.print(f"\nReport written to [cyan]{args.csv}[/cyan]")

    bad = counts.get(STATUS_MISMATCH, 0) + counts.get(STATUS_ERROR, 0)
    return 1 if bad else 0


def _interactive_verify(images, progress, show_progress, results):
    for img in images:
        results.append(verify_image(img, progress, show_progress))


def write_csv(path: str, results: list[dict]) -> bool:
    try:
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "path",
                    "case_number",
                    "evidence_number",
                    "description",
                    "examiner_name",
                    "notes",
                    "media_model",
                    "serial_number",
                    "platform_os",
                    "acquisition_date",
                    "system_date",
                    "segments",
                    "media_size",
                    "stored_md5",
                    "calculated_md5",
                    "status",
                    "error",
                ]
            )
            for r in results:
                m = r["meta"]
                writer.writerow(
                    [
                        str(r["first"]),
                        m.get("c", ""),
                        m.get("n", ""),
                        m.get("a", ""),
                        m.get("e", ""),
                        m.get("t", ""),
                        m.get("md", ""),
                        m.get("sn", ""),
                        m.get("ov", ""),
                        format_date(m["m"]) if "m" in m else "",
                        format_date(m["u"]) if "u" in m else "",
                        len(r["segments"]),
                        r["media_size"],
                        r["stored_md5"] or "",
                        r["calculated_md5"] or "",
                        r["status"],
                        r["error"] or "",
                    ]
                )
        return True
    except OSError as e:
        print(f"error: could not write CSV: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    sys.exit(main())