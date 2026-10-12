"""Collect crate-shipped license texts for binary redistribution."""
import json
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parent.parent
metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root))
destination = root / ".release-stage" / "DEPENDENCY-LICENSES.txt"
destination.parent.mkdir(exist_ok=True)
with destination.open("w", encoding="utf-8") as output:
    for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        base = pathlib.Path(package["manifest_path"]).parent
        files = [p for p in base.iterdir() if p.is_file() and (
            p.name.lower().startswith("license") or p.name.lower().startswith("copying")
            or p.name.lower().startswith("notice"))]
        directory = base / "LICENSES"
        if directory.is_dir():
            files.extend(p for p in directory.iterdir() if p.is_file())
        output.write(f"\n{'=' * 72}\n{package['name']} {package['version']}\n"
                     f"SPDX: {package.get('license') or 'see upstream'}\n"
                     f"Source: {package.get('repository') or package.get('source') or 'this repository'}\n")
        for file in sorted(files):
            output.write(f"\n--- {file.name} ---\n")
            output.write(file.read_text(encoding="utf-8", errors="replace"))
            output.write("\n")
