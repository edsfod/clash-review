"""pack.py - build the release zip of a tool that vendors web-kit: the tool's tracked files plus the
official Windows embeddable Python, so users unzip it and double-click the .bat without installing Python.

    python web-kit/pack.py [--tool DIR] [--name NAME] [--tag TAG] [--out DIR]

Run from anywhere; DIR defaults to the parent of this web-kit copy (the tool root). Only files tracked by git
(`git ls-files`) go in, so personal files kept out by .gitignore (settings.json, var/, ...) never ship.
.github/ is left out. The zip is <out>/<name>-<tag>-win64.zip with everything under <name>/, and
<name>/python/ holding the embeddable Python; find-python.ps1 looks there first.

Standard library only (runs on the GitHub Actions Ubuntu runner and on Windows). Needs git and network.
"""
import argparse, hashlib, io, os, subprocess, sys, urllib.request, zipfile

# Official embeddable package. When bumping: take the URL and sha256 from
# https://www.python.org/api/v2/downloads/release_file/?release=<id> (the "sha256_sum" field).
PY_VERSION = "3.14.7"
PY_URL = f"https://www.python.org/ftp/python/{PY_VERSION}/python-{PY_VERSION}-embed-amd64.zip"
PY_SHA256 = "d297e5ff019966817ad8502465176139f2d3d840fa4ed84b13bed399a6ab1f15"

HERE = os.path.dirname(os.path.abspath(__file__))


def tracked_files(tool):
    out = subprocess.run(["git", "-C", tool, "ls-files", "-z"], check=True, capture_output=True).stdout
    return [f for f in out.decode("utf-8").split("\0") if f and not f.startswith(".github/")]


def embeddable_python():
    with urllib.request.urlopen(PY_URL, timeout=120) as r:
        data = r.read()
    got = hashlib.sha256(data).hexdigest()
    if got != PY_SHA256:
        sys.exit(f"pack: {PY_URL} sha256 {got} != expected {PY_SHA256}")
    return zipfile.ZipFile(io.BytesIO(data))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", default=os.path.dirname(HERE))
    ap.add_argument("--name")
    ap.add_argument("--tag", default="dev")
    ap.add_argument("--out", default="dist")
    a = ap.parse_args()
    tool = os.path.abspath(a.tool)
    name = a.name or os.path.basename(tool)
    os.makedirs(a.out, exist_ok=True)
    dest = os.path.join(a.out, f"{name}-{a.tag}-win64.zip")

    files = tracked_files(tool)
    py = embeddable_python()
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            z.write(os.path.join(tool, f), f"{name}/{f}")
        for info in py.infolist():
            data = py.read(info)
            if info.filename.endswith("._pth"):
                # The embeddable Python ignores the script's folder; put the tool root (..) on sys.path
                # so the tools' `import advisor` etc. keep working.
                data = data.replace(b"\r\n", b"\n").rstrip(b"\n") + b"\n\n# tool root (added by web-kit/pack.py)\n..\n"
            z.writestr(f"{name}/python/{info.filename}", data)
    print(f"{dest}: {len(files)} tool files + Python {PY_VERSION} embeddable")


if __name__ == "__main__":
    main()
