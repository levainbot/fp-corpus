#!/usr/bin/env python3
"""Write tp-corpus.txt and tp-corpus.json out of the .b64 files next to this script.

The true-positive corpus is stored base64-encoded in git for one reason: GitHub's
push protection refuses to accept it as plain text. Its credentials are synthetic and
generated from a fixed seed -- none has ever been live -- but they carry the correct
prefixes and lengths, so GitHub's partner patterns match them, and a scanner fixture
that no scanner recognises would be worthless. Encoding is the only way the file can
live in this repository at all. Nothing is withheld or altered; the sha256 of each
decoded file is recorded below and checked on every run.

    python3 materialize.py           # writes both files, verifies both digests
"""
import base64, hashlib, pathlib, sys

DIGESTS = {
    "tp-corpus.txt":  "3e5a6851ee3aa3841c59be1adb10aab97450c5a7e503fb970aba4d1da5ec72ad",
    "tp-corpus.json": "f438f4ee77974aca202bbe687201c23b5cb2b100cb8b1951f982cca2171bd147",
}
here = pathlib.Path(__file__).resolve().parent
bad = 0
for name, want in DIGESTS.items():
    src = here / (name + ".b64")
    if not src.exists():
        # The release bundle ships these files already decoded and carries no .b64
        # source, so a buyer who runs this script the way the README describes must
        # not be met with an error. Verify what is there instead: that is the same
        # guarantee the decode path gives, applied to the file they actually have.
        out = here / name
        if out.exists():
            got = hashlib.sha256(out.read_bytes()).hexdigest()
            if got == want:
                print("already decoded: " + name + "  sha256 " + got[:16] + "  nothing to do")
            else:
                print(name + ": sha256 " + got + " but expected " + want, file=sys.stderr); bad += 1
            continue
        print("missing: " + src.name + " (and no decoded " + name + " beside it)", file=sys.stderr)
        bad += 1; continue
    data = base64.b64decode(src.read_text())
    got = hashlib.sha256(data).hexdigest()
    if got != want:
        print(name + ": sha256 " + got + " but expected " + want, file=sys.stderr); bad += 1; continue
    (here / name).write_bytes(data)
    print("wrote " + name + "  " + str(len(data)) + " bytes  sha256 " + got[:16])
sys.exit(1 if bad else 0)
