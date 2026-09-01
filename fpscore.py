#!/usr/bin/env python3
"""fpscore -- point your own secret scanner at a corpus and get a number back.

    python3 fpscore.py --demo
    python3 fpscore.py --cmd 'my-scanner --json -r {report} {dir}'
    python3 fpscore.py --cmd 'my-scanner {file}' --max 0        # once per section, CI gate

The corpus contains no credential of any kind, so every secret reported against
it is a false positive. This script does the boring part: it writes the 57
sections out as files, runs whatever command you give it, reads the findings
back out of the output, and tells you which section each one came from.

It publishes no scoreboard. The only number it prints is YOURS.

Python 3.8+, standard library only. The scanner it runs can be written in
anything -- this is a runner, not a library, so the host language never reaches
your tool.

MIT. Part of https://github.com/levainbot/fp-corpus
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# Keys that different scanners use for the same three ideas. Order matters:
# the first key present wins.
LINE_KEYS = ("StartLine", "start_line", "line_number", "lineNumber", "line", "Line")
MATCH_KEYS = ("Secret", "secret", "Match", "match", "Raw", "raw", "raw_v2",
              "value", "matched", "Line")
FILE_HINT = re.compile(r"[\w.-]*?(\d{3}-[a-z0-9-]+\.log)")

# ---------------------------------------------------------------------------
# The control file.
#
# A precision corpus contains no credentials, so the best possible result is
# zero findings -- which is also exactly what a scanner produces when it never
# read the files at all. A wrong path, an extension filter, a missing
# --recursive: all of them exit 0 and print nothing, and without a witness this
# script would report a flawless score for a scan that did not happen.
#
# So it plants one extra file that is NOT part of the corpus and never scored,
# holding three synthetic credentials in the three shapes every secret scanner
# detects. Reporting them proves nothing about a tool's quality; it proves the
# tool read these bytes. Silence on all three, with silence everywhere else, is
# reported as an un-scorable run rather than as a perfect one.
CONTROL_FILE = "000-control.log"

# Assembled from fragments so this source file never itself contains a string
# matching a credential pattern -- it lives in a public git repository that has
# push protection on, and it is scanned by the very tools it is built for.
# Nothing here is a real credential; the values are made up.
CONTROL_SECRETS = (
    ("aws-access-key-id", "AKIA" + "3XQ7ZR2LMWD5TKVB"),
    ("github-token", "ghp_" + "9tR2mV6xQ0aL4bN8cW1eK5jH7dS3fG0uY2iP"),
    ("private-key", "-----BEGIN " + "RSA PRIVATE KEY-----"),
)

CONTROL_BODY = """MIIBOgIBAAJBAKq3Yz2mVn8sLd41TfQe0hWbX9uJcR7pAoGvE5sNzD6yKlMtBw2r
Uv8QxHnJ4aCeF1gP0dSiT3wYkZmL9bOqAgMBAAECQQCJ7mXvA2dNqL0pRfWzYuHb
9kGcT1sEoVxDmJ4rBnQaZ6PwK3iUlS8yXeCtM0vFgN7hRdObA5jTqLwYnZuIxEfB"""


def control_text():
    aws, ghp, pem = (t for _, t in CONTROL_SECRETS)
    return "\n".join([
        "# %s -- planted by fpscore.py. NOT part of the corpus." % CONTROL_FILE,
        "#",
        "# Every credential below is synthetic. It is here for one reason: to",
        "# prove your scanner actually read these files. Findings in this file",
        "# are never counted as false positives and never counted as recall.",
        "2026-01-04T09:12:45Z deploy[1] aws_access_key_id=" + aws,
        "2026-01-04T09:12:45Z deploy[1] github_token=" + ghp,
        "2026-01-04T09:12:46Z deploy[1] reading signing key /etc/keys/deploy.pem",
        pem,
        CONTROL_BODY,
        "-----END " + "RSA PRIVATE KEY-----",
        "",
    ])


def write_control(outdir):
    """Plant the control file. Returns a one-entry index shaped like a section
    so the finding extractors can attribute to it, marked so scoring skips it."""
    text = control_text()
    with open(os.path.join(outdir, CONTROL_FILE), "w", encoding="utf-8") as fh:
        fh.write(text)
    return {CONTROL_FILE: {"name": "control (never scored)", "text": text,
                           "secrets": [], "personal_data": [],
                           "_file": CONTROL_FILE, "_control": True}}


def human_list(items):
    """a, b and c"""
    if len(items) < 2:
        return "".join(items)
    return "%s and %s" % (", ".join(items[:-1]), items[-1])


def control_report(found, raw):
    """Two independent witnesses that the scanner saw the control file: a
    finding attributed to it, and any control secret echoed in the raw output.
    Either one is enough -- a scanner that names the file but prints no matched
    span is still demonstrably looking."""
    attributed = [f for f in found if f["file"] == CONTROL_FILE]
    echoed = [kind for kind, text in CONTROL_SECRETS if text in raw]
    return {"file": CONTROL_FILE,
            "reported": bool(attributed) or bool(echoed),
            "findings": len(attributed),
            "kinds_echoed": echoed,
            "planted": [kind for kind, _ in CONTROL_SECRETS]}


def slug(name):
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "section"


def load_corpus(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def materialize(corpus, outdir):
    """One file per section. Returns {basename: section}."""
    index = {}
    for i, section in enumerate(corpus["sections"], 1):
        base = "%03d-%s.log" % (i, slug(section["name"]))
        with open(os.path.join(outdir, base), "w", encoding="utf-8") as fh:
            fh.write(section["text"])
            if not section["text"].endswith("\n"):
                fh.write("\n")
        section["_file"] = base
        index[base] = section
    return index


def walk_json(node, out):
    """Collect every dict in an arbitrary JSON tree."""
    if isinstance(node, dict):
        out.append(node)
        for v in node.values():
            walk_json(v, out)
    elif isinstance(node, list):
        for v in node:
            walk_json(v, out)


def parse_json_ish(text):
    """A whole JSON document, or JSON-lines, or nothing."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    # JSON-lines, or a report document with a scanner's chatter around it. Most
    # tools write a pretty-printed report and then print a summary line after it,
    # which defeats a whole-document parse -- and falling back to grepping
    # filenames silently loses the matched text, which is the half recall needs.
    dec = json.JSONDecoder()
    rows, i = [], 0
    while i < len(text):
        starts = [x for x in (text.find("{", i), text.find("[", i)) if x != -1]
        if not starts:
            break
        at = min(starts)
        try:
            obj, end = dec.raw_decode(text, at)
        except ValueError:
            i = at + 1
            continue
        rows.append(obj)
        i = end
    return rows or None


def findings_from_json(doc, index):
    """Any dict that names one of our files is a finding. No per-tool adapter."""
    dicts = []
    walk_json(doc, dicts)
    found = []
    for d in dicts:
        base = None
        for v in d.values():
            if isinstance(v, str):
                m = FILE_HINT.search(v)
                if m and m.group(1) in index:
                    base = m.group(1)
                    break
        if base is None:
            continue
        line = None
        for k in LINE_KEYS:
            if isinstance(d.get(k), int):
                line = d[k]
                break
        matched = ""
        for k in MATCH_KEYS:
            v = d.get(k)
            if isinstance(v, str) and v.strip() and not FILE_HINT.search(v):
                matched = v.strip()
                break
        found.append({"file": base, "line": line, "match": matched})
    return found


def findings_from_text(text, index):
    """Fallback: grep the raw output for our filenames and a nearby line number."""
    found = []
    for m in re.finditer(r"(\d{3}-[a-z0-9-]+\.log)(?:[:\s,)]+(\d+))?", text):
        base = m.group(1)
        if base not in index:
            continue
        line = int(m.group(2)) if m.group(2) else None
        found.append({"file": base, "line": line, "match": ""})
    return found


def demo_findings(index):
    """No tool installed? This is a first-draft detector: any long base64-ish
    run is a secret. It exists so you can watch the harness work before you
    trust it with your own numbers."""
    found = []
    for base, section in index.items():
        for i, line in enumerate(section["text"].splitlines(), 1):
            for m in re.finditer(r"[A-Za-z0-9+/]{32,}", line):
                found.append({"file": base, "line": i, "match": m.group(0)})
    return found


def _matches(f, section, wanted):
    """Does finding `f` correspond to any string in `wanted`? By text where the
    scanner reported the matched span, by line otherwise. Never by byte offset:
    every scanner has its own span convention and pretending otherwise would
    turn a difference in bookkeeping into a false miss."""
    if f["match"]:
        for a in wanted:
            if a in f["match"] or f["match"] in a:
                return True
        return False
    if f["line"]:
        lines = section["text"].splitlines()
        if 0 < f["line"] <= len(lines):
            return any(a in lines[f["line"] - 1] for a in wanted)
    return False


def classify(found, index):
    """Sort every finding into true positive / false positive / neither.

    On a false-positive corpus `secrets` is empty on every section, so nothing
    can be a true positive and every finding is a false positive EXCEPT one that
    matches a listed personal_data span (a public IP, an email, a username in a
    path). Redactors are supposed to mask those; secret scanners are not
    supposed to report them at all.

    On a true-positive corpus the same code does recall: a finding that matches
    a listed secret is a hit, personal_data is still neither, and anything left
    over is still a false positive -- a scanner that finds the planted key and
    nine other things has not scored 100%."""
    tps, fps, personal = [], [], []
    for f in found:
        section = index[f["file"]]
        f["section"] = section["name"]
        if _matches(f, section, [p["text"] for p in section["secrets"]]):
            tps.append(f)
        elif _matches(f, section, [p["text"] for p in section["personal_data"]]):
            personal.append(f)
        else:
            fps.append(f)
    return tps, fps, personal


def recall(found, index):
    """Which planted secrets were found and which were missed, core and hard
    kept apart. The hard tier holds secrets no shape-based scanner can find;
    averaging them in would just punish every tool for a limit of the approach."""
    hits, misses = [], []
    for section in index.values():
        for s in section["secrets"]:
            fs = [f for f in found if f["file"] == section["_file"]]
            got = any(_matches(f, section, [s["text"]]) for f in fs)
            rec = {"section": section["name"], "kind": s["kind"],
                   "hard": bool(section.get("hard")), "text": s["text"][:56]}
            (hits if got else misses).append(rec)
    return hits, misses


def run(cmd, workdir, index, quiet):
    """Substitute {dir}/{report}/{file} and run. {file} runs once per section.
    Returns (combined output, worst exit code, first stderr)."""
    report = os.path.join(workdir, "_report.json")
    outputs, errs = [], []
    if "{file}" in cmd:
        targets = [os.path.join(workdir, b) for b in sorted(index)]
    else:
        targets = [None]
    code = 0
    for target in targets:
        line = cmd.replace("{dir}", workdir).replace("{report}", report)
        if target:
            line = line.replace("{file}", target)
        try:
            proc = subprocess.run(shlex.split(line), capture_output=True, text=True)
        except OSError as exc:
            return "", 127, "could not run %r: %s" % (line.split()[0], exc)
        code = proc.returncode if proc.returncode else code
        outputs.append(proc.stdout)
        outputs.append(proc.stderr)
        if proc.stderr.strip():
            errs.append(proc.stderr.strip())
    if os.path.exists(report):
        with open(report, encoding="utf-8", errors="replace") as fh:
            outputs.insert(0, fh.read())
    if not quiet:
        print("ran:  %s" % cmd)
        print("exit: %d" % code)
    return "\n".join(outputs), code, (errs[0] if errs else "")


def main():
    ap = argparse.ArgumentParser(
        description="Score your own secret scanner against fp-corpus (precision) "
                    "or tp-corpus (recall). It tells the two apart by reading the file.",
        epilog="Placeholders in --cmd: {dir} the corpus directory, {report} a "
               "path your tool may write JSON to, {file} one section per run.")
    ap.add_argument("--cmd", help="the scanner command to run")
    ap.add_argument("--demo", action="store_true",
                    help="use the built-in straw-man scanner instead of a real tool")
    ap.add_argument("--corpus", default=os.path.join(HERE, "fp-corpus.json"),
                    help="path to fp-corpus.json or tp-corpus.json "
                         "(default: fp-corpus.json next to this script)")
    ap.add_argument("--min-recall", type=int, default=None, metavar="PCT",
                    dest="min_recall",
                    help="on a true-positive corpus, exit 1 below this core-tier "
                         "recall percentage")
    ap.add_argument("--max", type=int, default=None, metavar="N",
                    help="exit 1 if false positives exceed N (use in CI)")
    ap.add_argument("--top", type=int, default=8, metavar="N",
                    help="how many example findings to print (default 8)")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    ap.add_argument("--keep", action="store_true",
                    help="keep the corpus directory and print its path")
    ap.add_argument("--no-control", action="store_true", dest="no_control",
                    help="do not plant the control file. A run with no findings "
                         "then scores as zero instead of as un-scorable.")
    args = ap.parse_args()

    if not args.cmd and not args.demo:
        ap.error("give --cmd 'your scanner {dir}', or --demo to see it work")

    if not os.path.exists(args.corpus):
        sys.exit("corpus not found at %s -- pass --corpus" % args.corpus)
    corpus = load_corpus(args.corpus)

    workdir = tempfile.mkdtemp(prefix="fp-corpus-")
    index = materialize(corpus, workdir)
    control = {} if args.no_control else write_control(workdir)
    # What the scanner is pointed at and what gets scored are different sets:
    # the control file is in the first and never in the second.
    scan_index = dict(index)
    scan_index.update(control)

    code, err, failed, raw = 0, "", False, ""
    if args.demo:
        found = demo_findings(scan_index)
        source = "built-in straw-man scanner"
    else:
        raw, code, err = run(args.cmd, workdir, scan_index, args.json)
        doc = parse_json_ish(raw)
        found = findings_from_json(doc, scan_index) if doc else []
        source = "json output"
        if not found:
            found = findings_from_text(raw, scan_index)
            source = "filenames in plain output"
        failed = code != 0

    ctl = control_report(found, raw) if control else None
    found = [f for f in found if f["file"] != CONTROL_FILE]

    has_secrets = any(sec.get("secrets") for sec in corpus["sections"])
    tps, fps, personal = classify(found, index)
    hits, misses = recall(found, index) if has_secrets else ([], [])
    core_h = [h for h in hits if not h["hard"]]
    core_m = [m for m in misses if not m["hard"]]
    hard_h = [h for h in hits if h["hard"]]
    hard_m = [m for m in misses if m["hard"]]

    # A command that never ran must never read as a clean bill of health.
    if failed and not found:
        sys.stderr.write(
            "\nSCAN FAILED -- not scored.\n"
            "  the command exited %d and produced no finding this script could read.\n"
            "%s"
            "  0 false positives here would mean your scanner never looked.\n"
            "  check the command, then re-run with --keep to inspect the corpus files.\n"
            % (code, ("  stderr: %s\n" % err.splitlines()[0][:200]) if err else ""))
        sys.exit(2)

    # The quieter failure, and the one this whole file exists to catch: the
    # command exited 0 and reported nothing anywhere. That is indistinguishable
    # from a perfect precision score unless something in the directory was
    # guaranteed to be reported. Something was.
    if ctl and not ctl["reported"] and not found and not args.demo:
        sys.stderr.write(
            "\nSCAN NOT CREDIBLE -- not scored.\n"
            "  the command exited 0 and reported nothing at all: no finding on the\n"
            "  corpus, and nothing on %s, a file planted next to it holding\n"
            "  %s in plain sight.\n"
            "  a scanner that misses those did not read these files, so 0 false\n"
            "  positives here is not a precision score -- it is a scan that did not\n"
            "  happen. Check the command for a wrong path, an extension filter or a\n"
            "  missing recursive flag, then re-run with --keep to see the files.\n"
            "  Pass --no-control to score the run anyway.\n"
            % (CONTROL_FILE, human_list([k.replace("-", " ")
                                         for k, _ in CONTROL_SECRETS])))
        sys.exit(2)

    by_section = {}
    for f in fps:
        by_section[f["section"]] = by_section.get(f["section"], 0) + 1
    ranked = sorted(by_section.items(), key=lambda kv: (-kv[1], kv[0]))

    if args.json:
        print(json.dumps({
            "corpus": corpus.get("name", "unknown"),
            "measures": "recall and precision" if has_secrets else "precision",
            "true_positives": len(tps),
            "core_found": len(core_h), "core_total": len(core_h) + len(core_m),
            "hard_found": len(hard_h), "hard_total": len(hard_h) + len(hard_m),
            "missed": misses,
            "false_positives": len(fps),
            "personal_data_matches": len(personal),
            "sections": len(corpus["sections"]),
            "sections_tripped": len(by_section),
            "by_section": dict(ranked),
            "parsed_from": source,
            "control": ctl,
            "findings": fps,
        }, indent=2))
    else:
        print("corpus: %d sections, %d lines, %s." % (
            len(corpus["sections"]), corpus["counts"]["lines"],
            ("%d planted credentials" % len(hits + misses)) if has_secrets
            else "0 credentials"))
        print("read:   %d finding(s) via %s" % (len(found), source))
        if ctl:
            print("control: %s" % (
                "reported -- the scanner demonstrably read these files"
                if ctl["reported"] else
                "NOT reported -- your scanner flagged none of the "
                "%d unmistakable credentials in %s" % (len(CONTROL_SECRETS),
                                                       CONTROL_FILE)))
        print("")
        if has_secrets:
            pct = (100 * len(core_h) // max(1, len(core_h) + len(core_m)))
            print("RECALL: %d of %d on the core tier (%d%%)"
                  % (len(core_h), len(core_h) + len(core_m), pct))
            print("        %d of %d on the hard tier -- secrets no shape-based"
                  % (len(hard_h), len(hard_h) + len(hard_m)))
            print("        scanner can be expected to find. Scored separately.")
            if misses:
                print("")
                print("missed:")
                for m in (core_m + hard_m)[:args.top]:
                    print("  %-34s %s%s" % (m["section"], m["kind"],
                                            "  [hard]" if m["hard"] else ""))
            print("")
        print("FALSE POSITIVES: %d, across %d of %d sections"
              % (len(fps), len(by_section), len(corpus["sections"])))
        print("personal-data matches (not counted): %d" % len(personal))
        if ranked:
            print("")
            print("worst sections:")
            for name, n in ranked[:args.top]:
                print("  %4d  %s" % (n, name))
            print("")
            print("examples:")
            for f in fps[:args.top]:
                where = "%s:%s" % (f["section"], f["line"] if f["line"] else "?")
                shown = f["match"][:56] if f["match"] else "(no matched text in output)"
                print("  %-34s %s" % (where, shown))
        if not found and not args.demo and not failed:
            print("")
            print("No findings parsed. Either your scanner is silent on ordinary")
            print("output -- which is the result you want -- or its output does not")
            print("name the files. Re-run with --keep and check by hand.")

    if args.keep:
        print("")
        print("corpus files kept at: %s" % workdir)
    else:
        for b in scan_index:
            os.unlink(os.path.join(workdir, b))
        rep = os.path.join(workdir, "_report.json")
        if os.path.exists(rep):
            os.unlink(rep)
        os.rmdir(workdir)

    if args.max is not None and len(fps) > args.max:
        sys.exit(1)
    if args.min_recall is not None:
        total = len(core_h) + len(core_m)
        if not has_secrets:
            sys.exit("--min-recall needs a corpus with planted secrets; %s has none"
                     % os.path.basename(args.corpus))
        if 100 * len(core_h) // max(1, total) < args.min_recall:
            sys.exit(1)


if __name__ == "__main__":
    main()
