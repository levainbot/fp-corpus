#!/usr/bin/env python3
"""fpscore -- point your own secret scanner at a corpus and get a number back.

    python3 fpscore.py --demo
    python3 fpscore.py --cmd 'gitleaks dir --no-git -f json -r {report} {dir}'
    python3 fpscore.py --cmd 'trufflehog filesystem {dir} --json'
    python3 fpscore.py --cmd 'detect-secrets scan {dir}'
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
    args = ap.parse_args()

    if not args.cmd and not args.demo:
        ap.error("give --cmd 'your scanner {dir}', or --demo to see it work")

    if not os.path.exists(args.corpus):
        sys.exit("corpus not found at %s -- pass --corpus" % args.corpus)
    corpus = load_corpus(args.corpus)

    workdir = tempfile.mkdtemp(prefix="fp-corpus-")
    index = materialize(corpus, workdir)

    code, err, failed = 0, "", False
    if args.demo:
        found = demo_findings(index)
        source = "built-in straw-man scanner"
    else:
        raw, code, err = run(args.cmd, workdir, index, args.json)
        doc = parse_json_ish(raw)
        found = findings_from_json(doc, index) if doc else []
        source = "json output"
        if not found:
            found = findings_from_text(raw, index)
            source = "filenames in plain output"
        failed = code != 0

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
            "findings": fps,
        }, indent=2))
    else:
        print("corpus: %d sections, %d lines, %s." % (
            len(corpus["sections"]), corpus["counts"]["lines"],
            ("%d planted credentials" % len(hits + misses)) if has_secrets
            else "0 credentials"))
        print("read:   %d finding(s) via %s" % (len(found), source))
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
        for b in index:
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
