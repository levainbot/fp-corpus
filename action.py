#!/usr/bin/env python3
"""action.py -- the body of the fp-corpus GitHub Action.

`action.yml` is a five-line wrapper around this file. Everything that decides
whether your build goes green lives here, in one stdlib-only script you can run
by hand outside CI:

    LEVAIN_CMD='gitleaks dir -f json -r {report} --exit-code 0 {dir}' \\
    LEVAIN_MEASURE=both LEVAIN_MAX_FP=0 LEVAIN_MIN_RECALL=90 \\
    python3 action.py

It shells out to `fpscore.py` next to it -- once for the precision half
(fp-corpus: 0 credentials, so every finding is a false positive) and once for
the recall half (tp-corpus: an answer key, so every miss is a miss) -- reads the
JSON, writes a job summary, and exits non-zero when either gate is breached.

The one behaviour worth stating out loud, because getting it wrong is how a
scanner gate becomes a decoration: **a scan that did not run is a FAILURE, not a
score of zero.** fpscore exits 2 and prints nothing parseable when the command
it was handed never produced a finding it could read. This script turns that
into a red build and says so, rather than reporting a flawless 0 false
positives from a command that exited 127.
"""
import json
import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
FPSCORE = HERE / "fpscore.py"
MATERIALIZE = HERE / "materialize.py"


def env(name, default=""):
    return (os.environ.get(name) or default).strip()


def fail(msg):
    print("::error::" + msg, file=sys.stderr)
    print("\n" + msg)
    sys.exit(1)


def run_fpscore(corpus, cmd, extra=()):
    """Run fpscore and return its parsed JSON, or exit loudly."""
    argv = [sys.executable, str(FPSCORE), "--corpus", str(corpus),
            "--cmd", cmd, "--json", *extra]
    proc = subprocess.run(argv, capture_output=True, text=True)
    if proc.returncode == 2 or not proc.stdout.strip().startswith("{"):
        detail = (proc.stdout + proc.stderr).strip()
        fail("the scanner command did not run, so nothing was scored.\n"
             "A score of zero from a command that never executed is the one\n"
             "result this action will never report as a pass.\n\n" + detail)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        fail("fpscore.py did not return JSON.\n\n"
             + (proc.stdout + proc.stderr).strip())


def pct(found, total):
    return 100.0 * found / total if total else 0.0


def write(path_var, text):
    path = os.environ.get(path_var)
    if not path:
        return
    with open(path, "a", encoding="utf8") as fh:
        fh.write(text)


def main():
    cmd = env("LEVAIN_CMD")
    if not cmd:
        fail("no scanner command given. Set the action's `cmd` input, for "
             "example:\n    cmd: gitleaks dir -f json -r {report} "
             "--exit-code 0 {dir}")
    if "{dir}" not in cmd and "{file}" not in cmd:
        fail("the `cmd` input must contain {dir} or {file} -- otherwise the "
             "scanner is never pointed at the corpus.\n  got: " + cmd)

    measure = env("LEVAIN_MEASURE", "both").lower()
    if measure not in ("precision", "recall", "both"):
        fail("`measure` must be precision, recall or both -- got " + measure)

    try:
        max_fp = int(env("LEVAIN_MAX_FP", "0"))
    except ValueError:
        fail("`max-false-positives` must be a whole number -- got "
             + env("LEVAIN_MAX_FP"))
    min_recall_raw = env("LEVAIN_MIN_RECALL")
    min_recall = None
    if min_recall_raw:
        try:
            min_recall = float(min_recall_raw)
        except ValueError:
            fail("`min-recall` must be a number or empty -- got "
                 + min_recall_raw)

    lines = ["## Secret scanner score",
             "",
             "Scored against [fp-corpus](https://github.com/levainbot/fp-corpus),"
             " a two-halved test set for secret scanners.",
             "",
             "```",
             cmd,
             "```",
             ""]
    outputs = {}
    problems = []

    if measure in ("precision", "both"):
        fp_corpus = HERE / "fp-corpus.json"
        if not fp_corpus.exists():
            fail("fp-corpus.json is missing next to action.py")
        res = run_fpscore(fp_corpus, cmd)
        fps = res["false_positives"]
        tripped = res["sections_tripped"]
        total = res["sections"]
        outputs["false-positives"] = str(fps)
        outputs["sections-tripped"] = str(tripped)
        outputs["sections-total"] = str(total)
        verdict = "pass" if fps <= max_fp else "FAIL"
        lines += [
            "### Precision — %d formats that contain no credential" % total,
            "",
            "| measure | value | gate |",
            "| --- | --- | --- |",
            "| false positives | **%d** | at most %d — %s |" % (fps, max_fp, verdict),
            "| formats tripped on | %d of %d | |" % (tripped, total),
            "",
        ]
        worst = sorted(res.get("by_section", {}).items(),
                       key=lambda kv: -kv[1])[:10]
        if worst:
            lines += ["<details><summary>Where it tripped</summary>", "",
                      "| format | findings |", "| --- | --- |"]
            lines += ["| `%s` | %d |" % (name, n) for name, n in worst]
            lines += ["", "</details>", ""]
        if fps > max_fp:
            problems.append(
                "%d false positives, above the limit of %d" % (fps, max_fp))

    if measure in ("recall", "both"):
        # Two layouts ship this corpus. The git repo carries it base64-encoded
        # (push protection rejects the plaintext) and materialize.py decodes it;
        # the release bundle carries it already decoded, with no .b64 alongside.
        # Only materialize when the corpus is actually absent, or the release
        # bundle fails on a decode it never needed.
        tp_corpus = HERE / "tp-corpus.json"
        if not tp_corpus.exists():
            if not MATERIALIZE.exists():
                fail("tp-corpus.json is missing and so is materialize.py, so "
                     "the true-positive corpus cannot be obtained")
            mat = subprocess.run([sys.executable, str(MATERIALIZE)],
                                 capture_output=True, text=True, cwd=str(HERE))
            if mat.returncode != 0:
                fail("materialize.py failed, so the true-positive corpus could "
                     "not be decoded.\n\n" + (mat.stdout + mat.stderr).strip())
        if not tp_corpus.exists():
            fail("tp-corpus.json is still missing after materialization")
        res = run_fpscore(tp_corpus, cmd)
        core = pct(res["core_found"], res["core_total"])
        hard = pct(res["hard_found"], res["hard_total"])
        outputs["recall"] = "%.1f" % core
        outputs["hard-recall"] = "%.1f" % hard
        outputs["missed"] = str(len(res.get("missed", [])))
        gate = ("at least %.0f%% — %s" % (
            min_recall, "pass" if core >= min_recall else "FAIL")
            if min_recall is not None else "not gated")
        lines += [
            "### Recall — %d synthetic credentials, with an answer key"
            % (res["core_total"] + res["hard_total"]),
            "",
            "| tier | found | recall | gate |",
            "| --- | --- | --- | --- |",
            "| core | %d of %d | **%.0f%%** | %s |"
            % (res["core_found"], res["core_total"], core, gate),
            "| hard | %d of %d | %.0f%% | never gated |"
            % (res["hard_found"], res["hard_total"], hard),
            "",
            "The three hard-tier secrets have no recognisable shape — a "
            "password with no prefix, an in-house token format, and a key "
            "split across two lines. No shape-based scanner clears them, so "
            "they are reported on their own line and never averaged in.",
            "",
        ]
        missed = res.get("missed", [])
        if missed:
            # One row per (format, kind, tier) with a count. A section can hold two distinct
            # secrets of the same kind -- payment-processing-log holds two card numbers -- and
            # listing them raw printed two identical rows that read as a duplication bug.
            groups = []
            index = {}
            for m in missed:
                key = (m["section"], m["kind"], "hard" if m.get("hard") else "core")
                if key not in index:
                    index[key] = len(groups)
                    groups.append([key, 0])
                groups[index[key]][1] += 1
            shown = groups[:25]
            lines += ["<details><summary>What it missed</summary>", "",
                      "| format | kind | tier | secrets missed |", "| --- | --- | --- | --- |"]
            lines += ["| `%s` | `%s` | %s | %d |" % (k[0], k[1], k[2], n) for k, n in shown]
            if len(groups) > len(shown):
                lines += ["", "%d more format%s not listed above."
                          % (len(groups) - len(shown), "" if len(groups) - len(shown) == 1 else "s")]
            lines += ["", "</details>", ""]
        if min_recall is not None and core < min_recall:
            problems.append("core recall %.0f%%, below the floor of %.0f%%"
                            % (core, min_recall))

    lines += ["---", "",
              "The corpus and this action are built by "
              "[Levain](https://levain.bmac.io/), an autonomous AI agent. "
              "Its whole record is public at "
              "[levain.bmac.io/record.html](https://levain.bmac.io/record.html)."]
    summary = "\n".join(lines) + "\n"
    write("GITHUB_STEP_SUMMARY", summary)
    print(summary)

    write("GITHUB_OUTPUT",
          "".join("%s=%s\n" % (k, v) for k, v in outputs.items()))

    if problems:
        for p in problems:
            print("::error::" + p, file=sys.stderr)
        print("FAILED: " + "; ".join(problems))
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()
