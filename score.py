"""fp-score-demo.py -- the scoring loop published on false-positives.html, run
for real against the published fp-corpus.json.

Wake 022. The page claims that a naive scanner pointed at this corpus reports an
SSH host key fingerprint, an npm integrity hash and a git commit SHA. That is a
claim about output, so it is made by running the thing, not by remembering it.
fp-check.mjs executes this file and asserts the page and this output agree.

The "scanner" here is deliberately a straw man -- any long base64-ish run is a
secret -- because that is what a first-draft detector really looks like, and the
point is what ordinary log material does to it.

Refusal rule: a scan that did not run is a failure, never a score of zero -- no
sections read, or sections read and nothing found, prints no score and exits 2.

Prints: THRESHOLD, then one line per finding class, then the total.
"""
import json, os, re, sys

THRESHOLD = 32
HERE = os.path.dirname(os.path.abspath(__file__))
corpus = json.load(open(os.path.join(HERE, "fp-corpus.json")))


def scan(text):
    return re.findall(r"[A-Za-z0-9+/]{%d,}" % THRESHOLD, text)


def refuse(why):
    sys.stderr.write("SCORE REFUSED: %s\n" % why)
    sys.exit(2)


sections = corpus["sections"]
findings, total = [], 0
for section in sections:
    allowed = {p["text"] for p in section["personal_data"]}
    for finding in scan(section["text"]):
        if finding not in allowed:
            total += 1
            findings.append((section["name"], finding))

if not sections:
    refuse("read 0 sections from fp-corpus.json, so nothing was scanned. "
           "A scan that did not run is a failure, never a score of zero.")
if total == 0:
    refuse("the straw man found nothing across %d sections. Either the corpus "
           "changed or the regex did; a demo that is supposed to trip and did "
           "not is a broken demo, not a clean result." % len(sections))

print("THRESHOLD %d" % THRESHOLD)
print("SECTIONS %d" % len(sections))
print("TOTAL %d" % total)
for name, f in findings[:5]:
    print("FINDING %s | %s" % (name, f[:48]))
