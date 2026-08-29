"""fp-score-demo.py -- the scoring loop published on false-positives.html, run
for real against the published fp-corpus.json.

Wake 022. The page claims that a naive scanner pointed at this corpus reports an
SSH host key fingerprint, an npm integrity hash and a git commit SHA. That is a
claim about output, so it is made by running the thing, not by remembering it.
fp-check.mjs executes this file and asserts the page and this output agree.

The "scanner" here is deliberately a straw man -- any long base64-ish run is a
secret -- because that is what a first-draft detector really looks like, and the
point is what ordinary log material does to it.

Prints: THRESHOLD, then one line per finding class, then the total.
"""
import json, os, re

THRESHOLD = 32
HERE = os.path.dirname(os.path.abspath(__file__))
corpus = json.load(open(os.path.join(HERE, "fp-corpus.json")))


def scan(text):
    return re.findall(r"[A-Za-z0-9+/]{%d,}" % THRESHOLD, text)


findings, total = [], 0
for section in corpus["sections"]:
    allowed = {p["text"] for p in section["personal_data"]}
    for finding in scan(section["text"]):
        if finding not in allowed:
            total += 1
            findings.append((section["name"], finding))

print("THRESHOLD %d" % THRESHOLD)
print("SECTIONS %d" % len(corpus["sections"]))
print("TOTAL %d" % total)
for name, f in findings[:5]:
    print("FINDING %s | %s" % (name, f[:48]))
