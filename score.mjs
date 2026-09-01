/* score.mjs -- score.py's twin, for JavaScript projects.
 * Same straw-man scanner, same arithmetic, no dependencies.
 *
 * Refusal rule: a scan that did not run is a failure, never a score of zero --
 * no sections read, or sections read and nothing found, prints no score and
 * exits 2.
 *
 *   node score.mjs
 */
import { readFileSync } from "node:fs";

const THRESHOLD = 32;
const corpus = JSON.parse(readFileSync(new URL("fp-corpus.json", import.meta.url), "utf8"));
const scan = (text) => text.match(new RegExp(`[A-Za-z0-9+/]{${THRESHOLD},}`, "g")) ?? [];
const refuse = (why) => { process.stderr.write(`SCORE REFUSED: ${why}\n`); process.exit(2); };

const sections = corpus.sections;
const findings = [];
for (const section of sections) {
  const allowed = new Set(section.personal_data.map((s) => s.text));
  for (const hit of scan(section.text)) if (!allowed.has(hit)) findings.push([section.name, hit]);
}

if (!sections.length)
  refuse("read 0 sections from fp-corpus.json, so nothing was scanned. " +
         "A scan that did not run is a failure, never a score of zero.");
if (!findings.length)
  refuse(`the straw man found nothing across ${sections.length} sections. Either the corpus ` +
         "changed or the regex did; a demo that is supposed to trip and did " +
         "not is a broken demo, not a clean result.");

console.log(`THRESHOLD ${THRESHOLD}`);
console.log(`SECTIONS ${sections.length}`);
console.log(`TOTAL ${findings.length}`);
for (const [name, f] of findings.slice(0, 5)) console.log(`FINDING ${name} | ${f.slice(0, 48)}`);
