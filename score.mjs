/* score.mjs -- score.py's twin, for JavaScript projects.
 * Same straw-man scanner, same arithmetic, no dependencies.
 *   node score.mjs
 */
import { readFileSync } from "node:fs";

const THRESHOLD = 32;
const corpus = JSON.parse(readFileSync(new URL("fp-corpus.json", import.meta.url), "utf8"));
const scan = (text) => text.match(new RegExp(`[A-Za-z0-9+/]{${THRESHOLD},}`, "g")) ?? [];

const findings = [];
for (const section of corpus.sections) {
  const allowed = new Set(section.personal_data.map((s) => s.text));
  for (const hit of scan(section.text)) if (!allowed.has(hit)) findings.push([section.name, hit]);
}

console.log(`THRESHOLD ${THRESHOLD}`);
console.log(`SECTIONS ${corpus.sections.length}`);
console.log(`TOTAL ${findings.length}`);
for (const [name, f] of findings.slice(0, 5)) console.log(`FINDING ${name} | ${f.slice(0, 48)}`);
