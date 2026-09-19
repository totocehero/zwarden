/**
 * Measures function length and reports what exceeds the threshold.
 *
 * A purely lexical analysis: enough to spot functions worth splitting.
 *
 * ## What is counted, and why not everything
 *
 * The threshold targets **complexity**: too many decisions in one place. But a
 * line of JSX markup is not a decision — it is linear, branchless, and reads top
 * to bottom. Counting both together condemned a declarative one-hundred-and-
 * forty-line form on the same footing as a one-hundred-and-forty-line function
 * of logic, which made the warning useless exactly where it should have helped.
 *
 * Both numbers are therefore printed — logic, then total — and only the logic
 * raises the alert.
 *
 * ## What this script cannot tell apart
 *
 * Three shapes inflate the "logic" count without being logic, and it is worth
 * knowing before splitting anything on the strength of a number:
 *
 * - a component's **property list**, destructured and then typed — some fifty
 *   lines for a sixteen-property component, without a single decision;
 * - the **object literal** a hook returns when its methods are short: the script
 *   measures the whole object as one function;
 * - the **members of a type** declared in the body.
 *
 * An overrun is therefore to be read, not obeyed.
 *
 * Usage: node scripts/function-length.mjs [threshold]
 */

import { readFileSync } from 'node:fs';
import { globSync } from 'node:fs';

const THRESHOLD = Number(process.argv[2] ?? 40);

const sourceFiles = globSync('src/**/*.{ts,tsx}');

const SIGNATURE =
  /^\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:private\s+|public\s+|static\s+|readonly\s+)*(?:async\s+)?(\w+)\s*\()/;

const IGNORES = new Set(['if', 'for', 'while', 'switch', 'catch', 'return', 'constructor']);

/**
 * Rules out what looks like a signature without being one.
 *
 * SIGNATURE's second pattern — `name(` at the start of a line — targets class
 * methods, but also catches every function call (`setBusy('…');`) and every
 * arrow function passed as a JSX attribute (`onSubmit={(e) => {`). Both produced
 * absurd measurements: a call line was credited with the body of the function
 * surrounding it, and a JSX attribute with the component's.
 *
 * Two marks suffice to rule them out: a call ends with `;`, a JSX attribute
 * contains `={`.
 */
function isFalseSignature(line) {
  const bare = line.trim();
  return bare.endsWith(';') || bare.includes('={');
}

/**
 * Recognises a line of JSX markup.
 *
 * Three shapes: a tag (`<div`, `</ul>`, `/>`), an attribute (`value={…}`,
 * `class="…"`), or an expression's closing punctuation (`)}`, `>`). A heuristic,
 * like everything else in this script — it may get a contorted line wrong, never
 * enough to change an order of magnitude.
 */
function isMarkup(line) {
  const bare = line.trim();
  if (bare === '') return false;
  if (/^<|^\/>|^<\/|^\)\}|^>$|^\{' '\}$/.test(bare)) return true;
  return /^[\w-]+=(?:\{|")/.test(bare);
}

const results = [];

for (const file of sourceFiles) {
  const lines = readFileSync(file, 'utf8').split('\n');

  for (let i = 0; i < lines.length; i++) {
    const match = SIGNATURE.exec(lines[i]);
    if (!match) continue;

    const name = match[1] ?? match[2];
    if (!name || IGNORES.has(name)) continue;
    if (!lines[i].includes('(')) continue;
    if (isFalseSignature(lines[i])) continue;

    // Counts body lines up to the closing brace at the same level.
    let depth = 0;
    let start = -1;
    let body = 0;
    let logic = 0;

    for (let j = i; j < lines.length; j++) {
      const line = lines[j];
      const sansCommentaire = line.replace(/\/\/.*$/, '');

      for (const ch of sansCommentaire) {
        if (ch === '{') {
          if (start === -1) start = j;
          depth++;
        } else if (ch === '}') {
          depth--;
        }
      }

      if (start !== -1) {
        const bare = line.trim();
        if (bare && !bare.startsWith('*') && !bare.startsWith('//') && !bare.startsWith('/*')) {
          body++;
          if (!isMarkup(line)) logic++;
        }
      }

      if (start !== -1 && depth === 0) {
        results.push({ file, name, logic, lines: body, start: i + 1 });
        break;
      }
    }
  }
}

results.sort((a, b) => b.logic - a.logic);

const padNumber = (n) => String(n).padStart(4);

console.log(`Alert threshold: ${THRESHOLD} logic lines (JSX markup does not count)\n`);
console.log(`${'function'.padEnd(28)}${'logic'.padStart(8)}${'total'.padStart(7)}  file`);
console.log('-'.repeat(78));

let overruns = 0;
for (const r of results) {
  const alert = r.logic > THRESHOLD;
  if (alert) overruns++;
  const mark = alert ? ' <-- consider splitting' : '';
  console.log(
    `${r.name.padEnd(28)}${padNumber(r.logic)}${padNumber(r.lines)}   ` +
      `${r.file.replace(/\\/g, '/')}:${r.start}${mark}`,
  );
}

const total = results.reduce((s, r) => s + r.logic, 0);
console.log('-'.repeat(78));
console.log(
  `${results.length} functions, ${total} logic lines, ` +
    `average ${(total / results.length).toFixed(1)}, ${overruns} above the threshold`,
);
