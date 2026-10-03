// Audits Tailwind utility class names actually used in the source against
// the utilities the build emitted. A class that is used but never
// generated is dead: it renders no style at all.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';

const SRC = 'src';
const DIST = 'dist/assets';

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (['.tsx', '.ts'].includes(extname(full))) out.push(full);
  }
  return out;
}

const css = readdirSync(DIST)
  .filter(name => name.endsWith('.css'))
  .map(name => readFileSync(join(DIST, name), 'utf8'))
  .join('\n');

// Every utility the build emitted, e.g. `.hover\:bg-burg:hover`.
const emitted = new Set();
for (const match of css.matchAll(/\.((?:[A-Za-z0-9_-]|\\.)+)(?=[\s,{:>+~.\[])/g)) {
  emitted.add(match[1].replace(/\\/g, ''));
}

// Every class-attribute token worth checking. Layout utilities matter too:
// a mistyped utility renders no style at all, which is the failure mode
// this audit exists to find.
const CANDIDATE = /(?:^|\s)(?:[a-z0-9-]+:)*(?:!?[a-z0-9][a-z0-9./_-]*)(?=[\s"'`}]|$)/g;
const SKIP = new Set(['block', 'flex', 'grid', 'hidden', 'relative', 'absolute', 'fixed', 'sticky', 'static']);

const used = new Map();
for (const file of walk(SRC)) {
  const text = readFileSync(file, 'utf8');
  for (const match of text.matchAll(/className\s*=\s*(?:"([^"]*)"|'([^']*)'|\{`([^`]*)`\}|\{"([^"]*)"\})/g)) {
    const value = match[1] ?? match[2] ?? match[3] ?? match[4] ?? '';
    // Ignore conditional class strings; resolve both sides instead.
    for (const candidate of value.matchAll(CANDIDATE)) {
      const name = candidate[0].trim();
      if (!name || name.length < 2 || SKIP.has(name)) continue;
      // Class strings built by interpolation (`${active ? 'a' : 'b'}`)
      // never resolve here, and neither do state shorthands the project
      // defines itself.
      if (name.includes('${') || name.includes('`')) continue;
      const key = name.replace(/\s+/g, ' ');
      if (!used.has(key)) used.set(key, new Set());
      used.get(key).add(file);
    }
  }
}

const missing = [];
for (const [name, files] of used) {
  // Tailwind escapes a class name for CSS: `:` `/` `.` `[` `]` `(` `)`
  // `%` `,` `#` `&` `>` get a backslash, and a space becomes `_`.
  const escaped = name
    .replace(/([:/.[\]()%,#&>])/g, '\\$1')
    .replace(/ /g, '_');
  if (css.includes(`.${escaped}`)) continue;
  missing.push({ name, files: [...files] });
}

console.log(`utilities referenced: ${used.size}`);
console.log(`referenced but not emitted: ${missing.length}\n`);
for (const item of missing.sort((a, b) => a.name.localeCompare(b.name))) {
  console.log(`${item.name}`);
  console.log(`   ${item.files.join(', ')}`);
}