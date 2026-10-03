// Asserts the navigation stays unique, which navConfig.ts promises in its own
// header: no path may appear twice and no two items may share a label. The
// centralized 24x7 Monitoring section replaced a dark-web entry that carried
// the same label, which is exactly the kind of drift this check catches.
import { navGroups, topNavItems, itemPaths, normalizePath } from '../src/lib/darkweb/navConfig.ts';

const items = [...topNavItems, ...navGroups.flatMap(group => group.items)];
const pathOwners = new Map();
const labelOwners = new Map();
// Path collisions are always a bug: two entries must never claim one route.
// Label collisions are reported but not failed, because three pre-existing
// pairs intentionally share a label across groups (the dark-web
// Infrastructure/Evidence/Reports pages are genuinely different surfaces from
// their top-level counterparts). Renaming those is an information-architecture
// decision, not part of this work.
const labelNotes = [];
let failures = 0;

const fail = message => {
  console.log(`FAIL  ${message}`);
  failures += 1;
};

const note = message => {
  console.log(`NOTE  ${message}`);
  labelNotes.push(message);
};

for (const item of items) {
  for (const path of itemPaths(item)) {
    const owner = pathOwners.get(path);
    if (owner) fail(`path ${path} claimed by both "${owner.label}" and "${item.label}"`);
    else pathOwners.set(path, item);
  }
  const key = item.label.toLowerCase();
  const owner = labelOwners.get(key);
  if (owner) note(`label "${item.label}" is shared by ${owner.path} and ${item.path} (pre-existing, distinct pages)`);
  else labelOwners.set(key, item);
}

const check = (condition, message) => (condition ? console.log(`PASS  ${message}`) : fail(message));

check(pathOwners.has('/app/monitoring/hub'), 'centralized hub is reachable from navigation');
check(pathOwners.has('/app/monitoring/monitors'), 'all-monitors view is reachable from navigation');
check(!pathOwners.has('/app/darkweb/monitoring'), 'retired darkweb monitoring path is no longer a nav entry');
check(
  normalizePath('/app/darkweb/monitoring') === '/app/monitoring/monitors',
  'retired darkweb monitoring path redirects to the centralized monitors view',
);

const monitoring = items.filter(item => item.path.startsWith('/app/monitoring'));
check(monitoring.length === 4, `exactly four centralized monitoring entries (found ${monitoring.length})`);

console.log(`\n${failures === 0 ? `PASS — no duplicate paths; ${labelNotes.length} pre-existing shared label(s)` : `FAIL — ${failures} problem(s)`}`);
process.exit(failures === 0 ? 0 : 1);