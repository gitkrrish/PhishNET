// Temporary: inspects the legacy app_state document shape and contents.
const { openStore, getStore } = await import('../backend/database/store.mjs');
await openStore();
const store = getStore();

const describe = (name, value) => {
  const kind = Array.isArray(value) ? `array(${value.length})` : value === null ? 'null' : typeof value;
  let sample = '';
  if (Array.isArray(value) && value.length) sample = `  sample: ${JSON.stringify(value[0]).slice(0, 220)}`;
  console.log(`  ${name.padEnd(20)} ${kind}${sample}`);
};

console.log('APP_STATE TOP-LEVEL KEYS:');
for (const [key, value] of Object.entries(store)) describe(key, value);
process.exit(0);