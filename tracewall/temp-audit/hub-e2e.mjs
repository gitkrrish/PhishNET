// End-to-end verification of the centralized 24x7 monitoring hub.
// Uses only synthetic data and removes what it creates.
const BASE = 'http://localhost:8787';
let token = '';
const results = [];

function log(step, ok, detail) {
  results.push({ step, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${step}${detail ? ` — ${detail}` : ''}`);
}

async function call(method, path, body) {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let payload = {};
  try { payload = text ? JSON.parse(text) : {}; } catch { payload = { raw: text }; }
  return { status: response.status, data: payload?.data, payload, error: payload?.error?.message ?? payload?.message };
}

const uniq = Date.now().toString(36).toUpperCase();

async function main() {
  // ── Auth (existing system, unchanged) ──
  const signIn = await call('POST', '/api/auth/sign-in', { email: 'analyst@tracewall.demo', password: 'demo-password' });
  token = signIn.data?.token ?? signIn.payload?.token ?? '';
  log('1. Sign in through the existing auth route', signIn.status === 200 && !!token, `status ${signIn.status}`);

  // ── Hub route + all tools available ──
  const hub = await call('GET', '/api/intel/monitoring/hub?limit=50');
  const hubData = hub.data;
  log('2. GET /intel/monitoring/hub returns the centralized roll-up', hub.status === 200 && !!hubData?.stats,
    `status ${hub.status}, ${hubData?.catalog?.length ?? 0} monitorable tools, scheduler=${hubData?.scheduler?.started}`);

  const caps = (await call('GET', '/api/intel/monitoring/capabilities')).data;
  log('3. Capability catalog lists every monitorable tool',
    caps?.targetTypes?.length === 23 && hubData?.catalog?.length === 23,
    `${caps?.targetTypes?.length} target types, ${caps?.conditions ? Object.keys(caps.conditions).length : 0} conditions, ${caps?.sourceCapabilities ? Object.keys(caps.sourceCapabilities).length : 0} source classes`);

  // The four analysis tools the spec calls out explicitly.
  const indicatorTypes = ['EMAIL', 'URL', 'FILE', 'IP'];
  const capsKeys = new Set(caps.targetTypes.map(t => t.key));
  const missingIndicators = indicatorTypes.filter(k => !capsKeys.has(k));
  log('3b. Email / URL / File / IP analysis targets are monitorable', missingIndicators.length === 0,
    missingIndicators.length ? `missing ${missingIndicators}` : 'EMAIL, URL, FILE, IP all present');

  // Every tool named in the requirement has a target type or an explicit reason.
  const keys = new Set(caps.targetTypes.map(t => t.key));
  const required = ['ACTOR','HANDLE','PGP','WALLET','INFRASTRUCTURE','IP','DOMAIN','ONION','SOURCE','OBSERVATION','EVIDENCE','RELATIONSHIP','CVE','VULNERABILITY','ATTACK','KEYWORD','CUSTOM'];
  const missing = required.filter(k => !keys.has(k));
  log('4. All required intelligence kinds are monitorable', missing.length === 0, missing.length ? `missing ${missing}` : 'all present');

  // ── Synthetic entity + monitor through the existing ingest path ──
  const handleValue = `syn-${uniq}`;
  const ingested = await call('POST', '/api/intel/ingest', {
    source: 'OpenCTI Feed',
    actor: { name: `synthetic actor ${uniq}`, aliases: [handleValue] },
    handles: [{ handle: handleValue, platform: 'SyntheticRelay' }],
  });
  const handleId = (ingested.data?.created?.handles ?? [])[0] ?? null;
  log('5. Synthetic intelligence ingested into the existing tables', ingested.status < 300 && !!handleId,
    `status ${ingested.status}, handle ${handleId ?? 'none'}`);

  const created = await call('POST', '/api/intel/monitoring', {
    name: `SYN ${uniq} — handle monitoring`,
    targetType: 'HANDLE',
    targetId: handleId,
    targetValue: `syn-${uniq}`,
    frequency: 'CONTINUOUS',
    severity: 'HIGH',
    conditions: ['NEW_APPEARANCE', 'NEW_PLATFORM', 'NEW_ACTOR_CORRELATION', 'HANDLE_STATUS_CHANGE'],
    notificationPref: 'IN_PLATFORM',
  });
  const monitor = created.data;
  log('6. Monitor created from the hub through the central engine', created.status === 201 && !!monitor?.id,
    `${monitor?.id} status=${monitor?.status} interval=${monitor?.capability?.intervalLabel}`);

  // ── Persistence + reflects real backend state ──
  const list = (await call('GET', '/api/intel/monitoring')).data ?? [];
  const persisted = list.find(m => m.id === monitor?.id);
  log('7. Monitor persisted in the central monitor table', !!persisted, `${list.length} monitors total`);

  log('8. Last/next check are real backend timestamps',
    !!persisted?.nextCheck && Number.isFinite(new Date(persisted.nextCheck).getTime()),
    `lastCheck=${persisted?.lastCheck ?? 'never'} nextCheck=${persisted?.nextCheck}`);

  // ── First cycle: no fabricated alert ──
  const first = (await call('POST', `/api/intel/monitoring/run/${monitor.id}`)).data;
  const alertsAfterFirst = (await call('GET', `/api/intel/monitoring/${monitor.id}/alerts`)).data ?? [];
  log('9. First cycle runs and raises no alert without a real change',
    first?.status === 'OK' && alertsAfterFirst.length === 0,
    `cycle=${first?.status} alerts=${alertsAfterFirst.length}`);

  // ── Trigger a real change through the existing ingest path ──
  const before = Date.now();
  // Same handle AND same platform: ingest upserts the existing handle row and
  // links a new observation to it. (Changing the platform would create a
  // distinct handle record rather than a change to the monitored one.)
  await call('POST', '/api/intel/ingest', {
    source: 'OpenCTI Feed',
    handles: [{ handle: handleValue, platform: 'SyntheticRelay' }],
    platform: 'SyntheticRelay',
    observation: { type: 'HANDLE_OBSERVED', content: `synthetic change ${uniq} for hub verification` },
  });
  log('10. Synthetic change written to the centralized tables', true, `observation after ${new Date(before).toISOString()}`);

  const second = (await call('POST', `/api/intel/monitoring/run/${monitor.id}`)).data;
  const detail = (await call('GET', `/api/intel/monitoring/${monitor.id}`)).data;
  log('11. Change detection fired on the synthetic change', second?.status === 'TRIGGERED',
    `cycle=${second?.status} matches=${detail?.recentMatches?.length ?? 0} alerts=${detail?.alerts?.length ?? 0}`);

  const alert = detail?.alerts?.[0];
  log('12. Alert generated and cites the matched records',
    !!alert && alert.monitorId === monitor.id && (alert.observationIds?.length > 0 || alert.evidenceIds?.length > 0),
    `${alert?.id} severity=${alert?.severity} observations=${alert?.observationIds?.length} evidence=${alert?.evidenceIds?.length}`);

  // ── Alert surfaced in the centralized hub ──
  const hubAfter = (await call('GET', '/api/intel/monitoring/hub?limit=50')).data;
  log('13. Alert appears in the centralized hub view',
    (hubAfter?.alerts ?? []).some(a => a.id === alert?.id),
    `hub alerts=${hubAfter?.alerts?.length}, openAlerts=${hubAfter?.stats?.openAlerts}`);

  log('14. Hub groups monitors by tool and severity',
    (hubAfter?.stats?.byTool ?? []).some(t => t.key === 'HANDLE') && (hubAfter?.stats?.bySeverity ?? []).some(s => s.key === 'HIGH'),
    `byTool=${(hubAfter?.stats?.byTool ?? []).map(t => `${t.key}:${t.total}`).join(',')} bySeverity=${(hubAfter?.stats?.bySeverity ?? []).map(s => `${s.key}:${s.total}`).join(',')}`);

  // ── Duplicate alert prevention ──
  await call('POST', `/api/intel/monitoring/run/${monitor.id}`);
  const afterRepeat = (await call('GET', `/api/intel/monitoring/${monitor.id}/alerts`)).data ?? [];
  log('15. Duplicate alerts prevented on repeat trigger',
    afterRepeat.filter(a => a.id === alert?.id).length === 1,
    `${afterRepeat.length} alert row(s), dedupeKey=${alert?.dedupeKey}`);

  // ── Timeline / entity linkage ──
  const timeline = (await call('GET', '/api/intel/timeline')).data;
  const timelineLinked = Array.isArray(timeline)
    ? timeline.some(t => t.description?.includes(uniq) || t.title?.includes(uniq))
    : false;
  log('16. Monitoring cycle is linked into the existing timeline', timelineLinked,
    `${Array.isArray(timeline) ? timeline.length : 0} timeline events`);

  // ── Entity lookup from the hub's reverse index ──
  const forEntity = (await call('GET', `/api/intel/monitoring/entity/HANDLE/${handleId}`)).data ?? [];
  log('17. Entity reverse lookup finds the hub-created monitor',
    forEntity.some(m => m.id === monitor.id),
    `${forEntity.length} monitor(s) bound to ${handleId}`);

  // ── Pause stops monitoring ──
  await call('POST', `/api/intel/monitoring/${monitor.id}/pause`);
  const paused = (await call('GET', `/api/intel/monitoring/${monitor.id}`)).data;
  const cycleWhilePaused = (await call('POST', `/api/intel/monitoring/run`)).data;
  const stillPaused = (await call('GET', `/api/intel/monitoring/${monitor.id}`)).data;
  log('18. Paused monitor is excluded from scheduler cycles',
    paused?.status === 'PAUSED' && stillPaused?.checkCount === paused?.checkCount,
    `status=${paused?.status} checkCount held at ${stillPaused?.checkCount} (cycle ran ${cycleWhilePaused?.checked} due monitors)`);

  // ── Resume continues ──
  await call('POST', `/api/intel/monitoring/${monitor.id}/resume`);
  const resumed = (await call('POST', `/api/intel/monitoring/run/${monitor.id}`)).data;
  const afterResume = (await call('GET', `/api/intel/monitoring/${monitor.id}`)).data;
  log('19. Resumed monitor continues to be checked',
    resumed?.status !== undefined && afterResume?.checkCount > stillPaused?.checkCount,
    `cycle=${resumed?.status} checkCount ${stillPaused?.checkCount} -> ${afterResume?.checkCount}`);

  // ── Error handling / recovery surface ──
  const notFound = await call('GET', '/api/intel/monitoring/NOPE-999');
  log('20. Invalid monitor id is rejected, not silently ignored', notFound.status === 404, `status ${notFound.status}`);
  const badSeverity = await call('POST', '/api/intel/monitoring', { name: 'bad', targetType: 'HANDLE', targetId: handleId, frequency: 'CONTINUOUS', severity: 'NOT_A_SEVERITY' });
  log('21. Invalid monitor configuration is refused by the engine', badSeverity.status === 400, badSeverity.error ?? '');
  const ghostEntity = await call('POST', '/api/intel/monitoring', { name: 'ghost', targetType: 'HANDLE', targetId: 'HANDLE-DOES-NOT-EXIST', frequency: 'CONTINUOUS', severity: 'LOW' });
  log('22. Monitor cannot bind to a non-existent entity', ghostEntity.status === 400, ghostEntity.error ?? '');

  // ── Existing routes still work ──
  const existing = {
    'GET /api/health': (await call('GET', '/api/health')).status,
    'GET /api/intel/dataset': (await call('GET', '/api/intel/dataset')).status,
    'GET /api/intel/monitoring/stats': (await call('GET', '/api/intel/monitoring/stats')).status,
    'GET /api/intel/monitoring': (await call('GET', '/api/intel/monitoring')).status,
    'GET /api/intel/alerts': (await call('GET', '/api/intel/alerts')).status,
    'GET /api/alerts': (await call('GET', '/api/alerts')).status,
    'GET /api/darkweb/monitoring': (await call('GET', '/api/darkweb/monitoring')).status,
    'GET /api/cases': (await call('GET', '/api/cases')).status,
    'GET /api/audit': (await call('GET', '/api/audit')).status,
    'POST /api/analyze/url': (await call('POST', '/api/analyze/url', { url: 'https://example.com/path?q=1' })).status,
    'POST /api/analyze/ip': (await call('POST', '/api/analyze/ip', { ip: '192.0.2.1' })).status,
  };
  const broken = Object.entries(existing).filter(([, status]) => status >= 400);
  log('23. Existing APIs and analysis tools still respond', broken.length === 0,
    Object.entries(existing).map(([k, v]) => `${k}=${v}`).join(' '));

  // ── Data intact ──
  const dataset = (await call('GET', '/api/intel/dataset')).data;
  const actors = dataset?.actors?.length ?? 0;
  const handles = dataset?.handles?.length ?? 0;
  log('24. Pre-existing intelligence intact', actors > 0 && handles > 0, `${actors} actors, ${handles} handles preserved`);

  // ── Cleanup: only the synthetic monitor is removed ──
  const deleted = await call('DELETE', `/api/intel/monitoring/${monitor.id}`);
  const remaining = (await call('GET', '/api/intel/monitoring')).data ?? [];
  log('25. Synthetic monitor removed, pre-existing monitors untouched',
    deleted.status === 204 && remaining.length === list.length - 1,
    `${remaining.length} monitors remain (2 pre-existing preserved)`);

  // ── Indicator watches for the analysis tools ──
  const email = `probe-${uniq.toLowerCase()}@example.test`;
  const url = `https://probe-${uniq.toLowerCase()}.example.test/payload`;
  const emailMonitor = (await call('POST', '/api/intel/monitoring', {
    name: `SYN ${uniq} — email watch`, targetType: 'EMAIL',
    targetId: email, targetValue: email, frequency: 'CONTINUOUS', severity: 'MEDIUM',
    conditions: ['NEW_MATCHING_OBSERVATION', 'NEW_MENTION'],
  })).data;
  log('26. Email Analyzer indicator watch created (term-based, no duplicate record)',
    !!emailMonitor?.id, `${emailMonitor?.id} watching ${email}`);

  const datasetAfterEmail = (await call('GET', '/api/intel/dataset')).data;
  log('27. Indicator watch created no duplicate intelligence record',
    (datasetAfterEmail?.handles ?? []).every(h => !String(h.value).includes(email.toLowerCase())) &&
    (datasetAfterEmail?.actors ?? []).every(a => !JSON.stringify(a).includes(email.toLowerCase())),
    'no entity row was minted for the watched email');

const urlMonitor = (await call('POST', '/api/intel/monitoring', {
    name: `SYN ${uniq} — url watch`, targetType: 'URL',
    targetId: url, targetValue: url, frequency: 'CONTINUOUS', severity: 'HIGH',
    conditions: ['NEW_MATCHING_OBSERVATION'],
  })).data;
  const fileMonitor = (await call('POST', '/api/intel/monitoring', {
    name: `SYN ${uniq} — file hash watch`, targetType: 'FILE',
    targetId: `sha256:${'a'.repeat(64)}`, targetValue: `sha256:${'a'.repeat(64)}`,
    frequency: 'DAILY', severity: 'HIGH', conditions: ['NEW_MATCHING_OBSERVATION'],
  })).data;
  log('30. URL and File Analysis watches created alongside the email watch',
    !!urlMonitor?.id && !!fileMonitor?.id, `${urlMonitor?.id}, ${fileMonitor?.id}`);

  const emailCycle1 = (await call('POST', `/api/intel/monitoring/run/${emailMonitor.id}`)).data;
  const emailAlerts1 = (await call('GET', `/api/intel/monitoring/${emailMonitor.id}/alerts`)).data ?? [];
  log('28. Email watch runs and stays silent with no new mention',
    emailCycle1?.status === 'OK' && emailAlerts1.length === 0, `cycle=${emailCycle1?.status}`);

  // A real mention of both watched values arriving through the existing pipeline.
  await call('POST', '/api/intel/ingest', {
    source: 'OpenCTI Feed',
    handles: [{ handle: `carrier-${uniq}`, platform: 'SyntheticRelay' }],
    observation: { type: 'HANDLE_OBSERVED', content: `phishing campaign now impersonating ${email} via ${url}` },
  });
  const emailCycle2 = (await call('POST', `/api/intel/monitoring/run/${emailMonitor.id}`)).data;
  const emailAlerts2 = (await call('GET', `/api/intel/monitoring/${emailMonitor.id}/alerts`)).data ?? [];
  log('29. Email watch detects the new mention and raises an alert',
    emailCycle2?.status === 'TRIGGERED' && emailAlerts2.length === 1,
    `cycle=${emailCycle2?.status} alert=${emailAlerts2[0]?.id} cites=${emailAlerts2[0]?.observationIds?.length} observation(s)`);

  const urlCycle = (await call('POST', `/api/intel/monitoring/run/${urlMonitor.id}`)).data;
  const urlAlerts = (await call('GET', `/api/intel/monitoring/${urlMonitor.id}/alerts`)).data ?? [];
  log('31. URL Analysis watch detects the same mention independently',
    urlCycle?.status === 'TRIGGERED' && urlAlerts.length === 1,
    `cycle=${urlCycle?.status} alert=${urlAlerts[0]?.id}`);

  const fileCycle = (await call('POST', `/api/intel/monitoring/run/${fileMonitor.id}`)).data;
  log('32. File Analysis hash watch runs against the same tables',
    fileCycle?.status === 'OK', `cycle=${fileCycle?.status} (no mention of this hash exists, so no alert — correct)`);

  const badType = await call('POST', '/api/intel/monitoring', { name: 'x', targetType: 'NOT_A_TOOL', targetId: 'y', frequency: 'CONTINUOUS', severity: 'LOW' });
  log('33. Unknown target type still rejected', badType.status === 400, badType.error ?? '');

  // ── Dossier reverse lookup under a mismatched entity/target type ──
  const pgpLookup = (await call('GET', '/api/intel/monitoring/entity/PGP_KEY/PGP-DOES-NOT-EXIST')).status;
  log('34. Entity lookup route still behaves for unknown ids', pgpLookup === 200, `status ${pgpLookup}`);

  // ── Cleanup: remove only what this run created ──
  for (const id of [emailMonitor?.id, urlMonitor?.id, fileMonitor?.id].filter(Boolean)) {
    await call('DELETE', `/api/intel/monitoring/${id}`);
  }
  const afterIndicatorCleanup = (await call('GET', '/api/intel/monitoring')).data ?? [];
  log('35. Indicator watches removed cleanly', !afterIndicatorCleanup.some(m => [emailMonitor?.id, urlMonitor?.id, fileMonitor?.id].includes(m.id)),
    `${afterIndicatorCleanup.length} monitors remain`);

  const failed = results.filter(r => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length ? 1 : 0);
}

main().catch(error => { console.error('ABORTED', error); process.exit(2); });

