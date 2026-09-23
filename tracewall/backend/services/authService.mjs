import { randomBytes } from 'node:crypto';
import { config, demoAnalyst } from '../config/env.mjs';
import { getStore, persistStore } from '../database/store.mjs';
import { requiredString } from '../utils/validation.mjs';

export async function signIn(input) {
  const email = requiredString(input.email, 'email', 320);
  const password = requiredString(input.password, 'password', 1024);
  if (!email.includes('@')) throw Object.assign(new Error('email must be valid'), { status: 400 });
  if (email !== demoAnalyst.email || password !== config.demoPassword) throw Object.assign(new Error('Invalid credentials'), { status: 401 });
  const store = getStore();
  const token = randomBytes(32).toString('hex');
  store.sessions = store.sessions.filter(session => new Date(session.expiresAt) > new Date());
  const user = { ...demoAnalyst, email };
  store.sessions.push({ token, user, expiresAt: new Date(Date.now() + config.sessionHours * 60 * 60 * 1000).toISOString() });
  await persistStore();
  return { token, user };
}
