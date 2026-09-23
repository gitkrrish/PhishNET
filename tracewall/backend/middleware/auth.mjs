import { getStore } from '../database/store.mjs';
import { sendError } from './http.mjs';

export function requireAuth(request, response) {
  const header = request.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const session = getStore().sessions.find(item => item.token === token && new Date(item.expiresAt) > new Date());
  if (!session) {
    sendError(response, 401, 'Authentication required');
    return null;
  }
  return session.user;
}

export function requireRole(user, roles) {
  if (!roles.includes(user.role)) throw Object.assign(new Error('Insufficient permissions'), { status: 403 });
}
