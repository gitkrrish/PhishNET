import { handleRequest } from '../controllers/apiController.mjs';
import { requireAuth } from '../middleware/auth.mjs';
import { sendError, sendJson } from '../middleware/http.mjs';

export async function routeRequest(request, response) {
  if (request.method === 'OPTIONS') return sendJson(response, 204, {});
  const path = new URL(request.url, `http://${request.headers.host}`).pathname;
  const publicRoute = path === '/api/health' || path === '/api/auth/sign-in';
  const user = publicRoute ? null : requireAuth(request, response);
  if (!publicRoute && !user) return;
  return handleRequest(request, response, user, path);
}

export function handleRouteError(request, response, caught) {
  const status = caught.status || 500;
  if (status >= 500) console.error(`[api] ${request.method} ${request.url}: ${caught.message}`);
  sendError(response, status, status >= 500 ? 'Internal server error' : caught.message);
}
