import { createServer } from 'node:http';
import { config } from './config/env.mjs';
import { openStore } from './database/store.mjs';
import { handleRouteError, routeRequest } from './routes/apiRoutes.mjs';

await openStore();
const server = createServer((request, response) => routeRequest(request, response).catch(error => handleRouteError(request, response, error)));
server.listen(config.port, () => console.log(`PhishNet API listening on http://localhost:${config.port}`));
