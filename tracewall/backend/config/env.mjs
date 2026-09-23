import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config as loadDotenv } from 'dotenv';

const backendRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const projectRoot = dirname(backendRoot);
loadDotenv({ path: join(projectRoot, '.env.local') });
loadDotenv();

export const config = {
  port: Number(process.env.API_PORT || 8787),
  corsOrigin: process.env.CORS_ORIGIN || '*',
  databaseFile: join(backendRoot, 'database', 'tracewall.sqlite'),
  recoveryFile: join(backendRoot, 'database', 'tracewall.json'),
  sessionHours: Number(process.env.SESSION_HOURS || 8),
  demoPassword: process.env.DEMO_PASSWORD || 'demo-password',
  maxBodyBytes: Number(process.env.MAX_BODY_BYTES || 5 * 1024 * 1024),
  dnsServers: (process.env.EMAIL_DNS_SERVERS || '8.8.8.8,8.8.4.4').split(',').map(value => value.trim()).filter(Boolean),
  azureDnsServer: process.env.AZURE_DNS_SERVER || '168.63.129.16',
  virustotalApiKey: process.env.VIRUSTOTAL_API_KEY || '',
  abuseIpDbApiKey: process.env.ABUSEIPDB_API_KEY || '',
  otxApiKey: process.env.OTX_API_KEY || '',
  ipWhoApiKey: process.env.IPWHO_API_KEY || '',
  ipInfoToken: process.env.IPINFO_TOKEN || '',
  ipQualityScoreApiKey: process.env.IPQUALITYSCORE_API_KEY || '',
  proxyCheckApiKey: process.env.PROXYCHECK_API_KEY || '',
  groqApiKey: process.env.GROQ_API_KEY || '',
  requestTimeoutMs: Number(process.env.EMAIL_ANALYSIS_TIMEOUT_MS || 5000),
  infrastructureTimeoutMs: Number(process.env.IP_ANALYSIS_TIMEOUT_MS || 10000),
};

export const demoAnalyst = {
  id: 'USR-DEMO-001',
  name: 'Demo Analyst',
  role: 'Security Analyst',
  email: 'analyst@tracewall.demo',
};
