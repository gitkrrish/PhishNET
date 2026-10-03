import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { ThreeDProvider } from './context/ThreeDContext';
import { IntelligenceProvider } from './lib/intelligence/IntelligenceContext';
import LandingPage from './pages/LandingPage';
import {
  ProductPage,
  FeaturesPage,
  HowItWorksPage,
  SecurityPage,
  SignInPage,
  PrivacyPolicyPage,
  TermsOfUsePage,
  DocumentationPage,
  AuthorisedUsePolicyPage,
} from './pages/PublicPages';
import { AppLayout } from './components/layout/AppLayout';
import BriefingPage from './pages/app/BriefingPage';
import InvestigatePage from './pages/app/InvestigatePage';
import IntelligencePage from './pages/app/IntelligencePage';
import CasesPage from './pages/app/CasesPage';
import EvidencePage from './pages/app/EvidencePage';
import ReportsPage from './pages/app/ReportsPage';
import AlertsPage from './pages/app/AlertsPage';
import AuditPage from './pages/app/AuditPage';
import FeedbackPage from './pages/app/FeedbackPage';
import DecisionDeskPage from './pages/app/DecisionDeskPage';
import SettingsPage from './pages/app/SettingsPage';
import FileAnalysisPage from './pages/app/FileAnalysisPage';
import UrlAnalysisPage from './pages/app/UrlAnalysisPage';
import InfrastructurePage from './pages/app/InfrastructurePage';
import { AnalysisErrorBoundary } from './components/ui/AnalysisErrorBoundary';
import { lazy, Suspense } from 'react';

const MonitoringHubPage = lazy(() => import('./pages/monitoring/MonitoringHubPage'));
const MonitoringMonitorsPage = lazy(() => import('./pages/monitoring/MonitoringMonitorsPage'));
const MonitoringAlertsPage = lazy(() => import('./pages/monitoring/MonitoringAlertsPage'));
const MonitoringHealthPage = lazy(() => import('./pages/monitoring/MonitoringHealthPage'));

const ThreatActorsPage = lazy(() => import('./pages/darkweb/ThreatActorsPage'));
const ActorProfilePage = lazy(() => import('./pages/darkweb/ActorProfilePage'));
const SourcesPage = lazy(() => import('./pages/darkweb/SourcesPage'));
const AttackWorkspacePage = lazy(() => import('./pages/darkweb/AttackWorkspacePage'));
const GraphPage = lazy(() => import('./pages/darkweb/GraphPage'));
const InfrastructureDarkPage = lazy(() => import('./pages/darkweb/InfrastructurePage'));
const TimelinePage = lazy(() => import('./pages/darkweb/TimelinePage'));
const EvidenceLockerPage = lazy(() => import('./pages/darkweb/EvidenceLockerPage'));
const AlertsDarkPage = lazy(() => import('./pages/darkweb/AlertsPage'));
const InvestigationsPage = lazy(() => import('./pages/darkweb/InvestigationsPage'));
const InvestigationWorkspacePage = lazy(() => import('./pages/darkweb/InvestigationWorkspacePage'));
const ReportsDarkPage = lazy(() => import('./pages/darkweb/ReportsPage'));
const DemoInvestigationPage = lazy(() => import('./pages/darkweb/DemoInvestigationPage'));
const AddIntelligencePage = lazy(() => import('./pages/darkweb/AddIntelligencePage'));

const DarkWebCorrelationPage = lazy(() => import('./pages/darkweb/CorrelationPage'));
const DarkWebAIPage = lazy(() => import('./pages/darkweb/AIPage'));
const HandleIntelligencePage = lazy(() => import('./pages/darkweb/HandleIntelligencePage'));
const HandleProfilePage = lazy(() => import('./pages/darkweb/HandleProfilePage'));
const PgpIntelligencePage = lazy(() => import('./pages/darkweb/PgpIntelligencePage'));
const PgpProfilePage = lazy(() => import('./pages/darkweb/PgpProfilePage'));
const WalletIntelligencePage = lazy(() => import('./pages/darkweb/WalletIntelligencePage'));
const WalletProfilePage = lazy(() => import('./pages/darkweb/WalletProfilePage'));
const ObservationIntelligencePage = lazy(() => import('./pages/darkweb/ObservationIntelligencePage'));
const ObservationPage = lazy(() => import('./pages/darkweb/ObservationPage'));
const DarkWebLoadingFallback = () => <div className="p-12 text-center" style={{ color: 'var(--tw-text-muted)', fontFamily: 'monospace' }}>Loading…</div>;

export default function App() {
  return (
    <ThemeProvider>
      <ThreeDProvider>
        <IntelligenceProvider>
        <BrowserRouter>
          <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/product" element={<ProductPage />} />
          <Route path="/features" element={<FeaturesPage />} />
          <Route path="/how-it-works" element={<HowItWorksPage />} />
          <Route path="/security" element={<SecurityPage />} />
          <Route path="/signin" element={<SignInPage />} />
          <Route path="/privacy-policy" element={<PrivacyPolicyPage />} />
          <Route path="/terms-of-use" element={<TermsOfUsePage />} />
          <Route path="/documentation" element={<DocumentationPage />} />
          <Route path="/authorised-use-policy" element={<AuthorisedUsePolicyPage />} />
          <Route path="/app" element={<AppLayout />}>
            <Route index element={<Navigate to="/app/briefing" replace />} />
            <Route path="briefing" element={<BriefingPage />} />
            <Route path="investigate" element={<InvestigatePage />} />
            <Route path="file-analysis" element={<FileAnalysisPage />} />
            <Route path="url-analysis" element={<UrlAnalysisPage />} />
            <Route path="infrastructure" element={<AnalysisErrorBoundary><InfrastructurePage /></AnalysisErrorBoundary>} />
            <Route path="intelligence" element={<IntelligencePage />} />
            <Route path="campaigns" element={<FeedbackPage />} />
            <Route path="cases" element={<CasesPage />} />
            <Route path="cases/:id" element={<CasesPage />} />
            <Route path="evidence" element={<EvidencePage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="audit" element={<AuditPage />} />            <Route path="decisions" element={<DecisionDeskPage />} />
            <Route path="settings" element={<SettingsPage />} />
            {/* 24×7 Monitoring Hub — centralized monitoring for all tools */}
            <Route path="monitoring" element={<Navigate to="/app/monitoring/hub" replace />} />
            <Route path="monitoring/hub" element={<Suspense fallback={<DarkWebLoadingFallback />}><MonitoringHubPage /></Suspense>} />
            <Route path="monitoring/monitors" element={<Suspense fallback={<DarkWebLoadingFallback />}><MonitoringMonitorsPage /></Suspense>} />
            <Route path="monitoring/alerts" element={<Suspense fallback={<DarkWebLoadingFallback />}><MonitoringAlertsPage /></Suspense>} />
            <Route path="monitoring/health" element={<Suspense fallback={<DarkWebLoadingFallback />}><MonitoringHealthPage /></Suspense>} />
            {/* The standalone "Dark-Web Monitoring" module is retired. Its
                monitoring capability now lives inside Dark Web Intelligence
                → Monitoring & Alerts, so the old path redirects there. */}
            <Route path="exposure" element={<Navigate to="/app/darkweb/exposure" replace />} />
            <Route path="darkweb" element={<Navigate to="/app/briefing" replace />} />
            <Route path="*" element={<Navigate to="/app/briefing" replace />} />
                        <Route path="darkweb/actors" element={<Suspense fallback={<DarkWebLoadingFallback />}><ThreatActorsPage /></Suspense>} />
            <Route path="darkweb/actors/:id" element={<Suspense fallback={<DarkWebLoadingFallback />}><ActorProfilePage /></Suspense>} />
            <Route path="darkweb/sources" element={<Suspense fallback={<DarkWebLoadingFallback />}><SourcesPage /></Suspense>} />
    <Route path="darkweb/attack" element={<Suspense fallback={<DarkWebLoadingFallback />}><AttackWorkspacePage /></Suspense>} />
            <Route path="darkweb/correlation" element={<Suspense fallback={<DarkWebLoadingFallback />}><DarkWebCorrelationPage /></Suspense>} />
            <Route path="darkweb/graph" element={<Suspense fallback={<DarkWebLoadingFallback />}><GraphPage /></Suspense>} />
            <Route path="darkweb/infrastructure" element={<Suspense fallback={<DarkWebLoadingFallback />}><InfrastructureDarkPage /></Suspense>} />
            <Route path="darkweb/timeline" element={<Suspense fallback={<DarkWebLoadingFallback />}><TimelinePage /></Suspense>} />
            <Route path="darkweb/evidence" element={<Suspense fallback={<DarkWebLoadingFallback />}><EvidenceLockerPage /></Suspense>} />
            <Route path="darkweb/alerts" element={<Suspense fallback={<DarkWebLoadingFallback />}><AlertsDarkPage /></Suspense>} />
      <Route path="darkweb/monitoring" element={<Navigate to="/app/monitoring/monitors" replace />} />
            <Route path="darkweb/exposure" element={<Suspense fallback={<DarkWebLoadingFallback />}><AlertsDarkPage /></Suspense>} />
            <Route path="darkweb/investigations" element={<Suspense fallback={<DarkWebLoadingFallback />}><InvestigationsPage /></Suspense>} />
            <Route path="darkweb/investigations/:id" element={<Suspense fallback={<DarkWebLoadingFallback />}><InvestigationWorkspacePage /></Suspense>} />
            <Route path="darkweb/ai" element={<Suspense fallback={<DarkWebLoadingFallback />}><DarkWebAIPage /></Suspense>} />
            <Route path="darkweb/reports" element={<Suspense fallback={<DarkWebLoadingFallback />}><ReportsDarkPage /></Suspense>} />
            <Route path="darkweb/demo" element={<Suspense fallback={<DarkWebLoadingFallback />}><DemoInvestigationPage /></Suspense>} />
            <Route path="darkweb/add" element={<Suspense fallback={<DarkWebLoadingFallback />}><AddIntelligencePage /></Suspense>} />
            <Route path="darkweb/collect" element={<Navigate to="/app/darkweb/add" replace />} />
            <Route path="darkweb/handles" element={<Suspense fallback={<DarkWebLoadingFallback />}><HandleIntelligencePage /></Suspense>} />
            <Route path="darkweb/handles/:id" element={<Suspense fallback={<DarkWebLoadingFallback />}><HandleProfilePage /></Suspense>} />
            <Route path="darkweb/pgp-keys" element={<Suspense fallback={<DarkWebLoadingFallback />}><PgpIntelligencePage /></Suspense>} />
            <Route path="darkweb/pgp-keys/:id" element={<Suspense fallback={<DarkWebLoadingFallback />}><PgpProfilePage /></Suspense>} />
            <Route path="darkweb/pgp/:fingerprint" element={<Suspense fallback={<DarkWebLoadingFallback />}><PgpProfilePage /></Suspense>} />
            <Route path="darkweb/wallets" element={<Suspense fallback={<DarkWebLoadingFallback />}><WalletIntelligencePage /></Suspense>} />
            <Route path="darkweb/wallets/:id" element={<Suspense fallback={<DarkWebLoadingFallback />}><WalletProfilePage /></Suspense>} />
            <Route path="darkweb/wallets/:address" element={<Suspense fallback={<DarkWebLoadingFallback />}><WalletProfilePage /></Suspense>} />
            <Route path="darkweb/observations" element={<Suspense fallback={<DarkWebLoadingFallback />}><ObservationIntelligencePage /></Suspense>} />
            <Route path="darkweb/observations/:id" element={<Suspense fallback={<DarkWebLoadingFallback />}><ObservationPage /></Suspense>} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
        </IntelligenceProvider>
      </ThreeDProvider>
    </ThemeProvider>
  );
}
