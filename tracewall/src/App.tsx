import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { ThreeDProvider } from './context/ThreeDContext';
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
import ExposurePage from './pages/app/ExposurePage';
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

export default function App() {
  return (
    <ThemeProvider>
      <ThreeDProvider>
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
            <Route path="exposure" element={<ExposurePage />} />
            <Route path="intelligence" element={<IntelligencePage />} />
            <Route path="campaigns" element={<FeedbackPage />} />
            <Route path="cases" element={<CasesPage />} />
            <Route path="cases/:id" element={<CasesPage />} />
            <Route path="evidence" element={<EvidencePage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="decisions" element={<DecisionDeskPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/app/briefing" replace />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </ThreeDProvider>
    </ThemeProvider>
  );
}
