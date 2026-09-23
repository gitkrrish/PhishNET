import { useState, useCallback, useEffect } from 'react';
import { Upload, FileText, Shield, AlertTriangle, CheckCircle, Download, ExternalLink, FileCheck } from 'lucide-react';
import clsx from 'clsx';
import { motion } from 'framer-motion';
import { tv } from '../../lib/styles';
import { DemoLabel } from '../../components/ui/DemoLabel';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { EvidenceStamp } from '../../components/ui/EvidenceStamp';
import { currentAnalyst } from '../../data/mockData';
import ThreatEvidenceNetwork from '../../components/3d/ThreatEvidenceNetwork';

interface FileAnalysisResult {
  id: string;
  fileName: string;
  fileSize: string;
  fileType: string;
  mimeType: string;
  hash: string;
  uploadedAt: string;
  uploadedBy: string;
  riskScore: number;
  verdict: string;
  confidence: string;
  severity: string;
  suspiciousFindings: string[];
  metadata: {
    author?: string;
    creationDate?: string;
    modificationDate?: string;
    software?: string;
    pageCount?: number;
    wordCount?: number;
  };
  extractedIndicators: {
    urls: string[];
    domains: string[];
    ips: string[];
    emailAddresses: string[];
  };
  macroAnalysis?: {
    present: boolean;
    autoExec?: boolean;
    suspiciousFunctions?: string[];
  };
  scriptAnalysis?: {
    present: boolean;
    language?: string;
    obfuscated?: boolean;
  };
  archiveContents?: {
    fileName: string;
    size: string;
    suspicious: boolean;
  }[];
  recommendedAction: string;
  relatedCase?: string;
}

const demoFileAnalysis: FileAnalysisResult = {
  id: 'FILE-2026-0015',
  fileName: 'Invoice_Update_September.docm',
  fileSize: '384 KB',
  fileType: 'DOCM (Macro-Enabled Document)',
  mimeType: 'application/vnd.ms-word.document.macroEnabled.12',
  hash: 'e9a3f7c2d1b44e6855ab291c0f8e3d17492c1b8f5a2e0d9c6b4f3a7e8d1c059',
  uploadedAt: '2026-09-13T10:30:45Z',
  uploadedBy: currentAnalyst.name,
  riskScore: 82,
  verdict: 'SUSPICIOUS',
  confidence: 'HIGH',
  severity: 'HIGH',
  suspiciousFindings: [
    'Macro-enabled document format',
    'Auto-executable macro detected',
    'Suspicious VBA functions present',
    'Document contains external link',
    'Unusual metadata pattern',
    'Hash matches known delivery template',
  ],
  metadata: {
    author: 'Finance Department',
    creationDate: '2026-09-05T08:15:22Z',
    modificationDate: '2026-09-05T11:30:45Z',
    software: 'Microsoft Office Word',
    pageCount: 2,
    wordCount: 342,
  },
  extractedIndicators: {
    urls: ['https://asteron-billing.example/confirm'],
    domains: ['asteron-billing.example'],
    ips: [],
    emailAddresses: ['finance@asteron.example'],
  },
  macroAnalysis: {
    present: true,
    autoExec: true,
    suspiciousFunctions: ['Shell', 'URLDownloadToFile', 'CreateObject', 'WScript.Shell'],
  },
  scriptAnalysis: {
    present: true,
    language: 'VBA',
    obfuscated: true,
  },
  recommendedAction: 'Quarantine immediately. Submit to sandbox for full dynamic analysis. Do not enable macros.',
  relatedCase: 'CASE-2026-0142',
};

const demoFiles = [
  {
    id: 'demo-1',
    label: 'Invoice_Update_September.docm (Macro-Enabled)',
    fileName: 'Invoice_Update_September.docm',
    fileType: 'DOCM',
    description: 'Macro-enabled document with suspicious VBA functions and external links.',
  },
  {
    id: 'demo-2',
    label: 'HR_Policy_Update.pdf (Clean)',
    fileName: 'HR_Policy_Update.pdf',
    fileType: 'PDF',
    description: 'Standard PDF document with no suspicious indicators detected.',
  },
  {
    id: 'demo-3',
    label: 'Suspicious_Archive.zip (Archive)',
    fileName: 'Suspicious_Archive.zip',
    fileType: 'ZIP',
    description: 'Compressed archive containing multiple suspicious files.',
  },
];

const analysisSteps = [
  'Validating file type and size...',
  'Preserving original evidence...',
  'Calculating SHA-256 hash...',
  'Extracting safe metadata...',
  'Scanning for embedded scripts...',
  'Checking for macro content...',
  'Analyzing archive contents...',
  'Extracting URLs and indicators...',
  'Checking hash against threat feeds...',
  'Generating risk assessment...',
];

function AnalysisProgress({ onComplete }: { onComplete: () => void }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setStep(prev => {
        if (prev >= analysisSteps.length - 1) {
          clearInterval(interval);
          setTimeout(onComplete, 400);
          return prev;
        }
        return prev + 1;
      });
    }, 400);
    return () => clearInterval(interval);
  }, []);

  const progress = ((step + 1) / analysisSteps.length) * 100;

  return (
    <div className="min-h-[50vh] flex flex-col items-center justify-center gap-6 p-10" style={tv.canvas}>
      <div className="w-full max-w-sm space-y-4">
        <div className="text-center">
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase mb-2" style={tv.muted}>Analysis in Progress</p>
          <p className="font-serif text-xl" style={tv.text}>Examining File</p>
        </div>
        <div className="h-0.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--tw-border-mid)' }}>
          <motion.div
            className="h-full rounded-full"
            style={{ backgroundColor: 'var(--tw-burgundy)' }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.3 }}
          />
        </div>
        <div className="space-y-2">
          {analysisSteps.map((s, i) => (
            <div key={i} className={clsx('flex items-center gap-2 text-xs transition-all duration-300')}>
              {i < step ? (
                <CheckCircle size={11} className="shrink-0" style={tv.low} />
              ) : i === step ? (
                <div className="w-2.5 h-2.5 border rounded-full shrink-0 animate-pulse"
                  style={{ borderColor: 'var(--tw-burgundy)' }}
                />
              ) : (
                <div className="w-2.5 h-2.5 border rounded-full shrink-0"
                  style={{ borderColor: 'var(--tw-border-strong)' }}
                />
              )}
              <span className="font-mono"
                style={{ color: i < step ? 'var(--tw-low)' : i === step ? 'var(--tw-text)' : 'var(--tw-text-faint)' }}
              >
                {s}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function FileAnalysisPage() {
  const [step, setStep] = useState<'intake' | 'analyzing' | 'results'>('intake');
  const [inputMethod, setInputMethod] = useState<'upload' | 'demo'>('upload');
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [selectedDemoId, setSelectedDemoId] = useState('demo-1');
  const [analysisResult, setAnalysisResult] = useState<FileAnalysisResult | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);

  const validTypes = ['.pdf', '.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm', '.zip', '.txt', '.jpg', '.jpeg', '.png', '.gif'];
  const validMimes = [
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-word.document.macroEnabled.12',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-excel.sheet.macroEnabled.12',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.ms-powerpoint.presentation.macroEnabled.12',
    'application/zip',
    'text/plain',
    'image/jpeg',
    'image/png',
    'image/gif',
  ];

  const validateFile = useCallback((file: File): boolean => {
    const ext = file.name.toLowerCase().slice(file.name.lastIndexOf('.'));
    if (!validTypes.includes(ext) && !validMimes.includes(file.type)) {
      setUploadError(`Invalid file type. Accepted: ${validTypes.join(', ')}`);
      return false;
    }
    if (file.size > 25 * 1024 * 1024) {
      setUploadError('File too large. Maximum size: 25 MB');
      return false;
    }
    setUploadError(null);
    return true;
  }, []);

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const file = e.dataTransfer.files[0];
    if (file && validateFile(file)) {
      setUploadedFile(file);
      setInputMethod('upload');
    }
  }, [validateFile]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && validateFile(file)) {
      setUploadedFile(file);
      setInputMethod('upload');
    }
  }, [validateFile]);

  const computeFileHash = async (file: File): Promise<string> => {
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const startAnalysis = useCallback(async () => {
    if (!acknowledged) return;

    let result: FileAnalysisResult | null = null;

    if (inputMethod === 'demo') {
      result = { ...demoFileAnalysis };
    } else if (inputMethod === 'upload' && uploadedFile) {
      const hash = await computeFileHash(uploadedFile);
      result = {
        ...demoFileAnalysis,
        id: `FILE-${Date.now()}`,
        fileName: uploadedFile.name,
        fileSize: `${(uploadedFile.size / 1024).toFixed(1)} KB`,
        fileType: uploadedFile.name.split('.').pop()?.toUpperCase() || 'UNKNOWN',
        mimeType: uploadedFile.type,
        hash: hash,
        uploadedAt: new Date().toISOString(),
        uploadedBy: currentAnalyst.name,
      };
    }

    if (result) {
      setAnalysisResult(result);
      setStep('analyzing');
      setTimeout(() => {
        setStep('results');
      }, 4000);
    }
  }, [acknowledged, inputMethod, uploadedFile]);

  const resetAnalysis = useCallback(() => {
    setStep('intake');
    setAnalysisResult(null);
    setUploadedFile(null);
    setUploadError(null);
    setAcknowledged(false);
  }, []);

  if (step === 'intake') {
    return (
      <div className="min-h-screen" style={tv.canvas}>
        <div className="max-w-4xl mx-auto px-6 lg:px-10 py-10 space-y-8">
          <div className="space-y-2">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>File Analysis</p>
            <h1 className="font-serif text-3xl" style={tv.text}>Submit File for Analysis</h1>
          </div>

          {/* Privacy notice */}
          <div className="rounded-sm p-5 space-y-3"
            style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
          >
            <div className="flex items-start gap-3">
              <AlertTriangle size={15} className="mt-0.5 shrink-0" style={tv.medium} />
              <div className="space-y-2">
                <p className="font-mono text-[10px] tracking-[0.15em] uppercase" style={tv.medium}>Authorised Use Notice</p>
                <p className="text-xs leading-relaxed" style={tv.muted}>
                  This platform performs safe metadata extraction and static analysis. Files are not executed,
                  macros are not enabled, and dangerous content is not automatically accessed.
                  Original files are preserved as evidence with SHA-256 hash verification.
                </p>
                <label className="flex items-center gap-2 cursor-pointer pt-1">
                  <input type="checkbox" checked={acknowledged} onChange={e => setAcknowledged(e.target.checked)}
                    style={{ accentColor: 'var(--tw-burgundy)' }}
                    className="w-3.5 h-3.5"
                  />
                  <span className="text-xs" style={tv.text}>
                    I am an authorised analyst and understand the safe analysis limitations.
                  </span>
                </label>
              </div>
            </div>
          </div>

          {/* Input method */}
          <div className="space-y-4">
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Input Method</p>
            <div className="flex gap-2">
              {[
                { id: 'upload', label: 'Upload File' },
                { id: 'demo', label: 'Demo File' },
              ].map(m => (
                <button key={m.id} onClick={() => setInputMethod(m.id as 'upload' | 'demo')}
                  className="font-mono text-xs tracking-wide px-4 py-2 rounded-sm border transition-colors"
                  style={inputMethod === m.id
                    ? { backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6', borderColor: 'var(--tw-burgundy)' }
                    : { backgroundColor: 'transparent', color: 'var(--tw-text-muted)', borderColor: 'var(--tw-border-strong)' }
                  }
                >
                  {m.label}
                </button>
              ))}
            </div>

            {inputMethod === 'upload' && (
              <div className="space-y-3">
                <div
                  className={`border-2 border-dashed rounded-sm p-10 text-center transition-colors ${dragActive ? 'bg-[color-mix(in_srgb,_var(--tw-burgundy),_transparent)]' : ''}`}
                  style={{ borderColor: dragActive ? 'var(--tw-burgundy)' : 'var(--tw-border-strong)' }}
                  onDragOver={e => { e.preventDefault(); setDragActive(true); }}
                  onDragLeave={e => { e.preventDefault(); setDragActive(false); }}
                  onDrop={handleFileDrop}
                >
                  <input type="file" id="file-upload" accept={validTypes.join(',')} onChange={handleFileSelect} className="hidden" />
                  <label htmlFor="file-upload" className="cursor-pointer">
                    <Upload size={20} className="mx-auto mb-3" style={tv.faint} />
                    <p className="text-sm" style={tv.muted}>Drop a file here or click to browse</p>
                    <p className="font-mono text-[10px] mt-1" style={tv.faint}>
                      Accepted: {validTypes.join(', ')} · Max 25 MB
                    </p>
                  </label>
                </div>
                {uploadError && (
                  <p className="font-mono text-xs text-center" style={{ color: 'var(--tw-critical)' }}>{uploadError}</p>
                )}
                {uploadedFile && (
                  <div className="p-3 rounded-sm border flex items-center justify-between"
                    style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}
                  >
                    <div className="flex items-center gap-3">
                      <FileText size={16} style={tv.text} />
                      <div>
                        <p className="font-mono text-xs" style={tv.text}>{uploadedFile.name}</p>
                        <p className="font-mono text-[10px]" style={tv.muted}>{(uploadedFile.size / 1024).toFixed(1)} KB</p>
                      </div>
                    </div>
                    <button onClick={() => { setUploadedFile(null); }}
                      className="font-mono text-[10px] text-red-500 hover:underline">Remove</button>
                  </div>
                )}
              </div>
            )}

            {inputMethod === 'demo' && (
              <div className="p-4 rounded-sm border space-y-3"
                style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border)' }}
              >
                <div className="flex items-center justify-between">
                  <DemoLabel />
                  <select value={selectedDemoId} onChange={e => setSelectedDemoId(e.target.value)}
                    className="font-mono text-xs px-3 py-1.5 rounded-sm border focus:outline-none" style={tv.input}
                  >
                    {demoFiles.map(d => <option key={d.id} value={d.id}>{d.label}</option>)}
                  </select>
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-medium" style={tv.text}>{demoFiles.find(d => d.id === selectedDemoId)?.fileName}</p>
                  <p className="font-mono text-xs" style={tv.muted}>{demoFiles.find(d => d.id === selectedDemoId)?.description}</p>
                </div>
              </div>
            )}
          </div>

          <button onClick={startAnalysis} disabled={!acknowledged || (inputMethod === 'upload' && !uploadedFile)}
            className="font-mono text-xs tracking-widest uppercase px-6 py-3 rounded-sm transition-colors disabled:opacity-40 w-full"
            style={{ backgroundColor: 'var(--tw-burgundy)', color: '#FBFAF6' }}
          >
            Begin Analysis →
          </button>
        </div>
      </div>
    );
  }

  if (step === 'analyzing') {
    return <AnalysisProgress onComplete={() => setStep('results')} />;
  }

  if (!analysisResult) return null;

  return (
    <div className="min-h-screen" style={tv.canvas}>
      <div className="max-w-7xl mx-auto px-6 lg:px-10 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>
                Analysis Complete · {analysisResult.id}
              </p>
              <DemoLabel />
            </div>
            <h1 className="font-serif text-2xl" style={tv.text}>{analysisResult.fileName}</h1>
            <p className="font-mono text-[10px]" style={tv.muted}>SHA-256: {analysisResult.hash.slice(0, 32)}...</p>
          </div>
          <div className="flex gap-2">
            <button onClick={() => {
              const blob = new Blob([JSON.stringify(analysisResult, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `${analysisResult.id}-analysis.json`;
              a.click();
              URL.revokeObjectURL(url);
            }}
              className="font-mono text-xs border px-3 py-2 rounded-sm transition-colors flex items-center gap-2"
              style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
            >
              <Download size={12} /> Export JSON
            </button>
            <button onClick={() => {
              const caseId = `CASE-${Date.now()}`;
              alert(`Case ${caseId} would be created from this file analysis (demo mode)`);
            }}
              className="font-mono text-xs border px-3 py-2 rounded-sm transition-colors flex items-center gap-2"
              style={{ borderColor: 'var(--tw-burgundy)', color: 'var(--tw-burgundy)' }}
            >
              <FileCheck size={12} /> Create Case
            </button>
            <button onClick={resetAnalysis}
              className="font-mono text-xs border px-3 py-2 rounded-sm transition-colors"
              style={{ borderColor: 'var(--tw-border-strong)', color: 'var(--tw-text-muted)' }}
            >
              New Analysis
            </button>
          </div>
        </div>

        {/* Threat Evidence Network */}
        <ThreatEvidenceNetwork pageType="file" />

        {/* Verdict */}
        <div className="grid lg:grid-cols-3 gap-6 mb-6">
          <div className="lg:col-span-1 space-y-4">
            <div className="rounded-sm p-6 space-y-4 text-center" style={tv.panelBorder}>
              <EvidenceStamp verdict={analysisResult.verdict} size="lg" className="mx-auto" />
              <div>
                <div className="font-mono text-6xl font-light" style={tv.burg}>{analysisResult.riskScore}</div>
                <div className="font-mono text-xs tracking-wider" style={tv.muted}>/ 100 RISK SCORE</div>
              </div>
              <SeverityBadge severity={analysisResult.severity} />
              <p className="font-mono text-[10px]" style={tv.muted}>Confidence: {analysisResult.confidence}</p>
            </div>
          </div>

          <div className="lg:col-span-2 space-y-4">
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Suspicious Findings</p>
              </div>
              {analysisResult.suspiciousFindings.map((finding, i) => (
                <div key={i} className="flex items-center gap-3 px-5 py-3 border-b last:border-0"
                  style={{ borderColor: 'var(--tw-border-mid)' }}
                >
                  <span className="evidence-num shrink-0">{String(i + 1).padStart(2, '0')}</span>
                  <p className="text-sm" style={tv.text}>{finding}</p>
                </div>
              ))}
            </div>

            <div className="rounded-sm p-4 space-y-2" style={tv.panelBorder}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Recommended Action</p>
              <p className="text-sm leading-relaxed" style={tv.text}>{analysisResult.recommendedAction}</p>
            </div>
          </div>
        </div>

        {/* File Metadata */}
        <div className="grid lg:grid-cols-2 gap-6 mb-6">
          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>File Metadata</p>
            </div>
            {[
              { label: 'File Name', val: analysisResult.fileName },
              { label: 'File Size', val: analysisResult.fileSize },
              { label: 'File Type', val: analysisResult.fileType },
              { label: 'MIME Type', val: analysisResult.mimeType },
              { label: 'Uploaded At', val: new Date(analysisResult.uploadedAt).toLocaleString() },
              { label: 'Uploaded By', val: analysisResult.uploadedBy },
            ].map(row => (
              <div key={row.label} className="flex items-start gap-4 px-5 py-3 border-b last:border-0"
                style={{ borderColor: 'var(--tw-border-mid)' }}
              >
                <span className="font-mono text-[10px] uppercase tracking-wider w-28 shrink-0 pt-0.5" style={tv.muted}>{row.label}</span>
                <p className="font-mono text-xs flex-1" style={tv.text}>{row.val}</p>
              </div>
            ))}
          </div>

          <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
            <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
              <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Document Metadata</p>
            </div>
            {Object.entries(analysisResult.metadata).map(([key, val]) => (
              <div key={key} className="flex items-start gap-4 px-5 py-3 border-b last:border-0"
                style={{ borderColor: 'var(--tw-border-mid)' }}
              >
                <span className="font-mono text-[10px] uppercase tracking-wider w-28 shrink-0 pt-0.5" style={tv.muted}>{key}</span>
                <p className="font-mono text-xs flex-1" style={tv.text}>{val}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Security Analysis */}
        <div className="grid lg:grid-cols-2 gap-6 mb-6">
          {analysisResult.macroAnalysis && (
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Macro Analysis</p>
              </div>
              <div className="p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm" style={tv.text}>Macro Present</span>
                  <span className={`font-mono text-xs px-2 py-0.5 rounded-sm ${analysisResult.macroAnalysis.present ? 'bg-[color-mix(in_srgb,var(--tw-critical),transparent)] text-[var(--tw-critical)]' : 'bg-[color-mix(in_srgb,var(--tw-low),transparent)] text-[var(--tw-low)]'}`}>
                    {analysisResult.macroAnalysis.present ? 'YES' : 'NO'}
                  </span>
                </div>
                {analysisResult.macroAnalysis.autoExec && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm" style={tv.text}>Auto-Exec</span>
                    <span className="font-mono text-xs px-2 py-0.5 rounded-sm bg-[color-mix(in_srgb,var(--tw-critical),transparent)] text-[var(--tw-critical)]">
                      YES
                    </span>
                  </div>
                )}
                {analysisResult.macroAnalysis.suspiciousFunctions && (
                  <div className="space-y-2 pt-2 border-t" style={{ borderColor: 'var(--tw-border-mid)' }}>
                    <p className="font-mono text-[10px] uppercase tracking-wider" style={tv.muted}>Suspicious Functions</p>
                    {analysisResult.macroAnalysis.suspiciousFunctions.map((fn, i) => (
                      <div key={i} className="flex items-center gap-2">
                        <AlertTriangle size={10} style={tv.critical} />
                        <span className="font-mono text-xs" style={tv.text}>{fn}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {analysisResult.scriptAnalysis && (
            <div className="rounded-sm overflow-hidden" style={tv.panelBorder}>
              <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
                <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Script Analysis</p>
              </div>
              <div className="p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm" style={tv.text}>Script Present</span>
                  <span className={`font-mono text-xs px-2 py-0.5 rounded-sm ${analysisResult.scriptAnalysis.present ? 'bg-[color-mix(in_srgb,var(--tw-critical),transparent)] text-[var(--tw-critical)]' : 'bg-[color-mix(in_srgb,var(--tw-low),transparent)] text-[var(--tw-low)]'}`}>
                    {analysisResult.scriptAnalysis.present ? 'YES' : 'NO'}
                  </span>
                </div>
                {analysisResult.scriptAnalysis.language && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm" style={tv.text}>Language</span>
                    <span className="font-mono text-xs" style={tv.text}>{analysisResult.scriptAnalysis.language}</span>
                  </div>
                )}
                {analysisResult.scriptAnalysis.obfuscated && (
                  <div className="flex items-center justify-between">
                    <span className="text-sm" style={tv.text}>Obfuscated</span>
                    <span className="font-mono text-xs px-2 py-0.5 rounded-sm bg-[color-mix(in_srgb,var(--tw-medium),transparent)] text-[var(--tw-medium)]">
                      YES
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Extracted Indicators */}
        <div className="rounded-sm overflow-hidden mb-6" style={tv.panelBorder}>
          <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
            <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={tv.muted}>Extracted Indicators</p>
          </div>
          <div className="grid md:grid-cols-4 divide-y md:divide-y-0 md:divide-x" style={{ borderColor: 'var(--tw-border-mid)' }}>
            {[
              { label: 'URLs', items: analysisResult.extractedIndicators.urls },
              { label: 'Domains', items: analysisResult.extractedIndicators.domains },
              { label: 'IPs', items: analysisResult.extractedIndicators.ips },
              { label: 'Emails', items: analysisResult.extractedIndicators.emailAddresses },
            ].map(section => (
              <div key={section.label} className="p-5">
                <p className="font-mono text-[10px] uppercase tracking-wider mb-3" style={tv.muted}>{section.label}</p>
                {section.items.length > 0 ? (
                  <div className="space-y-2">
                    {section.items.map((item, i) => (
                      <div key={i} className="flex items-center gap-2">
                        <ExternalLink size={10} style={tv.muted} />
                        <span className="font-mono text-xs" style={tv.text}>{item}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="font-mono text-xs" style={tv.faint}>None found</p>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Evidence Disclaimer */}
        <div className="rounded-sm p-4 flex items-start gap-3"
          style={{ backgroundColor: 'var(--tw-canvas-mid)', border: '1px solid var(--tw-border)' }}
        >
          <Shield size={14} className="mt-0.5 shrink-0" style={tv.medium} />
          <p className="text-xs leading-relaxed" style={tv.muted}>
            Simulated File Analysis Result. No actual file was executed or macros enabled.
            Analysis is based on static metadata extraction and pattern matching.
            SHA-256 hash is computed for evidence integrity verification.
          </p>
        </div>
      </div>
    </div>
  );
}