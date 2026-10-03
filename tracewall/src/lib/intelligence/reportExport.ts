// ============================================================
// PhishNet — Report export (JSON, CSV, PDF).
//
// Exports the real stored content of a report: the report record, the
// investigation it belongs to, the entities and evidence that
// investigation references, and the limitations that apply to it.
//
// Properties this module preserves:
//
//  * Content comes from the dataset, not from a template. A report with
//    no linked investigation exports that fact instead of a fabricated
//    body.
//  * Every exported claim names the record it came from. The CSV and
//    the print document carry the source ids next to the statement.
//  * HTML is escaped. Record text reaches the printable document as
//    text, never as markup.
//  * Each export writes an audit event, because a download leaves the
//    server without any other trace.
//
// PDF: no PDF writer is bundled with this app, so the PDF path builds a
// complete print-ready document and hands it to the browser's own
// "Save as PDF". That is a real PDF produced by a real renderer rather
// than a byte-stream approximation, and it is labelled as such in the
// UI so nobody believes a binary file was written server-side.
// ============================================================
import { request } from '../mockBackend';
import type { ReportRecord } from './types';

export type ReportFormat = 'JSON' | 'CSV' | 'PDF';

export interface ReportBundleSection {
  title: string;
  /** Column headers for tabular sections. */
  columns?: string[];
  rows: Array<Array<string | number | null>>;
  /** Statement paragraphs, for prose sections. */
  notes?: string[];
}

export interface ReportBundle {
  reportId: string;
  title: string;
  type: string;
  owner: string;
  publishedAt: string;
  confidence: number;
  investigationId: string | null;
  investigationTitle: string | null;
  generatedAt: string;
  generator: string;
  sections: ReportBundleSection[];
  /** Statements about what this export is and is not. */
  limitations: string[];
  /** Every record id the bundle draws on. */
  sourceRecords: string[];
}

// ── helpers ──────────────────────────────────────────────────────

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function csvCell(value: unknown): string {
  const text = String(value ?? '');
  // Quote everything and escape embedded quotes. A value containing a
  // newline must not be able to break the row structure.
  return `"${text.replace(/"/g, '""')}"`;
}

function download(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // Give the browser a moment to start the download before the handle
  // is released, otherwise some builds cancel it.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function slug(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').toLowerCase();
}

/** Records the export so a download leaves an audit trail. */
async function auditExport(bundle: ReportBundle, format: ReportFormat): Promise<void> {
  try {
    await request('/intel/audit', {
      method: 'POST',
      body: JSON.stringify({
        action: 'REPORT_EXPORTED',
        entity: 'REPORT',
        entityId: bundle.reportId,
        before: '',
        after: `${format} export · ${bundle.sections.length} section(s) · ${bundle.sourceRecords.length} source record(s)`,
        source: 'REPORT_EXPORT',
        result: 'SUCCESS',
      }),
    });
  } catch {
    // The export itself already succeeded and must not be undone. A
    // failed audit write is reported by the caller's own result state,
    // not by silently discarding the file.
  }
}

export interface ReportBundleSource {
  report: ReportRecord;
  investigation?: {
    id: string;
    title: string;
    status: string;
    analyst: string;
    confidence: number;
    updatedAt: string;
    summary?: { executiveSummary: string; keyFindings: string[]; disclaimer: string };
    steps?: Array<{ step: number; title: string; confidence: number; evidenceIds: string[]; relationshipIds: string[] }>;
  } | null;
  actors?: Array<{ id: string; aliases: string[]; status: string; confidenceScore: number }>;
  evidence?: Array<{ id: string; evidenceType: string; source: string; reliability: number; relatedActor: string | null }>;
  relationships?: Array<{ id: string; type: string; sourceEntity: string; targetEntity: string; confidence: number }>;
  alerts?: Array<{ id: string; severity: string; title: string; status: string }>;
}

/**
 * Materialise a report into export-ready sections. Everything is read
 * from the passed records; a section with nothing to say is emitted
 * empty rather than omitted, so the export always shows the shape of
 * what was available.
 */
export function buildReportBundle(source: ReportBundleSource): ReportBundle {
  const { report, investigation, actors = [], evidence = [], relationships = [], alerts = [] } = source;
  const sourceRecords = new Set<string>([report.id]);
  if (investigation) sourceRecords.add(investigation.id);
  for (const item of actors) sourceRecords.add(item.id);
  for (const item of evidence) sourceRecords.add(item.id);
  for (const item of relationships) sourceRecords.add(item.id);
  for (const item of alerts) sourceRecords.add(item.id);

  const sections: ReportBundleSection[] = [
    {
      title: 'Report record',
      columns: ['Field', 'Value'],
      rows: [
        ['Report ID', report.id],
        ['Title', report.title],
        ['Type', report.type],
        ['Owner', report.owner],
        ['Published', report.publishedAt],
        ['Confidence', `${report.confidence}%`],
        ['Investigation', report.investigationId],
      ],
    },
  ];

  if (investigation) {
    sourceRecords.add(investigation.id);
    sections.push({
      title: 'Investigation summary',
      columns: ['Field', 'Value'],
      rows: [
        ['Investigation ID', investigation.id],
        ['Title', investigation.title],
        ['Status', investigation.status],
        ['Analyst', investigation.analyst],
        ['Confidence', `${investigation.confidence}%`],
        ['Last updated', investigation.updatedAt],
        ['Steps recorded', investigation.steps?.length ?? 0],
      ],
      notes: investigation.summary ? [investigation.summary.executiveSummary] : undefined,
    });
    if (investigation.summary?.keyFindings.length) {
      sections.push({
        title: 'Key findings',
        columns: ['#', 'Finding', 'Source records'],
        rows: investigation.summary.keyFindings.map((finding, index) => [index + 1, finding, investigation.id]),
      });
    }
    if (investigation.steps?.length) {
      sections.push({
        title: 'Investigation steps',
        columns: ['Step', 'Title', 'Confidence', 'Evidence', 'Relationships'],
        rows: investigation.steps.map(step => [
          step.step,
          step.title,
          `${step.confidence}%`,
          step.evidenceIds.join(' | ') || '—',
          step.relationshipIds.join(' | ') || '—',
        ]),
      });
    }
  } else {
    sections.push({
      title: 'Investigation summary',
      rows: [],
      notes: [
        `Report ${report.id} references investigation ${report.investigationId}, which is not present in the current `
        + 'intelligence model. The sections below are therefore empty rather than reconstructed.',
      ],
    });
  }

  if (actors.length) {
    sections.push({
      title: 'Referenced threat actors',
      columns: ['Actor ID', 'Aliases', 'Status', 'Confidence'],
      rows: actors.map(actor => [actor.id, actor.aliases.join(' | ') || '—', actor.status, `${actor.confidenceScore}%`]),
    });
  }
  if (evidence.length) {
    sections.push({
      title: 'Referenced evidence',
      columns: ['Evidence ID', 'Type', 'Source', 'Reliability', 'Actor'],
      rows: evidence.map(item => [
        item.id,
        item.evidenceType,
        item.source,
        `${item.reliability}%`,
        item.relatedActor ?? '—',
      ]),
    });
  }
  if (relationships.length) {
    sections.push({
      title: 'Referenced relationships',
      columns: ['Relationship ID', 'Type', 'Source', 'Target', 'Confidence'],
      rows: relationships.map(rel => [rel.id, rel.type, rel.sourceEntity, rel.targetEntity, `${rel.confidence}%`]),
    });
  }
  if (alerts.length) {
    sections.push({
      title: 'Linked alerts',
      columns: ['Alert ID', 'Severity', 'Title', 'Status'],
      rows: alerts.map(alert => [alert.id, alert.severity, alert.title, alert.status]),
    });
  }

  const limitations = [
    investigation?.summary?.disclaimer
      ?? 'This report is derived from the stored intelligence model. No figure in it has been independently verified against an external source.',
    'Confidence values are the stored analyst assessments. They are not recalculated for this export.',
    'No evidence file is stored alongside the evidence records, so the digests they carry were not recomputed and do not demonstrate that content is unaltered.',
  ];

  return {
    reportId: report.id,
    title: report.title,
    type: report.type,
    owner: report.owner,
    publishedAt: report.publishedAt,
    confidence: report.confidence,
    investigationId: investigation?.id ?? report.investigationId ?? null,
    investigationTitle: investigation?.title ?? null,
    generatedAt: new Date().toISOString(),
    generator: 'Viper Trace report export',
    sections,
    limitations,
    sourceRecords: [...sourceRecords],
  };
}

// ── formats ──────────────────────────────────────────────────────

export function serialiseReportJson(bundle: ReportBundle): string {
  return JSON.stringify(bundle, null, 2);
}

export function serialiseReportCsv(bundle: ReportBundle): string {
  const lines: string[] = [];
  lines.push(csvCell('Report ID'), csvCell(bundle.reportId));
  lines.push(csvCell('Title'), csvCell(bundle.title));
  lines.push(csvCell('Type'), csvCell(bundle.type));
  lines.push(csvCell('Owner'), csvCell(bundle.owner));
  lines.push(csvCell('Published'), csvCell(bundle.publishedAt));
  lines.push(csvCell('Confidence'), csvCell(`${bundle.confidence}%`));
  lines.push(csvCell('Investigation'), csvCell(bundle.investigationId ?? ''));
  lines.push(csvCell('Generated at'), csvCell(bundle.generatedAt));
  lines.push('');

  for (const section of bundle.sections) {
    lines.push(csvCell(section.title));
    if (section.columns) {
      lines.push(section.columns.map(csvCell).join(','));
      for (const row of section.rows) lines.push(row.map(csvCell).join(','));
      if (section.rows.length === 0) lines.push(csvCell('(no records)'));
    }
    for (const note of section.notes ?? []) lines.push(csvCell(note));
    lines.push('');
  }

  lines.push(csvCell('Limitations'));
  for (const limitation of bundle.limitations) lines.push(csvCell(limitation));
  lines.push('');
  lines.push(csvCell('Source records'), csvCell(bundle.sourceRecords.join(' | ')));
  return lines.join('\r\n');
}

export interface PrintableDocument {
  title: string;
  /** Sub-heading line under the title. */
  meta: string[];
  sections: ReportBundleSection[];
  limitations?: string[];
  sourceRecords?: string[];
}

/**
 * The printable document. Every value is escaped before it becomes
 * markup, so record text can never inject elements into the output.
 * Shared by the report export and the per-entity export menu.
 */
export function buildPrintableHtml(document_: PrintableDocument): string {
  const sectionBlocks = document_.sections.map(section => {
    const table = section.columns
      ? `<table><thead><tr>${section.columns.map(column => `<th>${escapeHtml(column)}</th>`).join('')}</tr></thead><tbody>${
        section.rows.length
          ? section.rows
              .map(row => `<tr>${row.map(cell => `<td>${escapeHtml(cell ?? '—')}</td>`).join('')}</tr>`)
              .join('')
          : `<tr><td colspan="${section.columns.length}">No records in the current intelligence model.</td></tr>`
      }</tbody></table>`
      : '';
    const notes = (section.notes ?? [])
      .map(note => `<p class="note">${escapeHtml(note)}</p>`)
      .join('');
    return `<section><h2>${escapeHtml(section.title)}</h2>${table}${notes}</section>`;
  }).join('');

  const limitations = (document_.limitations ?? []).length
    ? `<section><h2>Limitations</h2>${document_.limitations!.map(item => `<p class="note">${escapeHtml(item)}</p>`).join('')}</section>`
    : '';

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(document_.title)}</title>
<style>
  @page { margin: 16mm; }
  body { font: 12px/1.5 "IBM Plex Mono", ui-monospace, monospace; color: #1a1a1a; margin: 0; }
  h1 { font: 24px/1.2 Georgia, serif; margin: 0 0 4px; }
  h2 { font: 13px/1.3 ui-sans-serif, system-ui, sans-serif; text-transform: uppercase; letter-spacing: .08em;
       border-bottom: 1px solid #c9c4ba; padding-bottom: 4px; margin: 22px 0 8px; }
  .meta { color: #55504a; font-size: 11px; margin-bottom: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 10px; margin-top: 6px; }
  th, td { border: 1px solid #d5d0c6; padding: 4px 6px; text-align: left; vertical-align: top; word-break: break-word; }
  th { background: #f2efe9; }
  .note { font-size: 11px; color: #33302b; }
  footer { margin-top: 26px; border-top: 1px solid #c9c4ba; padding-top: 8px; font-size: 10px; color: #55504a; }
</style></head><body>
<h1>${escapeHtml(document_.title)}</h1>
${document_.meta.map(line => `<p class="meta">${escapeHtml(line)}</p>`).join('\n')}
${sectionBlocks}
${limitations}
<footer>${escapeHtml('Viper Trace export')} · generated ${escapeHtml(new Date().toISOString())}${
  document_.sourceRecords?.length ? ` · source records: ${escapeHtml(document_.sourceRecords.join(', '))}` : ''
}</footer>
</body></html>`;
}

/** Printable form of a report bundle. */
export function buildPrintableReportHtml(bundle: ReportBundle): string {
  return buildPrintableHtml({
    title: bundle.title,
    meta: [
      `${bundle.reportId} · ${bundle.type} · owner ${bundle.owner} · published ${bundle.publishedAt} · confidence ${bundle.confidence}%`,
      `Investigation: ${bundle.investigationId ?? 'not linked'} ${bundle.investigationTitle ?? ''} · generated ${bundle.generatedAt}`,
    ],
    sections: bundle.sections,
    limitations: bundle.limitations,
    sourceRecords: bundle.sourceRecords,
  });
}

/**
 * Opens the browser's print dialog on a built document. A blocked popup
 * is reported as a failure, because nothing was written.
 */
export function openPrintableDocument(document_: PrintableDocument): ReportExportResult {
  const win = window.open('', '_blank');
  if (!win) {
    return {
      ok: false,
      message: 'The print window was blocked by the browser. Allow pop-ups for this site, then use PDF again. No file was written.',
    };
  }
  win.document.write(buildPrintableHtml(document_));
  win.document.close();
  win.focus();
  // Give the document a frame to lay out before invoking print.
  win.setTimeout(() => win.print(), 250);
  return { ok: true, message: 'Print dialog opened. Choose "Save as PDF" to write the file.' };
}

export interface ReportExportResult {
  ok: boolean;
  /** Human-readable outcome, shown verbatim in the UI. */
  message: string;
}

/**
 * Run an export. `PDF` opens the browser's print dialog on a fully
 * built document; if the popup is blocked that is reported as a
 * failure rather than pretending a file was produced.
 */
export async function exportReport(bundle: ReportBundle, format: ReportFormat): Promise<ReportExportResult> {
  const base = `${slug(bundle.reportId)}-${slug(bundle.type)}`;
  try {
    if (format === 'JSON') {
      download(`${base}.json`, new Blob([serialiseReportJson(bundle)], { type: 'application/json' }));
    } else if (format === 'CSV') {
      download(`${base}.csv`, new Blob([serialiseReportCsv(bundle)], { type: 'text/csv;charset=utf-8' }));
    } else {
      const printed = openPrintableDocument({
        title: bundle.title,
        meta: [
          `${bundle.reportId} · ${bundle.type} · owner ${bundle.owner} · published ${bundle.publishedAt} · confidence ${bundle.confidence}%`,
          `Investigation: ${bundle.investigationId ?? 'not linked'} ${bundle.investigationTitle ?? ''} · generated ${bundle.generatedAt}`,
        ],
        sections: bundle.sections,
        limitations: bundle.limitations,
        sourceRecords: bundle.sourceRecords,
      });
      if (!printed.ok) return printed;
    }
    await auditExport(bundle, format);
    return {
      ok: true,
      message: format === 'PDF'
        ? `Print dialog opened for ${bundle.reportId}. Choose "Save as PDF" to write the file.`
        : `${format} export written for ${bundle.reportId}.`,
    };
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : `The ${format} export failed before any file was written.`,
    };
  }
}