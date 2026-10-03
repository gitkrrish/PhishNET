import { useState } from 'react';
import { dw } from '../../lib/darkweb/styles';
import { FileJson, FileText, Table } from 'lucide-react';
import { generateInvestigationSummary } from '../../lib/darkweb/aiEngine';
import { useIntelligenceData } from '../../lib/intelligence/IntelligenceContext';
import { openPrintableDocument, type PrintableDocument } from '../../lib/intelligence/reportExport';

interface ExportMenuProps {
  type: 'investigation' | 'actors' | 'evidence' | 'relationships';
  id: string;
}

const TYPE_LABEL: Record<ExportMenuProps['type'], string> = {
  investigation: 'Investigation',
  actors: 'Threat actor',
  evidence: 'Evidence item',
  relationships: 'Relationship',
};

export function ExportMenu({ type, id }: ExportMenuProps) {
  const { darkWebInvestigationById, darkWebActors, darkWebEvidenceById, darkWebRelationshipsById } = useIntelligenceData();
  const [status, setStatus] = useState<string | null>(null);

  const csvEscape = (value: string) => `"${value.replace(/"/g, '""')}"`;

  function download(filename: string, blob: Blob) {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const exportJSON = () => {
    let data: unknown;
    if (type === 'investigation') {
      data = generateInvestigationSummary(id).detail;
    } else if (type === 'actors') {
      data = darkWebActors.find(actor => actor.id === id) ?? null;
    } else if (type === 'evidence') {
      data = darkWebEvidenceById[id] ?? null;
    } else {
      data = darkWebRelationshipsById[id] ?? null;
    }
    if (data === null) {
      // Nothing is written when the record is not in the model. A file
      // containing "null" would look like an exported record.
      setStatus(`${id} is not present in the current intelligence model, so no ${type} export was written.`);
      return;
    }
    download(`${id}-${type}.json`, new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    setStatus(`JSON written for ${id}.`);
  };

  const exportCSV = () => {
    let rows: string[];
    if (type === 'investigation') {
      const inv = darkWebInvestigationById[id];
      rows = ['Step,Title,Confidence,Evidence,Relationships'];
      if (inv) inv.steps.forEach(step => { rows.push([step.step, csvEscape(step.title), step.confidence, step.evidenceIds.length, step.relationshipIds.length].join(',')); });
    } else if (type === 'actors') {
      const actor = darkWebActors.find(item => item.id === id);
      rows = ['id,aliases,status,confidence,handles,pgpFingerprints,walletAddrs'];
      if (actor) {
        rows.push([
          actor.id,
          csvEscape(actor.aliases.join(' | ')),
          actor.status,
          actor.confidenceScore,
          csvEscape(actor.handles.join(' | ')),
          csvEscape(actor.pgpFingerprints.join(' | ')),
          csvEscape(actor.walletAddrs.join(' | ')),
        ].join(','));
      }
    } else if (type === 'evidence') {
      const ev = darkWebEvidenceById[id];
      rows = ['id,evidenceType,source,provenance,reliability,timestamp,collectionTimestamp,relatedActor'];
      if (ev) {
        rows.push([
          ev.id,
          ev.evidenceType,
          csvEscape(ev.source),
          csvEscape(ev.provenance),
          ev.reliability,
          ev.timestamp,
          ev.collectionTimestamp,
          csvEscape(ev.relatedActor ?? ''),
        ].join(','));
      }
    } else {
      const rel = darkWebRelationshipsById[id];
      rows = ['id,type,sourceEntity,targetEntity,confidence,firstObserved,lastObserved,evidenceIds'];
      if (rel) {
        rows.push([
          rel.id,
          rel.type,
          rel.sourceEntity,
          rel.targetEntity,
          rel.confidence,
          rel.firstObserved,
          rel.lastObserved,
          csvEscape(rel.evidenceIds.join(' | ')),
        ].join(','));
      }
    }
    download(`${id}-${type}.csv`, new Blob([rows.join('\r\n')], { type: 'text/csv;charset=utf-8' }));
    setStatus(`CSV written for ${id}.`);
  };

  /** Real printable content for every type, so PDF never falls back to CSV. */
  const printableFor = (): PrintableDocument | null => {
    if (type === 'investigation') {
      const inv = darkWebInvestigationById[id];
      if (!inv) return null;
      const { detail } = generateInvestigationSummary(id);
      return {
        title: `Investigation Dossier — ${inv.title}`,
        meta: [`${inv.id} · ${inv.status} · analyst ${inv.analyst} · confidence ${inv.confidence}%`, `Last updated ${inv.updatedAt}`],
        sections: [
          {
            title: 'Executive summary',
            rows: [],
            notes: [detail.executiveSummary],
          },
          {
            title: 'Key findings',
            columns: ['#', 'Finding'],
            rows: detail.keyFindings.map((finding, i) => [i + 1, finding]),
          },
          {
            title: 'Confidence breakdown',
            columns: ['Factor', 'Value'],
            rows: detail.confidenceBreakdown.map(factor => [factor.label, `${factor.value}%`]),
          },
          {
            title: 'Investigation steps',
            columns: ['Step', 'Title', 'Confidence', 'Evidence', 'Relationships'],
            rows: inv.steps.map(step => [
              step.step,
              step.title,
              `${step.confidence}%`,
              step.evidenceIds.join(' | ') || '—',
              step.relationshipIds.join(' | ') || '—',
            ]),
          },
        ],
        limitations: [detail.disclaimer],
        sourceRecords: [inv.id, ...inv.steps.flatMap(step => [...step.evidenceIds, ...step.relationshipIds])],
      };
    }

    if (type === 'actors') {
      const actor = darkWebActors.find(item => item.id === id);
      if (!actor) return null;
      return {
        title: `Threat Actor Profile — ${actor.aliases[0] ?? actor.id}`,
        meta: [`${actor.id} · ${actor.status} · confidence ${actor.confidenceScore}%`, `First seen ${actor.firstSeen} · last seen ${actor.lastSeen}`],
        sections: [
          {
            title: 'Identity',
            columns: ['Field', 'Value'],
            rows: [
              ['Aliases', actor.aliases.join(' | ')],
              ['Handles', actor.handles.join(' | ')],
              ['PGP fingerprints', actor.pgpFingerprints.join(' | ') || '—'],
              ['Wallets', actor.walletAddrs.join(' | ') || '—'],
              ['Domains', actor.domains.join(' | ') || '—'],
              ['Platforms', actor.platforms.join(' | ')],
              ['Primary motivation', actor.primaryMotivation],
            ],
          },
          {
            title: 'Behavioural profile',
            columns: ['Field', 'Value'],
            rows: [
              ['Activity frequency', actor.behavioralProfile.activityFrequency],
              ['Topic clusters', actor.behavioralProfile.topicClusters.join(' | ')],
              ['Interaction pattern', actor.behavioralProfile.interactionPattern],
              ['Persona transitions', String(actor.behavioralProfile.personaTransitions)],
            ],
          },
          {
            title: 'Associated evidence',
            columns: ['Evidence ID'],
            rows: actor.associatedEvidence.map(item => [item]),
          },
        ],
        limitations: ['Confidence is the stored analyst assessment and is not recalculated for this export.'],
        sourceRecords: [actor.id, ...actor.associatedEvidence],
      };
    }

    if (type === 'evidence') {
      const item = darkWebEvidenceById[id];
      if (!item) return null;
      return {
        title: `Evidence Record — ${item.id}`,
        meta: [`${item.evidenceType} · source ${item.source} · reliability ${item.reliability}% · confidence ${item.confidence}%`],
        sections: [
          {
            title: 'Record',
            columns: ['Field', 'Value'],
            rows: [
              ['Evidence ID', item.id],
              ['Type', item.evidenceType],
              ['Source', item.source],
              ['Source type', item.sourceType],
              ['Observed', item.timestamp],
              ['Collected', item.collectionTimestamp],
              ['Recorded digest', item.hash],
              ['Related actor', item.relatedActor ?? '—'],
              ['Related relationship', item.relatedRelationship ?? '—'],
            ],
            notes: [item.provenance],
          },
        ],
        limitations: [
          'No evidence file is stored alongside this record, so the digest above was not recomputed and does not demonstrate that the content is unaltered.',
        ],
        sourceRecords: [item.id],
      };
    }

    const rel = darkWebRelationshipsById[id];
    if (!rel) return null;
    return {
      title: `Relationship — ${rel.id}`,
      meta: [`${rel.type} · ${rel.sourceEntity} → ${rel.targetEntity} · confidence ${rel.confidence}%`],
      sections: [
        {
          title: 'Record',
          columns: ['Field', 'Value'],
          rows: [
            ['Relationship ID', rel.id],
            ['Type', rel.type],
            ['Source entity', rel.sourceEntity],
            ['Target entity', rel.targetEntity],
            ['Confidence', `${rel.confidence}%`],
            ['First observed', rel.firstObserved],
            ['Last observed', rel.lastObserved],
            ['Supporting evidence', rel.evidenceIds.join(' | ') || '—'],
          ],
        },
      ],
      limitations: ['A recorded relationship is an analyst assessment stored in the model, not an independently verified fact.'],
      sourceRecords: [rel.id, ...rel.evidenceIds],
    };
  };

  const exportPDF = () => {
    const printable = printableFor();
    if (!printable) {
      // Previously this path silently downloaded a CSV. A missing record
      // is now reported instead of passing off another format as a PDF.
      setStatus(`${id} is not present in the current intelligence model, so no PDF was produced.`);
      return;
    }
    const result = openPrintableDocument(printable);
    setStatus(`${result.message} (${TYPE_LABEL[type]} ${id})`);
  };

  return (
    <div className="inline-flex flex-col items-start gap-1">
      <div className="inline-flex items-center gap-1">
        <button onClick={exportJSON} className="font-mono text-[9px] px-2 py-1 rounded-sm border flex items-center gap-1" type="button"
          style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }} title="Export JSON"><FileJson size={10} /> JSON</button>
        <button onClick={exportCSV} className="font-mono text-[9px] px-2 py-1 rounded-sm border flex items-center gap-1" type="button"
          style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }} title="Export CSV"><Table size={10} /> CSV</button>
        <button onClick={exportPDF} className="font-mono text-[9px] px-2 py-1 rounded-sm border flex items-center gap-1" type="button"
          style={{ backgroundColor: 'var(--tw-panel-alt)', borderColor: 'var(--tw-border-mid)', color: 'var(--tw-text-muted)' }} title="Open the print dialog on a generated document"><FileText size={10} /> PDF</button>
      </div>
      {status && <span className="font-mono text-[9px]" style={dw.faint}>{status}</span>}
    </div>
  );
}