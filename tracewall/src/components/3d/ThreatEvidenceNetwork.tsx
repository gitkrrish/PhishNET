import { useEffect, useMemo, useRef, useState } from 'react';
import { useThreeD, useRenderingQuality } from '../../context/ThreeDContext';
import { ThreeDErrorBoundary } from './ThreeDErrorBoundary';

// ============================================================================
// TYPES
// ============================================================================

export type NodeType = 
  | 'email' 
  | 'sender' 
  | 'replyTo' 
  | 'domain' 
  | 'lookalikeDomain' 
  | 'ip' 
  | 'relayServer' 
  | 'url' 
  | 'attachmentHash' 
  | 'threatIntel' 
  | 'darkWebExposure' 
  | 'campaign' 
  | 'case' 
  | 'responseAction' 
  | 'file' 
  | 'ioc' 
  | 'infrastructure' 
  | 'maskedIdentity';

export interface EvidenceNode {
  id: string;
  type: NodeType;
  label: string;
  x: number;
  y: number;
  z: number;
  severity?: 'neutral' | 'verified' | 'suspicious' | 'highRisk' | 'resolved';
  tooltip?: string;
}

export interface EvidenceEdge {
  source: string;
  target: string;
  label?: string;
}

export interface PageSpecificData {
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
  primaryRelationship: string;
}

// ============================================================================
// PAGE-SPECIFIC DATA GENERATORS
// ============================================================================

export function getDashboardData(): PageSpecificData {
  return {
    primaryRelationship: 'Threat activity → Cases → Response',
    nodes: [
      { id: 'org', type: 'campaign', label: 'ORGANIZATION', x: 0, y: 0, z: 0, severity: 'neutral' },
      { id: 'campaign1', type: 'campaign', label: 'ACTIVE CAMPAIGN', x: -60, y: -30, z: 20, severity: 'highRisk' },
      { id: 'campaign2', type: 'campaign', label: 'SECONDARY', x: 60, y: -30, z: -20, severity: 'suspicious' },
      { id: 'case1', type: 'case', label: 'OPEN CASE', x: -60, y: 30, z: -20, severity: 'highRisk' },
      { id: 'case2', type: 'case', label: 'PENDING', x: 60, y: 30, z: 20, severity: 'suspicious' },
      { id: 'exposure', type: 'darkWebExposure', label: 'EXPOSURE', x: 0, y: 50, z: 0, severity: 'highRisk' },
      { id: 'response', type: 'responseAction', label: 'RESPONSE', x: 0, y: -50, z: 0, severity: 'resolved' },
    ],
    edges: [
      { source: 'org', target: 'campaign1' },
      { source: 'org', target: 'campaign2' },
      { source: 'campaign1', target: 'case1' },
      { source: 'campaign2', target: 'case2' },
      { source: 'case1', target: 'exposure' },
      { source: 'case1', target: 'response' },
      { source: 'case2', target: 'response' },
    ],
  };
}

export function getEmailAnalysisData(): PageSpecificData {
  return {
    primaryRelationship: 'Email → Headers → Relay → Infrastructure → Verdict',
    nodes: [
      { id: 'email', type: 'email', label: 'SUSPICIOUS EMAIL', x: 0, y: 0, z: 0, severity: 'highRisk' },
      { id: 'sender', type: 'sender', label: 'SENDER', x: -70, y: -30, z: 30, severity: 'suspicious' },
      { id: 'replyTo', type: 'replyTo', label: 'REPLY-TO', x: 70, y: -30, z: -30, severity: 'suspicious' },
      { id: 'domain', type: 'domain', label: 'DOMAIN', x: -70, y: 30, z: -30, severity: 'suspicious' },
      { id: 'lookalike', type: 'lookalikeDomain', label: 'LOOKALIKE', x: 70, y: 30, z: 30, severity: 'highRisk' },
      { id: 'relay1', type: 'relayServer', label: 'RELAY 1', x: -100, y: 0, z: 0, severity: 'verified' },
      { id: 'relay2', type: 'relayServer', label: 'RELAY 2', x: 100, y: 0, z: 0, severity: 'verified' },
      { id: 'ip', type: 'ip', label: 'IP ADDRESS', x: 0, y: 60, z: 0, severity: 'suspicious' },
      { id: 'url', type: 'url', label: 'SUSPICIOUS URL', x: 0, y: -60, z: 0, severity: 'highRisk' },
    ],
    edges: [
      { source: 'email', target: 'sender' },
      { source: 'email', target: 'replyTo' },
      { source: 'sender', target: 'domain' },
      { source: 'replyTo', target: 'lookalike' },
      { source: 'email', target: 'relay1' },
      { source: 'relay1', target: 'relay2' },
      { source: 'relay2', target: 'ip' },
      { source: 'email', target: 'url' },
    ],
  };
}

export function getFileAnalysisData(): PageSpecificData {
  return {
    primaryRelationship: 'File → Hash → Indicators → Verdict',
    nodes: [
      { id: 'file', type: 'file', label: 'UPLOADED FILE', x: 0, y: 0, z: 0, severity: 'highRisk' },
      { id: 'hash', type: 'attachmentHash', label: 'FILE HASH', x: -60, y: -30, z: 20, severity: 'neutral' },
      { id: 'metadata', type: 'ioc', label: 'METADATA', x: 60, y: -30, z: -20, severity: 'neutral' },
      { id: 'url', type: 'url', label: 'EMBEDDED URL', x: -60, y: 30, z: -20, severity: 'suspicious' },
      { id: 'macro', type: 'ioc', label: 'MACRO INDICATOR', x: 60, y: 30, z: 20, severity: 'highRisk' },
      { id: 'verdict', type: 'responseAction', label: 'THREAT VERDICT', x: 0, y: 60, z: 0, severity: 'highRisk' },
    ],
    edges: [
      { source: 'file', target: 'hash' },
      { source: 'file', target: 'metadata' },
      { source: 'file', target: 'url' },
      { source: 'file', target: 'macro' },
      { source: 'macro', target: 'verdict' },
      { source: 'url', target: 'verdict' },
    ],
  };
}

export function getUrlAnalysisData(): PageSpecificData {
  return {
    primaryRelationship: 'URL → Redirect → Domain → Infrastructure → Risk',
    nodes: [
      { id: 'url', type: 'url', label: 'SUBMITTED URL', x: 0, y: 0, z: 0, severity: 'highRisk' },
      { id: 'redirect1', type: 'url', label: 'REDIRECT 1', x: -50, y: -30, z: 20, severity: 'suspicious' },
      { id: 'redirect2', type: 'url', label: 'REDIRECT 2', x: 50, y: -30, z: -20, severity: 'suspicious' },
      { id: 'domain', type: 'domain', label: 'FINAL DOMAIN', x: 0, y: -60, z: 0, severity: 'highRisk' },
      { id: 'hosting', type: 'infrastructure', label: 'HOSTING', x: -60, y: 30, z: -20, severity: 'suspicious' },
      { id: 'reputation', type: 'threatIntel', label: 'REPUTATION', x: 60, y: 30, z: 20, severity: 'highRisk' },
      { id: 'verdict', type: 'responseAction', label: 'THREAT VERDICT', x: 0, y: 60, z: 0, severity: 'highRisk' },
    ],
    edges: [
      { source: 'url', target: 'redirect1' },
      { source: 'redirect1', target: 'redirect2' },
      { source: 'redirect2', target: 'domain' },
      { source: 'domain', target: 'hosting' },
      { source: 'domain', target: 'reputation' },
      { source: 'reputation', target: 'verdict' },
    ],
  };
}

export function getInfrastructureData(): PageSpecificData {
  return {
    primaryRelationship: 'Domain → IP → Provider → Related Threats',
    nodes: [
      { id: 'domain', type: 'domain', label: 'DOMAIN', x: 0, y: 0, z: 0, severity: 'suspicious' },
      { id: 'ip', type: 'ip', label: 'IP ADDRESS', x: -60, y: -30, z: 20, severity: 'suspicious' },
      { id: 'asn', type: 'infrastructure', label: 'ASN', x: 60, y: -30, z: -20, severity: 'neutral' },
      { id: 'hosting', type: 'infrastructure', label: 'HOSTING', x: -60, y: 30, z: -20, severity: 'suspicious' },
      { id: 'relatedUrl', type: 'url', label: 'RELATED URL', x: 60, y: 30, z: 20, severity: 'highRisk' },
      { id: 'relatedEmail', type: 'email', label: 'RELATED EMAIL', x: 0, y: 60, z: 0, severity: 'suspicious' },
    ],
    edges: [
      { source: 'domain', target: 'ip' },
      { source: 'ip', target: 'asn' },
      { source: 'ip', target: 'hosting' },
      { source: 'domain', target: 'relatedUrl' },
      { source: 'domain', target: 'relatedEmail' },
    ],
  };
}

export function getDarkWebData(): PageSpecificData {
  return {
    primaryRelationship: 'Masked Identity → Exposure → Case → Remediation',
    nodes: [
      { id: 'identity', type: 'maskedIdentity', label: 'MASKED IDENTITY', x: 0, y: 0, z: 0, severity: 'neutral' },
      { id: 'exposure', type: 'darkWebExposure', label: 'EXPOSURE RECORD', x: -60, y: -30, z: 20, severity: 'highRisk' },
      { id: 'domain', type: 'domain', label: 'RELATED DOMAIN', x: 60, y: -30, z: -20, severity: 'suspicious' },
      { id: 'status', type: 'case', label: 'CREDENTIAL STATUS', x: -60, y: 30, z: -20, severity: 'highRisk' },
      { id: 'case', type: 'case', label: 'AFFECTED CASE', x: 60, y: 30, z: 20, severity: 'suspicious' },
      { id: 'remediation', type: 'responseAction', label: 'REMEDIATION', x: 0, y: 60, z: 0, severity: 'resolved' },
    ],
    edges: [
      { source: 'identity', target: 'exposure' },
      { source: 'exposure', target: 'domain' },
      { source: 'exposure', target: 'status' },
      { source: 'exposure', target: 'case' },
      { source: 'case', target: 'remediation' },
    ],
  };
}

export function getIntelligenceData(): PageSpecificData {
  return {
    primaryRelationship: 'IOC → Correlation → Campaign → Defensive Action',
    nodes: [
      { id: 'ioc', type: 'ioc', label: 'INDICATOR', x: 0, y: 0, z: 0, severity: 'suspicious' },
      { id: 'email', type: 'email', label: 'RELATED EMAIL', x: -60, y: -30, z: 20, severity: 'suspicious' },
      { id: 'domain', type: 'domain', label: 'DOMAIN', x: 60, y: -30, z: -20, severity: 'suspicious' },
      { id: 'ip', type: 'ip', label: 'IP ADDRESS', x: -60, y: 30, z: -20, severity: 'suspicious' },
      { id: 'url', type: 'url', label: 'URL', x: 60, y: 30, z: 20, severity: 'highRisk' },
      { id: 'campaign', type: 'campaign', label: 'CAMPAIGN', x: 0, y: 60, z: 0, severity: 'highRisk' },
      { id: 'action', type: 'responseAction', label: 'DEFENSIVE ACTION', x: 0, y: -60, z: 0, severity: 'resolved' },
    ],
    edges: [
      { source: 'ioc', target: 'email' },
      { source: 'ioc', target: 'domain' },
      { source: 'ioc', target: 'ip' },
      { source: 'ioc', target: 'url' },
      { source: 'email', target: 'campaign' },
      { source: 'domain', target: 'campaign' },
      { source: 'campaign', target: 'action' },
    ],
  };
}

export function getCampaignsData(): PageSpecificData {
  return {
    primaryRelationship: 'Campaign → Shared Infrastructure → Related Cases',
    nodes: [
      { id: 'campaign', type: 'campaign', label: 'CAMPAIGN CLUSTER', x: 0, y: 0, z: 0, severity: 'highRisk' },
      { id: 'email1', type: 'email', label: 'EMAIL 1', x: -70, y: -30, z: 20, severity: 'suspicious' },
      { id: 'email2', type: 'email', label: 'EMAIL 2', x: 70, y: -30, z: -20, severity: 'suspicious' },
      { id: 'domain', type: 'domain', label: 'SHARED DOMAIN', x: -70, y: 30, z: -20, severity: 'highRisk' },
      { id: 'ip', type: 'ip', label: 'SHARED IP', x: 70, y: 30, z: 20, severity: 'suspicious' },
      { id: 'case1', type: 'case', label: 'CASE 1', x: -100, y: 0, z: 0, severity: 'suspicious' },
      { id: 'case2', type: 'case', label: 'CASE 2', x: 100, y: 0, z: 0, severity: 'suspicious' },
    ],
    edges: [
      { source: 'campaign', target: 'email1' },
      { source: 'campaign', target: 'email2' },
      { source: 'email1', target: 'domain' },
      { source: 'email2', target: 'domain' },
      { source: 'domain', target: 'ip' },
      { source: 'email1', target: 'case1' },
      { source: 'email2', target: 'case2' },
    ],
  };
}

export function getCasesData(): PageSpecificData {
  return {
    primaryRelationship: 'Case → Evidence → Assessment → Response',
    nodes: [
      { id: 'case', type: 'case', label: 'INVESTIGATION CASE', x: 0, y: 0, z: 0, severity: 'suspicious' },
      { id: 'evidence1', type: 'email', label: 'EVIDENCE', x: -60, y: -30, z: 20, severity: 'neutral' },
      { id: 'evidence2', type: 'ioc', label: 'INDICATORS', x: 60, y: -30, z: -20, severity: 'suspicious' },
      { id: 'campaign', type: 'campaign', label: 'CAMPAIGN', x: -60, y: 30, z: -20, severity: 'highRisk' },
      { id: 'response', type: 'responseAction', label: 'RESPONSE', x: 60, y: 30, z: 20, severity: 'resolved' },
      { id: 'chain', type: 'case', label: 'CHAIN OF CUSTODY', x: 0, y: 60, z: 0, severity: 'verified' },
    ],
    edges: [
      { source: 'case', target: 'evidence1' },
      { source: 'case', target: 'evidence2' },
      { source: 'evidence2', target: 'campaign' },
      { source: 'case', target: 'response' },
      { source: 'evidence1', target: 'chain' },
    ],
  };
}

export function getReportsData(): PageSpecificData {
  return {
    primaryRelationship: 'Evidence → Findings → Report → Approval',
    nodes: [
      { id: 'report', type: 'case', label: 'REPORT', x: 0, y: 0, z: 0, severity: 'neutral' },
      { id: 'evidence', type: 'ioc', label: 'EVIDENCE', x: -60, y: -30, z: 20, severity: 'neutral' },
      { id: 'findings', type: 'case', label: 'FINDINGS', x: 60, y: -30, z: -20, severity: 'suspicious' },
      { id: 'case', type: 'case', label: 'CASE', x: -60, y: 30, z: -20, severity: 'suspicious' },
      { id: 'timeline', type: 'case', label: 'TIMELINE', x: 60, y: 30, z: 20, severity: 'neutral' },
      { id: 'approval', type: 'responseAction', label: 'APPROVAL', x: 0, y: 60, z: 0, severity: 'verified' },
    ],
    edges: [
      { source: 'report', target: 'evidence' },
      { source: 'evidence', target: 'findings' },
      { source: 'findings', target: 'case' },
      { source: 'case', target: 'timeline' },
      { source: 'findings', target: 'approval' },
    ],
  };
}

export function getAlertsData(): PageSpecificData {
  return {
    primaryRelationship: 'Alert → Evidence → Case → Action',
    nodes: [
      { id: 'alert', type: 'campaign', label: 'ALERT', x: 0, y: 0, z: 0, severity: 'highRisk' },
      { id: 'category', type: 'ioc', label: 'THREAT CATEGORY', x: -60, y: -30, z: 20, severity: 'suspicious' },
      { id: 'email', type: 'email', label: 'RELATED EMAIL', x: 60, y: -30, z: -20, severity: 'suspicious' },
      { id: 'ioc', type: 'ioc', label: 'RELATED IOC', x: -60, y: 30, z: -20, severity: 'suspicious' },
      { id: 'case', type: 'case', label: 'CASE', x: 60, y: 30, z: 20, severity: 'suspicious' },
      { id: 'action', type: 'responseAction', label: 'RECOMMENDED ACTION', x: 0, y: 60, z: 0, severity: 'resolved' },
    ],
    edges: [
      { source: 'alert', target: 'category' },
      { source: 'alert', target: 'email' },
      { source: 'alert', target: 'ioc' },
      { source: 'email', target: 'case' },
      { source: 'ioc', target: 'case' },
      { source: 'case', target: 'action' },
    ],
  };
}

// ============================================================================
// 3D RENDERING COMPONENT
// ============================================================================

interface Camera3D {
  zoom: number;
  yaw: number;
  pitch: number;
  panX: number;
  panY: number;
}

function ThreatEvidenceNetwork3D({ data, pageType }: { data: PageSpecificData; pageType: NetworkPageType }) {
  const { enabled, performanceTier } = useThreeD();
  const quality = useRenderingQuality();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const cameraRef = useRef<Camera3D>({ zoom: 1, yaw: 0, pitch: 0, panX: 0, panY: 0 });
  const drawRef = useRef<(() => void) | null>(null);
  const dragRef = useRef({ active: false, mode: 'orbit' as 'orbit' | 'pan', x: 0, y: 0, moved: false });

  const colors: Record<string, string> = {
    neutral: '#657581',
    verified: '#596E5B',
    suspicious: '#A47535',
    highRisk: '#7E1D2F',
    resolved: '#596E5B',
  };

  useEffect(() => {
    if (!enabled || performanceTier === 'low' || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const resizeCanvas = () => {
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * quality.pixelRatio;
      canvas.height = rect.height * quality.pixelRatio;
      drawRef.current?.();
    };

    const project = (node: EvidenceNode) => {
      const camera = cameraRef.current;
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      const yaw = camera.yaw;
      const pitch = camera.pitch;
      const rotatedX = node.x * Math.cos(yaw) - node.z * Math.sin(yaw);
      const rotatedZ = node.x * Math.sin(yaw) + node.z * Math.cos(yaw);
      const projectedY = node.y * Math.cos(pitch) - rotatedZ * Math.sin(pitch);
      const depth = node.y * Math.sin(pitch) + rotatedZ * Math.cos(pitch);
      const perspective = 1 / Math.max(0.18, 1 + depth / 520);
      return {
        x: width / 2 + (rotatedX + camera.panX) * camera.zoom * perspective,
        y: height / 2 + (projectedY + camera.panY) * camera.zoom * perspective,
        scale: camera.zoom * perspective,
        depth,
      };
    };

    const draw = () => {
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      if (!width || !height) return;
      ctx.setTransform(quality.pixelRatio, 0, 0, quality.pixelRatio, 0, 0);
      ctx.clearRect(0, 0, width, height);
      const projected = new Map(data.nodes.map(node => [node.id, project(node)]));
      const connected = new Set(data.edges.filter(edge => edge.source === selectedNode || edge.target === selectedNode).flatMap(edge => [edge.source, edge.target]));

      ctx.fillStyle = 'rgba(101, 117, 129, 0.08)';
      ctx.beginPath();
      ctx.arc(width / 2, height / 2, Math.min(width, height) * 0.42, 0, Math.PI * 2);
      ctx.fill();

      data.edges.forEach(edge => {
        const source = projected.get(edge.source);
        const target = projected.get(edge.target);
        if (!source || !target) return;
        const active = selectedNode && connected.has(edge.source) && connected.has(edge.target);
        ctx.strokeStyle = active ? '#731F32' : 'rgba(101, 117, 129, 0.68)';
        ctx.lineWidth = active ? Math.max(2, source.scale * 2) : Math.max(1.2, source.scale * 0.9);
        ctx.setLineDash(active ? [] : [6, 5]);
        ctx.beginPath();
        ctx.moveTo(source.x, source.y);
        ctx.lineTo(target.x, target.y);
        ctx.stroke();
        ctx.setLineDash([]);
      });

      [...data.nodes].sort((a, b) => (projected.get(a.id)?.depth || 0) - (projected.get(b.id)?.depth || 0)).forEach(node => {
        const point = projected.get(node.id);
        if (!point) return;
        const color = colors[node.severity || 'neutral'];
        const primary = node === data.nodes[0];
        const active = !selectedNode || connected.has(node.id);
        const radius = Math.max(7, (primary ? 19 : 14) * Math.min(5, point.scale));
        ctx.globalAlpha = active ? 1 : 0.25;
        if (primary || hoveredNode === node.id || selectedNode === node.id) {
          ctx.fillStyle = `${color}32`;
          ctx.beginPath();
          ctx.arc(point.x, point.y, radius + 9, 0, Math.PI * 2);
          ctx.fill();
        }
        ctx.fillStyle = `${color}d9`;
        ctx.strokeStyle = selectedNode === node.id ? '#FBFAF6' : color;
        ctx.lineWidth = selectedNode === node.id ? 3 : 1.5;
        ctx.beginPath();
        ctx.arc(point.x, point.y, radius, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#FBFAF6';
        ctx.font = `${Math.max(8, Math.min(13, 9 * Math.min(2.5, point.scale)))}px "IBM Plex Mono", monospace`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(node.label.slice(0, 18), point.x, point.y - 1);
        ctx.fillStyle = color;
        ctx.font = '8px "IBM Plex Mono", monospace';
        ctx.fillText(node.type.toUpperCase(), point.x, point.y + radius + 11);
        ctx.globalAlpha = 1;
      });
    };

    drawRef.current = draw;
    resizeCanvas();

    const resizeObserver = new ResizeObserver(resizeCanvas);
    resizeObserver.observe(canvas);

    return () => {
      resizeObserver.disconnect();
      drawRef.current = null;
    };
  }, [enabled, performanceTier, quality.pixelRatio, data, hoveredNode, selectedNode]);

  if (!enabled) {
    return null;
  }

  const selected = data.nodes.find(node => node.id === selectedNode);
  const focusSelected = () => {
    if (!selected) return;
    cameraRef.current = { ...cameraRef.current, zoom: 3.5, panX: -selected.x, panY: -selected.y };
    drawRef.current?.();
  };
  const resetCamera = () => {
    cameraRef.current = { zoom: 1, yaw: 0, pitch: 0, panX: 0, panY: 0 };
    setSelectedNode(null);
    drawRef.current?.();
  };

  return (
    <div className="relative h-full w-full">
      <canvas
        ref={canvasRef}
        className="w-full h-full cursor-grab active:cursor-grabbing"
        style={{ display: 'block' }}
        onContextMenu={event => event.preventDefault()}
        onWheel={event => {
          event.preventDefault();
          const factor = event.deltaY < 0 ? 1.18 : 0.84;
          cameraRef.current.zoom = Math.max(0.04, cameraRef.current.zoom * factor);
          drawRef.current?.();
        }}
        onPointerDown={event => {
          dragRef.current = { active: true, mode: event.shiftKey || event.button === 2 ? 'pan' : 'orbit', x: event.clientX, y: event.clientY, moved: false };
          canvasRef.current?.setPointerCapture(event.pointerId);
        }}
        onPointerMove={event => {
          if (!canvasRef.current) return;
          const drag = dragRef.current;
          if (drag.active) {
            const dx = event.clientX - drag.x;
            const dy = event.clientY - drag.y;
            if (Math.abs(dx) + Math.abs(dy) > 2) drag.moved = true;
            if (drag.mode === 'orbit') {
              cameraRef.current.yaw += dx * 0.008;
              cameraRef.current.pitch = Math.max(-1.45, Math.min(1.45, cameraRef.current.pitch + dy * 0.008));
            } else {
              cameraRef.current.panX += dx / Math.max(0.04, cameraRef.current.zoom);
              cameraRef.current.panY += dy / Math.max(0.04, cameraRef.current.zoom);
            }
            drag.x = event.clientX;
            drag.y = event.clientY;
            drawRef.current?.();
            return;
          }
          const rect = canvasRef.current.getBoundingClientRect();
          const pointerX = event.clientX - rect.left;
          const pointerY = event.clientY - rect.top;
          const camera = cameraRef.current;
          let found: string | null = null;
          data.nodes.forEach(node => {
            const yaw = camera.yaw;
            const rotatedX = node.x * Math.cos(yaw) - node.z * Math.sin(yaw);
            const rotatedZ = node.x * Math.sin(yaw) + node.z * Math.cos(yaw);
            const projectedY = node.y * Math.cos(camera.pitch) - rotatedZ * Math.sin(camera.pitch);
            const depth = node.y * Math.sin(camera.pitch) + rotatedZ * Math.cos(camera.pitch);
            const perspective = 1 / Math.max(0.18, 1 + depth / 520);
            const x = rect.width / 2 + (rotatedX + camera.panX) * camera.zoom * perspective;
            const y = rect.height / 2 + (projectedY + camera.panY) * camera.zoom * perspective;
            if (Math.hypot(pointerX - x, pointerY - y) < Math.max(16, 24 * camera.zoom * perspective)) found = node.id;
          });
          if (found !== hoveredNode) setHoveredNode(found);
        }}
        onPointerUp={event => {
          const drag = dragRef.current;
          dragRef.current.active = false;
          if (!drag.moved && hoveredNode) setSelectedNode(hoveredNode);
          canvasRef.current?.releasePointerCapture(event.pointerId);
        }}
        onPointerLeave={() => { if (!dragRef.current.active) setHoveredNode(null); }}
      />
      <div className="absolute right-2 top-2 flex gap-1">
        <button type="button" onClick={() => { cameraRef.current.zoom *= 1.5; drawRef.current?.(); }} className="font-mono text-xs px-2 py-1 rounded-sm border" style={{ color: '#FBFAF6', backgroundColor: 'rgba(24,24,24,.7)', borderColor: 'rgba(251,250,246,.25)' }} aria-label="Deep zoom in 3D network">+</button>
        <button type="button" onClick={() => { cameraRef.current.zoom = Math.max(0.04, cameraRef.current.zoom / 1.5); drawRef.current?.(); }} className="font-mono text-xs px-2 py-1 rounded-sm border" style={{ color: '#FBFAF6', backgroundColor: 'rgba(24,24,24,.7)', borderColor: 'rgba(251,250,246,.25)' }} aria-label="Zoom out 3D network">−</button>
        <button type="button" onClick={focusSelected} disabled={!selected} className="font-mono text-[9px] px-2 py-1 rounded-sm border disabled:opacity-40" style={{ color: '#FBFAF6', backgroundColor: 'rgba(24,24,24,.7)', borderColor: 'rgba(251,250,246,.25)' }}>FOCUS</button>
        <button type="button" onClick={resetCamera} className="font-mono text-[9px] px-2 py-1 rounded-sm border" style={{ color: '#FBFAF6', backgroundColor: 'rgba(24,24,24,.7)', borderColor: 'rgba(251,250,246,.25)' }}>RESET</button>
      </div>
      <div className="absolute left-2 bottom-2 rounded-sm border px-2 py-1" style={{ color: '#FBFAF6', backgroundColor: 'rgba(24,24,24,.7)', borderColor: 'rgba(251,250,246,.25)' }}>
        <p className="font-mono text-[8px] tracking-wider uppercase">{pageType} · orbit / shift-pan / deep zoom</p>
        {selected && <p className="font-mono text-[9px] mt-1">Selected: {selected.label} · {selected.type}</p>}
      </div>
    </div>
  );
}

// ============================================================================
// Context-aware 2D network
// ============================================================================

type NetworkPageType = 'dashboard' | 'email' | 'file' | 'url' | 'infrastructure' | 'darkweb' | 'intelligence' | 'campaigns' | 'cases' | 'reports' | 'alerts';
type Point = { x: number; y: number };

const nodeColors: Record<string, string> = {
  neutral: 'var(--tw-text-muted)',
  verified: 'var(--tw-low)',
  suspicious: 'var(--tw-medium)',
  highRisk: 'var(--tw-critical)',
  resolved: 'var(--tw-low)',
};

const networkLayouts: Record<NetworkPageType, Point[]> = {
  dashboard: [{ x: 480, y: 205 }, { x: 220, y: 105 }, { x: 740, y: 105 }, { x: 220, y: 315 }, { x: 740, y: 315 }, { x: 480, y: 335 }, { x: 480, y: 75 }],
  email: [{ x: 120, y: 205 }, { x: 270, y: 105 }, { x: 270, y: 305 }, { x: 450, y: 105 }, { x: 450, y: 305 }, { x: 630, y: 205 }, { x: 790, y: 205 }, { x: 790, y: 90 }, { x: 790, y: 320 }],
  file: [{ x: 480, y: 205 }, { x: 235, y: 105 }, { x: 725, y: 105 }, { x: 235, y: 315 }, { x: 725, y: 315 }, { x: 480, y: 350 }],
  url: [{ x: 120, y: 205 }, { x: 300, y: 105 }, { x: 300, y: 305 }, { x: 480, y: 205 }, { x: 680, y: 105 }, { x: 680, y: 305 }, { x: 850, y: 205 }],
  infrastructure: [{ x: 480, y: 205 }, { x: 240, y: 105 }, { x: 720, y: 105 }, { x: 240, y: 315 }, { x: 720, y: 315 }, { x: 480, y: 350 }],
  darkweb: [{ x: 480, y: 205 }, { x: 240, y: 105 }, { x: 720, y: 105 }, { x: 240, y: 315 }, { x: 720, y: 315 }, { x: 480, y: 350 }],
  intelligence: [{ x: 480, y: 205 }, { x: 220, y: 105 }, { x: 740, y: 105 }, { x: 220, y: 315 }, { x: 740, y: 315 }, { x: 480, y: 335 }, { x: 480, y: 75 }],
  campaigns: [{ x: 480, y: 205 }, { x: 170, y: 105 }, { x: 790, y: 105 }, { x: 290, y: 315 }, { x: 670, y: 315 }, { x: 70, y: 205 }, { x: 890, y: 205 }],
  cases: [{ x: 480, y: 205 }, { x: 220, y: 105 }, { x: 740, y: 105 }, { x: 220, y: 315 }, { x: 740, y: 315 }, { x: 480, y: 350 }],
  reports: [{ x: 480, y: 205 }, { x: 220, y: 105 }, { x: 740, y: 105 }, { x: 220, y: 315 }, { x: 740, y: 315 }, { x: 480, y: 350 }],
  alerts: [{ x: 480, y: 205 }, { x: 220, y: 105 }, { x: 740, y: 105 }, { x: 220, y: 315 }, { x: 740, y: 315 }, { x: 480, y: 350 }],
};

const networkContextLabels: Record<NetworkPageType, string> = {
  dashboard: 'Posture → campaign → case → response',
  email: 'Message path and sender-controlled indicators',
  file: 'Artifact → indicators → verdict',
  url: 'Redirect chain → hosting → reputation',
  infrastructure: 'Domain → infrastructure → related threats',
  darkweb: 'Exposure → affected identity → remediation',
  intelligence: 'IOC correlation → campaign → action',
  campaigns: 'Campaign cluster → shared infrastructure → cases',
  cases: 'Investigation → evidence → response',
  reports: 'Evidence → findings → approval',
  alerts: 'Alert → evidence → case → action',
};

function ThreatEvidenceNetwork2D({ data, pageType }: { data: PageSpecificData; pageType: NetworkPageType }) {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const points = networkLayouts[pageType] || networkLayouts.cases;
  const positions = new Map(data.nodes.map((node, index) => [node.id, points[index] || { x: 480, y: 205 }]));
  const selected = data.nodes.find(node => node.id === selectedNode);
  const connected = new Set(data.edges.filter(edge => edge.source === selectedNode || edge.target === selectedNode).flatMap(edge => [edge.source, edge.target]));

  return (
    <div className="relative h-full w-full" aria-label={`${pageType} threat evidence network`}>
      <svg viewBox="0 0 960 420" className="w-full h-full" role="img" aria-label={`${networkContextLabels[pageType]} network`}>
        <defs>
          <marker id={`arrow-${pageType}`} markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
            <path d="M0,0 L0,6 L7,3 z" fill="var(--tw-border-strong)" />
          </marker>
        </defs>
        <g transform={`translate(${480 - 480 * zoom} ${210 - 210 * zoom}) scale(${zoom})`}>
          {data.edges.map((edge, index) => {
            const source = positions.get(edge.source);
            const target = positions.get(edge.target);
            if (!source || !target) return null;
            const active = selectedNode ? connected.has(edge.source) && connected.has(edge.target) : false;
            return <line key={`${edge.source}-${edge.target}-${index}`} x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke={active ? 'var(--tw-burgundy)' : 'var(--tw-border-strong)'} strokeWidth={active ? 3 : 1.5} strokeDasharray={active ? undefined : '5 5'} opacity={selectedNode && !active ? 0.2 : 0.72} markerEnd={`url(#arrow-${pageType})`} />;
          })}
          {data.nodes.map(node => {
            const point = positions.get(node.id) || { x: 480, y: 205 };
            const color = nodeColors[node.severity || 'neutral'];
            const primary = node === data.nodes[0];
            const active = !selectedNode || connected.has(node.id);
            return (
              <g key={node.id} transform={`translate(${point.x} ${point.y})`} opacity={active ? 1 : 0.3} onClick={() => setSelectedNode(current => current === node.id ? null : node.id)} onMouseEnter={() => setSelectedNode(node.id)} className="cursor-pointer">
                {primary && <circle r="34" fill="none" stroke={color} strokeOpacity="0.22" strokeWidth="8" />}
                <circle r={primary ? 27 : 21} fill="var(--tw-panel)" stroke={color} strokeWidth={selectedNode === node.id ? 3 : 2} />
                <circle r={primary ? 20 : 15} fill={color} fillOpacity="0.17" />
                <text y="-3" textAnchor="middle" fill="var(--tw-text)" fontSize={primary ? 11 : 9} fontFamily="IBM Plex Mono" fontWeight={primary ? 600 : 500}>{node.label.slice(0, 16)}</text>
                <text y="12" textAnchor="middle" fill="var(--tw-text-muted)" fontSize="7" fontFamily="IBM Plex Mono">{node.type.toUpperCase()}</text>
              </g>
            );
          })}
        </g>
      </svg>
      <div className="absolute left-3 top-3 max-w-[58%] rounded-sm border px-3 py-2" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-panel) 92%, transparent)', borderColor: 'var(--tw-border)' }}>
        <p className="font-mono text-[9px] tracking-[0.12em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>{networkContextLabels[pageType]}</p>
      </div>
      <div className="absolute right-3 top-3 flex gap-1">
        <button aria-label="Zoom out network" onClick={() => setZoom(value => Math.max(0.8, value - 0.1))} className="font-mono text-xs px-2 py-1 rounded-sm border" style={{ color: 'var(--tw-text-muted)', borderColor: 'var(--tw-border)' }}>−</button>
        <button aria-label="Reset network view" onClick={() => { setZoom(1); setSelectedNode(null); }} className="font-mono text-[9px] px-2 py-1 rounded-sm border" style={{ color: 'var(--tw-text-muted)', borderColor: 'var(--tw-border)' }}>RESET</button>
        <button aria-label="Zoom in network" onClick={() => setZoom(value => Math.min(1.3, value + 0.1))} className="font-mono text-xs px-2 py-1 rounded-sm border" style={{ color: 'var(--tw-text-muted)', borderColor: 'var(--tw-border)' }}>+</button>
      </div>
      {selected && (
        <div className="absolute bottom-3 left-3 max-w-[70%] rounded-sm border px-3 py-2" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-panel) 94%, transparent)', borderColor: nodeColors[selected.severity || 'neutral'] }}>
          <p className="font-mono text-[10px]" style={{ color: 'var(--tw-text)' }}>{selected.label}</p>
          <p className="font-mono text-[9px] mt-1" style={{ color: 'var(--tw-text-muted)' }}>{selected.type.toUpperCase()} · {selected.severity || 'neutral'} · {connected.size - 1} connected entities</p>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// STATIC DIAGRAM FALLBACK
// ============================================================================

function ThreatEvidenceNetworkStatic({ data }: { data: PageSpecificData }) {
  return (
    <div className="w-full h-full flex flex-col items-center justify-center p-4 space-y-3">
      <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>
        {data.primaryRelationship}
      </p>
      <div className="flex flex-wrap gap-2 justify-center">
        {data.nodes.map((node) => (
          <div
            key={node.id}
            className="px-2 py-1 rounded-sm border text-[9px] font-mono"
            style={{
              borderColor: 'var(--tw-border)',
              backgroundColor: 'var(--tw-panel-alt)',
              color: 'var(--tw-text-muted)',
            }}
          >
            {node.label}
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// CONTROLS AND DEBUG PANEL
// ============================================================================

interface ControlsProps {
  viewMode: '3d' | '2d' | 'disabled';
  onViewModeChange: (mode: '3d' | '2d' | 'disabled') => void;
  showDebug: boolean;
  onToggleDebug: () => void;
  debugInfo: DebugInfo;
}

function Controls({ viewMode, onViewModeChange, showDebug, onToggleDebug, debugInfo }: ControlsProps) {
  return (
    <div className="flex items-center justify-between px-3 py-2 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
      <div className="flex items-center gap-2">
        <span className="font-mono text-[9px] tracking-wider uppercase" style={{ color: 'var(--tw-text-muted)' }}>
          Threat Evidence Network
        </span>
      </div>
      <div className="flex items-center gap-1">
        {(['3d', '2d', 'disabled'] as const).map((mode) => (
          <button
            key={mode}
            onClick={() => onViewModeChange(mode)}
            className="font-mono text-[9px] px-2 py-1 rounded-sm transition-colors"
            style={{
              backgroundColor: viewMode === mode ? 'var(--tw-burgundy)' : 'transparent',
              color: viewMode === mode ? '#FBFAF6' : 'var(--tw-text-muted)',
            }}
          >
            {mode.toUpperCase()}
          </button>
        ))}
        {import.meta.env.DEV && (
          <button
            onClick={onToggleDebug}
            className="font-mono text-[9px] px-2 py-1 rounded-sm transition-colors ml-2"
            style={{
              backgroundColor: showDebug ? 'var(--tw-medium)' : 'transparent',
              color: showDebug ? '#FBFAF6' : 'var(--tw-text-muted)',
            }}
          >
            DEBUG
          </button>
        )}
      </div>
    </div>
  );
}

interface DebugInfo {
  webglAvailable: boolean;
  canvasDimensions: { width: number; height: number };
  sceneMounted: boolean;
  nodeCount: number;
  edgeCount: number;
  renderingMode: string;
  performanceTier: string;
}

function DebugPanel({ info }: { info: DebugInfo }) {
  return (
    <div className="p-2 space-y-1 border-t" style={{ borderColor: 'var(--tw-border-mid)', backgroundColor: 'var(--tw-panel-alt)' }}>
      <p className="font-mono text-[8px] tracking-wider uppercase" style={{ color: 'var(--tw-text-muted)' }}>
        Development Debug Panel
      </p>
      <div className="grid grid-cols-2 gap-1 font-mono text-[8px]" style={{ color: 'var(--tw-text-muted)' }}>
        <span>WebGL:</span>
        <span>{info.webglAvailable ? '✓' : '✗'}</span>
        <span>Canvas:</span>
        <span>{info.canvasDimensions.width}×{info.canvasDimensions.height}</span>
        <span>Mounted:</span>
        <span>{info.sceneMounted ? '✓' : '✗'}</span>
        <span>Nodes:</span>
        <span>{info.nodeCount}</span>
        <span>Edges:</span>
        <span>{info.edgeCount}</span>
        <span>Mode:</span>
        <span>{info.renderingMode}</span>
        <span>Tier:</span>
        <span>{info.performanceTier}</span>
      </div>
    </div>
  );
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

interface ThreatEvidenceNetworkProps {
  pageType: 'dashboard' | 'email' | 'file' | 'url' | 'infrastructure' | 'darkweb' | 'intelligence' | 'campaigns' | 'cases' | 'reports' | 'alerts';
  customData?: PageSpecificData;
}

export default function ThreatEvidenceNetwork({ pageType, customData }: ThreatEvidenceNetworkProps) {
  const { enabled, performanceTier } = useThreeD();
  const [viewMode, setViewMode] = useState<'3d' | '2d' | 'disabled'>(enabled ? '3d' : 'disabled');
  const [showDebug, setShowDebug] = useState(false);
  const [debugInfo, setDebugInfo] = useState<DebugInfo>({
    webglAvailable: true,
    canvasDimensions: { width: 0, height: 0 },
    sceneMounted: true,
    nodeCount: 0,
    edgeCount: 0,
    renderingMode: '3d',
    performanceTier,
  });

  // Get page-specific data
  const getData = (): PageSpecificData => {
    if (customData) return customData;
    
    switch (pageType) {
      case 'dashboard': return getDashboardData();
      case 'email': return getEmailAnalysisData();
      case 'file': return getFileAnalysisData();
      case 'url': return getUrlAnalysisData();
      case 'infrastructure': return getInfrastructureData();
      case 'darkweb': return getDarkWebData();
      case 'intelligence': return getIntelligenceData();
      case 'campaigns': return getCampaignsData();
      case 'cases': return getCasesData();
      case 'reports': return getReportsData();
      case 'alerts': return getAlertsData();
      default: return getDashboardData();
    }
  };

  const data = useMemo(() => getData(), [customData, pageType]);

  // Update debug info
  useEffect(() => {
    setDebugInfo(prev => ({
      ...prev,
      nodeCount: data.nodes.length,
      edgeCount: data.edges.length,
      renderingMode: viewMode,
      performanceTier,
    }));
  }, [data, viewMode, performanceTier]);

  // Sync view mode with enabled state - fixed to avoid infinite loop
  useEffect(() => {
    if (!enabled && viewMode === '3d') {
      setViewMode('disabled');
    }
  }, [enabled]);

  const renderContent = () => {
    switch (viewMode) {
      case '3d':
        if (performanceTier === 'low') {
          return <ThreatEvidenceNetwork2D data={data} pageType={pageType} />;
        }
        return <ThreatEvidenceNetwork3D data={data} pageType={pageType} />;
      case '2d':
        return <ThreatEvidenceNetwork2D data={data} pageType={pageType} />;
      case 'disabled':
        return <ThreatEvidenceNetworkStatic data={data} />;
      default:
        return <ThreatEvidenceNetworkStatic data={data} />;
    }
  };

  return (
    <div className="rounded-sm overflow-hidden border" style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-panel-alt)' }}>
      <Controls
        viewMode={viewMode}
        onViewModeChange={setViewMode}
        showDebug={showDebug}
        onToggleDebug={() => setShowDebug(!showDebug)}
        debugInfo={debugInfo}
      />
      <div 
        className="relative"
        style={{ 
          minHeight: 'min(160px, 20vh)',
        }}
      >
        <div className="absolute inset-0" style={{ minHeight: '160px' }}>
          <ThreeDErrorBoundary fallback={<ThreatEvidenceNetwork2D data={data} pageType={pageType} />}>
            {renderContent()}
          </ThreeDErrorBoundary>
        </div>
      </div>
      {showDebug && import.meta.env.DEV && (
        <DebugPanel info={debugInfo} />
      )}
    </div>
  );
}
