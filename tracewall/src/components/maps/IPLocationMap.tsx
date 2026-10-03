import { useEffect, useMemo, useRef, useState } from 'react';
import { LngLatBounds, Map, MapStyle, Marker, NavigationControl, Popup } from '@maptiler/sdk';
import '@maptiler/sdk/dist/maptiler-sdk.css';

export interface IPLocationRecord {
  ip: string;
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  asn?: string;
  asnName?: string;
  isp?: string;
  hostingProvider?: string;
  reputation?: string;
  riskScore?: number;
  verdict?: string;
}

interface IPLocationMapProps {
  records: IPLocationRecord[];
  selectedIp?: string;
}

const mapTilerApiKey = import.meta.env.VITE_MAPTILER_API_KEY;
const configuredMapTilerStyle = import.meta.env.VITE_MAPTILER_STYLE || '';
const mapTilerStyle = /(?:^|\/)streets-v2(?:\/style\.json)?(?:\?.*)?$/i.test(configuredMapTilerStyle)
  ? MapStyle.STREETS_V2
  : configuredMapTilerStyle || undefined;

function hasCoordinates(record: IPLocationRecord) {
  return Number.isFinite(record.latitude) && Number.isFinite(record.longitude);
}

function markerColor(record: IPLocationRecord) {
  if (record.verdict === 'SUSPICIOUS' || record.reputation === 'POOR') return '#7E1D2F';
  if (record.reputation === 'NEUTRAL') return '#A47535';
  return '#596E5B';
}

function markerElement(record: IPLocationRecord) {
  const element = document.createElement('button');
  element.type = 'button';
  element.setAttribute('aria-label', `Show location details for ${record.ip}`);
  element.style.width = '18px';
  element.style.height = '18px';
  element.style.borderRadius = '50%';
  element.style.border = '2px solid #FBFAF6';
  element.style.background = markerColor(record);
  element.style.boxShadow = '0 0 0 5px color-mix(in srgb, #7E1D2F 18%, transparent), 0 2px 8px rgba(0,0,0,.35)';
  element.style.cursor = 'pointer';
  return element;
}

function popupHtml(record: IPLocationRecord) {
  const location = [record.city, record.region, record.country].filter(Boolean).join(', ') || 'Location unavailable';
  const provider = record.asnName || record.isp || record.hostingProvider || 'Not available';
  return `<div style="font-family:IBM Plex Mono,monospace;font-size:11px;line-height:1.6;color:#181818"><strong>${record.ip}</strong><br>${location}<br>Provider: ${provider}${record.asn ? `<br>ASN: ${record.asn}` : ''}${record.verdict ? `<br>Verdict: ${record.verdict}` : ''}</div>`;
}

export default function IPLocationMap({ records, selectedIp }: IPLocationMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<Map | null>(null);
  const markersRef = useRef<Marker[]>([]);
  const [mapError, setMapError] = useState<string | null>(null);
  const locatedRecords = useMemo(() => records.filter(hasCoordinates), [records]);

  useEffect(() => {
    if (!containerRef.current || !mapTilerApiKey) return;
    const map = new Map({
      container: containerRef.current,
      apiKey: mapTilerApiKey,
      style: mapTilerStyle,
      center: [0, 20],
      zoom: 1.25,
    });
    mapRef.current = map;
    map.addControl(new NavigationControl({ showCompass: true }), 'top-right');
    map.on('error', event => {
      const message = event.error?.message || 'Map tiles or style could not be loaded.';
      setMapError(message);
    });

    const resizeObserver = new ResizeObserver(() => map.resize());
    resizeObserver.observe(containerRef.current);

    return () => {
      resizeObserver.disconnect();
      markersRef.current.forEach(marker => marker.remove());
      markersRef.current = [];
      map.remove();
      mapRef.current = null;
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    if (!map) return;
    markersRef.current.forEach(marker => marker.remove());
    markersRef.current = locatedRecords.map(record => {
      const marker = new Marker({ element: markerElement(record) })
        .setLngLat([record.longitude as number, record.latitude as number])
        .setPopup(new Popup({ offset: 14, closeButton: true }).setHTML(popupHtml(record)))
        .addTo(map);
      if (record.ip === selectedIp) marker.togglePopup();
      return marker;
    });
    if (locatedRecords.length === 1) {
      map.flyTo({ center: [locatedRecords[0].longitude as number, locatedRecords[0].latitude as number], zoom: 5, essential: true });
    } else if (locatedRecords.length > 1) {
      const bounds = new LngLatBounds();
      locatedRecords.forEach(record => bounds.extend([record.longitude as number, record.latitude as number]));
      map.fitBounds(bounds, { padding: 60, maxZoom: 6, duration: 500 });
    }
  }, [locatedRecords, selectedIp]);

  return (
    <div className="rounded-sm overflow-hidden border" style={{ borderColor: 'var(--tw-border)', backgroundColor: 'var(--tw-panel-alt)' }}>
      <div className="flex items-center justify-between gap-4 px-4 py-3 border-b" style={{ borderColor: 'var(--tw-border-mid)' }}>
        <div>
          <p className="font-mono text-[10px] tracking-[0.2em] uppercase" style={{ color: 'var(--tw-text-muted)' }}>IP Location Map</p>
          <p className="font-mono text-[10px] mt-1" style={{ color: 'var(--tw-text-faint)' }}>MapTiler · Interactive location intelligence</p>
        </div>
        <span className="font-mono text-[10px]" style={{ color: locatedRecords.length ? 'var(--tw-low)' : 'var(--tw-text-muted)' }}>
          {locatedRecords.length ? `${locatedRecords.length} located` : 'Location unavailable'}
        </span>
      </div>
      <div ref={containerRef} className="relative h-[360px] w-full" aria-label="Interactive IP location map">
        {!mapTilerApiKey && (
          <div className="absolute inset-4 z-10 flex items-center justify-center rounded-sm border p-4 text-center" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-panel) 92%, transparent)', borderColor: 'var(--tw-border)', color: 'var(--tw-text-muted)' }}>
            <p className="font-mono text-xs">MapTiler is not configured. Set VITE_MAPTILER_API_KEY to load the map.</p>
          </div>
        )}
        {mapError && (
          <div className="absolute inset-4 z-10 flex items-center justify-center rounded-sm border p-4 text-center" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-panel) 92%, transparent)', borderColor: 'var(--tw-border)', color: 'var(--tw-text-muted)' }}>
            <p className="font-mono text-xs">Map unavailable. Check the configured map style or network connection.</p>
          </div>
        )}
        {!locatedRecords.length && !mapError && (
          <div className="absolute bottom-4 left-4 z-10 max-w-xs rounded-sm border px-3 py-2" style={{ backgroundColor: 'color-mix(in srgb, var(--tw-panel) 92%, transparent)', borderColor: 'var(--tw-border)' }}>
            <p className="font-mono text-[10px] leading-relaxed" style={{ color: 'var(--tw-text-muted)' }}>No latitude/longitude is available for this record. No marker was placed.</p>
          </div>
        )}
      </div>
    </div>
  );
}
