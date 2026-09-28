import { ChartPoint } from '../components/charts/chartUtils';

/** Quote a field only when it would otherwise break the CSV. */
function escapeCsvField(value: string): string {
  return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

/**
 * Serialise a series as CSV with a stable header. Timestamps are written as ISO
 * strings so exports open cleanly in spreadsheets regardless of locale.
 */
export function seriesToCsv(points: ChartPoint[]): string {
  const header = 'date,label,value';

  const rows = points.map((point) =>
    [
      point.timestamp === undefined ? '' : new Date(point.timestamp).toISOString(),
      point.label,
      String(point.value),
    ]
      .map(escapeCsvField)
      .join(',')
  );

  return [header, ...rows].join('\n');
}

/** Click a synthetic anchor to save `href` as `filename`. */
export function triggerDownload(href: string, filename: string): void {
  if (typeof document === 'undefined') {
    return;
  }

  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = filename;
  anchor.rel = 'noopener';
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
}

/** Save a string as a file, when blob URLs are available. */
export function downloadText(
  content: string,
  filename: string,
  mimeType = 'text/csv;charset=utf-8'
): void {
  if (typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') {
    return;
  }

  const url = URL.createObjectURL(new Blob([content], { type: mimeType }));

  try {
    triggerDownload(url, filename);
  } finally {
    URL.revokeObjectURL(url);
  }
}

/** Convenience wrapper: series straight to a downloaded CSV. */
export function exportSeriesToCsv(points: ChartPoint[], filename: string): void {
  downloadText(seriesToCsv(points), filename);
}

/**
 * Presentational properties copied onto the serialised clone.
 *
 * Charts are styled with CSS custom properties, which are not resolved inside a
 * standalone SVG data URL, so the computed values have to be baked in or the
 * exported PNG comes out invisible.
 */
const INLINED_STYLE_PROPERTIES = [
  'fill',
  'fill-opacity',
  'stroke',
  'stroke-width',
  'stroke-opacity',
  'stroke-dasharray',
  'stroke-dashoffset',
  'stroke-linecap',
  'stroke-linejoin',
  'font-family',
  'font-size',
  'font-weight',
  'text-anchor',
  'opacity',
];

/** Copy resolved computed styles from the live SVG onto the clone. */
export function inlineComputedStyles(source: SVGSVGElement, clone: SVGSVGElement): void {
  if (typeof window === 'undefined' || typeof window.getComputedStyle !== 'function') {
    return;
  }

  const sourceNodes: Element[] = [source, ...Array.from(source.querySelectorAll('*'))];
  const cloneNodes: Element[] = [clone, ...Array.from(clone.querySelectorAll('*'))];

  sourceNodes.forEach((node, index) => {
    const target = cloneNodes[index];

    if (!(target instanceof SVGElement)) {
      return;
    }

    const computed = window.getComputedStyle(node);

    INLINED_STYLE_PROPERTIES.forEach((property) => {
      const value = computed.getPropertyValue(property);
      if (value) {
        target.style.setProperty(property, value.trim());
      }
    });
  });
}

/** Serialise an SVG element into standalone markup with styles inlined. */
export function serializeSvg(svg: SVGSVGElement): string {
  const clone = svg.cloneNode(true) as SVGSVGElement;
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  inlineComputedStyles(svg, clone);

  const size = intrinsicSize(svg);
  clone.setAttribute('width', String(size.width));
  clone.setAttribute('height', String(size.height));

  return new XMLSerializer().serializeToString(clone);
}

/** Read the drawing size from `viewBox`, falling back to the rendered box. */
export function intrinsicSize(svg: SVGSVGElement): { width: number; height: number } {
  const viewBox = svg.getAttribute('viewBox');

  if (viewBox) {
    const parts = viewBox.split(/[\s,]+/).map(Number);
    if (parts.length === 4 && parts[2] > 0 && parts[3] > 0) {
      return { width: parts[2], height: parts[3] };
    }
  }

  return {
    width: svg.clientWidth || 800,
    height: svg.clientHeight || 400,
  };
}

function loadImage(src: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error('Unable to rasterise the chart'));
    image.src = src;
  });
}

/** Rasterise an SVG element to a PNG blob at `pixelRatio` density. */
export async function svgElementToPngBlob(
  svg: SVGSVGElement,
  pixelRatio = 2
): Promise<Blob> {
  const { width, height } = intrinsicSize(svg);
  const markup = serializeSvg(svg);
  const image = await loadImage(
    `data:image/svg+xml;charset=utf-8,${encodeURIComponent(markup)}`
  );

  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, Math.round(width * pixelRatio));
  canvas.height = Math.max(1, Math.round(height * pixelRatio));

  const context = canvas.getContext('2d');
  if (!context) {
    throw new Error('Canvas 2D context is unavailable');
  }

  context.drawImage(image, 0, 0, canvas.width, canvas.height);

  return new Promise<Blob>((resolve, reject) => {
    canvas.toBlob(
      (blob) => (blob ? resolve(blob) : reject(new Error('PNG encoding failed'))),
      'image/png'
    );
  });
}

/** Rasterise an SVG element and save it as a PNG file. */
export async function exportSvgElementToPng(
  svg: SVGSVGElement,
  filename: string,
  pixelRatio = 2
): Promise<void> {
  const blob = await svgElementToPngBlob(svg, pixelRatio);
  const url = URL.createObjectURL(blob);

  try {
    triggerDownload(url, filename);
  } finally {
    URL.revokeObjectURL(url);
  }
}
