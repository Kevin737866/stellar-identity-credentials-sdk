import { ChartPoint } from '../../components/charts/chartUtils';
import {
  downloadText,
  intrinsicSize,
  serializeSvg,
  seriesToCsv,
  svgElementToPngBlob,
  triggerDownload,
} from '../analyticsExport';

const points: ChartPoint[] = [
  { label: '1 Mar', value: 12, timestamp: Date.UTC(2026, 2, 1) },
  { label: '2 Mar', value: 30, timestamp: Date.UTC(2026, 2, 2) },
];

function createSvg(): SVGSVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 600 220');
  svg.innerHTML = '<circle cx="10" cy="10" r="4" />';
  document.body.appendChild(svg);
  return svg;
}

afterEach(() => {
  document.body.innerHTML = '';
  jest.restoreAllMocks();
});

describe('seriesToCsv', () => {
  it('writes a stable header', () => {
    expect(seriesToCsv(points).split('\n')[0]).toBe('date,label,value');
  });

  it('writes ISO timestamps so exports are locale independent', () => {
    const [, firstRow] = seriesToCsv(points).split('\n');

    expect(firstRow).toBe('2026-03-01T00:00:00.000Z,1 Mar,12');
  });

  it('emits one row per point', () => {
    expect(seriesToCsv(points).split('\n')).toHaveLength(points.length + 1);
  });

  it('leaves the date blank when a point has no timestamp', () => {
    expect(seriesToCsv([{ label: 'total', value: 5 }]).split('\n')[1]).toBe(',total,5');
  });

  it('quotes fields containing commas, quotes or newlines', () => {
    const csv = seriesToCsv([{ label: 'London, "UK"', value: 1 }]);

    expect(csv.split('\n')[1]).toBe(',"London, ""UK""",1');
  });

  it('returns just the header for an empty series', () => {
    expect(seriesToCsv([])).toBe('date,label,value');
  });
});

describe('triggerDownload', () => {
  it('saves the href under the given filename', () => {
    const click = jest
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    triggerDownload('blob:chart', 'issuance.csv');

    expect(click).toHaveBeenCalledTimes(1);
    // The synthetic anchor must not be left behind in the document.
    expect(document.querySelector('a')).toBeNull();
  });
});

describe('downloadText', () => {
  it('creates and revokes an object URL around the download', () => {
    const createObjectURL = jest.fn(() => 'blob:generated');
    const revokeObjectURL = jest.fn();
    Object.assign(URL, { createObjectURL, revokeObjectURL });
    const click = jest
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    downloadText('date,label,value', 'report.csv');

    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(click).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:generated');
  });

  it('does nothing when blob URLs are unavailable', () => {
    const original = URL.createObjectURL;
    // @ts-expect-error simulate a runtime without blob URL support
    URL.createObjectURL = undefined;
    const click = jest
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    downloadText('x', 'report.csv');

    expect(click).not.toHaveBeenCalled();
    URL.createObjectURL = original;
  });
});

describe('intrinsicSize', () => {
  it('prefers the viewBox dimensions', () => {
    expect(intrinsicSize(createSvg())).toEqual({ width: 600, height: 220 });
  });

  it('falls back to defaults when there is no viewBox', () => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');

    expect(intrinsicSize(svg)).toEqual({ width: 800, height: 400 });
  });
});

describe('serializeSvg', () => {
  it('produces standalone, namespace-qualified markup', () => {
    const markup = serializeSvg(createSvg());

    expect(markup).toContain('xmlns="http://www.w3.org/2000/svg"');
    expect(markup).toContain('width="600"');
    expect(markup).toContain('<circle');
  });
});

describe('svgElementToPngBlob', () => {
  const originalImage = global.Image;

  afterEach(() => {
    global.Image = originalImage;
  });

  it('rasterises the chart at the requested density', async () => {
    const drawImage = jest.fn();
    const pngBlob = new Blob(['png'], { type: 'image/png' });

    class FakeImage {
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      set src(_value: string) {
        Promise.resolve().then(() => this.onload?.());
      }
    }

    global.Image = FakeImage as unknown as typeof Image;
    HTMLCanvasElement.prototype.getContext = jest
      .fn()
      .mockReturnValue({ drawImage }) as unknown as typeof HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.toBlob = jest
      .fn()
      .mockImplementation((callback: BlobCallback) => callback(pngBlob)) as unknown as typeof HTMLCanvasElement.prototype.toBlob;

    const blob = await svgElementToPngBlob(createSvg(), 2);

    expect(blob).toBe(pngBlob);
    expect(drawImage).toHaveBeenCalledTimes(1);
    // The canvas is sized from the viewBox scaled by the pixel ratio.
    expect(drawImage.mock.calls[0].slice(1)).toEqual([0, 0, 1200, 440]);
  });

  it('rejects when the chart cannot be rasterised', async () => {
    class FailingImage {
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      set src(_value: string) {
        Promise.resolve().then(() => this.onerror?.());
      }
    }

    global.Image = FailingImage as unknown as typeof Image;

    await expect(svgElementToPngBlob(createSvg())).rejects.toThrow(
      'Unable to rasterise the chart'
    );
  });

  it('rejects when the canvas has no 2D context', async () => {
    class FakeImage {
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      set src(_value: string) {
        Promise.resolve().then(() => this.onload?.());
      }
    }

    global.Image = FakeImage as unknown as typeof Image;
    HTMLCanvasElement.prototype.getContext = jest
      .fn()
      .mockReturnValue(null) as unknown as typeof HTMLCanvasElement.prototype.getContext;

    await expect(svgElementToPngBlob(createSvg())).rejects.toThrow(
      'Canvas 2D context is unavailable'
    );
  });
});
