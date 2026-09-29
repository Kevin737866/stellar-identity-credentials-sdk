// Mock for lucide-react - return simple span elements
const React = require('react');

const createIcon = (name) => {
  const Icon = ({ className, size, ...props }) =>
    React.createElement('span', { 'data-testid': `icon-${name}`, className, ...props });
  Icon.displayName = name;
  return Icon;
};

const icons = [
  'Shield', 'CheckCircle', 'XCircle', 'AlertTriangle', 'Search', 'RefreshCw',
  'Eye', 'Flag', 'Ban', 'CheckSquare', 'Activity', 'Globe', 'Database',
  'FileText', 'AlertCircle', 'Calendar', 'Download', 'Clock', 'FileSpreadsheet',
  'FileJson', 'FileType', 'Plus', 'BarChart3', 'TrendingUp', 'Settings',
  'Trash2', 'ChevronDown', 'Upload', 'ClipboardList', 'ZoomIn', 'ZoomOut',
  'Maximize2', 'Info', 'Users', 'Link', 'Star', 'Award', 'Network',
  'GitBranch', 'Layers', 'Move', 'RotateCcw', 'Filter', 'ChevronRight',
  'ChevronLeft', 'ArrowRight', 'ArrowLeft', 'Check', 'X', 'AlertOctagon',
  'Share', 'Share2', 'Copy', 'FileDown', 'Wallet', 'Fingerprint', 'BadgeCheck',
  'LayoutDashboard', 'CheckCircle2', 'KeyRound',
];

const mocks = {};
icons.forEach((name) => {
  mocks[name] = createIcon(name);
});

// A Proxy resolves any icon not on the list above to a generic span, so adding
// an icon to a component does not also require editing this mock. Known names
// still resolve to their stable `icon-<name>` testid.
const fallback = createIcon('unknown');
module.exports = new Proxy(mocks, {
  get(target, prop) {
    if (typeof prop !== 'string' || prop in target) return target[prop];
    return fallback;
  },
});
