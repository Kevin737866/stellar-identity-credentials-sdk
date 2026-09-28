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
];

const mocks = {};
icons.forEach((name) => {
  mocks[name] = createIcon(name);
});

module.exports = mocks;
