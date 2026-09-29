// Design System Base Components
export { Button } from './components/ui/button';
export type { ButtonProps } from './components/ui/button';

export { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from './components/ui/card';
export type { CardProps } from './components/ui/card';

export { Badge } from './components/ui/badge';
export type { BadgeProps } from './components/ui/badge';

export { Input, Textarea, Label } from './components/ui/input';
export type { InputProps, TextareaProps, LabelProps } from './components/ui/input';

export { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from './components/ui/select';
export type { SelectProps, SelectItemProps } from './components/ui/select';

export { Dialog, DialogTrigger, DialogContent, DialogHeader, DialogTitle } from './components/ui/modal';
export type { DialogProps } from './components/ui/modal';

export { Alert, AlertDescription } from './components/ui/alert';
export type { AlertProps } from './components/ui/alert';

export { Progress } from './components/ui/progress';
export type { ProgressProps } from './components/ui/progress';

export { Tabs, TabsList, TabsTrigger, TabsContent } from './components/ui/tabs';
export type { TabsProps, TabsTriggerProps, TabsContentProps } from './components/ui/tabs';

export { Checkbox } from './components/ui/checkbox';
export type { CheckboxProps } from './components/ui/checkbox';

// Layout
export { Layout } from './components/Layout';
export type { LayoutProps, NavItem } from './components/Layout';

// Responsive layout primitives
export { MobileNav, MOBILE_NAV_MORE_ID } from './components/MobileNav';
export type { MobileNavProps, MobileNavItem } from './components/MobileNav';
export { ResponsiveTable } from './components/ResponsiveTable';
export type { ResponsiveTableProps, ResponsiveTableColumn } from './components/ResponsiveTable';
export {
  BREAKPOINTS,
  getBreakpoint,
  useBreakpoint,
  useMediaQuery,
  useViewportWidth,
} from './hooks/useBreakpoint';
export type { Breakpoint, BreakpointInfo } from './hooks/useBreakpoint';

// Feature Components
export { DIDManager, ConnectedDIDManager } from './components/DIDManager';
export { CredentialWallet } from './components/CredentialWallet';
export { ReputationBadge } from './components/ReputationBadge';
export { ProofRequest } from './components/ProofRequest';
export { ComplianceCheck } from './components/ComplianceCheck';
export { RegulatoryDashboard } from './components/RegulatoryDashboard';
export { DIDRecoveryWizard } from './components/DIDRecoveryWizard';
export type { DIDRecoveryWizardProps, RecoveryMethod, RecoveryConfig, Guardian } from './components/DIDRecoveryWizard';
export { SelectiveDisclosure } from './components/SelectiveDisclosure';

// Notifications
export { NotificationCenter } from './components/NotificationCenter';
export type { NotificationCenterProps } from './components/NotificationCenter';
export { NotificationRow } from './components/NotificationRow';
export type { NotificationRowProps } from './components/NotificationRow';
export { BellIcon } from './components/icons/BellIcon';
export type { BellIconProps } from './components/icons/BellIcon';
export {
  NOTIFICATION_PRESENTATION,
  NOTIFICATION_TONES,
  formatRelativeTime,
  isCredentialNotification,
  toCredentialNotification,
} from './types/notifications';
export type {
  CredentialNotification,
  CredentialNotificationType,
  NotificationPresentation,
  NotificationTone,
} from './types/notifications';
export { NotificationStream, parseNotificationPayload } from './services/notificationStream';
export type {
  NotificationStreamOptions,
  NotificationStreamStatus,
} from './services/notificationStream';
export {
  useNotifications,
  mergeNotification,
  readStoredNotifications,
  writeStoredNotifications,
} from './hooks/useNotifications';
export type {
  UseNotificationsOptions,
  UseNotificationsResult,
} from './hooks/useNotifications';

// Pages
export { Dashboard } from './pages/Dashboard';
export type { DashboardProps } from './pages/Dashboard';
export { ApiPlayground } from './pages/ApiPlayground';
export type { ApiPlaygroundProps } from './pages/ApiPlayground';

// Hooks
export {
  useStellarIdentity,
  useDID,
  useCredentials,
  useReputation,
  useCompliance,
} from './hooks/useStellarIdentity';

// Analytics
export { AnalyticsDashboard } from './components/AnalyticsDashboard';
export type {
  AnalyticsDashboardProps,
  AnalyticsExportPayload,
} from './components/AnalyticsDashboard';
export { MetricCard, formatChange, inferTone } from './components/MetricCard';
export type { MetricCardProps } from './components/MetricCard';
export { LineChart } from './components/charts/LineChart';
export type { LineChartProps } from './components/charts/LineChart';
export { BarChart } from './components/charts/BarChart';
export type { BarChartProps } from './components/charts/BarChart';
export { DonutChart } from './components/charts/DonutChart';
export type { DonutChartProps, DonutSegment } from './components/charts/DonutChart';
export {
  DATE_RANGE_PRESETS,
  MS_PER_DAY,
  filterSeriesByRange,
  formatDateLabel,
  formatNumber,
  formatPercent,
  getDateRangeBounds,
  presetLabel,
  successRate,
  summariseSeries,
} from './types/analytics';
export type {
  AnalyticsDataset,
  DateRange,
  DateRangePreset,
  SeriesSummary,
  TimeSeriesPoint,
  VerificationBreakdown,
} from './types/analytics';
export {
  downloadText,
  exportSeriesToCsv,
  exportSvgElementToPng,
  intrinsicSize,
  serializeSvg,
  seriesToCsv,
  svgElementToPngBlob,
  triggerDownload,
} from './utils/analyticsExport';
