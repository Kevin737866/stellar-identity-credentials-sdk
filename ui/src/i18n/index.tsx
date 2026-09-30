/**
 * Internationalisation for the React components (#215).
 *
 * Identity applications serve a global audience, and hard-coded English strings
 * make a UI unusable outside English. This module provides:
 *
 * - {@link I18nProvider} / {@link useTranslation} — a provider with language
 *   detection from browser settings, RTL support, and a re-render on change.
 * - A message catalogue for English, Spanish, French, Japanese, and Korean,
 *   with **Arabic** included to exercise and prove the RTL path.
 * - Locale-aware date, number, and currency formatting, replacing the
 *   `toLocaleDateString()` calls that silently stayed `en-US` regardless of the
 *   active language.
 *
 * The implementation is dependency-free. `react-i18next` is the usual choice,
 * but adding a runtime dependency to a published design-system package forces
 * every consumer onto a particular i18n stack; keeping the catalogue and the
 * interpolation primitive here means consumers can swap in any library later
 * without a breaking change.
 *
 * @module i18n
 * @category Utilities
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

// ── Locale model ─────────────────────────────────────────────────────────────

/**
 * Every language the components ship translations for.
 */
export type SupportedLocale =
  | 'en'
  | 'es'
  | 'fr'
  | 'ja'
  | 'ko'
  | 'ar';

/** Every supported locale, in menu order. */
export const SUPPORTED_LOCALES: readonly SupportedLocale[] = [
  'en',
  'es',
  'fr',
  'ja',
  'ko',
  'ar',
] as const;

/** The locale used when none is specified and detection finds nothing. */
export const DEFAULT_LOCALE: SupportedLocale = 'en';

/** Locales that render right-to-left. */
const RTL_LOCALES: ReadonlySet<string> = new Set(['ar', 'he', 'fa', 'ur']);

/** Display names for the language picker, each in its own language. */
export const LOCALE_LABELS: Readonly<Record<SupportedLocale, string>> = {
  en: 'English',
  es: 'Español',
  fr: 'Français',
  ja: '日本語',
  ko: '한국어',
  ar: 'العربية',
};

/** `true` when `locale` is written right-to-left. */
export function isRTL(locale: string): boolean {
  const base = locale.split('-')[0].toLowerCase();
  return RTL_LOCALES.has(base);
}

/** The BCP-47 tag to hand to `Intl`, given one of our locale codes. */
function intlLocale(locale: SupportedLocale): string {
  // Japanese and Korean need their region for correct formatting conventions
  // (notably the Japanese imperial-calendar-adjacent date ordering and Korean
  // week rules), so they are pinned rather than left to the runtime default.
  switch (locale) {
    case 'ja':
      return 'ja-JP';
    case 'ko':
      return 'ko-KR';
    case 'ar':
      return 'ar-EG';
    default:
      return locale;
  }
}

// ── Messages ─────────────────────────────────────────────────────────────────

/**
 * The message catalogue.
 *
 * Keys are dot-namespaced by feature. Adding a language means adding one entry
 * to this record — the type below enforces that no key is missing from any
 * locale, so a partially-translated catalogue is a compile error rather than a
 * runtime `undefined` in the UI.
 */
const en = {
  common: {
    loading: 'Loading…',
    error: 'Error',
    retry: 'Retry',
    cancel: 'Cancel',
    close: 'Close',
    save: 'Save',
    confirm: 'Confirm',
    copy: 'Copy',
    copied: 'Copied!',
    loadingAria: 'Loading',
  },
  network: {
    title: 'Network',
    switchTo: 'Switch network',
    switching: 'Switching…',
    connected: 'Connected',
    disconnected: 'Disconnected',
    connect: 'Connect',
    disconnect: 'Disconnect',
    language: 'Language',
  },
  credential: {
    wallet: 'Credential Wallet',
    issue: 'Issue Credential',
    issueNew: 'Issue New Credential',
    issuing: 'Issuing…',
    empty: 'No credentials found',
    emptyHint: 'Issue your first credential to get started',
    loadFailed: 'Failed to load credentials',
    issueSucceeded: 'Credential issued successfully: {{id}}',
    issueFailed: 'Failed to issue credential',
    revokeConfirm: 'Are you sure you want to revoke this credential?',
    revokeReason: 'User requested revocation',
    revokeSucceeded: 'Credential revoked successfully',
    revokeFailed: 'Failed to revoke credential',
    shareSucceeded: 'Share link copied to clipboard!',
    shareFailed: 'Failed to share credential',
    details: 'Credential Details',
    id: 'Credential ID',
    type: 'Type',
    issuer: 'Issuer',
    subject: 'Subject',
    issuedBy: 'Issued by: {{issuer}}',
    issuanceDate: 'Issuance Date',
    expirationDate: 'Expiration Date',
    data: 'Credential Data',
    proof: 'Proof',
    subjectAddress: 'Subject Address',
    typesLabel: 'Credential Types',
    dataLabel: 'Credential Data (JSON)',
    expirationOptional: 'Expiration Date (Optional)',
    viewDetails: 'View details',
    viewDetailsFor: 'View details for {{label}}',
    exportJson: 'Export as JSON',
    exportJsonFor: 'Export {{label}} as JSON',
    shareAction: 'Share',
    shareFor: 'Share {{label}}',
    revokeAction: 'Revoke',
    revokeFor: 'Revoke {{label}}',
    shareSheetTitle: 'Verifiable Credential',
    shareSheetText: 'Share your verifiable credential',
    requiredFields: 'Please fill in all required fields',
    status: {
      valid: 'Valid',
      revoked: 'Revoked',
      expired: 'Expired',
      unknown: 'Unknown',
    },
  },
  did: {
    title: 'Decentralized Identity (DID)',
    create: 'Create DID',
    createNew: 'Create New DID',
    creating: 'Creating…',
    update: 'Update',
    deactivate: 'Deactivate',
    deactivateConfirm:
      'Are you sure you want to deactivate this DID? This action cannot be undone.',
    deactivateSucceeded: 'DID deactivated successfully',
    empty: 'No DID found for this address',
    emptyHint: 'Create a DID to start managing your decentralized identity',
    loadFailed: 'Loading DID information…',
    createSucceeded: 'DID created successfully: {{did}}',
    createFailed: 'Failed to create DID',
    updateSucceeded: 'DID updated successfully',
    updateFailed: 'Failed to update DID',
    deactivateFailed: 'Failed to deactivate DID',
    verificationMethods: 'Verification Methods',
    services: 'Services',
    currentMethods: 'Current Methods:',
    currentServices: 'Current Services:',
    addMethod: 'Add Verification Method',
    addService: 'Add Service',
    vmRequired: 'Please fill in all verification method fields',
    serviceRequired: 'Please fill in all service fields',
    controller: 'Controller',
    created: 'Created',
    lastUpdated: 'Last Updated',
    publicKey: 'Public Key',
    endpoint: 'Endpoint',
    connecting: 'Connecting to Stellar network…',
    notConnected: 'Not connected to Stellar network',
    notConnectedHint: 'Use the connect function to establish a connection',
  },
  proof: {
    title: 'Zero-Knowledge Proofs',
    create: 'Create Proof',
    createNew: 'Create Zero-Knowledge Proof',
    creating: 'Creating…',
    custom: 'Custom',
    customTitle: 'Custom Proof',
    customDescription: 'Create a custom zero-knowledge proof',
    age: 'Age Verification',
    ageDescription: "Prove you're over 18 without revealing your age",
    income: 'Income Verification',
    incomeDescription: 'Prove minimum income without revealing exact amount',
    identity: 'Identity Verification',
    identityDescription: 'Prove you own a credential without revealing details',
    quickActions: 'Quick Actions',
    myProofs: 'My Proofs',
    availableCircuits: 'Available Circuits',
    empty: 'No proofs found',
    emptyHint: 'Create your first zero-knowledge proof',
    loadFailed: 'Failed to load proofs',
    loading: 'Loading zero-knowledge proofs',
    circuitsLoadFailed: 'Failed to load circuits',
    requiredFields: 'Please fill in all required fields',
    createSucceeded: 'Proof created successfully: {{id}}',
    createFailed: 'Failed to create proof',
    ageSucceeded: 'Age proof created successfully: {{id}}',
    ageFailed: 'Failed to create age proof',
    incomeSucceeded: 'Income proof created successfully: {{id}}',
    incomeFailed: 'Failed to create income proof',
    verifyFailed: 'Failed to verify proof',
    details: 'Proof Details',
    proofId: 'Proof ID',
    circuitId: 'Circuit ID',
    circuitLabel: 'Circuit',
    verifierAddress: 'Verifier Address',
    createdAt: 'Created At',
    expiresAt: 'Expires At',
    expires: 'Expires',
    publicInputs: 'Public Inputs',
    publicInputsCount: 'Public inputs: {{count}}',
    privateInputsCount: 'Private inputs: {{count}}',
    selectCircuit: 'Select circuit',
    inputPlaceholder: 'Input {{index}}',
    addInput: 'Add Input',
    proofBytes: 'Proof Bytes',
    proofBytesPlaceholder: 'Generated proof bytes from ZK circuit',
    expirationDateOptional: 'Expiration Date (Optional)',
    metadata: 'Metadata',
    useCircuit: 'Use Circuit',
    active: 'Active',
    inactive: 'Inactive',
    status: {
      valid: 'Valid',
      invalid: 'Invalid',
    },
  },
  compliance: {
    title: 'Compliance Check',
    refresh: 'Refresh',
    check: 'Check',
    checking: 'Performing compliance check…',
    invalidAddress: 'Invalid Stellar address format',
    checkFailed: 'Failed to perform compliance check',
    status: 'Compliance Status',
    riskScore: 'Risk Score',
    riskLevel: 'Risk Level',
    sanctionsLists: 'Sanctions Lists',
    lastChecked: 'Last Checked',
    metrics: 'Compliance Metrics',
    overallScore: 'Overall Compliance Score',
    totalCredentials: 'Total Credentials',
    validCredentials: 'Valid Credentials',
    recommendations: 'Recommendations',
    detailedAnalysis: 'Detailed Analysis',
    summary: 'Compliance Summary',
    sanctionsScreening: 'Sanctions Screening',
    identityVerification: 'Identity Verification',
    riskAssessment: 'Risk Assessment',
      overallStatus: 'Overall Status',
      addressPlaceholder: 'Enter Stellar address (G...)',
      currentlyChecking: 'Currently checking:',
      listsFound: '{{count}} found',
      noneFound: 'None found',
      validShort: 'Valid',
      risk: {
      high: 'High Risk',
      medium: 'Medium Risk',
      low: 'Low Risk',
      veryLow: 'Very Low Risk',
    },
    verdict: {
      cleared: 'Cleared',
      flagged: 'Flagged',
      blocked: 'Blocked',
      unknown: 'Unknown',
    },
    assessment: {
      clear: 'Clear',
      alert: 'Alert',
      verified: 'Verified',
      notVerified: 'Not Verified',
    },
  },
  reputation: {
    title: 'Reputation Score',
    loading: 'Loading reputation score',
    noData: 'No reputation data available',
    loadFailed: 'Failed to load reputation data',
    scoreRange: 'Score Range',
    totalTransactions: 'Total Transactions',
    successRate: 'Success Rate',
    credentialCount: 'Credential Count',
    percentile: 'Percentile',
    nextTier: 'Next tier: {{tier}}',
    maximum: 'Maximum',
    atPoints: 'at {{count}} points',
    lastUpdated: 'Last Updated',
    factors: 'Reputation Factors',
    noFactors: 'No factor data available',
    activity: 'Recent Activity',
    current: 'Current',
    updatesAgo: '{{count}} updates ago',
    noHistory: 'No history available',
    insights: 'Reputation Insights',
    currentScore: 'Current Score',
    percentileRank: 'Percentile Rank',
    activeFactors: 'Active Factors',
    recommendations: 'Recommendations:',
    recommendationTransactions:
      '• Focus on successful transactions to improve your score',
    recommendationCredentials:
      '• Obtain more verifiable credentials to strengthen your reputation',
    recommendationDeclining:
      '• Recent activity shows a declining trend - consider reviewing recent transactions',
    recommendationExcellent:
      '• Excellent reputation! Maintain your current activity level',
    notAvailable: 'N/A',
    tier: 'Tier:',
    tierProgress: 'Tier Progress:',
    tierLabel: '{{tier}} Tier',
    tiers: {
      diamond: 'Diamond',
      platinum: 'Platinum',
      gold: 'Gold',
      silver: 'Silver',
      bronze: 'Bronze',
      unranked: 'Unranked',
    },
  },
  notifications: {
    title: 'Notifications',
    empty: 'No notifications yet',
    markAllRead: 'Mark all as read',
    clearAll: 'Clear all',
    unreadCount: '{{count}} unread',
    status: {
      idle: 'Inactive',
      connecting: 'Connecting…',
      open: 'Live',
      closed: 'Disconnected',
      error: 'Unavailable',
    },
    type: {
      'credential-issued': 'Credential issued',
      'credential-verified': 'Credential verified',
      'credential-revoked': 'Credential revoked',
      'credential-expiring': 'Credential expiring soon',
      'offer-received': 'Credential offer received',
    },
  },
  time: {
    justNow: 'just now',
    secondsAgo: '{{count}}s ago',
    minutesAgo: '{{count}}m ago',
    hoursAgo: '{{count}}h ago',
    daysAgo: '{{count}}d ago',
    weeksAgo: '{{count}}w ago',
  },
  analytics: {
    dateRange: 'Date range',
    showing: 'Showing the last {{count}} days',
    preset: {
      '7d': '7 days',
      '30d': '30 days',
      '90d': '90 days',
    },
  },
  dashboard: {
    title: 'Stellar Identity Dashboard',
    initializing: 'Initializing Stellar Identity Dashboard',
    connectingTo: 'Connecting to {{network}}…',
    connectWallet:
      'Connect your wallet to manage your decentralized identity, credentials, and reputation.',
    createKeypair: 'Create New Keypair',
    orEnterSecret: 'or enter a secret key below',
    secretPlaceholder: 'Enter your Stellar secret key (starts with S...)',
    address: 'Address',
    status: 'Status',
    credentials: 'Credentials',
    proofs: 'Proofs',
    compliance: 'Compliance',
    reporting: 'Reporting',
    reputation: 'Reputation',
    reputationAnalytics: 'Reputation & Analytics',
    footer:
      'Manage your decentralized identity, verifiable credentials, and reputation on the Stellar {{network}} network.',
    toggleMenu: 'Toggle menu',
    toggleTheme: 'Toggle theme',
    collapseSidebar: 'Collapse sidebar',
    expandSidebar: 'Expand sidebar',
    openNavigation: 'Open navigation',
  },
}

/**
 * A nested message catalogue for one locale.
 *
 * Typing the other locales against the English block is what makes a partial
 * translation a compile error rather than a runtime `undefined` in the UI.
 *
 * The English block is deliberately NOT declared `as const`. `as const` would
 * widen each leaf to a string *literal* type, so `es.common.loading` would
 * have to be the exact text `'Loading…'` rather than any string — which
 * inverts the check and rejects every real translation.
 */
export type Messages = typeof en;

/**
 * Interpolate `{{name}}` placeholders.
 *
 * Deliberately not a full ICU implementation: it handles the named
 * interpolation the components need, and refuses to silently produce a
 * half-substituted string. A missing placeholder is left visible as
 * `{{name}}` rather than blanked, so a translation gap is obvious during
 * development instead of producing a confusing empty gap in the UI.
 */
function interpolate(
  template: string,
  values?: Record<string, string | number>,
): string {
  if (!values) return template;
  return template.replace(/\{\{(\w+)\}\}/g, (match, key: string) => {
    const value = values[key];
    return value === undefined ? match : String(value);
  });
}

/**
 * Look up a dot-namespaced key in a catalogue, falling back to English and
 * then to the key itself.
 */
function lookup(catalogue: Record<string, unknown>, key: string): string | undefined {
  const value = key
    .split('.')
    .reduce<unknown>(
      (acc, part) =>
        acc && typeof acc === 'object' ? (acc as Record<string, unknown>)[part] : undefined,
      catalogue,
    );
  return typeof value === 'string' ? value : undefined;
}

// ── Translations ─────────────────────────────────────────────────────────────

/**
 * Message catalogues.
 *
 * Each locale is typed against {@link Messages}, so omitting a key is a
 * compile error. That matters because a partially-translated catalogue would
 * otherwise show raw keys to users in exactly the languages that most need
 * the translation.
 */
export const TRANSLATIONS: Readonly<Record<SupportedLocale, Messages>> = {
  en,
  es: {
    common: {
      loading: 'Cargando…',
      error: 'Error',
      retry: 'Reintentar',
      cancel: 'Cancelar',
      close: 'Cerrar',
      save: 'Guardar',
      confirm: 'Confirmar',
      copy: 'Copiar',
      copied: '¡Copiado!',
      loadingAria: 'Cargando',
    },
    network: {
      title: 'Red',
      switchTo: 'Cambiar de red',
      switching: 'Cambiando…',
      connected: 'Conectado',
      disconnected: 'Desconectado',
      connect: 'Conectar',
      disconnect: 'Desconectar',
      language: 'Idioma',
    },
    credential: {
      wallet: 'Cartera de Credenciales',
      issue: 'Emitir Credencial',
      issueNew: 'Emitir Nueva Credencial',
      issuing: 'Emitiendo…',
      empty: 'No se encontraron credenciales',
      emptyHint: 'Emite tu primera credencial para empezar',
      loadFailed: 'No se pudieron cargar las credenciales',
      issueSucceeded: 'Credencial emitida correctamente: {{id}}',
      issueFailed: 'No se pudo emitir la credencial',
      revokeConfirm: '¿Seguro que quieres revocar esta credencial?',
      revokeReason: 'El usuario solicitó la revocación',
      revokeSucceeded: 'Credencial revocada correctamente',
      revokeFailed: 'No se pudo revocar la credencial',
      shareSucceeded: '¡Enlace copiado al portapapeles!',
      shareFailed: 'No se pudo compartir la credencial',
      details: 'Detalles de la Credencial',
      id: 'ID de Credencial',
      type: 'Tipo',
      issuer: 'Emisor',
      subject: 'Sujeto',
      issuedBy: 'Emitido por: {{issuer}}',
      issuanceDate: 'Fecha de Emisión',
      expirationDate: 'Fecha de Vencimiento',
      data: 'Datos de la Credencial',
      proof: 'Prueba',
      subjectAddress: 'Dirección del Sujeto',
      typesLabel: 'Tipos de Credencial',
      dataLabel: 'Datos de la Credencial (JSON)',
      expirationOptional: 'Fecha de Vencimiento (Opcional)',
      viewDetails: 'Ver detalles',
      viewDetailsFor: 'Ver detalles de {{label}}',
      exportJson: 'Exportar como JSON',
      exportJsonFor: 'Exportar {{label}} como JSON',
      shareAction: 'Compartir',
      shareFor: 'Compartir {{label}}',
      revokeAction: 'Revocar',
      revokeFor: 'Revocar {{label}}',
      shareSheetTitle: 'Credencial Verificable',
      shareSheetText: 'Comparte tu credencial verificable',
      requiredFields: 'Por favor, completa todos los campos obligatorios',
      status: {
        valid: 'Válida',
        revoked: 'Revocada',
        expired: 'Expirada',
        unknown: 'Desconocida',
      },
    },
    did: {
      title: 'Identidad Descentralizada (DID)',
      create: 'Crear DID',
      createNew: 'Crear Nuevo DID',
      creating: 'Creando…',
      update: 'Actualizar',
      deactivate: 'Desactivar',
      deactivateConfirm:
        '¿Seguro que quieres desactivar este DID? Esta acción no se puede deshacer.',
      deactivateSucceeded: 'DID desactivado correctamente',
      empty: 'No se encontró ningún DID para esta dirección',
      emptyHint: 'Crea un DID para gestionar tu identidad descentralizada',
      loadFailed: 'Cargando información del DID…',
      createSucceeded: 'DID creado correctamente: {{did}}',
      createFailed: 'No se pudo crear el DID',
      updateSucceeded: 'DID actualizado correctamente',
      updateFailed: 'No se pudo actualizar el DID',
      deactivateFailed: 'No se pudo desactivar el DID',
      verificationMethods: 'Métodos de Verificación',
      services: 'Servicios',
      currentMethods: 'Métodos Actuales:',
      currentServices: 'Servicios Actuales:',
      addMethod: 'Añadir Método de Verificación',
      addService: 'Añadir Servicio',
      vmRequired: 'Por favor, completa todos los campos del método de verificación',
      serviceRequired: 'Por favor, completa todos los campos del servicio',
      controller: 'Controlador',
      created: 'Creado',
      lastUpdated: 'Última Actualización',
      publicKey: 'Clave Pública',
      endpoint: 'Punto Final',
      connecting: 'Conectando a la red Stellar…',
      notConnected: 'No conectado a la red Stellar',
      notConnectedHint: 'Usa la función connect para establecer una conexión',
    },
    proof: {
      title: 'Pruebas de Conocimiento Cero',
      create: 'Crear Prueba',
      createNew: 'Crear Prueba de Conocimiento Cero',
      creating: 'Creando…',
      custom: 'Personalizada',
      customTitle: 'Prueba Personalizada',
      customDescription: 'Crear una prueba de conocimiento cero personalizada',
      age: 'Verificación de Edad',
      ageDescription: 'Demuestra que tienes más de 18 años sin revelar tu edad',
      income: 'Verificación de Ingresos',
      incomeDescription: 'Demuestra ingresos mínimos sin revelar la cantidad exacta',
      identity: 'Verificación de Identidad',
      identityDescription: 'Demuestra que posees una credencial sin revelar detalles',
      quickActions: 'Acciones Rápidas',
      myProofs: 'Mis Pruebas',
      availableCircuits: 'Circuitos Disponibles',
      empty: 'No se encontraron pruebas',
      emptyHint: 'Crea tu primera prueba de conocimiento cero',
      loadFailed: 'No se pudieron cargar las pruebas',
      loading: 'Cargando pruebas de conocimiento cero',
      circuitsLoadFailed: 'No se pudieron cargar los circuitos',
      requiredFields: 'Por favor, completa todos los campos obligatorios',
      createSucceeded: 'Prueba creada correctamente: {{id}}',
      createFailed: 'No se pudo crear la prueba',
      ageSucceeded: 'Prueba de edad creada correctamente: {{id}}',
      ageFailed: 'No se pudo crear la prueba de edad',
      incomeSucceeded: 'Prueba de ingresos creada correctamente: {{id}}',
      incomeFailed: 'No se pudo crear la prueba de ingresos',
      verifyFailed: 'No se pudo verificar la prueba',
      details: 'Detalles de la Prueba',
      proofId: 'ID de Prueba',
      circuitId: 'ID del Circuito',
      circuitLabel: 'Circuito',
      verifierAddress: 'Dirección del Verificador',
      createdAt: 'Creado el',
      expiresAt: 'Expira el',
      expires: 'Expira',
      publicInputs: 'Entradas Públicas',
      publicInputsCount: 'Entradas públicas: {{count}}',
      privateInputsCount: 'Entradas privadas: {{count}}',
      selectCircuit: 'Selecciona un circuito',
      inputPlaceholder: 'Entrada {{index}}',
      addInput: 'Añadir Entrada',
      proofBytes: 'Bytes de la Prueba',
      proofBytesPlaceholder: 'Bytes de la prueba generados por el circuito ZK',
      expirationDateOptional: 'Fecha de Vencimiento (Opcional)',
      metadata: 'Metadatos',
      useCircuit: 'Usar Circuito',
      active: 'Activo',
      inactive: 'Inactivo',
      status: {
        valid: 'Válida',
        invalid: 'Inválida',
      },
    },
    compliance: {
      title: 'Verificación de Cumplimiento',
      refresh: 'Actualizar',
      check: 'Verificar',
      checking: 'Realizando verificación de cumplimiento…',
      invalidAddress: 'Formato de dirección Stellar inválido',
      checkFailed: 'No se pudo realizar la verificación de cumplimiento',
      status: 'Estado de Cumplimiento',
      riskScore: 'Puntuación de Riesgo',
      riskLevel: 'Nivel de Riesgo',
      sanctionsLists: 'Listas de Sanciones',
      lastChecked: 'Última Verificación',
      metrics: 'Métricas de Cumplimiento',
      overallScore: 'Puntuación General de Cumplimiento',
      totalCredentials: 'Credenciales Totales',
      validCredentials: 'Credenciales Válidas',
      recommendations: 'Recomendaciones',
      detailedAnalysis: 'Análisis Detallado',
      summary: 'Resumen de Cumplimiento',
      sanctionsScreening: 'Cribado de Sanciones:',
      identityVerification: 'Verificación de Identidad:',
      riskAssessment: 'Evaluación de Riesgo:',
      overallStatus: 'Estado General:',
      addressPlaceholder: 'Introduce una dirección Stellar (G...)',
      currentlyChecking: 'Comprobando actualmente:',
      listsFound: '{{count}} encontradas',
      noneFound: 'Ninguna encontrada',
      validShort: 'Válidas',
      risk: {
        high: 'Riesgo Alto',
        medium: 'Riesgo Medio',
        low: 'Riesgo Bajo',
        veryLow: 'Riesgo Muy Bajo',
      },
      verdict: {
        cleared: 'Desbloqueado',
        flagged: 'Marcado',
        blocked: 'Bloqueado',
        unknown: 'Desconocido',
      },
      assessment: {
        clear: 'Claro',
        alert: 'Alerta',
        verified: 'Verificado',
        notVerified: 'No Verificado',
      },
    },
    reputation: {
      title: 'Puntuación de Reputación',
      loading: 'Cargando puntuación de reputación',
      noData: 'No hay datos de reputación disponibles',
      loadFailed: 'No se pudieron cargar los datos de reputación',
      scoreRange: 'Rango de Puntuación',
      totalTransactions: 'Transacciones Totales',
      successRate: 'Tasa de Éxito',
      credentialCount: 'Credenciales',
      percentile: 'Percentil',
      nextTier: 'Siguiente nivel: {{tier}}',
      maximum: 'Máximo',
      atPoints: 'a {{count}} puntos',
      lastUpdated: 'Última Actualización',
      factors: 'Factores de Reputación',
      noFactors: 'No hay datos de factores disponibles',
      activity: 'Actividad Reciente',
      current: 'Actual',
      updatesAgo: 'hace {{count}} actualizaciones',
      noHistory: 'No hay historial disponible',
      insights: 'Perspectivas de Reputación',
      currentScore: 'Puntuación Actual',
      percentileRank: 'Rango Percentual',
      activeFactors: 'Factores Activos',
      recommendations: 'Recomendaciones:',
      recommendationTransactions:
        '• Céntrate en las transacciones exitosas para mejorar tu puntuación',
      recommendationCredentials:
        '• Obtén más credenciales verificables para fortalecer tu reputación',
      recommendationDeclining:
        '• La actividad reciente muestra una tendencia a la baja: revisa las transacciones recientes',
      recommendationExcellent:
        '• ¡Excelente reputación! Mantén tu nivel de actividad actual',
      notAvailable: 'N/D',
      tier: 'Nivel:',
      tierProgress: 'Progreso del nivel:',
      tierLabel: 'Nivel {{tier}}',
      tiers: {
        diamond: 'Diamante',
        platinum: 'Platino',
        gold: 'Oro',
        silver: 'Plata',
        bronze: 'Bronce',
        unranked: 'Sin Rango',
      },
    },
    notifications: {
      title: 'Notificaciones',
      empty: 'Aún no hay notificaciones',
      markAllRead: 'Marcar todas como leídas',
      clearAll: 'Limpiar todo',
      unreadCount: '{{count}} sin leer',
      status: {
        idle: 'Inactivo',
        connecting: 'Conectando…',
        open: 'En vivo',
        closed: 'Desconectado',
        error: 'No disponible',
      },
      type: {
        'credential-issued': 'Credencial emitida',
        'credential-verified': 'Credencial verificada',
        'credential-revoked': 'Credencial revocada',
        'credential-expiring': 'Credencial próxima a expirar',
        'offer-received': 'Oferta de credencial recibida',
      },
    },
    time: {
      justNow: 'ahora mismo',
      secondsAgo: 'hace {{count}}s',
      minutesAgo: 'hace {{count}}m',
      hoursAgo: 'hace {{count}}h',
      daysAgo: 'hace {{count}}d',
      weeksAgo: 'hace {{count}}sem',
    },
    analytics: {
      dateRange: 'Rango de fechas',
      showing: 'Mostrando los últimos {{count}} días',
      preset: {
        '7d': '7 días',
        '30d': '30 días',
        '90d': '90 días',
      },
    },
    dashboard: {
      title: 'Panel de Identidad Stellar',
      initializing: 'Iniciando el panel de identidad Stellar',
      connectingTo: 'Conectando a {{network}}…',
      connectWallet:
        'Conecta tu cartera para gestionar tu identidad descentralizada, credenciales y reputación.',
      createKeypair: 'Crear Nuevo Par de Claves',
      orEnterSecret: 'o introduce una clave secreta abajo',
      secretPlaceholder: 'Introduce tu clave secreta Stellar (empieza con S...)',
      address: 'Dirección',
      status: 'Estado',
      credentials: 'Credenciales',
      proofs: 'Pruebas',
      compliance: 'Cumplimiento',
      reporting: 'Informes',
      reputation: 'Reputación',
      reputationAnalytics: 'Reputación y Analítica',
      footer:
        'Gestiona tu identidad descentralizada, credenciales verificables y reputación en la red Stellar {{network}}.',
      toggleMenu: 'Alternar menú',
      toggleTheme: 'Alternar tema',
      collapseSidebar: 'Contraer barra lateral',
      expandSidebar: 'Expandir barra lateral',
      openNavigation: 'Abrir navegación',
    },
  },
  fr: {
    common: {
      loading: 'Chargement…',
      error: 'Erreur',
      retry: 'Réessayer',
      cancel: 'Annuler',
      close: 'Fermer',
      save: 'Enregistrer',
      confirm: 'Confirmer',
      copy: 'Copier',
      copied: 'Copié !',
      loadingAria: 'Chargement',
    },
    network: {
      title: 'Réseau',
      switchTo: 'Changer de réseau',
      switching: 'Changement…',
      connected: 'Connecté',
      disconnected: 'Déconnecté',
      connect: 'Connecter',
      disconnect: 'Déconnecter',
      language: 'Langue',
    },
    credential: {
      wallet: 'Portefeuille de Credentials',
      issue: 'Émettre un Credential',
      issueNew: 'Émettre un Nouveau Credential',
      issuing: 'Émission…',
      empty: 'Aucun credential trouvé',
      emptyHint: 'Émettez votre premier credential pour commencer',
      loadFailed: 'Échec du chargement des credentials',
      issueSucceeded: 'Credential émis avec succès : {{id}}',
      issueFailed: "Échec de l'émission du credential",
      revokeConfirm: 'Voulez-vous vraiment révoquer ce credential ?',
      revokeReason: "Révocation demandée par l'utilisateur",
      revokeSucceeded: 'Credential révoqué avec succès',
      revokeFailed: 'Échec de la révocation du credential',
      shareSucceeded: 'Lien copié dans le presse-papiers !',
      shareFailed: 'Échec du partage du credential',
      details: 'Détails du Credential',
      id: 'ID du Credential',
      type: 'Type',
      issuer: 'Émetteur',
      subject: 'Sujet',
      issuedBy: 'Émis par : {{issuer}}',
      issuanceDate: "Date d'émission",
      expirationDate: "Date d'expiration",
      data: 'Données du Credential',
      proof: 'Preuve',
      subjectAddress: 'Adresse du Sujet',
      typesLabel: 'Types de Credential',
      dataLabel: 'Données du Credential (JSON)',
      expirationOptional: "Date d'expiration (Optionnel)",
      viewDetails: 'Voir les détails',
      viewDetailsFor: 'Voir les détails de {{label}}',
      exportJson: 'Exporter en JSON',
      exportJsonFor: 'Exporter {{label}} en JSON',
      shareAction: 'Partager',
      shareFor: 'Partager {{label}}',
      revokeAction: 'Révoquer',
      revokeFor: 'Révoquer {{label}}',
      shareSheetTitle: 'Credential Vérifiable',
      shareSheetText: 'Partagez votre credential vérifiable',
      requiredFields: 'Veuillez remplir tous les champs obligatoires',
      status: {
        valid: 'Valide',
        revoked: 'Révoqué',
        expired: 'Expiré',
        unknown: 'Inconnu',
      },
    },
    did: {
      title: 'Identité Décentralisée (DID)',
      create: 'Créer un DID',
      createNew: 'Créer un Nouveau DID',
      creating: 'Création…',
      update: 'Mettre à jour',
      deactivate: 'Désactiver',
      deactivateConfirm:
        'Voulez-vous vraiment désactiver ce DID ? Cette action est irréversible.',
      deactivateSucceeded: 'DID désactivé avec succès',
      empty: 'Aucun DID trouvé pour cette adresse',
      emptyHint: 'Créez un DID pour gérer votre identité décentralisée',
      loadFailed: 'Chargement des informations du DID…',
      createSucceeded: 'DID créé avec succès : {{did}}',
      createFailed: 'Échec de la création du DID',
      updateSucceeded: 'DID mis à jour avec succès',
      updateFailed: 'Échec de la mise à jour du DID',
      deactivateFailed: 'Échec de la désactivation du DID',
      verificationMethods: 'Méthodes de Vérification',
      services: 'Services',
      currentMethods: 'Méthodes Actuelles :',
      currentServices: 'Services Actuels :',
      addMethod: 'Ajouter une Méthode de Vérification',
      addService: 'Ajouter un Service',
      vmRequired: 'Veuillez remplir tous les champs de la méthode de vérification',
      serviceRequired: 'Veuillez remplir tous les champs du service',
      controller: 'Contrôleur',
      created: 'Créé',
      lastUpdated: 'Dernière Mise à Jour',
      publicKey: 'Clé Publique',
      endpoint: 'Point de Terminaison',
      connecting: 'Connexion au réseau Stellar…',
      notConnected: 'Non connecté au réseau Stellar',
      notConnectedHint: "Utilisez la fonction connect pour établir une connexion",
    },
    proof: {
      title: 'Preuves à Connaissance Zéro',
      create: 'Créer une Preuve',
      createNew: 'Créer une Preuve à Connaissance Zéro',
      creating: 'Création…',
      custom: 'Personnalisée',
      customTitle: 'Preuve Personnalisée',
      customDescription: 'Créer une preuve à connaissance zéro personnalisée',
      age: "Vérification d'Âge",
      ageDescription: "Prouvez que vous avez plus de 18 ans sans révéler votre âge",
      income: 'Vérification de Revenu',
      incomeDescription: 'Prouvez un revenu minimum sans révéler le montant exact',
      identity: "Vérification d'Identité",
      identityDescription: 'Prouvez que vous détenez un credential sans révéler de détails',
      quickActions: 'Actions Rapides',
      myProofs: 'Mes Preuves',
      availableCircuits: 'Circuits Disponibles',
      empty: 'Aucune preuve trouvée',
      emptyHint: 'Créez votre première preuve à connaissance zéro',
      loadFailed: 'Échec du chargement des preuves',
      loading: 'Chargement des preuves à connaissance zéro',
      circuitsLoadFailed: 'Échec du chargement des circuits',
      requiredFields: 'Veuillez remplir tous les champs obligatoires',
      createSucceeded: 'Preuve créée avec succès : {{id}}',
      createFailed: 'Échec de la création de la preuve',
      ageSucceeded: "Preuve d'âge créée avec succès : {{id}}",
      ageFailed: "Échec de la création de la preuve d'âge",
      incomeSucceeded: 'Preuve de revenu créée avec succès : {{id}}',
      incomeFailed: 'Échec de la création de la preuve de revenu',
      verifyFailed: 'Échec de la vérification de la preuve',
      details: 'Détails de la Preuve',
      proofId: 'ID de Preuve',
      circuitId: 'ID du Circuit',
      circuitLabel: 'Circuit',
      verifierAddress: 'Adresse du Vérificateur',
      createdAt: 'Créé le',
      expiresAt: 'Expire le',
      expires: 'Expire',
      publicInputs: 'Entrées Publiques',
      publicInputsCount: 'Entrées publiques : {{count}}',
      privateInputsCount: 'Entrées privées : {{count}}',
      selectCircuit: 'Sélectionnez un circuit',
      inputPlaceholder: 'Entrée {{index}}',
      addInput: 'Ajouter une Entrée',
      proofBytes: 'Octets de Preuve',
      proofBytesPlaceholder: 'Octets de preuve générés par le circuit ZK',
      expirationDateOptional: 'Date d\'Expiration (Facultatif)',
      metadata: 'Métadonnées',
      useCircuit: 'Utiliser le Circuit',
      active: 'Actif',
      inactive: 'Inactif',
      status: {
        valid: 'Valide',
        invalid: 'Invalide',
      },
    },
    compliance: {
      title: 'Vérification de Conformité',
      refresh: 'Actualiser',
      check: 'Vérifier',
      checking: 'Vérification de conformité en cours…',
      invalidAddress: 'Format d\'adresse Stellar invalide',
      checkFailed: 'Échec de la vérification de conformité',
      status: 'État de Conformité',
      riskScore: 'Score de Risque',
      riskLevel: 'Niveau de Risque',
      sanctionsLists: 'Listes de Sanctions',
      lastChecked: 'Dernière Vérification',
      metrics: 'Métriques de Conformité',
      overallScore: 'Score Global de Conformité',
      totalCredentials: 'Total des Credentials',
      validCredentials: 'Credentials Valides',
      recommendations: 'Recommandations',
      detailedAnalysis: 'Analyse Détaillée',
      summary: 'Résumé de Conformité',
      sanctionsScreening: 'Criblage des Sanctions :',
      identityVerification: "Vérification d'Identité :",
      riskAssessment: 'Évaluation du Risque :',
      overallStatus: 'État Global :',
      addressPlaceholder: 'Saisissez une adresse Stellar (G...)',
      currentlyChecking: 'Vérification en cours :',
      listsFound: '{{count}} trouvée(s)',
      noneFound: 'Aucune trouvée',
      validShort: 'Valides',
      risk: {
        high: 'Risque Élevé',
        medium: 'Risque Moyen',
        low: 'Risque Faible',
        veryLow: 'Risque Très Faible',
      },
      verdict: {
        cleared: 'Dégagé',
        flagged: 'Signalé',
        blocked: 'Bloqué',
        unknown: 'Inconnu',
      },
      assessment: {
        clear: 'Favorable',
        alert: 'Alerte',
        verified: 'Vérifié',
        notVerified: 'Non Vérifié',
      },
    },
    reputation: {
      title: 'Score de Réputation',
      loading: 'Chargement du score de réputation',
      noData: 'Aucune donnée de réputation disponible',
      loadFailed: 'Échec du chargement des données de réputation',
      scoreRange: 'Plage de Score',
      totalTransactions: 'Transactions Totales',
      successRate: 'Taux de Réussite',
      credentialCount: 'Nombre de Credentials',
      percentile: 'Percentile',
      nextTier: 'Palier suivant : {{tier}}',
      maximum: 'Maximum',
      atPoints: 'à {{count}} points',
      lastUpdated: 'Dernière Mise à Jour',
      factors: 'Facteurs de Réputation',
      noFactors: 'Aucune donnée de facteur disponible',
      activity: 'Activité Récente',
      current: 'Actuel',
      updatesAgo: 'il y a {{count}} mises à jour',
      noHistory: 'Aucun historique disponible',
      insights: 'Analyses de Réputation',
      currentScore: 'Score Actuel',
      percentileRank: 'Rang Percentile',
      activeFactors: 'Facteurs Actifs',
      recommendations: 'Recommandations :',
      recommendationTransactions:
        '• Concentrez-vous sur les transactions réussies pour améliorer votre score',
      recommendationCredentials:
        "• Obtenez davantage de credentials vérifiables pour renforcer votre réputation",
      recommendationDeclining:
        "• L'activité récente montre une tendance à la baisse - consultez vos transactions récentes",
      recommendationExcellent:
        '• Excellente réputation ! Maintenez votre niveau d\'activité actuel',
      notAvailable: 'N/D',
      tier: 'Palier :',
      tierProgress: 'Progression du palier :',
      tierLabel: 'Palier {{tier}}',
      tiers: {
        diamond: 'Diamant',
        platinum: 'Platine',
        gold: 'Or',
        silver: 'Argent',
        bronze: 'Bronze',
        unranked: 'Non Classé',
      },
    },
    notifications: {
      title: 'Notifications',
      empty: 'Aucune notification pour le moment',
      markAllRead: 'Tout marquer comme lu',
      clearAll: 'Tout effacer',
      unreadCount: '{{count}} non lues',
      status: {
        idle: 'Inactif',
        connecting: 'Connexion…',
        open: 'En direct',
        closed: 'Déconnecté',
        error: 'Indisponible',
      },
      type: {
        'credential-issued': 'Credential émis',
        'credential-verified': 'Credential vérifié',
        'credential-revoked': 'Credential révoqué',
        'credential-expiring': 'Credential bientôt expiré',
        'offer-received': 'Offre de credential reçue',
      },
    },
    time: {
      justNow: "à l'instant",
      secondsAgo: 'il y a {{count}}s',
      minutesAgo: 'il y a {{count}}m',
      hoursAgo: 'il y a {{count}}h',
      daysAgo: 'il y a {{count}}j',
      weeksAgo: 'il y a {{count}}sem',
    },
    analytics: {
      dateRange: 'Période',
      showing: 'Affichage des {{count}} derniers jours',
      preset: {
        '7d': '7 jours',
        '30d': '30 jours',
        '90d': '90 jours',
      },
    },
    dashboard: {
      title: 'Tableau de Bord Identité Stellar',
      initializing: 'Initialisation du tableau de bord identité Stellar',
      connectingTo: 'Connexion à {{network}}…',
      connectWallet:
        'Connectez votre portefeuille pour gérer votre identité décentralisée, vos credentials et votre réputation.',
      createKeypair: 'Créer une Nouvelle Paire de Clés',
      orEnterSecret: 'ou saisissez une clé secrète ci-dessous',
      secretPlaceholder: 'Saisissez votre clé secrète Stellar (commence par S...)',
      address: 'Adresse',
      status: 'État',
      credentials: 'Credentials',
      proofs: 'Preuves',
      compliance: 'Conformité',
      reporting: 'Rapports',
      reputation: 'Réputation',
      reputationAnalytics: 'Réputation et Analyses',
      footer:
        'Gérez votre identité décentralisée, vos credentials vérifiables et votre réputation sur le réseau Stellar {{network}}.',
      toggleMenu: 'Afficher/masquer le menu',
      toggleTheme: 'Changer de thème',
      collapseSidebar: 'Réduire la barre latérale',
      expandSidebar: 'Développer la barre latérale',
      openNavigation: 'Ouvrir la navigation',
    },
  },
  ja: {
    common: {
      loading: '読み込み中…',
      error: 'エラー',
      retry: '再試行',
      cancel: 'キャンセル',
      close: '閉じる',
      save: '保存',
      confirm: '確認',
      copy: 'コピー',
      copied: 'コピーしました！',
      loadingAria: '読み込み中',
    },
    network: {
      title: 'ネットワーク',
      switchTo: 'ネットワークを切り替え',
      switching: '切り替え中…',
      connected: '接続済み',
      disconnected: '未接続',
      connect: '接続',
      disconnect: '切断',
      language: '言語',
    },
    credential: {
      wallet: 'クレデンシャルウォレット',
      issue: 'クレデンシャルを発行',
      issueNew: '新しいクレデンシャルを発行',
      issuing: '発行中…',
      empty: 'クレデンシャルが見つかりません',
      emptyHint: '最初のクレデンシャルを発行して始めましょう',
      loadFailed: 'クレデンシャルの読み込みに失敗しました',
      issueSucceeded: 'クレデンシャルを発行しました: {{id}}',
      issueFailed: 'クレデンシャルの発行に失敗しました',
      revokeConfirm: 'このクレデンシャルを失効させてもよろしいですか？',
      revokeReason: 'ユーザーによる失効要求',
      revokeSucceeded: 'クレデンシャルを失効させました',
      revokeFailed: 'クレデンシャルの失効に失敗しました',
      shareSucceeded: '共有リンクをコピーしました！',
      shareFailed: 'クレデンシャルの共有に失敗しました',
      details: 'クレデンシャルの詳細',
      id: 'クレデンシャルID',
      type: '種類',
      issuer: '発行者',
      subject: 'subject',
      issuedBy: '発行者: {{issuer}}',
      issuanceDate: '発行日',
      expirationDate: '有効期限',
      data: 'クレデンシャルデータ',
      proof: '証明',
      subjectAddress: 'subjectアドレス',
      typesLabel: 'クレデンシャル種別',
      dataLabel: 'クレデンシャルデータ (JSON)',
      expirationOptional: '有効期限 (任意)',
      viewDetails: '詳細を表示',
      viewDetailsFor: '{{label}} の詳細を表示',
      exportJson: 'JSONでエクスポート',
      exportJsonFor: '{{label}} をJSONでエクスポート',
      shareAction: '共有',
      shareFor: '{{label}} を共有',
      revokeAction: '取り消す',
      revokeFor: '{{label}} を取り消す',
      shareSheetTitle: '検証可能クレデンシャル',
      shareSheetText: '検証可能クレデンシャルを共有',
      requiredFields: 'すべての必須項目を入力してください',
      status: {
        valid: '有効',
        revoked: '失効済み',
        expired: '期限切れ',
        unknown: '不明',
      },
    },
    did: {
      title: '分散型アイデンティティ (DID)',
      create: 'DIDを作成',
      createNew: '新しいDIDを作成',
      creating: '作成中…',
      update: '更新',
      deactivate: '無効化',
      deactivateConfirm:
        'このDIDを無効化してもよろしいですか？この操作は取り消せません。',
      deactivateSucceeded: 'DIDを無効化しました',
      empty: 'このアドレスのDIDが見つかりません',
      emptyHint: 'DIDを作成して分散型アイデンティティを管理しましょう',
      loadFailed: 'DID情報を読み込み中…',
      createSucceeded: 'DIDを作成しました: {{did}}',
      createFailed: 'DIDの作成に失敗しました',
      updateSucceeded: 'DIDを更新しました',
      updateFailed: 'DIDの更新に失敗しました',
      deactivateFailed: 'DIDの無効化に失敗しました',
      verificationMethods: '検証方法',
      services: 'サービス',
      currentMethods: '現在の検証方法:',
      currentServices: '現在のサービス:',
      addMethod: '検証方法を追加',
      addService: 'サービスを追加',
      vmRequired: '検証方法のすべての項目を入力してください',
      serviceRequired: 'サービスのすべての項目を入力してください',
      controller: 'コントローラー',
      created: '作成日',
      lastUpdated: '最終更新',
      publicKey: '公開鍵',
      endpoint: 'エンドポイント',
      connecting: 'Stellarネットワークに接続中…',
      notConnected: 'Stellarネットワークに接続されていません',
      notConnectedHint: 'connect関数を使用して接続を確立してください',
    },
    proof: {
      title: 'ゼロ知識証明',
      create: '証明を作成',
      createNew: 'ゼロ知識証明を作成',
      creating: '作成中…',
      custom: 'カスタム',
      customTitle: 'カスタム証明',
      customDescription: 'カスタムゼロ知識証明を作成',
      age: '年齢検証',
      ageDescription: '年齢を明かさずに18歳以上であることを証明',
      income: '収入検証',
      incomeDescription: '正確な金額を開示せずに最低収入を証明',
      identity: 'アイデンティティ検証',
      identityDescription: '詳細を開かずにクレデンシャルを所有していることを証明',
      quickActions: 'クイックアクション',
      myProofs: 'マイ証明',
      availableCircuits: '利用可能なサーキット',
      empty: '証明が見つかりません',
      emptyHint: '最初のゼロ知識証明を作成しましょう',
      loadFailed: '証明の読み込みに失敗しました',
      loading: 'ゼロ知識証明を読み込み中…',
      circuitsLoadFailed: 'サーキットの読み込みに失敗しました',
      requiredFields: 'すべての必須項目を入力してください',
      createSucceeded: '証明を作成しました: {{id}}',
      createFailed: '証明の作成に失敗しました',
      ageSucceeded: '年齢証明を作成しました: {{id}}',
      ageFailed: '年齢証明の作成に失敗しました',
      incomeSucceeded: '収入証明を作成しました: {{id}}',
      incomeFailed: '収入証明の作成に失敗しました',
      verifyFailed: '証明の検証に失敗しました',
      details: '証明の詳細',
      proofId: '証明ID',
      circuitId: 'サーキットID',
      circuitLabel: 'サーキット',
      verifierAddress: '検証者アドレス',
      createdAt: '作成日時',
      expiresAt: '有効期限',
      expires: '有効期限',
      publicInputs: '公開入力',
      publicInputsCount: '公開入力: {{count}}',
      privateInputsCount: '非公開入力: {{count}}',
      selectCircuit: 'サーキットを選択',
      inputPlaceholder: '入力 {{index}}',
      addInput: '入力を追加',
      proofBytes: '証明バイト',
      proofBytesPlaceholder: 'ZKサーキットが生成した証明バイト',
      expirationDateOptional: '有効期限（任意）',
      metadata: 'メタデータ',
      useCircuit: 'サーキットを使用',
      active: 'アクティブ',
      inactive: '非アクティブ',
      status: {
        valid: '有効',
        invalid: '無効',
      },
    },
    compliance: {
      title: 'コンプライアンス確認',
      refresh: '更新',
      check: '確認',
      checking: 'コンプライアンスを確認中…',
      invalidAddress: 'Stellarアドレスの形式が不正です',
      checkFailed: 'コンプライアンス確認に失敗しました',
      status: 'コンプライアンス状態',
      riskScore: 'リスクスコア',
      riskLevel: 'リスクレベル',
      sanctionsLists: '制裁リスト',
      lastChecked: '最終確認',
      metrics: 'コンプライアンス指標',
      overallScore: '総合コンプライアンススコア',
      totalCredentials: 'クレデンシャル総数',
      validCredentials: '有効なクレデンシャル',
      recommendations: '推奨事項',
      detailedAnalysis: '詳細分析',
      summary: 'コンプライアンス概要',
      sanctionsScreening: '制裁スクリーニング:',
      identityVerification: 'アイデンティティ検証:',
      riskAssessment: 'リスク評価:',
      overallStatus: '総合状態:',
      addressPlaceholder: 'Stellarアドレスを入力（G...）',
      currentlyChecking: '確認中:',
      listsFound: '{{count}}件',
      noneFound: '該当なし',
      validShort: '有効',
      risk: {
        high: '高リスク',
        medium: '中リスク',
        low: '低リスク',
        veryLow: '非常に低リスク',
      },
      verdict: {
        cleared: 'クリア',
        flagged: '要注意',
        blocked: 'ブロック',
        unknown: '不明',
      },
      assessment: {
        clear: 'クリア',
        alert: 'アラート',
        verified: '検証済み',
        notVerified: '未検証',
      },
    },
    reputation: {
      title: '評判スコア',
      loading: '評判スコアを読み込み中',
      noData: '評判データがありません',
      loadFailed: '評判データの読み込みに失敗しました',
      scoreRange: 'スコア範囲',
      totalTransactions: '取引総数',
      successRate: '成功率',
      credentialCount: 'クレデンシャル数',
      percentile: 'パーセンタイル',
      nextTier: '次のティア: {{tier}}',
      maximum: '最大',
      atPoints: '{{count}}ポイントで',
      lastUpdated: '最終更新',
      factors: '評判の要因',
      noFactors: '要因データがありません',
      activity: '最近のアクティビティ',
      current: '現在',
      updatesAgo: '{{count}}回の更新前',
      noHistory: '履歴がありません',
      insights: '評判のインサイト',
      currentScore: '現在のスコア',
      percentileRank: 'パーセンタイル順位',
      activeFactors: '有効な要因',
      recommendations: '推奨事項:',
      recommendationTransactions:
        '• スコアを上げるために成功する取引に注力しましょう',
      recommendationCredentials:
        '• より多くの検証可能なクレデンシャルを取得して評判を強化しましょう',
      recommendationDeclining:
        '• 最近のアクティビティは下降トレンドです。最近の取引を確認しましょう',
      recommendationExcellent:
        '• 素晴らしい評判です！現在のアクティビティ水準を維持しましょう',
      notAvailable: '該当なし',
      tier: 'ティア:',
      tierProgress: 'ティアの進捗:',
      tierLabel: '{{tier}}ティア',
      tiers: {
        diamond: 'ダイヤモンド',
        platinum: 'プラチナ',
        gold: 'ゴールド',
        silver: 'シルバー',
        bronze: 'ブロンズ',
        unranked: '未ランク',
      },
    },
    notifications: {
      title: '通知',
      empty: '通知はまだありません',
      markAllRead: 'すべて既読にする',
      clearAll: 'すべてクリア',
      unreadCount: '未読 {{count}}件',
      status: {
        idle: '非アクティブ',
        connecting: '接続中…',
        open: 'ライブ',
        closed: '切断済み',
        error: '利用不可',
      },
      type: {
        'credential-issued': 'クレデンシャルが発行されました',
        'credential-verified': 'クレデンシャルが検証されました',
        'credential-revoked': 'クレデンシャルが失効されました',
        'credential-expiring': 'クレデンシャルの有効期限が近づいています',
        'offer-received': 'クレデンシャルのオファーを受け取りました',
      },
    },
    time: {
      justNow: 'たった今',
      secondsAgo: '{{count}}秒前',
      minutesAgo: '{{count}}分前',
      hoursAgo: '{{count}}時間前',
      daysAgo: '{{count}}日前',
      weeksAgo: '{{count}}週間前',
    },
    analytics: {
      dateRange: '期間',
      showing: '過去{{count}}日間を表示',
      preset: {
        '7d': '7日間',
        '30d': '30日間',
        '90d': '90日間',
      },
    },
    dashboard: {
      title: 'Stellarアイデンティティダッシュボード',
      initializing: 'Stellarアイデンティティダッシュボードを初期化中',
      connectingTo: '{{network}}に接続中…',
      connectWallet:
        'ウォレットを接続して、分散型アイデンティティ、クレデンシャル、評判を管理しましょう。',
      createKeypair: '新しいキーペアを作成',
      orEnterSecret: 'または下にシークレットキーを入力',
      secretPlaceholder: 'Stellarシークレットキーを入力（Sで始まります）',
      address: 'アドレス',
      status: '状態',
      credentials: 'クレデンシャル',
      proofs: '証明',
      compliance: 'コンプライアンス',
      reporting: 'レポート',
      reputation: '評判',
      reputationAnalytics: '評判とアナリティクス',
      footer:
        'Stellar {{network}}ネットワーク上で分散型アイデンティティ、検証可能なクレデンシャル、評判を管理しましょう。',
      toggleMenu: 'メニューを切り替え',
      toggleTheme: 'テーマを切り替え',
      collapseSidebar: 'サイドバーを折りたたむ',
      expandSidebar: 'サイドバーを展開',
      openNavigation: 'ナビゲーションを開く',
    },
  },
  ko: {
    common: {
      loading: '불러오는 중…',
      error: '오류',
      retry: '다시 시도',
      cancel: '취소',
      close: '닫기',
      save: '저장',
      confirm: '확인',
      copy: '복사',
      copied: '복사되었습니다!',
      loadingAria: '불러오는 중',
    },
    network: {
      title: '네트워크',
      switchTo: '네트워크 전환',
      switching: '전환 중…',
      connected: '연결됨',
      disconnected: '연결 안 됨',
      connect: '연결',
      disconnect: '연결 해제',
      language: '언어',
    },
    credential: {
      wallet: '자격 증명 지갑',
      issue: '자격 증명 발급',
      issueNew: '새 자격 증명 발급',
      issuing: '발급 중…',
      empty: '자격 증명이 없습니다',
      emptyHint: '첫 자격 증명을 발급해 보세요',
      loadFailed: '자격 증명을 불러오지 못했습니다',
      issueSucceeded: '자격 증명이 성공적으로 발급되었습니다: {{id}}',
      issueFailed: '자격 증명 발급에 실패했습니다',
      revokeConfirm: '이 자격 증명을 취소하시겠습니까?',
      revokeReason: '사용자가 취소를 요청함',
      revokeSucceeded: '자격 증명이 취소되었습니다',
      revokeFailed: '자격 증명 취소에 실패했습니다',
      shareSucceeded: '공유 링크가 클립보드에 복사되었습니다!',
      shareFailed: '자격 증명 공유에 실패했습니다',
      details: '자격 증명 세부 정보',
      id: '자격 증명 ID',
      type: '유형',
      issuer: '발급자',
      subject: '주체',
      issuedBy: '발급자: {{issuer}}',
      issuanceDate: '발급일',
      expirationDate: '만료일',
      data: '자격 증명 데이터',
      proof: '증명',
      subjectAddress: '주체 주소',
      typesLabel: '자격 증명 유형',
      dataLabel: '자격 증명 데이터 (JSON)',
      expirationOptional: '만료일 (선택 사항)',
      viewDetails: '세부 정보 보기',
      viewDetailsFor: '{{label}} 세부 정보 보기',
      exportJson: 'JSON으로 내보내기',
      exportJsonFor: '{{label}}을 JSON으로 내보내기',
      shareAction: '공유',
      shareFor: '{{label}} 공유',
      revokeAction: '취소',
      revokeFor: '{{label}} 취소',
      shareSheetTitle: '검증 가능한 자격 증명',
      shareSheetText: '검증 가능한 자격 증명을 공유하세요',
      requiredFields: '필수 항목을 모두 입력해 주세요',
      status: {
        valid: '유효',
        revoked: '취소됨',
        expired: '만료됨',
        unknown: '알 수 없음',
      },
    },
    did: {
      title: '분산 신원 (DID)',
      create: 'DID 생성',
      createNew: '새 DID 생성',
      creating: '생성 중…',
      update: '업데이트',
      deactivate: '비활성화',
      deactivateConfirm: '이 DID를 비활성화하시겠습니까? 되돌릴 수 없습니다.',
      deactivateSucceeded: 'DID가 비활성화되었습니다',
      empty: '이 주소의 DID를 찾을 수 없습니다',
      emptyHint: 'DID를 만들어 분산 신원을 관리해 보세요',
      loadFailed: 'DID 정보를 불러오는 중…',
      createSucceeded: 'DID가 생성되었습니다: {{did}}',
      createFailed: 'DID 생성에 실패했습니다',
      updateSucceeded: 'DID가 업데이트되었습니다',
      updateFailed: 'DID 업데이트에 실패했습니다',
      deactivateFailed: 'DID 비활성화에 실패했습니다',
      verificationMethods: '검증 방법',
      services: '서비스',
      currentMethods: '현재 검증 방법:',
      currentServices: '현재 서비스:',
      addMethod: '검증 방법 추가',
      addService: '서비스 추가',
      vmRequired: '검증 방법의 모든 항목을 입력해 주세요',
      serviceRequired: '서비스의 모든 항목을 입력해 주세요',
      controller: '컨트롤러',
      created: '생성일',
      lastUpdated: '마지막 업데이트',
      publicKey: '공개 키',
      endpoint: '엔드포인트',
      connecting: 'Stellar 네트워크에 연결 중…',
      notConnected: 'Stellar 네트워크에 연결되어 있지 않습니다',
      notConnectedHint: 'connect 함수로 연결을 설정하세요',
    },
    proof: {
      title: '제로 지식 증명',
      create: '증명 생성',
      createNew: '제로 지식 증명 생성',
      creating: '생성 중…',
      custom: '사용자 지정',
      customTitle: '사용자 지정 증명',
      customDescription: '사용자 지정 제로 지식 증명 생성',
      age: '나이 검증',
      ageDescription: '나이를 공개하지 않고 만 18세 이상임을 증명',
      income: '소득 검증',
      incomeDescription: '정확한 금액을 공개하지 않고 최저 소득을 증명',
      identity: '신원 검증',
      identityDescription: '세부 정보를 공개하지 않고 자격 증명을 소유함을 증명',
      quickActions: '빠른 작업',
      myProofs: '내 증명',
      availableCircuits: '사용 가능한 회로',
      empty: '증명이 없습니다',
      emptyHint: '첫 제로 지식 증명을 만들어 보세요',
      loadFailed: '증명을 불러오지 못했습니다',
      loading: '제로 지식 증명을 불러오는 중…',
      circuitsLoadFailed: '회로를 불러오지 못했습니다',
      requiredFields: '필수 항목을 모두 입력해 주세요',
      createSucceeded: '증명이 생성되었습니다: {{id}}',
      createFailed: '증명 생성에 실패했습니다',
      ageSucceeded: '나이 증명이 생성되었습니다: {{id}}',
      ageFailed: '나이 증명 생성에 실패했습니다',
      incomeSucceeded: '소득 증명이 생성되었습니다: {{id}}',
      incomeFailed: '소득 증명 생성에 실패했습니다',
      verifyFailed: '증명 검증에 실패했습니다',
      details: '증명 세부 정보',
      proofId: '증명 ID',
      circuitId: '회로 ID',
      circuitLabel: '회로',
      verifierAddress: '검증자 주소',
      createdAt: '생성 시각',
      expiresAt: '만료 시각',
      expires: '만료',
      publicInputs: '공개 입력',
      publicInputsCount: '공개 입력: {{count}}',
      privateInputsCount: '비공개 입력: {{count}}',
      selectCircuit: '회로 선택',
      inputPlaceholder: '입력 {{index}}',
      addInput: '입력 추가',
      proofBytes: '증명 바이트',
      proofBytesPlaceholder: 'ZK 회로에서 생성된 증명 바이트',
      expirationDateOptional: '만료일 (선택 사항)',
      metadata: '메타데이터',
      useCircuit: '회로 사용',
      active: '활성',
      inactive: '비활성',
      status: {
        valid: '유효',
        invalid: '무효',
      },
    },
    compliance: {
      title: '컴플라이언스 확인',
      refresh: '새로고침',
      check: '확인',
      checking: '컴플라이언스를 확인하는 중…',
      invalidAddress: '잘못된 Stellar 주소 형식',
      checkFailed: '컴플라이언스 확인에 실패했습니다',
      status: '컴플라이언스 상태',
      riskScore: '위험 점수',
      riskLevel: '위험 등급',
      sanctionsLists: '제재 목록',
      lastChecked: '마지막 확인',
      metrics: '컴플라이언스 지표',
      overallScore: '종합 컴플라이언스 점수',
      totalCredentials: '총 자격 증명',
      validCredentials: '유효한 자격 증명',
      recommendations: '권장 사항',
      detailedAnalysis: '상세 분석',
      summary: '컴플라이언스 요약',
      sanctionsScreening: '제재 여부 확인:',
      identityVerification: '신원 검증:',
      riskAssessment: '위험 평가:',
      overallStatus: '종합 상태:',
      addressPlaceholder: 'Stellar 주소 입력 (G...)',
      currentlyChecking: '확인 중:',
      listsFound: '{{count}}건',
      noneFound: '없음',
      validShort: '유효',
      risk: {
        high: '높은 위험',
        medium: '중간 위험',
        low: '낮은 위험',
        veryLow: '매우 낮은 위험',
      },
      verdict: {
        cleared: '통과',
        flagged: '주의',
        blocked: '차단',
        unknown: '알 수 없음',
      },
      assessment: {
        clear: '양호',
        alert: '경고',
        verified: '검증됨',
        notVerified: '미검증',
      },
    },
    reputation: {
      title: '평판 점수',
      loading: '평판 점수를 불러오는 중',
      noData: '평판 데이터가 없습니다',
      loadFailed: '평판 데이터를 불러오지 못했습니다',
      scoreRange: '점수 범위',
      totalTransactions: '총 거래 수',
      successRate: '성공률',
      credentialCount: '자격 증명 수',
      percentile: '백분위',
      nextTier: '다음 등급: {{tier}}',
      maximum: '최대',
      atPoints: '{{count}}포인트에서',
      lastUpdated: '마지막 업데이트',
      factors: '평판 요인',
      noFactors: '요인 데이터가 없습니다',
      activity: '최근 활동',
      current: '현재',
      updatesAgo: '{{count}}회 업데이트 전',
      noHistory: '기록이 없습니다',
      insights: '평판 인사이트',
      currentScore: '현재 점수',
      percentileRank: '백분위 순위',
      activeFactors: '활성 요인',
      recommendations: '권장 사항:',
      recommendationTransactions:
        '• 성공적인 거래에 집중하여 점수를 높이세요',
      recommendationCredentials:
        '• 검증 가능한 자격 증명을 더 확보하여 평판을 강화하세요',
      recommendationDeclining:
        '• 최근 활동이 하락 추세를 보이고 있습니다 - 최근 거래를 검토하세요',
      recommendationExcellent:
        '• 평판이 훌륭합니다! 현재 활동 수준을 유지하세요',
      notAvailable: '해당 없음',
      tier: '등급:',
      tierProgress: '등급 진행도:',
      tierLabel: '{{tier}} 등급',
      tiers: {
        diamond: '다이아몬드',
        platinum: '플래티넘',
        gold: '골드',
        silver: '실버',
        bronze: '브론즈',
        unranked: '순위 없음',
      },
    },
    notifications: {
      title: '알림',
      empty: '아직 알림이 없습니다',
      markAllRead: '모두 읽음으로 표시',
      clearAll: '모두 지우기',
      unreadCount: '읽지 않음 {{count}}개',
      status: {
        idle: '비활성',
        connecting: '연결 중…',
        open: '실시간',
        closed: '연결 끊김',
        error: '사용 불가',
      },
      type: {
        'credential-issued': '자격 증명이 발급되었습니다',
        'credential-verified': '자격 증명이 검증되었습니다',
        'credential-revoked': '자격 증명이 취소되었습니다',
        'credential-expiring': '자격 증명 곧 만료됩니다',
        'offer-received': '자격 증명 제안을 받았습니다',
      },
    },
    time: {
      justNow: '방금',
      secondsAgo: '{{count}}초 전',
      minutesAgo: '{{count}}분 전',
      hoursAgo: '{{count}}시간 전',
      daysAgo: '{{count}}일 전',
      weeksAgo: '{{count}}주 전',
    },
    analytics: {
      dateRange: '기간',
      showing: '최근 {{count}}일 표시',
      preset: {
        '7d': '7일',
        '30d': '30일',
        '90d': '90일',
      },
    },
    dashboard: {
      title: 'Stellar 신원 대시보드',
      initializing: 'Stellar 신원 대시보드 초기화 중',
      connectingTo: '{{network}}에 연결 중…',
      connectWallet:
        '지갑을 연결하여 분산 신원, 자격 증명, 평판을 관리하세요.',
      createKeypair: '새 키페어 생성',
      orEnterSecret: '또는 아래에 시크릿 키를 입력하세요',
      secretPlaceholder: 'Stellar 시크릿 키를 입력하세요 (S로 시작)',
      address: '주소',
      status: '상태',
      credentials: '자격 증명',
      proofs: '증명',
      compliance: '컴플라이언스',
      reporting: '보고',
      reputation: '평판',
      reputationAnalytics: '평판 및 분석',
      footer:
        'Stellar {{network}} 네트워크에서 분산 신원, 검증 가능한 자격 증명, 평판을 관리하세요.',
      toggleMenu: '메뉴 전환',
      toggleTheme: '테마 전환',
      collapseSidebar: '사이드바 접기',
      expandSidebar: '사이드바 펼치기',
      openNavigation: '탐색 열기',
    },
  },
  ar: {
    common: {
      loading: 'جارٍ التحميل…',
      error: 'خطأ',
      retry: 'إعادة المحاولة',
      cancel: 'إلغاء',
      close: 'إغلاق',
      save: 'حفظ',
      confirm: 'تأكيد',
      copy: 'نسخ',
      copied: 'تم النسخ!',
      loadingAria: 'جارٍ التحميل',
    },
    network: {
      title: 'الشبكة',
      switchTo: 'تبديل الشبكة',
      switching: 'جارٍ التبديل…',
      connected: 'متصل',
      disconnected: 'غير متصل',
      connect: 'اتصال',
      disconnect: 'قطع الاتصال',
      language: 'اللغة',
    },
    credential: {
      wallet: 'محفظة بيانات الاعتماد',
      issue: 'إصدار بيانات اعتماد',
      issueNew: 'إصدار بيانات اعتماد جديدة',
      issuing: 'جارٍ الإصدار…',
      empty: 'لم يتم العثور على بيانات اعتماد',
      emptyHint: 'أصدر أول بيانات اعتماد للبدء',
      loadFailed: 'فشل تحميل بيانات الاعتماد',
      issueSucceeded: 'تم إصدار بيانات الاعتماد بنجاح: {{id}}',
      issueFailed: 'فشل إصدار بيانات الاعتماد',
      revokeConfirm: 'هل أنت متأكد من رغبتك في إلغاء بيانات الاعتماد هذه؟',
      revokeReason: 'طلب المستخدم الإلغاء',
      revokeSucceeded: 'تم إلغاء بيانات الاعتماد بنجاح',
      revokeFailed: 'فشل إلغاء بيانات الاعتماد',
      shareSucceeded: 'تم نسخ رابط المشاركة!',
      shareFailed: 'فشل مشاركة بيانات الاعتماد',
      details: 'تفاصيل بيانات الاعتماد',
      id: 'معرف بيانات الاعتماد',
      type: 'النوع',
      issuer: 'الجهة المصدرة',
      subject: 'الموضوع',
      issuedBy: 'صادرة عن: {{issuer}}',
      issuanceDate: 'تاريخ الإصدار',
      expirationDate: 'تاريخ الانتهاء',
      data: 'بيانات الاعتماد',
      proof: 'إثبات',
      subjectAddress: 'عنوان الموضوع',
      typesLabel: 'أنواع بيانات الاعتماد',
      dataLabel: 'بيانات الاعتماد (JSON)',
      expirationOptional: 'تاريخ الانتهاء (اختياري)',
      viewDetails: 'عرض التفاصيل',
      viewDetailsFor: 'عرض تفاصيل {{label}}',
      exportJson: 'تصدير كـ JSON',
      exportJsonFor: 'تصدير {{label}} كـ JSON',
      shareAction: 'مشاركة',
      shareFor: 'مشاركة {{label}}',
      revokeAction: 'إلغاء',
      revokeFor: 'إلغاء {{label}}',
      shareSheetTitle: 'بيانات اعتماد قابلة للتحقق',
      shareSheetText: 'شارك بيانات اعتمادك القابلة للتحقق',
      requiredFields: 'يرجى تعبئة جميع الحقول المطلوبة',
      status: {
        valid: 'سارية',
        revoked: 'ملغاة',
        expired: 'منتهية',
        unknown: 'غير معروف',
      },
    },
    did: {
      title: 'الهوية اللامركزية (DID)',
      create: 'إنشاء DID',
      createNew: 'إنشاء DID جديد',
      creating: 'جارٍ الإنشاء…',
      update: 'تحديث',
      deactivate: 'إلغاء التفعيل',
      deactivateConfirm: 'هل أنت متأكد من إلغاء تفعيل هذا DID؟ لا يمكن التراجع عن هذا الإجراء.',
      deactivateSucceeded: 'تم إلغاء تفعيل DID بنجاح',
      empty: 'لم يتم العثور على DID لهذا العنوان',
      emptyHint: 'أنشئ DID لبدء إدارة هويتك اللامركزية',
      loadFailed: 'جارٍ تحميل معلومات DID…',
      createSucceeded: 'تم إنشاء DID بنجاح: {{did}}',
      createFailed: 'فشل إنشاء DID',
      updateSucceeded: 'تم تحديث DID بنجاح',
      updateFailed: 'فشل تحديث DID',
      deactivateFailed: 'فشل إلغاء تفعيل DID',
      verificationMethods: 'طرق التحقق',
      services: 'الخدمات',
      currentMethods: 'الطرق الحالية:',
      currentServices: 'الخدمات الحالية:',
      addMethod: 'إضافة طريقة تحقق',
      addService: 'إضافة خدمة',
      vmRequired: 'يرجى تعبئة جميع حقول طريقة التحقق',
      serviceRequired: 'يرجى تعبئة جميع حقول الخدمة',
      controller: ' المتحكم',
      created: 'تاريخ الإنشاء',
      lastUpdated: 'آخر تحديث',
      publicKey: 'المفتاح العام',
      endpoint: 'نقطة النهاية',
      connecting: 'جارٍ الاتصال بشبكة Stellar…',
      notConnected: 'غير متصل بشبكة Stellar',
      notConnectedHint: 'استخدم دالة connect لإنشاء الاتصال',
    },
    proof: {
      title: 'إثباتات المعرفة الصفرية',
      create: 'إنشاء إثبات',
      createNew: 'إنشاء إثبات معرفة صفرية',
      creating: 'جارٍ الإنشاء…',
      custom: 'مخصص',
      customTitle: 'إثبات مخصص',
      customDescription: 'إنشاء إثبات معرفة صفرية مخصص',
      age: 'التحقق من العمر',
      ageDescription: 'أثبت أنك تتجاوز 18 عامًا دون كشف عمرك',
      income: 'التحقق من الدخل',
      incomeDescription: 'أثبت حدًا أدنى للدخل دون كشف المبلغ الدقيق',
      identity: 'التحقق من الهوية',
      identityDescription: 'أثبت امتلاكك لبيانات اعتماد دون كشف التفاصيل',
      quickActions: 'إجراءات سريعة',
      myProofs: 'إثباتاتي',
      availableCircuits: 'الدوائر المتاحة',
      empty: 'لم يتم العثور على إثباتات',
      emptyHint: 'أنشئ أول إثبات معرفة صفرية',
      loadFailed: 'فشل تحميل الإثباتات',
      loading: 'جارٍ تحميل إثباتات المعرفة الصفرية…',
      circuitsLoadFailed: 'فشل تحميل الدوائر',
      requiredFields: 'يرجى تعبئة جميع الحقول المطلوبة',
      createSucceeded: 'تم إنشاء الإثبات بنجاح: {{id}}',
      createFailed: 'فشل إنشاء الإثبات',
      ageSucceeded: 'تم إنشاء إثبات العمر بنجاح: {{id}}',
      ageFailed: 'فشل إنشاء إثبات العمر',
      incomeSucceeded: 'تم إنشاء إثبات الدخل بنجاح: {{id}}',
      incomeFailed: 'فشل إنشاء إثبات الدخل',
      verifyFailed: 'فشل التحقق من الإثبات',
      details: 'تفاصيل الإثبات',
      proofId: 'معرف الإثبات',
      circuitId: 'معرف الدائرة',
      circuitLabel: 'الدائرة',
      verifierAddress: 'عنوان المدقق',
      createdAt: 'تاريخ الإنشاء',
      expiresAt: 'تاريخ الانتهاء',
      expires: 'تنتهي في',
      publicInputs: 'المدخلات العامة',
      publicInputsCount: 'المدخلات العامة: {{count}}',
      privateInputsCount: 'المدخلات الخاصة: {{count}}',
      selectCircuit: 'اختر دائرة',
      inputPlaceholder: 'المدخل {{index}}',
      addInput: 'إضافة مدخل',
      proofBytes: 'بايتات الإثبات',
      proofBytesPlaceholder: 'بايتات الإثبات التي تم إنشاؤها بواسطة دائرة ZK',
      expirationDateOptional: 'تاريخ الانتهاء (اختياري)',
      metadata: 'البيانات الوصفية',
      useCircuit: 'استخدام الدائرة',
      active: 'نشط',
      inactive: 'غير نشط',
      status: {
        valid: 'صالح',
        invalid: 'غير صالح',
      },
    },
    compliance: {
      title: 'فحص الامتثال',
      refresh: 'تحديث',
      check: 'فحص',
      checking: 'جارٍ فحص الامتثال…',
      invalidAddress: 'تنسيق عنوان Stellar غير صالح',
      checkFailed: 'فشل فحص الامتثال',
      status: 'حالة الامتثال',
      riskScore: 'درجة المخاطر',
      riskLevel: 'مستوى المخاطر',
      sanctionsLists: 'قوائم العقوبات',
      lastChecked: 'آخر فحص',
      metrics: 'مقاييس الامتثال',
      overallScore: 'درجة الامتثال الإجمالية',
      totalCredentials: 'إجمالي بيانات الاعتماد',
      validCredentials: 'بيانات اعتماد صالحة',
      recommendations: 'التوصيات',
      detailedAnalysis: 'تحليل مفصل',
      summary: 'ملخص الامتثال',
      sanctionsScreening: 'فحص العقوبات:',
      identityVerification: 'التحقق من الهوية:',
      riskAssessment: 'تقييم المخاطر:',
      overallStatus: 'الحالة الإجمالية:',
      addressPlaceholder: 'أدخل عنوان Stellar (G...)',
      currentlyChecking: 'جارٍ الفحص:',
      listsFound: 'تم العثور على {{count}}',
      noneFound: 'لم يتم العثور على أي منها',
      validShort: 'صالحة',
      risk: {
        high: 'مخاطر عالية',
        medium: 'مخاطر متوسطة',
        low: 'مخاطر منخفضة',
        veryLow: 'مخاطر منخفضة جدًا',
      },
      verdict: {
        cleared: 'مُسموح',
        flagged: 'موسوم',
        blocked: 'محظور',
        unknown: 'غير معروف',
      },
      assessment: {
        clear: 'واضح',
        alert: 'تنبيه',
        verified: 'موثق',
        notVerified: 'غير موثق',
      },
    },
    reputation: {
      title: 'درجة السمعة',
      loading: 'جارٍ تحميل درجة السمعة',
      noData: 'لا تتوفر بيانات السمعة',
      loadFailed: 'فشل تحميل بيانات السمعة',
      scoreRange: 'نطاق الدرجة',
      totalTransactions: 'إجمالي المعاملات',
      successRate: 'معدل النجاح',
      credentialCount: 'عدد بيانات الاعتماد',
      percentile: 'المئين',
      nextTier: 'الفئة التالية: {{tier}}',
      maximum: 'الأقصى',
      atPoints: 'عند {{count}} نقطة',
      lastUpdated: 'آخر تحديث',
      factors: 'عوامل السمعة',
      noFactors: 'لا تتوفر بيانات العوامل',
      activity: 'النشاط الأخير',
      current: 'الحالي',
      updatesAgo: 'قبل {{count}} تحديثات',
      noHistory: 'لا يتوفر سجل',
      insights: 'رؤى السمعة',
      currentScore: 'الدرجة الحالية',
      percentileRank: 'ترتيب المئين',
      activeFactors: 'العوامل النشطة',
      recommendations: 'التوصيات:',
      recommendationTransactions:
        '• ركّز على المعاملات الناجحة لتحسين درجتك',
      recommendationCredentials:
        '• احصل على المزيد من بيانات الاعتماد القابلة للتحقق لتقوية سمعتك',
      recommendationDeclining:
        '• يُظهر النشاط الأخير اتجاهًا هابطًا - راجع معاملاتك الأخيرة',
      recommendationExcellent:
        '• سمعة ممتازة! حافظ على مستوى نشاطك الحالي',
      notAvailable: 'غير متاح',
      tier: 'الفئة:',
      tierProgress: 'تقدم الفئة:',
      tierLabel: 'فئة {{tier}}',
      tiers: {
        diamond: 'ماسي',
        platinum: 'بلاتيني',
        gold: 'ذهبي',
        silver: 'فضي',
        bronze: 'برونزي',
        unranked: 'غير مصنّف',
      },
    },
    notifications: {
      title: 'الإشعارات',
      empty: 'لا توجد إشعارات بعد',
      markAllRead: 'تحديد الكل كمقروء',
      clearAll: 'مسح الكل',
      unreadCount: '{{count}} غير مقروء',
      status: {
        idle: 'غير نشط',
        connecting: 'جارٍ الاتصال…',
        open: 'مباشر',
        closed: 'غير متصل',
        error: 'غير متاح',
      },
      type: {
        'credential-issued': 'تم إصدار بيانات الاعتماد',
        'credential-verified': 'تم التحقق من بيانات الاعتماد',
        'credential-revoked': 'تم إلغاء بيانات الاعتماد',
        'credential-expiring': 'تنتهي بيانات الاعتماد قريبًا',
        'offer-received': 'تم استلام عرض بيانات اعتماد',
      },
    },
    time: {
      justNow: 'الآن',
      secondsAgo: 'قبل {{count}} ث',
      minutesAgo: 'قبل {{count}} د',
      hoursAgo: 'قبل {{count}} س',
      daysAgo: 'قبل {{count}} ي',
      weeksAgo: 'قبل {{count}} أسبوع',
    },
    analytics: {
      dateRange: 'النطاق الزمني',
      showing: 'عرض آخر {{count}} يومًا',
      preset: {
        '7d': '7 أيام',
        '30d': '30 يومًا',
        '90d': '90 يومًا',
      },
    },
    dashboard: {
      title: 'لوحة هوية Stellar',
      initializing: 'جارٍ تهيئة لوحة هوية Stellar',
      connectingTo: 'جارٍ الاتصال بـ {{network}}…',
      connectWallet:
        'قم بتوصيل محفظتك لإدارة هويتك اللامركزية وبيانات اعتمادك وسمعتك.',
      createKeypair: 'إنشاء زوج مفاتيح جديد',
      orEnterSecret: 'أو أدخل المفتاح السري أدناه',
      secretPlaceholder: 'أدخل مفتاحك السري لـ Stellar (يبدأ بـ S...)',
      address: 'العنوان',
      status: 'الحالة',
      credentials: 'بيانات الاعتماد',
      proofs: 'الإثباتات',
      compliance: 'الامتثال',
      reporting: 'التقارير',
      reputation: 'السمعة',
      reputationAnalytics: 'السمعة والتحليلات',
      footer:
        'أدر هويتك اللامركزية وبيانات اعتمادك القابلة للتحقق وسمعتك على شبكة Stellar {{network}}.',
      toggleMenu: 'تبديل القائمة',
      toggleTheme: 'تبديل المظهر',
      collapseSidebar: 'طي الشريط الجانبي',
      expandSidebar: 'توسيع الشريط الجانبي',
      openNavigation: 'فتح التنقل',
    },
  },
};

// ── Detection ────────────────────────────────────────────────────────────────

/**
 * Best-effort match of a browser language tag to a supported locale.
 *
 * Handles the region-qualified tags browsers actually send (`en-GB`,
 * `pt-BR`) by falling back to the base language, and returns `null` rather
 * than defaulting, so the caller can decide whether to honour the browser
 * choice or fall back to {@link DEFAULT_LOCALE}.
 */
export function matchLocale(tag: string | undefined | null): SupportedLocale | null {
  if (!tag) return null;
  const base = tag.toLowerCase().split(/[-_]/)[0];
  return (SUPPORTED_LOCALES as readonly string[]).includes(base)
    ? (base as SupportedLocale)
    : null;
}

/**
 * Detect a preferred locale from browser settings.
 *
 * Checks, in order: an explicit `?lang=` query parameter, `localStorage`, the
 * navigator's language list, then the platform default. Returns `null` when
 * nothing matches, so a caller can distinguish "detected nothing" from
 * "detected English".
 */
export function detectLocale(): SupportedLocale | null {
  const g = globalThis as unknown as {
    navigator?: { languages?: readonly string[]; language?: string };
    localStorage?: { getItem(k: string): string | null };
    location?: { search?: string };
  };

  try {
    const fromQuery = g.location?.search
      ? matchLocale(new URLSearchParams(g.location.search).get('lang') ?? undefined)
      : null;
    if (fromQuery) return fromQuery;
  } catch {
    // `location` may be absent in SSR; fall through.
  }

  try {
    const stored = matchLocale(g.localStorage?.getItem('stellar_identity_locale') ?? undefined);
    if (stored) return stored;
  } catch {
    // localStorage throws in sandboxed frames; fall through.
  }

  const languages = g.navigator?.languages ?? (g.navigator?.language ? [g.navigator.language] : []);
  for (const tag of languages) {
    const match = matchLocale(tag);
    if (match) return match;
  }

  return null;
}

// ── Locale-aware formatting ──────────────────────────────────────────────────

/**
 * Formaters bound to a locale.
 *
 * These replace `toLocaleDateString()` / `toLocaleString()` calls that took no
 * locale argument and therefore silently stayed `en-US` no matter what the
 * user had selected.
 */
export interface LocaleFormatters {
  /** The active locale code. */
  locale: SupportedLocale;
  /** `true` when the locale renders right-to-left. */
  isRTL: boolean;
  /** The BCP-47 tag handed to `Intl`. */
  intlLocale: string;
  /** A short date, e.g. `29/09/2026` or `2026/09/29`. */
  formatDate(value: number | Date, options?: Intl.DateTimeFormatOptions): string;
  /** A date and time. */
  formatDateTime(value: number | Date, options?: Intl.DateTimeFormatOptions): string;
  /** A compact relative time, e.g. `3 days ago`. */
  formatRelativeTime(value: number, now?: number): string;
  /** A grouped number, e.g. `1,234.5`. */
  formatNumber(value: number, options?: Intl.NumberFormatOptions): string;
  /** A compact number, e.g. `1.2K`. */
  formatCompact(value: number): string;
  /** A percentage, e.g. `92%`. */
  formatPercent(value: number, fractionDigits?: number): string;
  /** A currency amount, using the locale's own conventions. */
  formatCurrency(value: number, currency: string): string;
  /** Truncate a long identifier with an ellipsis in the middle. */
  truncateMiddle(value: string, maxLength?: number): string;
}

/** Build the formatter set for a locale. */
export function createFormatters(locale: SupportedLocale): LocaleFormatters {
  const tag = intlLocale(locale);
  const rtl = isRTL(locale);

  // `Intl.RelativeTimeFormat` handles the plural and the word order, which
  // differ substantially between these languages — hand-rolled "3d ago" is
  // wrong in Japanese and Arabic, not merely untranslated.
  const rtf = typeof Intl !== 'undefined' && 'RelativeTimeFormat' in Intl
    ? new Intl.RelativeTimeFormat(tag, { numeric: 'auto' })
    : null;

  const relativeUnits: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ['week', 604_800_000],
    ['day', 86_400_000],
    ['hour', 3_600_000],
    ['minute', 60_000],
    ['second', 1_000],
  ];

  return {
    locale,
    isRTL: rtl,
    intlLocale: tag,

    formatDate(value, options) {
      return new Intl.DateTimeFormat(
        tag,
        options ?? { year: 'numeric', month: 'short', day: 'numeric' },
      ).format(value);
    },

    formatDateTime(value, options) {
      return new Intl.DateTimeFormat(
        tag,
        options ?? { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' },
      ).format(value);
    },

    formatRelativeTime(value, now = Date.now()) {
      const delta = value - now;
      const magnitude = Math.abs(delta);
      if (rtf) {
        for (const [unit, ms] of relativeUnits) {
          if (magnitude >= ms) {
            return rtf.format(Math.round(delta / ms), unit);
          }
        }
        return rtf.format(Math.round(delta / 1000), 'second');
      }
      // Environments without RelativeTimeFormat (older Hermes) fall back to
      // the English catalogue rather than showing a raw unit code.
      return interpolate(
        lookup(TRANSLATIONS[locale] as unknown as Record<string, unknown>, 'time.justNow') ?? 'just now',
      );
    },

    formatNumber(value, options) {
      return new Intl.NumberFormat(tag, options).format(value);
    },

    formatCompact(value) {
      return new Intl.NumberFormat(tag, {
        notation: 'compact',
        maximumFractionDigits: 1,
      }).format(value);
    },

    formatPercent(value, fractionDigits = 0) {
      return new Intl.NumberFormat(tag, {
        style: 'percent',
        maximumFractionDigits: fractionDigits,
      }).format(value / 100);
    },

    formatCurrency(value, currency) {
      return new Intl.NumberFormat(tag, {
        style: 'currency',
        currency,
      }).format(value);
    },

    truncateMiddle(value, maxLength = 20) {
      if (value.length <= maxLength) return value;
      const head = Math.ceil((maxLength - 1) / 2);
      const tail = Math.floor((maxLength - 1) / 2);
      return `${value.slice(0, head)}…${value.slice(value.length - tail)}`;
    },
  };
}

// ── Context & provider ───────────────────────────────────────────────────────

/** The value exposed by {@link I18nProvider}. */
export interface I18nContextValue {
  /** The active locale. */
  locale: SupportedLocale;
  /** Switch the active locale. */
  setLocale: (locale: SupportedLocale) => void;
  /** `true` when the locale renders right-to-left. */
  isRTL: boolean;
  /** The `dir` attribute to put on the document or a subtree. */
  dir: 'ltr' | 'rtl';
  /** Translate a dot-namespaced key, interpolating `{{placeholders}}`. */
  t: (key: string, values?: Record<string, string | number>) => string;
  /** Locale-bound date, number, and currency formatters. */
  format: LocaleFormatters;
}

const I18nContext = createContext<I18nContextValue | null>(null);

/** Props for {@link I18nProvider}. */
export interface I18nProviderProps {
  children?: React.ReactNode;
  /**
   * Locale to start in.
   *
   * Defaults to browser detection, then to {@link DEFAULT_LOCALE}. Pass an
   * explicit value to pin the language (useful in tests and Storybook).
   */
  locale?: SupportedLocale;
  /**
   * Mirror the active locale into `<html lang>` and `<html dir>`.
   *
   * Off by default, because a component library should not mutate the host
   * document without being asked — an app embedding two independently
   * configured surfaces would fight over the attributes.
   */
  applyDocumentAttributes?: boolean;
  /**
   * Persist the chosen locale to storage under this key, so a reload keeps
   * the user's choice. Omit to disable persistence.
   */
  storageKey?: string;
  /** Additional catalogues merged over the built-ins, for app-specific strings. */
  messages?: Partial<Record<SupportedLocale, Record<string, unknown>>>;
}

/**
 * Provide translations to the components below it.
 *
 * ```tsx
 * <I18nProvider locale="ja">
 *   <App />
 * </I18nProvider>
 * ```
 *
 * @category Utilities
 */
export function I18nProvider({
  children,
  locale: initialLocale,
  applyDocumentAttributes = false,
  storageKey = 'stellar_identity_locale',
  messages,
}: I18nProviderProps): React.JSX.Element {
  const [locale, setLocaleState] = useState<SupportedLocale>(
    () => initialLocale ?? detectLocale() ?? DEFAULT_LOCALE,
  );

  useEffect(() => {
    if (initialLocale) setLocaleState(initialLocale);
  }, [initialLocale]);

  useEffect(() => {
    if (!applyDocumentAttributes) return;
    if (typeof document === 'undefined') return;
    const root = document.documentElement;
    root.setAttribute('lang', locale);
    root.setAttribute('dir', isRTL(locale) ? 'rtl' : 'ltr');
  }, [locale, applyDocumentAttributes]);

  const setLocale = useCallback(
    (next: SupportedLocale) => {
      setLocaleState(next);
      if (!storageKey) return;
      try {
        const g = globalThis as unknown as { localStorage?: { setItem(k: string, v: string): void } };
        g.localStorage?.setItem(storageKey, next);
      } catch {
        // Persistence is a convenience; a failure must not break switching.
      }
    },
    [storageKey],
  );

  const value = useMemo<I18nContextValue>(() => {
    const merged: Record<string, unknown> = {
      ...(TRANSLATIONS[locale] as unknown as Record<string, unknown>),
      ...(messages?.[locale] ?? {}),
    };
    const fallback: Record<string, unknown> =
      TRANSLATIONS[DEFAULT_LOCALE] as unknown as Record<string, unknown>;

    return {
      locale,
      setLocale,
      isRTL: isRTL(locale),
      dir: isRTL(locale) ? 'rtl' : 'ltr',
      format: createFormatters(locale),
      t(key: string, values?: Record<string, string | number>): string {
        // Fall back to English, then to the key itself. Returning the key
        // rather than an empty string means a missing translation is visible
        // in the UI instead of leaving an unexplained blank.
        const template = lookup(merged, key) ?? lookup(fallback, key) ?? key;
        return interpolate(template, values);
      },
    };
  }, [locale, setLocale, messages]);

  return React.createElement(I18nContext.Provider, { value }, children);
}

/**
 * Read the i18n context.
 *
 * Outside an {@link I18nProvider} this returns a working English-only context
 * rather than throwing, so a component rendered in isolation — a Storybook
 * story, a unit test — still produces readable output instead of crashing.
 *
 * @category Utilities
 */
export function useTranslation(): I18nContextValue {
  const ctx = useContext(I18nContext);
  const fallback = useMemo<I18nContextValue>(
    () => ({
      locale: DEFAULT_LOCALE,
      setLocale: () => {},
      isRTL: false,
      dir: 'ltr',
      format: createFormatters(DEFAULT_LOCALE),
      t: (key, values) => {
        const template = lookup(TRANSLATIONS[DEFAULT_LOCALE] as unknown as Record<string, unknown>, key) ?? key;
        return interpolate(template, values);
      },
    }),
    [],
  );
  return ctx ?? fallback;
}

/**
 * A standalone `<select>` for switching languages.
 *
 * Ships with the package so every consumer does not have to write their own,
 * and so the option list stays in sync with {@link SUPPORTED_LOCALES}.
 *
 * @category Utilities
 */
export function LanguageSwitcher(props: {
  className?: string;
  id?: string;
  onChange?: (locale: SupportedLocale) => void;
}): React.JSX.Element {
  const { locale, setLocale, t } = useTranslation();
  return React.createElement(
    'select',
    {
      id: props.id,
      className: props.className,
      'aria-label': t('network.language'),
      value: locale,
      onChange: (event: React.ChangeEvent<HTMLSelectElement>) => {
        const next = event.target.value as SupportedLocale;
        setLocale(next);
        props.onChange?.(next);
      },
    },
    SUPPORTED_LOCALES.map((code) =>
      React.createElement('option', { key: code, value: code }, LOCALE_LABELS[code]),
    ),
  );
}
