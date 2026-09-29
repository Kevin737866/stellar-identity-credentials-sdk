import React from 'react';

export interface BellIconProps {
  size?: number;
  className?: string;
}

/**
 * Inline bell glyph used by the notification center. Kept dependency-free so
 * the UI package does not need an icon library for a single symbol.
 */
export const BellIcon: React.FC<BellIconProps> = ({ size = 20, className }) => (
  <svg
    className={className}
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={2}
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
    <path d="M13.73 21a2 2 0 0 1-3.46 0" />
  </svg>
);
