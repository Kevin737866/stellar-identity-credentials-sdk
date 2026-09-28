import React from 'react';

export interface ResponsiveTableColumn<T> {
  /** Unique key for the column, also used as the default accessor. */
  key: string;
  header: React.ReactNode;
  /**
   * Plain-text label shown next to the value once the table collapses into
   * cards. Defaults to `header` when it is a string.
   */
  mobileLabel?: string;
  /** Custom cell renderer. Defaults to `row[key]`. */
  render?: (row: T) => React.ReactNode;
  align?: 'left' | 'right';
  /** Drop this column once the table collapses into cards. */
  hideOnMobile?: boolean;
}

export interface ResponsiveTableProps<T> {
  columns: ResponsiveTableColumn<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  caption?: string;
  emptyMessage?: React.ReactNode;
  /** Collapse each row into a card below the tablet breakpoint. Default `true`. */
  stackOnMobile?: boolean;
  /** Makes every row clickable. Cells containing controls should not use this. */
  onRowClick?: (row: T) => void;
}

function cellValue<T>(column: ResponsiveTableColumn<T>, row: T): React.ReactNode {
  if (column.render) {
    return column.render(row);
  }
  return (row as Record<string, unknown>)[column.key] as React.ReactNode;
}

function mobileLabelFor<T>(column: ResponsiveTableColumn<T>): string | undefined {
  if (column.mobileLabel !== undefined) {
    return column.mobileLabel;
  }
  return typeof column.header === 'string' ? column.header : undefined;
}

const emptyStateStyle: React.CSSProperties = {
  padding: 'var(--space-8) var(--space-4)',
  textAlign: 'center',
  color: 'var(--color-text-secondary)',
  fontSize: 'var(--font-size-sm)',
  fontFamily: 'var(--font-family)',
};

/**
 * A data table that is usable at 320px: below the tablet breakpoint every row
 * becomes a labelled card. The collapse is pure CSS (`styles/responsive.css`),
 * so the DOM stays a real `<table>` for assistive technology and the component
 * needs no JavaScript breakpoint check.
 */
export function ResponsiveTable<T>({
  columns,
  rows,
  rowKey,
  caption,
  emptyMessage = 'No data available',
  stackOnMobile = true,
  onRowClick,
}: ResponsiveTableProps<T>): React.ReactElement {
  if (rows.length === 0) {
    return (
      <div role="status" style={emptyStateStyle}>
        {emptyMessage}
      </div>
    );
  }

  const className = stackOnMobile ? 'si-table si-table--stack' : 'si-table';

  return (
    <table className={className}>
      {caption ? <caption>{caption}</caption> : null}
      <thead>
        <tr>
          {columns.map((column) => (
            <th
              key={column.key}
              scope="col"
              className={column.hideOnMobile ? 'si-table__hide-mobile' : undefined}
            >
              {column.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr
            key={rowKey(row)}
            onClick={onRowClick ? () => onRowClick(row) : undefined}
            onKeyDown={
              onRowClick
                ? (event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      onRowClick(row);
                    }
                  }
                : undefined
            }
            tabIndex={onRowClick ? 0 : undefined}
            style={onRowClick ? { cursor: 'pointer' } : undefined}
          >
            {columns.map((column) => {
              const label = mobileLabelFor(column);
              return (
                <td
                  key={column.key}
                  data-label={label}
                  className={[
                    column.align === 'right' ? 'si-table__numeric' : '',
                    column.hideOnMobile ? 'si-table__hide-mobile' : '',
                  ]
                    .filter(Boolean)
                    .join(' ') || undefined}
                >
                  {cellValue(column, row)}
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
