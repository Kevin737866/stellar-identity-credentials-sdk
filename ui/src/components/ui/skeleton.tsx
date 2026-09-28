import React from 'react';

export interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Visual width. Accepts any CSS length, or a 1–12 shorthand. */
  width?: string | number;
  /** Visual height. Accepts any CSS length, or a number of pixels. */
  height?: string | number;
  /** Border radius preset. */
  shape?: 'text' | 'rect' | 'circle';
  /** Repeat the block to approximate multiple lines of text. */
  count?: number;
}

/**
 * Resolve the `width` shorthand.
 *
 * A bare number 1–12 maps to a percentage so a caller can write `width={6}`
 * instead of `'50%'`. A number outside that range is treated as pixels.
 */
function resolveWidth(width: string | number | undefined): string | undefined {
  if (width === undefined) return undefined;
  if (typeof width === 'string') return width;
  if (width >= 1 && width <= 12 && Number.isInteger(width)) {
    return `${Math.round((width / 12) * 100)}%`;
  }
  return `${width}px`;
}

function resolveHeight(height: string | number | undefined): string | undefined {
  if (height === undefined) return undefined;
  return typeof height === 'string' ? height : `${height}px`;
}

/**
 * A placeholder block shown while content loads.
 *
 * Shimmer is applied via the `skeleton-shimmer` class defined in
 * `src/styles/tokens.css`; when the user has asked for reduced motion the
 * animation is disabled there and the block simply stays static.
 *
 * @example
 * ```tsx
 * <Skeleton width={12} height={16} count={3} />
 * <Skeleton shape="circle" height={40} width={40} />
 * ```
 */
export const Skeleton = React.forwardRef<HTMLDivElement, SkeletonProps>(
  ({ width, height, shape = 'rect', count = 1, style, className, ...props }, ref) => {
    const resolvedWidth = resolveWidth(width);
    const resolvedHeight = resolveHeight(height);

    const baseStyle: React.CSSProperties = {
      display: 'block',
      backgroundColor: 'var(--color-bg-tertiary)',
      borderRadius:
        shape === 'circle'
          ? '50%'
          : shape === 'text'
            ? 'var(--radius-sm)'
            : 'var(--radius-md)',
      flexShrink: 0,
      ...style,
    };

    if (count <= 1) {
      return (
        <div
          ref={ref}
          data-skeleton="true"
          data-testid="skeleton"
          aria-hidden="true"
          className={['skeleton', className].filter(Boolean).join(' ')}
          style={{ ...baseStyle, width: resolvedWidth, height: resolvedHeight }}
          {...props}
        />
      );
    }

    return (
      <div
        data-skeleton-group="true"
        data-testid="skeleton-group"
        aria-hidden="true"
        style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}
      >
        {Array.from({ length: count }, (_, index) => (
          <div
            key={index}
            data-skeleton="true"
            data-testid="skeleton"
            className={['skeleton', className].filter(Boolean).join(' ')}
            // The final line is shortened so the block reads as a paragraph
            // rather than a solid rectangle.
            style={{
              ...baseStyle,
              width: index === count - 1 ? '60%' : resolvedWidth,
              height: resolvedHeight,
            }}
          />
        ))}
      </div>
    );
  }
);
Skeleton.displayName = 'Skeleton';

/**
 * Skeleton shaped like a single line of text, with a comfortable reading
 * rhythm when stacked.
 */
export const SkeletonText: React.FC<{ lines?: number; className?: string }> = ({
  lines = 3,
  className,
}) => (
  <div
    role="status"
    aria-live="polite"
    aria-busy="true"
    aria-label="Loading content"
    style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}
  >
    <Skeleton count={lines} height={12} shape="text" className={className} />
    <span className="sr-only">Loading content</span>
  </div>
);
SkeletonText.displayName = 'SkeletonText';

/** Circular skeleton, sized for an avatar or icon placeholder. */
export const SkeletonAvatar: React.FC<{ size?: number; className?: string }> = ({
  size = 40,
  className,
}) => (
  <Skeleton
    shape="circle"
    height={size}
    width={size}
    className={className}
    data-testid="skeleton-avatar"
  />
);
SkeletonAvatar.displayName = 'SkeletonAvatar';

/**
 * Skeleton approximating a list of rows, so the layout does not jump when
 * the real list arrives.
 */
export const SkeletonList: React.FC<{ rows?: number; className?: string }> = ({
  rows = 3,
  className,
}) => (
  <div
    role="status"
    aria-live="polite"
    aria-busy="true"
    aria-label="Loading list"
    style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}
  >
    {Array.from({ length: rows }, (_, index) => (
      <div
        key={index}
        data-testid="skeleton-row"
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-3)',
          padding: 'var(--space-4)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--color-border)',
        }}
      >
        <SkeletonAvatar size={32} />
        <div style={{ flex: 1 }}>
          <Skeleton height={12} shape="text" className={className} />
          <div style={{ height: 'var(--space-2)' }} />
          <Skeleton height={10} shape="text" width={8} className={className} />
        </div>
      </div>
    ))}
    <span className="sr-only">Loading list</span>
  </div>
);
SkeletonList.displayName = 'SkeletonList';

/**
 * Skeleton for a single card, matching the shape of a credential or DID card
 * so the transition to loaded content is visually stable.
 */
export const SkeletonCard: React.FC<{ className?: string }> = ({ className }) => (
  <div
    role="status"
    aria-live="polite"
    aria-busy="true"
    aria-label="Loading card"
    data-testid="skeleton-card"
    style={{
      display: 'flex',
      flexDirection: 'column',
      gap: 'var(--space-3)',
      padding: 'var(--space-4)',
      borderRadius: 'var(--radius-lg)',
      border: '1px solid var(--color-border)',
      backgroundColor: 'var(--color-bg)',
    }}
  >
    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
      <SkeletonAvatar size={32} className={className} />
      <div style={{ flex: 1 }}>
        <Skeleton height={14} shape="text" width={7} className={className} />
        <div style={{ height: 'var(--space-2)' }} />
        <Skeleton height={10} shape="text" width={10} className={className} />
      </div>
    </div>
    <Skeleton height={10} shape="text" count={2} className={className} />
    <span className="sr-only">Loading card</span>
  </div>
);
SkeletonCard.displayName = 'SkeletonCard';

/**
 * Skeleton approximating a detail view: a header block followed by a grid of
 * labelled fields.
 */
export const SkeletonDetail: React.FC<{ fields?: number; className?: string }> = ({
  fields = 6,
  className,
}) => (
  <div
    role="status"
    aria-live="polite"
    aria-busy="true"
    aria-label="Loading details"
    data-testid="skeleton-detail"
    style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}
  >
    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
      <SkeletonAvatar size={48} className={className} />
      <div style={{ flex: 1 }}>
        <Skeleton height={18} shape="text" width={8} className={className} />
        <div style={{ height: 'var(--space-2)' }} />
        <Skeleton height={12} shape="text" width={5} className={className} />
      </div>
    </div>

    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(12rem, 1fr))',
        gap: 'var(--space-4)',
      }}
    >
      {Array.from({ length: fields }, (_, index) => (
        <div key={index} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
          <Skeleton height={10} shape="text" width={4} className={className} />
          <Skeleton height={14} shape="text" width={8} className={className} />
        </div>
      ))}
    </div>
    <span className="sr-only">Loading details</span>
  </div>
);
SkeletonDetail.displayName = 'SkeletonDetail';

/**
 * Skeleton for a table, matching the row structure of {@link ResponsiveTable}.
 */
export const SkeletonTable: React.FC<{ rows?: number; columns?: number; className?: string }> = ({
  rows = 5,
  columns = 4,
  className,
}) => (
  <div
    role="status"
    aria-live="polite"
    aria-busy="true"
    aria-label="Loading table"
    data-testid="skeleton-table"
    style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}
  >
    {Array.from({ length: rows }, (_, rowIndex) => (
      <div
        key={rowIndex}
        data-testid="skeleton-table-row"
        style={{
          display: 'grid',
          gridTemplateColumns: `repeat(${columns}, 1fr)`,
          gap: 'var(--space-4)',
          padding: 'var(--space-3) var(--space-4)',
          borderRadius: 'var(--radius-md)',
          backgroundColor: rowIndex === 0 ? 'var(--color-bg-tertiary)' : 'transparent',
        }}
      >
        {Array.from({ length: columns }, (_, colIndex) => (
          <Skeleton
            key={colIndex}
            height={12}
            shape="text"
            width={colIndex === 0 ? 6 : 8}
            className={className}
          />
        ))}
      </div>
    ))}
    <span className="sr-only">Loading table</span>
  </div>
);
SkeletonTable.displayName = 'SkeletonTable';
