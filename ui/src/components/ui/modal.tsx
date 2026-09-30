import React, { useId } from 'react';
import { useFocusTrap } from '@/hooks/useFocusTrap';

export interface DialogProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  children: React.ReactNode;
}

export const Dialog: React.FC<DialogProps> = ({ open, onOpenChange, children }) => {
  if (!open) {
    return <>{React.Children.toArray(children).filter(
      (child) => React.isValidElement(child) && (child as React.ReactElement<any>).type === DialogTrigger
    )}</>;
  }
  return <>{children}</>;
};

export interface DialogTriggerProps {
  asChild?: boolean;
  children: React.ReactNode;
}

export const DialogTrigger: React.FC<DialogTriggerProps> = ({ children }) => {
  return <>{children}</>;
};

export interface DialogContentProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  /** Close the dialog when Escape is pressed. Default true. */
  closeOnEscape?: boolean;
  /** Close the dialog when the backdrop is clicked. Default true. */
  closeOnOverlayClick?: boolean;
  /** Accessible name, required when there is no {@link DialogTitle}. */
  'aria-label'?: string;
}

export const DialogContent = React.forwardRef<HTMLDivElement, DialogContentProps>(
  ({ style, children, closeOnEscape = true, closeOnOverlayClick = true, ...props }, ref) => {
    const titleId = useId();
    const descriptionId = useId();

    // The overlay is the focus-trap container: focus is moved inside it on
    // open and returned to the trigger on close.
    const trapRef = useFocusTrap<HTMLDivElement>(true, {
      onEscape: closeOnEscape
        ? () => trapRef.current?.dispatchEvent(new CustomEvent('dialog-close'))
        : undefined,
    });

    const handleOverlayClick = (e: React.MouseEvent) => {
      if (!closeOnOverlayClick) return;
      if (e.target === trapRef.current) {
        trapRef.current?.dispatchEvent(new CustomEvent('dialog-close'));
      }
    };

    // A dialog with no accessible name is unusable with a screen reader, so
    // fail loudly in development rather than shipping an unlabelled overlay.
    const hasTitle = React.Children.toArray(children).some(
      child => React.isValidElement(child) && (child.type as any)?.displayName === 'DialogTitle',
    );
    // Only reference ids that a matching child actually renders, otherwise
    // aria-labelledby/describedby point at nothing.
    const hasDescription = React.Children.toArray(children).some(
      child => React.isValidElement(child) && (child.type as any)?.displayName === 'DialogDescription',
    );
    if (process.env.NODE_ENV !== 'production' && !hasTitle && !props['aria-label']) {
      // eslint-disable-next-line no-console
      console.warn(
        'DialogContent: provide a DialogTitle or an aria-label so the dialog has an accessible name.',
      );
    }

    const hasAriaLabel = props['aria-label'] !== undefined;

    return (
      <div
        ref={trapRef}
        onClick={handleOverlayClick}
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 50,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
        }}
      >
        <div
          ref={ref}
          role="dialog"
          aria-modal="true"
          aria-labelledby={hasTitle && !hasAriaLabel ? titleId : undefined}
          aria-describedby={hasDescription ? descriptionId : undefined}
          style={{
            backgroundColor: 'var(--color-bg)',
            borderRadius: 'var(--radius-lg)',
            boxShadow: 'var(--shadow-xl)',
            padding: 'var(--space-6)',
            width: '100%',
            maxWidth: '32rem',
            maxHeight: '85vh',
            overflowY: 'auto',
            margin: 'var(--space-4)',
            ...style,
          }}
          {...props}
        >
          {/* The generated title id reaches DialogTitle through context so the
              caller does not have to thread ids through by hand. */}
          <DialogTitleContext.Provider value={{ titleId, descriptionId }}>
            {children}
          </DialogTitleContext.Provider>
        </div>
      </div>
    );
  }
);
DialogContent.displayName = 'DialogContent';

const DialogTitleContext = React.createContext<{ titleId: string; descriptionId: string } | null>(null);

export const DialogHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ style, children, ...props }) => (
  <div
    style={{
      display: 'flex',
      flexDirection: 'column',
      gap: 'var(--space-2)',
      marginBottom: 'var(--space-4)',
      ...style,
    }}
    {...props}
  >
    {children}
  </div>
);

export const DialogTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({ style, children, id, ...props }) => {
  const context = React.useContext(DialogTitleContext);
  return (
    <h2
      id={id ?? context?.titleId}
      style={{
        fontSize: 'var(--font-size-lg)',
        fontWeight: 'var(--font-weight-semibold)' as any,
        color: 'var(--color-text)',
        margin: 0,
        ...style,
      }}
      {...props}
    >
      {children}
    </h2>
  );
};
DialogTitle.displayName = 'DialogTitle';

export const DialogDescription: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({
  style,
  children,
  id,
  ...props
}) => {
  const context = React.useContext(DialogTitleContext);
  return (
    <p
      id={id ?? context?.descriptionId}
      style={{
        fontSize: 'var(--font-size-sm)',
        color: 'var(--color-text-secondary)',
        margin: 0,
        lineHeight: 'var(--line-height-normal)',
        ...style,
      }}
      {...props}
    >
      {children}
    </p>
  );
};
DialogDescription.displayName = 'DialogDescription';

export const DialogFooter: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({ style, children, ...props }) => (
  <div
    style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'flex-end',
      gap: 'var(--space-3)',
      marginTop: 'var(--space-6)',
      ...style,
    }}
    {...props}
  >
    {children}
  </div>
);
DialogFooter.displayName = 'DialogFooter';
