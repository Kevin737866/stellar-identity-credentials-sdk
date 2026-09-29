import React, { useState } from 'react';
import { render, screen, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useFocusTrap, getFocusableElements, useRovingIndex } from '@/hooks/useFocusTrap';

describe('getFocusableElements', () => {
  it('collects focusable descendants in order', () => {
    const { container } = render(
      <div>
        <button>One</button>
        <a href="#two">Two</a>
        <input />
        <select />
        <textarea />
        <div tabIndex={0}>Div</div>
      </div>,
    );

    expect(getFocusableElements(container)).toHaveLength(6);
  });

  it('excludes disabled and hidden controls', () => {
    const { container } = render(
      <div>
        <button>Enabled</button>
        <button disabled>Disabled</button>
        <input disabled />
        <div tabIndex={-1}>Not tabbable</div>
        <input type="hidden" />
      </div>,
    );

    const found = getFocusableElements(container);
    expect(found).toHaveLength(1);
    expect(found[0].textContent).toBe('Enabled');
  });

  it('excludes aria-hidden elements', () => {
    const { container } = render(
      <div>
        <button>Visible</button>
        <div aria-hidden="true">
          <button>Hidden</button>
        </div>
      </div>,
    );

    const found = getFocusableElements(container);
    expect(found.some(el => el.textContent === 'Hidden')).toBe(false);
  });

  it('returns nothing for a null container', () => {
    expect(getFocusableElements(null)).toEqual([]);
  });
});

const Trap: React.FC<{ onEscape?: () => void; enabled?: boolean }> = ({
  onEscape,
  enabled = true,
}) => {
  const ref = useFocusTrap<HTMLDivElement>(true, {
    ...(onEscape ? { onEscape } : {}),
    enabled,
  });
  return (
    <div>
      <button>Outside</button>
      <div ref={ref} data-testid="trap">
        <button>First</button>
        <button>Second</button>
        <button>Last</button>
      </div>
    </div>
  );
};

describe('useFocusTrap', () => {
  it('moves focus inside the container on mount', () => {
    render(<Trap />);
    const trap = screen.getByTestId('trap');
    expect(trap).toContainElement(document.activeElement as HTMLElement);
  });

  it('wraps Tab from the last element to the first', async () => {
    const user = userEvent.setup();
    render(<Trap />);

    const buttons = screen.getByTestId('trap').querySelectorAll('button');
    (buttons[buttons.length - 1] as HTMLButtonElement).focus();

    await user.tab();

    expect(buttons[0]).toHaveFocus();
  });

  it('wraps Shift+Tab from the first element to the last', async () => {
    const user = userEvent.setup();
    render(<Trap />);

    const buttons = screen.getByTestId('trap').querySelectorAll('button');
    (buttons[0] as HTMLButtonElement).focus();

    await user.tab({ shift: true });

    expect(buttons[buttons.length - 1]).toHaveFocus();
  });

  it('leaves focus alone when it is inside the container', async () => {
    const user = userEvent.setup();
    render(<Trap />);

    const buttons = screen.getByTestId('trap').querySelectorAll('button');
    (buttons[0] as HTMLButtonElement).focus();

    await user.tab();

    expect(buttons[1]).toHaveFocus();
  });

  it('calls onEscape when Escape is pressed', async () => {
    const user = userEvent.setup();
    const onEscape = jest.fn();
    render(<Trap onEscape={onEscape} />);

    await user.keyboard('{Escape}');

    expect(onEscape).toHaveBeenCalledTimes(1);
  });

  it('does not call onEscape when it is not supplied', async () => {
    const user = userEvent.setup();
    render(<Trap />);

    await expect(user.keyboard('{Escape}')).resolves.not.toThrow();
  });

  it('restores focus to the previously focused element on unmount', async () => {
    const user = userEvent.setup();

    const Host: React.FC = () => {
      const [open, setOpen] = useState(false);
      return (
        <div>
          <button onClick={() => setOpen(true)}>Open</button>
          {open && <Trap />}
          {open && (
            <button onClick={() => setOpen(false)}>Close</button>
          )}
        </div>
      );
    };

    render(<Host />);
    const opener = screen.getByRole('button', { name: 'Open' });
    await user.click(opener);
    expect(opener).not.toHaveFocus();

    await user.click(screen.getByRole('button', { name: 'Close' }));
    expect(opener).toHaveFocus();
  });

  it('can be disabled without unmounting', () => {
    const { rerender } = render(<Trap enabled />);
    expect(screen.getByTestId('trap')).toContainElement(document.activeElement as HTMLElement);

    rerender(<Trap enabled={false} />);
    expect(screen.getByTestId('trap')).not.toContainElement(document.activeElement as HTMLElement);
  });
});

const Roving: React.FC = () => {
  const { getItemProps } = useRovingIndex(3);
  return (
    <div>
      {['A', 'B', 'C'].map((label, index) => (
        <button key={label} {...getItemProps(index)}>
          {label}
        </button>
      ))}
    </div>
  );
};

describe('useRovingIndex', () => {
  it('puts only the active item in the tab order', () => {
    render(<Roving />);
    const buttons = screen.getAllByRole('button');

    expect(buttons[0]).toHaveAttribute('tabindex', '0');
    expect(buttons[1]).toHaveAttribute('tabindex', '-1');
    expect(buttons[2]).toHaveAttribute('tabindex', '-1');
  });

  it('moves forward with ArrowRight', async () => {
    const user = userEvent.setup();
    render(<Roving />);

    screen.getAllByRole('button')[0].focus();
    await user.keyboard('{ArrowRight}');

    expect(screen.getAllByRole('button')[1]).toHaveFocus();
  });

  it('moves backward with ArrowLeft', async () => {
    const user = userEvent.setup();
    render(<Roving />);

    screen.getAllByRole('button')[2].focus();
    await user.keyboard('{ArrowLeft}');

    expect(screen.getAllByRole('button')[1]).toHaveFocus();
  });

  it('wraps around at both ends', async () => {
    const user = userEvent.setup();
    render(<Roving />);

    screen.getAllByRole('button')[2].focus();
    await user.keyboard('{ArrowRight}');
    expect(screen.getAllByRole('button')[0]).toHaveFocus();
  });

  it('jumps with Home and End', async () => {
    const user = userEvent.setup();
    render(<Roving />);

    screen.getAllByRole('button')[0].focus();
    await user.keyboard('{End}');
    expect(screen.getAllByRole('button')[2]).toHaveFocus();

    await user.keyboard('{Home}');
    expect(screen.getAllByRole('button')[0]).toHaveFocus();
  });

  it('ignores unrelated keys', async () => {
    const user = userEvent.setup();
    render(<Roving />);

    screen.getAllByRole('button')[0].focus();
    await user.keyboard('{ArrowDown}');

    expect(screen.getAllByRole('button')[0]).toHaveFocus();
  });
});
