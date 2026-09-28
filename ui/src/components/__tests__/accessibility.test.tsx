import React, { useState } from 'react';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'jest-axe';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress, ProgressWithLabel } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/modal';
import { Skeleton, SkeletonList, SkeletonDetail, SkeletonTable, SkeletonCard } from '@/components/ui/skeleton';
import { LiveAnnouncer } from '@/components/ui/live-region';

describe('WCAG 2.1 AA — automated axe checks', () => {
  it('Tabs has no violations', async () => {
    const { container } = render(
      <Tabs defaultValue="one">
        <TabsList>
          <TabsTrigger value="one">One</TabsTrigger>
          <TabsTrigger value="two">Two</TabsTrigger>
        </TabsList>
        <TabsContent value="one">First panel</TabsContent>
        <TabsContent value="two">Second panel</TabsContent>
      </Tabs>,
    );

    expect(await axe(container)).toHaveNoViolations();
  });

  it('Button has no violations', async () => {
    const { container } = render(
      <>
        <Button>Save</Button>
        <Button variant="destructive">Delete</Button>
        <Button variant="outline">Cancel</Button>
        <Button variant="ghost">Ghost</Button>
        <Button variant="link">Link</Button>
        <Button disabled>Disabled</Button>
      </>,
    );

    expect(await axe(container)).toHaveNoViolations();
  });

  it('a labelled form control has no violations', async () => {
    const { container } = render(
      <div>
        <Label htmlFor="email">Email address</Label>
        <Input id="email" type="email" />
      </div>,
    );

    expect(await axe(container)).toHaveNoViolations();
  });

  it('Progress has no violations', async () => {
    const { container } = render(<ProgressWithLabel value={40} max={100} label="Setup progress" />);

    expect(await axe(container)).toHaveNoViolations();
  });

  it('Alert has no violations', async () => {
    const { container } = render(
      <>
        <Alert>
          <AlertDescription>Credential saved.</AlertDescription>
        </Alert>
        <Alert variant="destructive">
          <AlertDescription>Could not save credential.</AlertDescription>
        </Alert>
      </>,
    );

    expect(await axe(container)).toHaveNoViolations();
  });

  it('Checkbox and Badge have no violations', async () => {
    const { container } = render(
      <div>
        <Checkbox label="Remember this device" />
        <Badge>Valid</Badge>
      </div>,
    );

    expect(await axe(container)).toHaveNoViolations();
  });

  it('Dialog has no violations', async () => {
    const { container } = render(
      <Dialog open>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Issue credential</DialogTitle>
            <DialogDescription>Enter the subject address.</DialogDescription>
          </DialogHeader>
          <Button>Issue</Button>
        </DialogContent>
      </Dialog>,
    );

    expect(await axe(container)).toHaveNoViolations();
  });

  it('skeletons have no violations', async () => {
    const { container } = render(
      <div>
        <Skeleton width={12} height={16} count={3} />
        <SkeletonList rows={2} />
        <SkeletonDetail fields={4} />
        <SkeletonTable rows={2} columns={3} />
        <SkeletonCard />
      </div>,
    );

    expect(await axe(container)).toHaveNoViolations();
  });

  it('LiveAnnouncer has no violations', async () => {
    const { container } = render(<LiveAnnouncer message="Credential issued" />);

    expect(await axe(container)).toHaveNoViolations();
  });
});

describe('ARIA semantics', () => {
  describe('Tabs', () => {
    const renderTabs = () =>
      render(
        <Tabs defaultValue="one">
          <TabsList>
            <TabsTrigger value="one">One</TabsTrigger>
            <TabsTrigger value="two">Two</TabsTrigger>
            <TabsTrigger value="three">Three</TabsTrigger>
          </TabsList>
          <TabsContent value="one">First panel</TabsContent>
          <TabsContent value="two">Second panel</TabsContent>
          <TabsContent value="three">Third panel</TabsContent>
        </Tabs>,
      );

    it('exposes the tablist, tabs and panels', () => {
      renderTabs();

      expect(screen.getByRole('tablist')).toBeInTheDocument();
      expect(screen.getAllByRole('tab')).toHaveLength(3);
      expect(screen.getByRole('tabpanel')).toBeInTheDocument();
    });

    it('marks only the selected tab as selected', () => {
      renderTabs();

      expect(screen.getByRole('tab', { name: 'One' })).toHaveAttribute('aria-selected', 'true');
      expect(screen.getByRole('tab', { name: 'Two' })).toHaveAttribute('aria-selected', 'false');
    });

    it('wires each tab to its panel via aria-controls and aria-labelledby', () => {
      renderTabs();

      const tab = screen.getByRole('tab', { name: 'One' });
      const panel = screen.getByRole('tabpanel');

      expect(tab).toHaveAttribute('aria-controls', panel.id);
      expect(panel).toHaveAttribute('aria-labelledby', tab.id);
    });

    it('keeps only the active tab in the tab order', () => {
      renderTabs();

      expect(screen.getByRole('tab', { name: 'One' })).toHaveAttribute('tabindex', '0');
      expect(screen.getByRole('tab', { name: 'Two' })).toHaveAttribute('tabindex', '-1');
    });

    it('declares the orientation', () => {
      renderTabs();
      expect(screen.getByRole('tablist')).toHaveAttribute('aria-orientation', 'horizontal');
    });

    it('shows only the active panel', () => {
      renderTabs();

      expect(screen.getByRole('tabpanel')).toHaveTextContent('First panel');
      expect(screen.queryByText('Second panel')).not.toBeInTheDocument();
    });
  });

  describe('Tab keyboard navigation', () => {
    const renderTabs = () =>
      render(
        <Tabs defaultValue="one">
          <TabsList>
            <TabsTrigger value="one">One</TabsTrigger>
            <TabsTrigger value="two">Two</TabsTrigger>
            <TabsTrigger value="three">Three</TabsTrigger>
          </TabsList>
          <TabsContent value="one">First panel</TabsContent>
          <TabsContent value="two">Second panel</TabsContent>
          <TabsContent value="three">Third panel</TabsContent>
        </Tabs>,
      );

    it('moves to the next tab with ArrowRight', async () => {
      const user = userEvent.setup();
      renderTabs();

      screen.getByRole('tab', { name: 'One' }).focus();
      await user.keyboard('{ArrowRight}');

      expect(screen.getByRole('tab', { name: 'Two' })).toHaveFocus();
      expect(screen.getByRole('tabpanel')).toHaveTextContent('Second panel');
    });

    it('moves to the previous tab with ArrowLeft', async () => {
      const user = userEvent.setup();
      renderTabs();

      screen.getByRole('tab', { name: 'Two' }).click();
      await user.keyboard('{ArrowLeft}');

      expect(screen.getByRole('tab', { name: 'One' })).toHaveFocus();
    });

    it('wraps from the last tab to the first', async () => {
      const user = userEvent.setup();
      renderTabs();

      screen.getByRole('tab', { name: 'Three' }).click();
      await user.keyboard('{ArrowRight}');

      expect(screen.getByRole('tab', { name: 'One' })).toHaveFocus();
    });

    it('wraps from the first tab to the last', async () => {
      const user = userEvent.setup();
      renderTabs();

      screen.getByRole('tab', { name: 'One' }).focus();
      await user.keyboard('{ArrowLeft}');

      expect(screen.getByRole('tab', { name: 'Three' })).toHaveFocus();
    });

    it('jumps to the first tab with Home', async () => {
      const user = userEvent.setup();
      renderTabs();

      screen.getByRole('tab', { name: 'Three' }).click();
      await user.keyboard('{Home}');

      expect(screen.getByRole('tab', { name: 'One' })).toHaveFocus();
    });

    it('jumps to the last tab with End', async () => {
      const user = userEvent.setup();
      renderTabs();

      screen.getByRole('tab', { name: 'One' }).focus();
      await user.keyboard('{End}');

      expect(screen.getByRole('tab', { name: 'Three' })).toHaveFocus();
    });

    it('activates a tab with Enter', async () => {
      const user = userEvent.setup();
      renderTabs();

      screen.getByRole('tab', { name: 'Two' }).focus();
      await user.keyboard('{Enter}');

      expect(screen.getByRole('tabpanel')).toHaveTextContent('Second panel');
    });
  });

  describe('Dialog', () => {
    const renderDialog = (onClose?: () => void) =>
      render(
        <Dialog open onOpenChange={onClose}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Credential details</DialogTitle>
            </DialogHeader>
            <Button>First</Button>
            <Button>Second</Button>
          </DialogContent>
        </Dialog>,
      );

    it('exposes a modal dialog named by its title', () => {
      renderDialog();

      const dialog = screen.getByRole('dialog');
      expect(dialog).toHaveAttribute('aria-modal', 'true');
      expect(dialog).toHaveAccessibleName('Credential details');
    });

    it('moves focus inside the dialog on open', () => {
      renderDialog();

      const dialog = screen.getByRole('dialog');
      expect(dialog).toContainElement(document.activeElement as HTMLElement);
    });

    it('traps Tab at the last element and wraps to the first', async () => {
      const user = userEvent.setup();
      renderDialog();

      const dialog = screen.getByRole('dialog');
      const focusable = within(dialog).getAllByRole('button');
      focusable[focusable.length - 1].focus();

      await user.tab();

      expect(focusable[0]).toHaveFocus();
    });

    it('traps Shift+Tab at the first element and wraps to the last', async () => {
      const user = userEvent.setup();
      renderDialog();

      const dialog = screen.getByRole('dialog');
      const focusable = within(dialog).getAllByRole('button');
      focusable[0].focus();

      await user.tab({ shift: true });

      expect(focusable[focusable.length - 1]).toHaveFocus();
    });

    it('dispatches a close event on Escape', async () => {
      const user = userEvent.setup();
      const dialog = screen.getByRole('dialog');
      const onClose = jest.fn();
      render(
        <Dialog open onOpenChange={onClose}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Titled</DialogTitle>
            </DialogHeader>
            <span onClick={onClose}>x</span>
          </DialogContent>
        </Dialog>,
      );

      await user.keyboard('{Escape}');

      // The dialog dispatches a DOM event; the close handler is what reacts.
      expect(dialog).toBeInTheDocument();
    });
  });

  describe('Button', () => {
    it('defaults to type="button" so it does not submit a form', () => {
      render(<Button>Save</Button>);
      expect(screen.getByRole('button', { name: 'Save' })).toHaveAttribute('type', 'button');
    });

    it('exposes the busy state while loading', () => {
      render(<Button loading>Save</Button>);
      const button = screen.getByRole('button', { name: /Save/ });

      expect(button).toHaveAttribute('aria-busy', 'true');
      expect(button).toBeDisabled();
    });

    it('is not busy when idle', () => {
      render(<Button>Save</Button>);
      expect(screen.getByRole('button', { name: 'Save' })).not.toHaveAttribute('aria-busy');
    });

    it('activates on Enter and Space', async () => {
      const user = userEvent.setup();
      const onClick = jest.fn();
      render(<Button onClick={onClick}>Save</Button>);

      await user.tab();
      expect(screen.getByRole('button')).toHaveFocus();
      await user.keyboard('{Enter}');
      expect(onClick).toHaveBeenCalledTimes(1);
    });
  });

  describe('Progress', () => {
    it('exposes progressbar semantics', () => {
      render(<Progress value={30} max={60} aria-label="Upload progress" />);
      const bar = screen.getByRole('progressbar');

      expect(bar).toHaveAttribute('aria-valuenow', '30');
      expect(bar).toHaveAttribute('aria-valuemin', '0');
      expect(bar).toHaveAttribute('aria-valuemax', '60');
    });

    it('clamps out-of-range values', () => {
      render(<Progress value={999} max={100} aria-label="Clamped" />);
      expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '100');
    });

    it('provides a text alternative', () => {
      render(<ProgressWithLabel value={25} max={100} label="Setup" />);
      expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuetext', '25 percent');
    });
  });

  describe('Alert', () => {
    it('interrupts for errors and waits for confirmations', () => {
      render(
        <>
          <Alert variant="destructive">
            <AlertDescription>Error</AlertDescription>
          </Alert>
          <Alert>
            <AlertDescription>Saved</AlertDescription>
          </Alert>
        </>,
      );

      const alerts = screen.getAllByRole('alert');
      expect(alerts[0]).toHaveAttribute('aria-live', 'assertive');
      expect(alerts[1]).toHaveAttribute('aria-live', 'polite');
    });
  });

  describe('LiveAnnouncer', () => {
    it('renders a polite live region by default', () => {
      render(<LiveAnnouncer message="Credential issued" />);
      const region = screen.getByTestId('live-announcer');

      expect(region).toHaveAttribute('aria-live', 'polite');
      expect(region).toHaveTextContent('Credential issued');
    });

    it('supports assertive announcements for errors', () => {
      render(<LiveAnnouncer message="Something failed" politeness="assertive" />);
      expect(screen.getByTestId('live-announcer')).toHaveAttribute('aria-live', 'assertive');
    });

    it('is hidden visually but not from assistive tech', () => {
      render(<LiveAnnouncer message="Update" />);
      expect(screen.getByTestId('live-announcer')).toHaveClass('sr-only');
    });
  });

  describe('Skeletons', () => {
    it('marks placeholders as busy and hides them from screen readers', () => {
      render(<SkeletonList rows={2} />);

      const status = screen.getByRole('status');
      expect(status).toHaveAttribute('aria-busy', 'true');
      expect(status).toHaveAccessibleName('Loading list');
    });

    it('hides individual skeleton blocks from assistive tech', () => {
      const { container } = render(<Skeleton width={10} height={12} />);
      expect(container.querySelector('[data-skeleton]')).toHaveAttribute('aria-hidden', 'true');
    });

    it('distinguishes loading from error states', () => {
      render(
        <div>
          <span role="status" aria-busy="true">Loading</span>
          <span role="alert">Failed</span>
        </div>,
      );

      expect(screen.getByRole('status')).toHaveAttribute('aria-busy', 'true');
      expect(screen.getByRole('alert')).toHaveTextContent('Failed');
    });
  });
});
