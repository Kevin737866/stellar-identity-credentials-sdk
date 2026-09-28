import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { ResponsiveTable, ResponsiveTableColumn } from '../ResponsiveTable';

interface Row {
  id: string;
  issuer: string;
  type: string;
  risk: number;
}

const rows: Row[] = [
  { id: 'cred-1', issuer: 'Verified Identity Inc.', type: 'KYCCredential', risk: 12 },
  { id: 'cred-2', issuer: 'Gov Registry', type: 'AddressCredential', risk: 47 },
];

const columns: ResponsiveTableColumn<Row>[] = [
  { key: 'type', header: 'Credential' },
  { key: 'issuer', header: 'Issuer' },
  {
    key: 'risk',
    header: 'Risk',
    mobileLabel: 'Risk score',
    align: 'right',
    render: (row) => `${row.risk}/100`,
  },
  { key: 'id', header: 'Id', hideOnMobile: true },
];

describe('ResponsiveTable', () => {
  it('renders headers and one row per record', () => {
    render(<ResponsiveTable columns={columns} rows={rows} rowKey={(row) => row.id} />);

    expect(screen.getByRole('table')).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(rows.length + 1);
    expect(screen.getByText('Verified Identity Inc.')).toBeInTheDocument();
    expect(screen.getByText('47/100')).toBeInTheDocument();
  });

  it('collapses rows into cards below the tablet breakpoint', () => {
    render(<ResponsiveTable columns={columns} rows={rows} rowKey={(row) => row.id} />);

    expect(screen.getByRole('table')).toHaveClass('si-table--stack');
  });

  it('labels each cell so the collapsed card stays readable', () => {
    render(<ResponsiveTable columns={columns} rows={rows} rowKey={(row) => row.id} />);

    const riskCells = screen.getAllByText('12/100');
    expect(riskCells[0]).toHaveAttribute('data-label', 'Risk score');

    const issuerCells = screen.getAllByText('Gov Registry');
    expect(issuerCells[0]).toHaveAttribute('data-label', 'Issuer');
  });

  it('omits the mobile label when the header is not plain text', () => {
    const richColumns: ResponsiveTableColumn<Row>[] = [
      { key: 'type', header: <span>Credential</span> },
      { key: 'issuer', header: 'Issuer' },
    ];

    render(<ResponsiveTable columns={richColumns} rows={rows} rowKey={(row) => row.id} />);

    const cells = document.querySelectorAll('tbody td');
    expect(cells[0]).not.toHaveAttribute('data-label');
    expect(cells[1]).toHaveAttribute('data-label', 'Issuer');
  });

  it('marks columns that should drop out of the card view', () => {
    render(<ResponsiveTable columns={columns} rows={rows} rowKey={(row) => row.id} />);

    expect(screen.getByRole('columnheader', { name: 'Id' })).toHaveClass('si-table__hide-mobile');
  });

  it('right-aligns numeric columns for scannability', () => {
    render(<ResponsiveTable columns={columns} rows={rows} rowKey={(row) => row.id} />);

    expect(screen.getByText('12/100')).toHaveClass('si-table__numeric');
  });

  it('keeps the plain table layout when stacking is disabled', () => {
    render(
      <ResponsiveTable
        columns={columns}
        rows={rows}
        rowKey={(row) => row.id}
        stackOnMobile={false}
      />
    );

    expect(screen.getByRole('table')).toHaveClass('si-table');
    expect(screen.getByRole('table')).not.toHaveClass('si-table--stack');
  });

  it('renders a caption when provided', () => {
    render(
      <ResponsiveTable
        columns={columns}
        rows={rows}
        rowKey={(row) => row.id}
        caption="Held credentials"
      />
    );

    expect(screen.getByText('Held credentials')).toBeInTheDocument();
  });

  it('renders the empty state instead of a table when there are no rows', () => {
    render(
      <ResponsiveTable
        columns={columns}
        rows={[]}
        rowKey={(row) => row.id}
        emptyMessage="No credentials found"
      />
    );

    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('No credentials found');
  });

  it('makes rows interactive by click and by keyboard', () => {
    const onRowClick = jest.fn();
    render(
      <ResponsiveTable
        columns={columns}
        rows={rows}
        rowKey={(row) => row.id}
        onRowClick={onRowClick}
      />
    );

    fireEvent.click(screen.getByText('Verified Identity Inc.'));
    expect(onRowClick).toHaveBeenCalledWith(rows[0]);

    const secondRow = screen.getByText('Gov Registry').closest('tr') as HTMLTableRowElement;
    fireEvent.keyDown(secondRow, { key: 'Enter' });
    expect(onRowClick).toHaveBeenCalledWith(rows[1]);
  });
});
