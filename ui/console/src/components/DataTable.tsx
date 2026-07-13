// Reusable TanStack Table wrapper for SolidJS. Handles sorting,
// pagination, and column definitions so analytics pages don't
// re-implement the boilerplate per page.
//
// Usage:
//   <DataTable
//     data={rows()}
//     columns={columnDefs}
//     pageSize={20}
//   />

import { createSignal, For, Show, type JSX } from "solid-js";
import {
  createSolidTable,
  getCoreRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  flexRender,
  type ColumnDef,
  type SortingState,
} from "@tanstack/solid-table";

export interface DataTableProps<T> {
  data: T[];
  columns: ColumnDef<T, any>[];
  pageSize?: number;
  emptyMessage?: string;
  // rowClick receives the original row data — pages wire this to
  // open a side panel (e.g. the Decision Inspector's re-explain).
  rowClick?: (row: T) => void;
}

export function DataTable<T>(props: DataTableProps<T>): JSX.Element {
  const [sorting, setSorting] = createSignal<SortingState>([]);

  const table = createSolidTable({
    get data() {
      return props.data;
    },
    columns: props.columns,
    state: {
      get sorting() {
        return sorting();
      },
    },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: {
      pagination: { pageSize: props.pageSize ?? 20 },
    },
  });

  return (
    <div class="flex flex-col">
      <div class="overflow-auto">
        <table class="w-full text-sm">
          <thead class="bg-gray-50/80 sticky top-0 z-10">
            <For each={table.getHeaderGroups()}>
              {(headerGroup) => (
                <tr class="text-left text-[11px] font-medium text-gray-500 uppercase tracking-wider">
                  <For each={headerGroup.headers}>
                    {(header) => (
                      <th
                        class="px-4 py-3 select-none"
                        onClick={header.column.getToggleSortingHandler()}
                        style={{ cursor: header.column.getCanSort() ? "pointer" : "default" }}
                      >
                        <div class="flex items-center gap-1">
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          <Show when={header.column.getIsSorted()}>
                            <span class="text-gray-400 text-[9px]">
                              {header.column.getIsSorted() === "asc" ? "▲" : "▼"}
                            </span>
                          </Show>
                        </div>
                      </th>
                    )}
                  </For>
                </tr>
              )}
            </For>
          </thead>
          <tbody class="divide-y divide-gray-50">
            <For each={table.getRowModel().rows}>
              {(row) => (
                <tr
                  class="hover:bg-gray-50/50 transition-colors"
                  onClick={() => props.rowClick?.(row.original)}
                  style={{ cursor: props.rowClick ? "pointer" : "default" }}
                >
                  <For each={row.getVisibleCells()}>
                    {(cell) => (
                      <td class="px-4 py-2.5">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    )}
                  </For>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </div>

      <Show when={props.data.length === 0}>
        <div class="py-12 text-center">
          <p class="text-sm text-gray-400">{props.emptyMessage ?? "No data"}</p>
        </div>
      </Show>

      {/* Pagination controls */}
      <Show when={table.getPageCount() > 1}>
        <div class="flex items-center gap-2 px-4 py-3 border-t border-gray-100">
          <button
            class="px-2.5 py-1.5 text-xs font-medium rounded-md border border-gray-200 disabled:opacity-40 hover:bg-gray-50 transition-colors"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
          >
            ← Prev
          </button>
          <span class="text-xs text-gray-500">
            Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
          </span>
          <button
            class="px-2.5 py-1.5 text-xs font-medium rounded-md border border-gray-200 disabled:opacity-40 hover:bg-gray-50 transition-colors"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
          >
            Next →
          </button>
          <span class="ml-auto text-xs text-gray-400">
            {table.getFilteredRowModel().rows.length} rows
          </span>
        </div>
      </Show>
    </div>
  );
}