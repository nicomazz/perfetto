/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import m from 'mithril';
import {SortDirection} from '../base/comparison_utils';
import {sqliteString} from '../base/string_utils';
import {Actions} from '../common/actions';
import {DropDirection} from '../common/dragndrop_logic';
import {COUNT_AGGREGATION} from '../common/empty_state';
import {PivotTableResult} from '../common/state';
import {Area} from '../public/selection';
import {raf} from '../core/raf_scheduler';
import {ColumnType} from '../trace_processor/query_result';
import {globals} from './globals';
import {
  aggregationIndex,
  areaFilters,
  sliceAggregationColumns,
  tables,
} from './pivot_table_query_generator';
import {
  Aggregation,
  AggregationFunction,
  columnKey,
  PivotTree,
  TableColumn,
} from './pivot_table_types';
import {PopupMenuButton, popupMenuIcon, PopupMenuItem} from './popup_menu';
import {ReorderableCell, ReorderableCellGroup} from './reorderable_cells';
import {AttributeModalHolder} from './tables/attribute_modal_holder';
import {DurationWidget} from './widgets/duration';
import {addSqlTableTab} from './sql_table_tab_interface';
import {getSqlTableDescription} from './widgets/sql/table/sql_table_registry';
import {assertExists, assertFalse} from '../base/logging';
import {Filter, SqlColumn} from './widgets/sql/table/column';
import {argSqlColumn} from './widgets/sql/table/well_known_columns';
import {Trace} from '../public/trace';

interface PathItem {
  tree: PivotTree;
  nextKey: ColumnType;
}

interface PivotTableAttrs {
  trace: Trace;
  selectionArea: Area;
}

interface DrillFilter {
  column: TableColumn;
  value: ColumnType;
}

function drillFilterColumnName(column: TableColumn): SqlColumn {
  switch (column.kind) {
    case 'argument':
      return argSqlColumn('arg_set_id', column.argument);
    case 'regular':
      return `${column.column}`;
  }
}

// Convert DrillFilter to SQL condition to be used in WHERE clause.
function renderDrillFilter(filter: DrillFilter): Filter {
  const column = drillFilterColumnName(filter.column);
  const value = filter.value;
  if (value === null) {
    return {op: (cols) => `${cols[0]} IS NULL`, columns: [column]};
  } else if (typeof value === 'number' || typeof value === 'bigint') {
    return {op: (cols) => `${cols[0]} = ${filter.value}`, columns: [column]};
  } else if (value instanceof Uint8Array) {
    throw new Error(`BLOB as DrillFilter not implemented`);
  }
  return {
    op: (cols) => `${cols[0]} = ${sqliteString(value)}`,
    columns: [column],
  };
}

function readableColumnName(column: TableColumn) {
  switch (column.kind) {
    case 'argument':
      return `Argument ${column.argument}`;
    case 'regular':
      return `${column.column}`;
  }
}

export function markFirst(index: number) {
  if (index === 0) {
    return '.first';
  }
  return '';
}

export class PivotTable implements m.ClassComponent<PivotTableAttrs> {
  constructor() {
    this.attributeModalHolder = new AttributeModalHolder((arg) => {
      globals.dispatch(
        Actions.setPivotTablePivotSelected({
          column: {kind: 'argument', argument: arg},
          selected: true,
        }),
      );
      globals.dispatch(
        Actions.setPivotTableQueryRequested({queryRequested: true}),
      );
    });
  }

  get pivotState() {
    return globals.state.nonSerializableState.pivotTable;
  }
  get constrainToArea() {
    return globals.state.nonSerializableState.pivotTable.constrainToArea;
  }

  renderDrillDownCell(attrs: PivotTableAttrs, filters: DrillFilter[]) {
    return m(
      'td',
      m(
        'button',
        {
          title: 'All corresponding slices',
          onclick: () => {
            const queryFilters = filters.map(renderDrillFilter);
            if (this.constrainToArea) {
              queryFilters.push(...areaFilters(attrs.selectionArea));
            }
            addSqlTableTab(attrs.trace, {
              table: assertExists(getSqlTableDescription('slice')),
              // TODO(altimin): this should properly reference the required columns, but it works for now (until the pivot table is going to be rewritten to be more flexible).
              filters: queryFilters,
            });
          },
        },
        m('i.material-icons', 'arrow_right'),
      ),
    );
  }

  renderSectionRow(
    attrs: PivotTableAttrs,
    path: PathItem[],
    tree: PivotTree,
    result: PivotTableResult,
  ): m.Vnode {
    const renderedCells = [];
    for (let j = 0; j + 1 < path.length; j++) {
      renderedCells.push(m('td', m('span.indent', ' '), `${path[j].nextKey}`));
    }

    const treeDepth = result.metadata.pivotColumns.length;
    const colspan = treeDepth - path.length + 1;
    const button = m(
      'button',
      {
        onclick: () => {
          tree.isCollapsed = !tree.isCollapsed;
          raf.scheduleFullRedraw();
        },
      },
      m('i.material-icons', tree.isCollapsed ? 'expand_more' : 'expand_less'),
    );

    renderedCells.push(
      m('td', {colspan}, button, `${path[path.length - 1].nextKey}`),
    );

    for (let i = 0; i < result.metadata.aggregationColumns.length; i++) {
      const renderedValue = this.renderCell(
        result.metadata.aggregationColumns[i].column,
        tree.aggregates[i],
      );
      renderedCells.push(m('td' + markFirst(i), renderedValue));
    }

    const drillFilters: DrillFilter[] = [];
    for (let i = 0; i < path.length; i++) {
      drillFilters.push({
        value: `${path[i].nextKey}`,
        column: result.metadata.pivotColumns[i],
      });
    }

    renderedCells.push(this.renderDrillDownCell(attrs, drillFilters));
    return m('tr', renderedCells);
  }

  renderCell(column: TableColumn, value: ColumnType): m.Children {
    if (
      column.kind === 'regular' &&
      (column.column === 'dur' || column.column === 'thread_dur')
    ) {
      if (typeof value === 'bigint') {
        return m(DurationWidget, {dur: value});
      } else if (typeof value === 'number') {
        return m(DurationWidget, {dur: BigInt(Math.round(value))});
      }
    }
    return `${value}`;
  }

  renderTree(
    attrs: PivotTableAttrs,
    path: PathItem[],
    tree: PivotTree,
    result: PivotTableResult,
    sink: m.Vnode[],
  ) {
    if (tree.isCollapsed) {
      sink.push(this.renderSectionRow(attrs, path, tree, result));
      return;
    }
    if (tree.children.size > 0) {
      // Avoid rendering the intermediate results row for the root of tree
      // and in case there's only one child subtree.
      if (!tree.isCollapsed && path.length > 0 && tree.children.size !== 1) {
        sink.push(this.renderSectionRow(attrs, path, tree, result));
      }
      for (const [key, childTree] of tree.children.entries()) {
        path.push({tree: childTree, nextKey: key});
        this.renderTree(attrs, path, childTree, result, sink);
        path.pop();
      }
      return;
    }

    // Avoid rendering the intermediate results row if it has only one leaf
    // row.
    if (!tree.isCollapsed && path.length > 0 && tree.rows.length > 1) {
      sink.push(this.renderSectionRow(attrs, path, tree, result));
    }
    for (const row of tree.rows) {
      const renderedCells = [];
      const drillFilters: DrillFilter[] = [];
      const treeDepth = result.metadata.pivotColumns.length;
      for (let j = 0; j < treeDepth; j++) {
        const value = this.renderCell(result.metadata.pivotColumns[j], row[j]);
        if (j < path.length) {
          renderedCells.push(m('td', m('span.indent', ' '), value));
        } else {
          renderedCells.push(m(`td`, value));
        }
        drillFilters.push({
          column: result.metadata.pivotColumns[j],
          value: row[j],
        });
      }
      for (let j = 0; j < result.metadata.aggregationColumns.length; j++) {
        const value = row[aggregationIndex(treeDepth, j)];
        const renderedValue = this.renderCell(
          result.metadata.aggregationColumns[j].column,
          value,
        );
        renderedCells.push(m('td.aggregation' + markFirst(j), renderedValue));
      }

      renderedCells.push(this.renderDrillDownCell(attrs, drillFilters));
      sink.push(m('tr', renderedCells));
    }
  }

  renderTotalsRow(queryResult: PivotTableResult) {
    const overallValuesRow = [
      m(
        'td.total-values',
        {colspan: queryResult.metadata.pivotColumns.length},
        m('strong', 'Total values:'),
      ),
    ];
    for (let i = 0; i < queryResult.metadata.aggregationColumns.length; i++) {
      overallValuesRow.push(
        m(
          'td' + markFirst(i),
          this.renderCell(
            queryResult.metadata.aggregationColumns[i].column,
            queryResult.tree.aggregates[i],
          ),
        ),
      );
    }
    overallValuesRow.push(m('td'));
    return m('tr', overallValuesRow);
  }

  sortingItem(aggregationIndex: number, order: SortDirection): PopupMenuItem {
    return {
      itemType: 'regular',
      text: order === 'DESC' ? 'Highest first' : 'Lowest first',
      callback() {
        globals.dispatch(
          Actions.setPivotTableSortColumn({aggregationIndex, order}),
        );
        globals.dispatch(
          Actions.setPivotTableQueryRequested({queryRequested: true}),
        );
      },
    };
  }

  readableAggregationName(aggregation: Aggregation) {
    if (aggregation.aggregationFunction === 'COUNT') {
      return 'Count';
    }
    return `${aggregation.aggregationFunction}(${readableColumnName(
      aggregation.column,
    )})`;
  }

  aggregationPopupItem(
    aggregation: Aggregation,
    index: number,
    nameOverride?: string,
  ): PopupMenuItem {
    return {
      itemType: 'regular',
      text: nameOverride ?? readableColumnName(aggregation.column),
      callback: () => {
        globals.dispatch(
          Actions.addPivotTableAggregation({aggregation, after: index}),
        );
        globals.dispatch(
          Actions.setPivotTableQueryRequested({queryRequested: true}),
        );
      },
    };
  }

  aggregationPopupTableGroup(
    table: string,
    columns: string[],
    index: number,
  ): PopupMenuItem | undefined {
    const items = [];
    for (const column of columns) {
      const tableColumn: TableColumn = {kind: 'regular', table, column};
      items.push(
        this.aggregationPopupItem(
          {aggregationFunction: 'SUM', column: tableColumn},
          index,
        ),
      );
    }

    if (items.length === 0) {
      return undefined;
    }

    return {
      itemType: 'group',
      itemId: `aggregations-${table}`,
      text: `Add ${table} aggregation`,
      children: items,
    };
  }

  renderAggregationHeaderCell(
    aggregation: Aggregation,
    index: number,
    removeItem: boolean,
  ): ReorderableCell {
    const popupItems: PopupMenuItem[] = [];
    const state = globals.state.nonSerializableState.pivotTable;
    if (aggregation.sortDirection === undefined) {
      popupItems.push(
        this.sortingItem(index, 'DESC'),
        this.sortingItem(index, 'ASC'),
      );
    } else {
      // Table is already sorted by the same column, return one item with
      // opposite direction.
      popupItems.push(
        this.sortingItem(
          index,
          aggregation.sortDirection === 'DESC' ? 'ASC' : 'DESC',
        ),
      );
    }
    const otherAggs: AggregationFunction[] = ['SUM', 'MAX', 'MIN', 'AVG'];
    if (aggregation.aggregationFunction !== 'COUNT') {
      for (const otherAgg of otherAggs) {
        if (aggregation.aggregationFunction === otherAgg) {
          continue;
        }

        popupItems.push({
          itemType: 'regular',
          text: otherAgg,
          callback() {
            globals.dispatch(
              Actions.setPivotTableAggregationFunction({
                index,
                function: otherAgg,
              }),
            );
            globals.dispatch(
              Actions.setPivotTableQueryRequested({queryRequested: true}),
            );
          },
        });
      }
    }

    if (removeItem) {
      popupItems.push({
        itemType: 'regular',
        text: 'Remove',
        callback: () => {
          globals.dispatch(Actions.removePivotTableAggregation({index}));
          globals.dispatch(
            Actions.setPivotTableQueryRequested({queryRequested: true}),
          );
        },
      });
    }

    let hasCount = false;
    for (const agg of state.selectedAggregations.values()) {
      if (agg.aggregationFunction === 'COUNT') {
        hasCount = true;
      }
    }

    if (!hasCount) {
      popupItems.push(
        this.aggregationPopupItem(
          COUNT_AGGREGATION,
          index,
          'Add count aggregation',
        ),
      );
    }

    const sliceAggregationsItem = this.aggregationPopupTableGroup(
      assertExists(getSqlTableDescription('slice')).name,
      sliceAggregationColumns,
      index,
    );
    if (sliceAggregationsItem !== undefined) {
      popupItems.push(sliceAggregationsItem);
    }

    return {
      extraClass: '.aggregation' + markFirst(index),
      content: [
        this.readableAggregationName(aggregation),
        m(PopupMenuButton, {
          icon: popupMenuIcon(aggregation.sortDirection),
          items: popupItems,
        }),
      ],
    };
  }

  attributeModalHolder: AttributeModalHolder;

  renderPivotColumnHeader(
    queryResult: PivotTableResult,
    pivot: TableColumn,
    selectedPivots: Set<string>,
  ): ReorderableCell {
    const items: PopupMenuItem[] = [
      {
        itemType: 'regular',
        text: 'Add argument pivot',
        callback: () => {
          this.attributeModalHolder.start();
        },
      },
    ];
    if (queryResult.metadata.pivotColumns.length > 1) {
      items.push({
        itemType: 'regular',
        text: 'Remove',
        callback() {
          globals.dispatch(
            Actions.setPivotTablePivotSelected({
              column: pivot,
              selected: false,
            }),
          );
          globals.dispatch(
            Actions.setPivotTableQueryRequested({queryRequested: true}),
          );
        },
      });
    }

    for (const table of tables) {
      const group: PopupMenuItem[] = [];
      for (const columnName of table.columns) {
        const column: TableColumn = {
          kind: 'regular',
          table: table.name,
          column: columnName,
        };
        if (selectedPivots.has(columnKey(column))) {
          continue;
        }

        group.push({
          itemType: 'regular',
          text: columnName,
          callback() {
            globals.dispatch(
              Actions.setPivotTablePivotSelected({column, selected: true}),
            );
            globals.dispatch(
              Actions.setPivotTableQueryRequested({queryRequested: true}),
            );
          },
        });
      }
      items.push({
        itemType: 'group',
        itemId: `pivot-${table.name}`,
        text: `Add ${table.displayName} pivot`,
        children: group,
      });
    }

    return {
      content: [
        readableColumnName(pivot),
        m(PopupMenuButton, {icon: 'more_horiz', items}),
      ],
    };
  }

  renderResultsTable(attrs: PivotTableAttrs) {
    const state = globals.state.nonSerializableState.pivotTable;
    if (state.queryResult === null) {
      return m('div', 'Loading...');
    }
    const queryResult: PivotTableResult = state.queryResult;

    const renderedRows: m.Vnode[] = [];

    // We should not even be showing the tab if there's no results.
    const tree = state.queryResult.tree;
    assertFalse(tree.children.size === 0 && tree.rows.length === 0);

    this.renderTree(attrs, [], tree, state.queryResult, renderedRows);

    const selectedPivots = new Set(
      this.pivotState.selectedPivots.map(columnKey),
    );
    const pivotTableHeaders = state.selectedPivots.map((pivot) =>
      this.renderPivotColumnHeader(queryResult, pivot, selectedPivots),
    );

    const removeItem = state.queryResult.metadata.aggregationColumns.length > 1;
    const aggregationTableHeaders =
      state.queryResult.metadata.aggregationColumns.map((aggregation, index) =>
        this.renderAggregationHeaderCell(aggregation, index, removeItem),
      );

    return m(
      'table.pivot-table',
      m(
        'thead',
        // First row of the table, containing names of pivot and aggregation
        // columns, as well as popup menus to modify the columns. Last cell
        // is empty because of an extra column with "drill down" button for
        // each pivot table row.
        m(
          'tr.header',
          m(ReorderableCellGroup, {
            cells: pivotTableHeaders,
            onReorder: (from: number, to: number, direction: DropDirection) => {
              globals.dispatch(
                Actions.changePivotTablePivotOrder({from, to, direction}),
              );
              globals.dispatch(
                Actions.setPivotTableQueryRequested({queryRequested: true}),
              );
            },
          }),
          m(ReorderableCellGroup, {
            cells: aggregationTableHeaders,
            onReorder: (from: number, to: number, direction: DropDirection) => {
              globals.dispatch(
                Actions.changePivotTableAggregationOrder({from, to, direction}),
              );
              globals.dispatch(
                Actions.setPivotTableQueryRequested({queryRequested: true}),
              );
            },
          }),
          m(
            'td.menu',
            m(PopupMenuButton, {
              icon: 'menu',
              items: [
                {
                  itemType: 'regular',
                  text: state.constrainToArea
                    ? 'Query data for the whole timeline'
                    : 'Constrain to selected area',
                  callback: () => {
                    globals.dispatch(
                      Actions.setPivotTableConstrainToArea({
                        constrain: !state.constrainToArea,
                      }),
                    );
                    globals.dispatch(
                      Actions.setPivotTableQueryRequested({
                        queryRequested: true,
                      }),
                    );
                  },
                },
              ],
            }),
          ),
        ),
      ),
      m('tbody', this.renderTotalsRow(state.queryResult), renderedRows),
    );
  }

  view({attrs}: m.Vnode<PivotTableAttrs>): m.Children {
    return m('.pivot-table', this.renderResultsTable(attrs));
  }
}
