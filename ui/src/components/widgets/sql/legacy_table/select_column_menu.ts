// Copyright (C) 2025 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import m from 'mithril';
import {
  LegacyTableColumn,
  LegacyTableManager,
  tableColumnId,
} from './table_column';
import {MenuDivider, MenuItem} from '../../../../widgets/menu';
import {raf} from '../../../../core/raf_scheduler';
import {uuidv4} from '../../../../base/uuid';
import {hasModKey, modKey} from '../../../../base/hotkeys';
import {TextInput} from '../../../../widgets/text_input';
import {Spinner} from '../../../../widgets/spinner';

export interface SelectColumnMenuAttrs {
  columns:
    | {key: string; column: LegacyTableColumn}[]
    | (() => Promise<{key: string; column: LegacyTableColumn}[]>);
  primaryColumn?: {key: string; column: LegacyTableColumn};
  filterable?: 'on' | 'off';
  manager: LegacyTableManager;
  existingColumnIds: Set<string>;
  onColumnSelected: (column: LegacyTableColumn) => void;
}

interface SelectColumnMenuImplAttrs {
  columns: {key: string; column: LegacyTableColumn}[];
  manager: LegacyTableManager;
  existingColumnIds: Set<string>;
  onColumnSelected: (column: LegacyTableColumn) => void;
  firstButtonUuid: string;
}

// Core implementation of the selectable column list.
class SelectColumnMenuImpl
  implements m.ClassComponent<SelectColumnMenuImplAttrs>
{
  // When the menu elements are updated (e.g. when filtering), the popup
  // can flicker a lot. To prevent that, we fix the size of the popup
  // after the first layout.
  private size?: {width: number; height: number};

  oncreate(vnode: m.VnodeDOM<SelectColumnMenuImplAttrs, this>) {
    this.size = {
      width: vnode.dom.clientWidth,
      height: vnode.dom.clientHeight,
    };
  }

  view({attrs}: m.CVnode<SelectColumnMenuImplAttrs>) {
    return m(
      '.pf-sql-table__select-column-menu',
      {
        style: {
          minWidth: this.size && `${this.size.width}px`,
          minHeight: this.size && `${this.size.height}px`,
        },
      },
      attrs.columns.map(({key, column}, index) => {
        const derivedColumns = column.listDerivedColumns?.(attrs.manager);
        return m(
          MenuItem,
          {
            id: index === 0 ? attrs.firstButtonUuid : undefined,
            label: key,
            onclick: (event) => {
              if (derivedColumns !== undefined) return;
              attrs.onColumnSelected(column);
              // For Control-Click, we don't want to close the menu to allow the user
              // to select multiple items in one go.
              if (hasModKey(event)) {
                event.stopPropagation();
              }
              // Otherwise this popup will be closed.
            },
          },
          derivedColumns &&
            m(SelectColumnMenu, {
              primaryColumn: {key, column},
              existingColumnIds: attrs.existingColumnIds,
              onColumnSelected: attrs.onColumnSelected,
              manager: attrs.manager,
              columns: async () => {
                const cols = await derivedColumns();
                return [...cols.entries()].map(([key, column]) => ({
                  key,
                  column,
                }));
              },
            }),
        );
      }),
    );
  }
}

export class SelectColumnMenu
  implements m.ClassComponent<SelectColumnMenuAttrs>
{
  private searchText = '';
  columns?: {key: string; column: LegacyTableColumn}[];

  constructor(vnode: m.CVnode<SelectColumnMenuAttrs>) {
    if (Array.isArray(vnode.attrs.columns)) {
      this.columns = vnode.attrs.columns;
    } else {
      vnode.attrs.columns().then((columns) => {
        this.columns = columns;
        raf.scheduleFullRedraw();
      });
    }
  }

  view(vnode: m.CVnode<SelectColumnMenuAttrs>) {
    const columns = this.columns || [];
    const {attrs} = vnode;

    // Candidates are the columns which have not been selected yet.
    const candidates = [...columns].filter(
      ({column}) =>
        !attrs.existingColumnIds.has(tableColumnId(column)) ||
        column.listDerivedColumns?.(attrs.manager) !== undefined,
    );

    const filterable =
      attrs.filterable === 'on' ||
      (attrs.filterable === undefined && candidates.length > 10);

    // Filter the candidates based on the search text.
    const filtered = candidates.filter(({key}) => {
      return key.toLowerCase().includes(this.searchText.toLowerCase());
    });

    const primaryColumn = attrs.primaryColumn;
    const firstButtonUuid = uuidv4();

    return [
      primaryColumn &&
        m(MenuItem, {
          label: primaryColumn.key,
          disabled: attrs.existingColumnIds.has(
            tableColumnId(primaryColumn.column),
          ),
          onclick: (event) => {
            attrs.onColumnSelected(primaryColumn.column);
            // For Control-Click, we don't want to close the menu to allow the user
            // to select multiple items in one go.
            if (hasModKey(event)) {
              event.stopPropagation();
            }
            // Otherwise this popup will be closed.
          },
        }),
      primaryColumn && m(MenuDivider),
      filterable &&
        m(TextInput, {
          autofocus: true,
          oninput: (event: Event) => {
            const eventTarget = event.target as HTMLTextAreaElement;
            this.searchText = eventTarget.value;
          },
          onkeydown: (event: KeyboardEvent) => {
            if (filtered.length === 0) return;
            if (event.key === 'Enter') {
              // If there is only one item or Mod-Enter was pressed, select the first element.
              if (filtered.length === 1 || hasModKey(event)) {
                const params = {bubbles: true};
                if (hasModKey(event)) {
                  Object.assign(params, modKey());
                }
                const pointerEvent = new PointerEvent('click', params);
                (
                  document.getElementById(firstButtonUuid) as HTMLElement | null
                )?.dispatchEvent(pointerEvent);
              }
            }
          },
          value: this.searchText,
          placeholder: 'Filter...',
          className: 'pf-sql-table__column-filter',
        }),
      filterable && m(MenuDivider),
      this.columns === undefined && m(Spinner),
      this.columns !== undefined &&
        m(SelectColumnMenuImpl, {
          columns: filtered,
          manager: attrs.manager,
          existingColumnIds: attrs.existingColumnIds,
          onColumnSelected: attrs.onColumnSelected,
          firstButtonUuid,
        }),
    ];
  }
}
