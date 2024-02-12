/*
 * Copyright (C) 2023 The Android Open Source Project
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
#ifndef SRC_TRACE_PROCESSOR_DB_COLUMN_ID_STORAGE_H_
#define SRC_TRACE_PROCESSOR_DB_COLUMN_ID_STORAGE_H_

#include <cstdint>
#include <limits>
#include <memory>
#include <string>

#include "perfetto/trace_processor/basic_types.h"
#include "src/trace_processor/containers/bit_vector.h"
#include "src/trace_processor/db/column/data_layer.h"
#include "src/trace_processor/db/column/types.h"

namespace perfetto::trace_processor::column {

// Base level storage for id columns.
//
// Note: This storage does not have any size instead spanning the entire
// uint32_t space (any such integer is a valid id). Overlays (e.g.
// RangeOverlay/SelectorOverlay) can be used to limit which ids are
// included in the column.
class IdStorage final : public DataLayer {
 public:
  std::unique_ptr<DataLayerChain> MakeChain() override;

 private:
  class ChainImpl : public DataLayerChain {
   public:
    SearchValidationResult ValidateSearchConstraints(SqlValue,
                                                     FilterOp) const override;

    RangeOrBitVector Search(FilterOp, SqlValue, Range) const override;

    RangeOrBitVector IndexSearch(FilterOp, SqlValue, Indices) const override;

    Range OrderedIndexSearch(FilterOp, SqlValue, Indices) const override;

    void StableSort(uint32_t*, uint32_t) const override;

    void Sort(uint32_t*, uint32_t) const override;

    void Serialize(StorageProto*) const override;

    uint32_t size() const override {
      return std::numeric_limits<uint32_t>::max();
    }

    std::string DebugString() const override { return "IdStorage"; }

   private:
    using Id = uint32_t;

    BitVector IndexSearch(FilterOp, Id, uint32_t*, uint32_t) const;
    static Range BinarySearchIntrinsic(FilterOp, Id, Range);
  };
};

}  // namespace perfetto::trace_processor::column

#endif  // SRC_TRACE_PROCESSOR_DB_COLUMN_ID_STORAGE_H_
