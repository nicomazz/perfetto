/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef SRC_TRACE_PROCESSOR_IMPORTERS_DTRACE_DTRACE_PARSER_H_
#define SRC_TRACE_PROCESSOR_IMPORTERS_DTRACE_DTRACE_PARSER_H_

#include <stdint.h>

#include <map>
#include <stack>
#include <string>

#include "src/trace_processor/chunked_trace_reader.h"
#include "src/trace_processor/trace_parser.h"

namespace perfetto {
namespace trace_processor {

class TraceProcessorContext;

class DTraceParser : public ChunkedTraceReader {
 public:
  explicit DTraceParser(TraceProcessorContext*);
  ~DTraceParser() override;
  DTraceParser(const DTraceParser&) = delete;
  DTraceParser& operator=(const DTraceParser&) = delete;

  // ChunkedTraceReader implementation
  util::Status Parse(std::unique_ptr<uint8_t[]>, size_t) override;
  void NotifyEndOfFile() override;

 private:
  struct fbt_entry_t {
    fbt_entry_t(const std::string& n,
              int64_t s,
              int64_t e,
              int64_t p,
              int64_t t)
        : start_ms(s), end_ms(e), pid(p), tid(t), name(n) {}

    int64_t start_ms;
    int64_t end_ms;
    int64_t pid;
    int64_t tid;

    std::string name;
  };

  TraceProcessorContext* const ctx_;
  std::vector<char> log_;
  std::vector<fbt_entry_t> jobs_;
  std::map<int64_t, std::map<std::string, std::stack<fbt_entry_t>>>
      last_;  //[pid][name] -> stack of function entry

  void entry(int64_t tid, int64_t pid, const std::string& name, int64_t ts);
  void ret(int64_t tid, const std::string& name, int64_t ts);
};

}  // namespace trace_processor
}  // namespace perfetto

#endif  // SRC_TRACE_PROCESSOR_IMPORTERS_DTRACE_DTRACE_PARSER_H_
