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

#include "src/trace_processor/importers/dtrace/dtrace_parser.h"

#include "perfetto/ext/base/string_splitter.h"
#include "perfetto/ext/base/string_utils.h"
#include "src/trace_processor/process_tracker.h"
#include "src/trace_processor/slice_tracker.h"
#include "src/trace_processor/storage/trace_storage.h"
#include "src/trace_processor/trace_sorter.h"
#include "src/trace_processor/track_tracker.h"

namespace perfetto {
namespace trace_processor {

using base::StringSplitter;

DTraceParser::DTraceParser(TraceProcessorContext* ctx) : ctx_(ctx) {}
DTraceParser::~DTraceParser() = default;

util::Status DTraceParser::Parse(std::unique_ptr<uint8_t[]> buf, size_t len) {

  // A trace is read in chunks of arbitrary size (for http fetch() pipeliniing),
  // not necessarily aligned on a line boundary.
  // Here we push everything into a vector and, on each call, consume only
  // the leading part until the last \n, keeping the rest for the next call.
  const char* src = reinterpret_cast<const char*>(&buf[0]);
  log_.insert(log_.end(), src, src + len);

  // Find the last \n.
  size_t valid_size = log_.size();
  for (; valid_size > 0 && log_[valid_size - 1] != '\n'; --valid_size) {
  }

  bool first = true;
  for (StringSplitter line(log_.data(), valid_size, '\n'); line.Next();) {
    // static const char kHeader[] = "# ninja log v";
    if (first){
      first = false;
      continue;
    }
    // Each line in the dtrace log looks like this:
    // execve return ts: 1960680546975 tid: 100100 pid: 790 depth: 4
    // readlink entry ts: 1960732265529 tid: 100100 pid: 790 depth: 4

    StringSplitter tok(&line, ' ');
    const char* name = tok.Next() ? tok.cur_token() : nullptr;
    const char* type = tok.Next() ? tok.cur_token() : nullptr;
    tok.Next();  // ts:
    auto ts = base::CStringToInt64(tok.Next() ? tok.cur_token() : "");
    tok.Next();  // tid:
    auto tid = base::CStringToInt64(tok.Next() ? tok.cur_token() : "");
    tok.Next();  // pid:
    auto pid = base::CStringToInt64(tok.Next() ? tok.cur_token() : "");

    if (!name || !type || !name || !ts || !tid || !pid) {
      ctx_->storage->IncrementStats(stats::ninja_parse_errors);
      continue;
    }
    std::string name_str = std::string(name);
    if (std::string(type) == "entry") {
      entry(*tid, *pid, name_str, *ts);
    } else {
      ret(*tid, name_str, *ts);
    }

  }
  return util::OkStatus();
}

void DTraceParser::entry(int64_t tid,
                         int64_t pid,
                         const std::string& name,
                         int64_t ts) {
  last_[tid][name].push(fbt_entry_t(name, ts, 0, pid, tid));
}
void DTraceParser::ret(int64_t tid, const std::string& name, int64_t ts) {
  if (last_[tid][name].size() == 0) return;
  fbt_entry_t att = last_[tid][name].top();
  last_[tid][name].pop();
  att.end_ms = ts;
  jobs_.push_back(att);
}

// This is called after the last Parse() call. At this point all |jobs_| have
// been populated.
void DTraceParser::NotifyEndOfFile() {
  std::sort(jobs_.begin(), jobs_.end(),
            [](const fbt_entry_t& x, const fbt_entry_t& y) {
              return x.start_ms < y.start_ms;
            });

  for (const auto& job : jobs_) {
    const int64_t start_ns = job.start_ms;
    const int64_t dur_ns = (job.end_ms - job.start_ms);

    auto utid = ctx_->process_tracker->UpdateThread(
        static_cast<uint32_t>(job.tid), static_cast<uint32_t>(job.pid));

    StringId name_id = ctx_->storage->InternString(base::StringView(job.name));
    TrackId track_id = ctx_->track_tracker->InternThreadTrack(utid);

    ctx_->slice_tracker->Scoped(start_ns, track_id, StringId::Null(), name_id,
                                dur_ns);
  }
}

}  // namespace trace_processor
}  // namespace perfetto
