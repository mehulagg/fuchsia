// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "peridot/bin/ledger/storage/public/types.h"

namespace storage {

bool operator==(const ObjectIdentifier& lhs, const ObjectIdentifier& rhs) {
  return std::tie(lhs.key_index, lhs.deletion_scope_id, lhs.object_digest) ==
         std::tie(rhs.key_index, rhs.deletion_scope_id, rhs.object_digest);
}

bool operator!=(const ObjectIdentifier& lhs, const ObjectIdentifier& rhs) {
  return !(lhs == rhs);
}

bool operator<(const ObjectIdentifier& lhs, const ObjectIdentifier& rhs) {
  return std::tie(lhs.key_index, lhs.deletion_scope_id, lhs.object_digest) <
         std::tie(rhs.key_index, rhs.deletion_scope_id, rhs.object_digest);
}

bool operator==(const Entry& lhs, const Entry& rhs) {
  return std::tie(lhs.key, lhs.object_digest, lhs.priority) ==
         std::tie(rhs.key, rhs.object_digest, rhs.priority);
}

bool operator!=(const Entry& lhs, const Entry& rhs) {
  return !(lhs == rhs);
}

bool operator==(const EntryChange& lhs, const EntryChange& rhs) {
  return lhs.deleted == rhs.deleted &&
         (lhs.deleted ? lhs.entry.key == rhs.entry.key
                      : lhs.entry == rhs.entry);
}

bool operator!=(const EntryChange& lhs, const EntryChange& rhs) {
  return !(lhs == rhs);
}

fxl::StringView StatusToString(Status status) {
  switch (status) {
    case Status::OK:
      return "OK";
    case Status::IO_ERROR:
      return "IO_ERROR";
    case Status::NOT_FOUND:
      return "NOT_FOUND";
    case Status::FORMAT_ERROR:
      return "FORMAT_ERROR";
    case Status::ILLEGAL_STATE:
      return "ILLEGAL_STATE";
    case Status::INTERNAL_IO_ERROR:
      return "INTERNAL_IO_ERROR";
    case Status::INTERRUPTED:
      return "INTERRUPTED";
    case Status::NOT_CONNECTED_ERROR:
      return "NOT_CONNECTED_ERROR";
    case Status::NO_SUCH_CHILD:
      return "NO_SUCH_CHILD";
    case Status::OBJECT_DIGEST_MISMATCH:
      return "OBJECT_DIGEST_MISMATCH";
    case Status::NOT_IMPLEMENTED:
      return "NOT_IMPLEMENTED";
  }
}

std::ostream& operator<<(std::ostream& os, Status status) {
  return os << StatusToString(status);
}

}  // namespace storage
