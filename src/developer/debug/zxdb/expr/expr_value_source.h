// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SRC_DEVELOPER_DEBUG_ZXDB_EXPR_EXPR_VALUE_SOURCE_H_
#define SRC_DEVELOPER_DEBUG_ZXDB_EXPR_EXPR_VALUE_SOURCE_H_

#include <stdint.h>

#include "src/developer/debug/ipc/register_desc.h"

namespace zxdb {

// Holds the source of a value. This allows taking the address of an object stored in an ExprValue
// ("&foo"), and for updating the contents of variables (currently not supported yet).
class ExprValueSource {
 public:
  // Where this value came from.
  enum class Type { kTemporary, kMemory, kRegister, kConstant };

  // Indicates an unknown, temporary (the output of "i + 4"), or constant source.
  explicit ExprValueSource(Type type = Type::kTemporary) : type_(type) {}

  // Initializes indicating a memory address and optional bitfield information.
  explicit ExprValueSource(uint64_t address, uint32_t bit_size = 0, uint32_t bit_shift = 0)
      : type_(Type::kMemory), address_(address), bit_size_(bit_size), bit_shift_(bit_shift) {}

  // Initializes indicating a register and optional bitfield information. The register does not have
  // to be a canonical register.
  explicit ExprValueSource(debug_ipc::RegisterID id, uint32_t bit_size = 0, uint32_t bit_shift = 0)
      : type_(Type::kRegister), register_id_(id), bit_size_(bit_size), bit_shift_(bit_shift) {}

  Type type() const { return type_; }

  bool is_bitfield() const { return bit_size_ != 0; }

  // Valid when type_ == kAddress.
  uint64_t address() const { return address_; }

  // Valid when type_ == kRegister.
  debug_ipc::RegisterID register_id() const { return register_id_; }

  // Number of bits used for bitfields. 0 means use all bits. See bit_shift().
  uint32_t bit_size() const { return bit_size_; }

  // Number of bits to shift to the left to get the storage location. This is the offset of the low
  // bit. Note that this is different than the DWARF definition.
  //
  // If a bitfield occupies bits 3-6 (inclusive) of a 32-bit integer:
  //
  //   high                            low
  //    3           2         1          0
  //   10987654 32109876 54321098 76543210
  //                               [--]
  //                                   <--  bit_shift
  //
  // Then the bit_size() will be 4 and the bit_shift() will be 3.
  //
  // The memory layout will be the result of doing the shift and mask and memcpy-ing out which
  // will reorder the bytes in little-endian.
  uint32_t bit_shift() const { return bit_shift_; }

  // Returns a new ExprValueSource pointing to the given offset inside of this one. If this one is
  // not in memory, the returned one will be the same.
  //
  // When computing offsets of bitfields, the shifts are just added to any existing one, but the bit
  // size (if given) will overwrite any existing one.
  ExprValueSource GetOffsetInto(uint32_t offset, uint32_t new_bit_size = 0,
                                uint32_t bit_shift = 0) const {
    if (type_ == Type::kMemory) {
      return ExprValueSource(address_ + offset, new_bit_size == 0 ? bit_size_ : new_bit_size,
                             bit_shift_ + bit_shift);
    }
    return ExprValueSource();
  }

  bool operator==(const ExprValueSource& other) const {
    return type_ == other.type_ && address_ == other.address_ && bit_size_ == other.bit_size_ &&
           bit_shift_ == other.bit_shift_;
  }
  bool operator!=(const ExprValueSource& other) const { return !operator==(other); }

 private:
  Type type_ = Type::kTemporary;
  uint64_t address_ = 0;
  debug_ipc::RegisterID register_id_ = debug_ipc::RegisterID::kUnknown;

  uint32_t bit_size_ = 0;
  uint32_t bit_shift_ = 0;
};

}  // namespace zxdb

#endif  // SRC_DEVELOPER_DEBUG_ZXDB_EXPR_EXPR_VALUE_SOURCE_H_
