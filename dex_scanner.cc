#include "dex_scanner.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <utility>
#include <sstream>
#include <string>
#include <vector>

#include "dex_asm.h"

using std::cout;
using std::cerr;
using std::endl;
using std::isalnum;
using std::isspace;
using std::lower_bound;
using std::ostream;
using std::pair;
using std::string;
using std::stringstream;
using std::vector;

namespace egorich {
namespace rev {

void DexScanner::ParseHeader() {
  endianness_ = *reinterpret_cast<const uint32_t*>(content_.data() + kEndiannessOffset);
  string_ids_size_ = ReadUint32(kStringIdsOffset);
  string_ids_offs_ = ReadUint32(kStringIdsOffset + 4);
  type_ids_size_ = ReadUint32(kTypeIdsOffset);
  type_ids_offs_ = ReadUint32(kTypeIdsOffset + 4);
  method_ids_size_ = ReadUint32(kMethodIdsOffset);
  method_ids_offs_ = ReadUint32(kMethodIdsOffset + 4);
  class_defs_size_ = ReadUint32(kClassDefsOffset);
  class_defs_offs_ = ReadUint32(kClassDefsOffset + 4);

  cout << "E: " << (IsMachineEndian() ? "machine" : "reverse") << endl;
  cout << "SS: offs=" << string_ids_offs_ << " size=" << string_ids_size_ << endl;
  cout << "TS: offs=" << type_ids_offs_ << " size=" << type_ids_size_ << endl;
  cout << "MS: offs=" << method_ids_offs_ << " size=" << method_ids_size_ << endl;
  cout << "CS: offs=" << class_defs_offs_ << " size=" << class_defs_size_ << endl;
}

void DexScanner::LoadStrings() {
  for (size_t t = 0; t < string_ids_size_; ++t) {
    size_t offs = ReadUint32(string_ids_offs_ + 4*t);
    ReadUleb128(&offs);
    string_ids_.emplace_back(content_.data() + offs);
  }

  /*
  for (const string& s : string_ids_) {
    cout << "S: " << s << endl;
  }
  */
}

void DexScanner::LoadTypes() {
  for (size_t t = 0; t < type_ids_size_; ++t) {
    type_ids_.push_back({ReadUint32(type_ids_offs_ + 4*t)});
  }

  /*
  for (const TypeIdItem& type_id : type_ids_) {
    cout << "T: " << string_ids_[type_id.descriptor_idx] << endl;
  }
  */
}

void DexScanner::LoadMethods() {
  for (size_t t = 0; t < method_ids_size_; ++t) {
    uint16_t class_idx = ReadUShort(method_ids_offs_ + kMethodIdSize*t);
    uint16_t proto_idx = ReadUShort(method_ids_offs_ + kMethodIdSize*t + 2);
    uint32_t name_idx = ReadUint32(method_ids_offs_ + kMethodIdSize*t + 4);
    method_ids_.push_back({class_idx, proto_idx, name_idx});
  }
  cout << "MS: loaded." << endl;
}

void DexScanner::LoadClassDefs() {
  for (size_t t = 0; t < class_defs_size_; ++t) {
    class_defs_.emplace_back(this, class_defs_offs_ + kClassDefSize*t);
  }
  cout << "CS: loaded." << endl;
}

CodeItem::CodeItem(const DexScanner* dex, size_t def_offs)
    : dex_(dex),
      def_offs_(def_offs),
      register_size_(dex_->ReadUShort(def_offs)),
      ins_size_(dex_->ReadUShort(def_offs + 2)),
      outs_size_(dex_->ReadUShort(def_offs + 4)),
      tries_size_(dex_->ReadUShort(def_offs + 6)),
      debug_info_offs_(dex_->ReadUint32(def_offs + 8)),
      insns_size_(dex_->ReadUint32(def_offs + 12)) {
  /*
  cout << "def_offs: " << def_offs_ << endl
       << "register_size: " << register_size_ << endl
       << "ins_size: " << ins_size_ << endl
       << "outs_size: " << outs_size_ << endl
       << "tries_size: " << tries_size_ << endl
       << "debug_info_offs: " << debug_info_offs_ << endl
       << "insns_size: " << insns_size_ << endl;
  */
  Init();
}

void CodeItem::Init() {
  if (!tries_size_) return;

  uint32_t tries_offs = (def_offs_ + 16 + 2*insns_size_ + 2) & 0xFFFFFFFC;
  uint32_t catch_offs = tries_offs + 8*tries_size_;
  size_t scan = catch_offs;
  const uint32_t catch_size = dex_->ReadUleb128(&scan);
  for (size_t t = 0; t < catch_size; ++t) {
    uint32_t offs = scan - catch_offs;
    int32_t types_size = dex_->ReadSleb128(&scan);
    handlers_.push_back(EncodedCatchHandler());
    handlers_.back().offset = offs;
    for (size_t p = 0; p < std::abs(types_size); ++p) {
      uint32_t type_idx = dex_->ReadUleb128(&scan);
      uint32_t addr = dex_->ReadUleb128(&scan);
      handlers_.back().handlers.push_back({type_idx, addr});
    }
    if (types_size <= 0) {
      handlers_.back().catch_all_addr = dex_->ReadUleb128(&scan);
    } else {
      handlers_.back().catch_all_addr = 0;
    }
  }

  for (size_t t = 0; t < tries_size_; ++t) {
    uint32_t start_addr = dex_->ReadUint32(tries_offs + 8*t);
    uint16_t insn_count = dex_->ReadUShort(tries_offs + 8*t + 4);
    uint16_t handler_offs = dex_->ReadUShort(tries_offs + 8*t + 6);
    EncodedCatchHandler s;
    s.offset = handler_offs;
    uint16_t handler_idx = lower_bound(
        handlers_.begin(), handlers_.end(), s,
        [] (const EncodedCatchHandler& lhs, const EncodedCatchHandler& rhs) -> bool { return lhs.offset < rhs.offset; }) - handlers_.begin();
    tries_.push_back({start_addr, insn_count, handler_idx});
  }
}

uint8_t CodeItem::opcode(size_t addr) const {
  return dex_->ReadUShort(instr_offs() + 2 * addr) & 0xFF;
}

size_t CodeItem::opsize(size_t addr) const {
  return instr(addr)->size(dex_, instr_offs() + 2 * addr);
}

const IDefBase* CodeItem::instr(size_t addr) const {
  return iTable[opcode(addr)];
}

ClassDefItem::ClassDefItem(const DexScanner* dex, size_t def_offs)
    : dex_(dex),
      def_offs_(def_offs),
      type_idx_(dex_->ReadUint32(def_offs_)),
      access_flags_(dex_->ReadUint32(def_offs_ + 4)),
      superclass_idx_(dex_->ReadUint32(def_offs_ + 8)),
      interfaces_offs_(dex_->ReadUint32(def_offs_ + 12)),
      source_file_idx_(dex_->ReadUint32(def_offs_ + 16)),
      annotations_offs_(dex_->ReadUint32(def_offs_ + 20)),
      class_data_offs_(dex_->ReadUint32(def_offs_ + 24)),
      static_values_offs_(dex_->ReadUint32(def_offs_ + 28)),

      static_fields_size_(),
      instance_fields_size_(),
      direct_methods_size_(),
      virtual_methods_size_() {
  Init();
}

void ClassDefItem::Init() {
  if (!class_data_offs_) return;
  size_t scan = class_data_offs_;
  static_fields_size_ = dex_->ReadUleb128(&scan);
  instance_fields_size_ = dex_->ReadUleb128(&scan);
  direct_methods_size_ = dex_->ReadUleb128(&scan);
  virtual_methods_size_ = dex_->ReadUleb128(&scan);

  for (uint32_t t = 0; t < static_fields_size_; ++t) {
    uint32_t field_idx_diff_ = dex_->ReadUleb128(&scan);
    uint32_t access_flags_ = dex_->ReadUleb128(&scan);
    static_fields_.push_back({field_idx_diff_, access_flags_});
  }

  for (uint32_t t = 0; t < instance_fields_size_; ++t) {
    uint32_t field_idx_diff_ = dex_->ReadUleb128(&scan);
    uint32_t access_flags_ = dex_->ReadUleb128(&scan);
    instance_fields_.push_back({field_idx_diff_, access_flags_});
  }

  for (uint32_t t = 0; t < direct_methods_size_; ++t) {
    uint32_t method_idx_diff_ = dex_->ReadUleb128(&scan);
    uint32_t access_flags_ = dex_->ReadUleb128(&scan);
    uint32_t code_offs_ = dex_->ReadUleb128(&scan);
    direct_methods_.push_back({method_idx_diff_, access_flags_, code_offs_});
  }

  for (uint32_t t = 0; t < virtual_methods_size_; ++t) {
    uint32_t method_idx_diff_ = dex_->ReadUleb128(&scan);
    uint32_t access_flags_ = dex_->ReadUleb128(&scan);
    uint32_t code_offs_ = dex_->ReadUleb128(&scan);
    virtual_methods_.push_back({method_idx_diff_, access_flags_, code_offs_});
  }
}

}  // namespace rev
}  // namespace egorich
