#ifndef REV_DEX_SCANNER_H__
#define REV_DEX_SCANNER_H__

#include <cstdint>
#include <string>
#include <vector>

using std::string;
using std::vector;

namespace egorich {
namespace rev {

class DexScanner;

struct TypeIdItem {
  uint32_t descriptor_idx;
};

struct EncodedField {
  uint32_t field_idx_diff;
  uint32_t access_flags;
};

struct EncodedMethod {
  uint32_t method_idx_diff;
  uint32_t access_flags;
  uint32_t code_offs;
};

struct MethodIdItem {
  uint16_t class_idx;
  uint16_t proto_idx;
  uint32_t name_idx;
};

struct TryItem {
  uint32_t start_addr;
  uint16_t insn_count;
  uint16_t handler_idx;
};

struct EncodedTypeAddrPair {
  uint32_t type_idx;
  uint32_t addr;
};

struct EncodedCatchHandler {
  uint32_t offset;
  vector<EncodedTypeAddrPair> handlers;
  uint32_t catch_all_addr;
};

class CodeItem {
 public:
  CodeItem(const DexScanner* dex, size_t def_offs);
  uint32_t instr_offs() const { return def_offs_ + 16; }
  uint32_t instr_size() const { return insns_size_; }

 private:
  void Init();

  const DexScanner* dex_;
  size_t def_offs_;
  uint16_t register_size_;
  uint16_t ins_size_;
  uint16_t outs_size_;
  uint16_t tries_size_;
  uint32_t debug_info_offs_;
  uint32_t insns_size_;

  vector<TryItem> tries_;
  vector<EncodedCatchHandler> handlers_;
};

class ClassDefItem {
 public:
  ClassDefItem(const DexScanner* dex, size_t def_offs);
  const vector<EncodedMethod>& direct_methods() const { return direct_methods_; }
  const vector<EncodedMethod>& virtual_methods() const { return virtual_methods_; }
  uint32_t type_idx() const { return type_idx_; }

 private:
  void Init();

  const DexScanner* dex_;
  size_t def_offs_;

  uint32_t type_idx_;
  uint32_t access_flags_;
  uint32_t superclass_idx_;
  uint32_t interfaces_offs_;
  uint32_t source_file_idx_;
  uint32_t annotations_offs_;
  uint32_t class_data_offs_;
  uint32_t static_values_offs_;

  uint32_t static_fields_size_;
  uint32_t instance_fields_size_;
  uint32_t direct_methods_size_;
  uint32_t virtual_methods_size_;

  vector<EncodedField> static_fields_;
  vector<EncodedField> instance_fields_;
  vector<EncodedMethod> direct_methods_;
  vector<EncodedMethod> virtual_methods_;
};

class DexScanner {
 public:
  explicit DexScanner(string&& content) : content_(content) {
  }

  void Parse() {
    ParseHeader();
    LoadStrings();
    LoadTypes();
    LoadProtos();
    LoadFields();
    LoadMethods();
    LoadClassDefs();
  }

  uint32_t ReadUint32(size_t position) const {
    uint32_t result = *reinterpret_cast<const uint32_t*>(content_.data() + position);
    if (IsMachineEndian()) {
      return result;
    }
    return ((result & 0xFFU) << 24)
           | ((result & 0xFF00U) << 8)
           | ((result & 0xFF0000U) >> 8)
           | ((result & 0xFF000000U) >> 24);
  }

  uint32_t ReadUleb128(size_t* position) const {
    uint32_t result = 0;
    int s = 0;
    uint8_t c;
    do {
      c = content_[*position];
      result |= (c & 0x7F) << s;
      s += 7;
      ++*position;
    } while (c & 0x80);
    return result;
  }

  int32_t ReadSleb128(size_t* position) const {
    uint32_t result = 0;
    uint32_t one_pad = 0xFFFFFFFFU;
    int s = 0;
    uint8_t c;
    do {
      c = content_[*position];
      result |= (c & 0x7F) << s;
      s += 7;
      one_pad <<= 7;
      ++*position;
    } while (c & 0x80);
    if (c & 0x40) {
      result |= one_pad;
    }
    return static_cast<int32_t>(result);
  }

  uint16_t ReadUShort(size_t position) const {
    uint16_t result = *reinterpret_cast<const uint16_t*>(content_.data() + position);
    if (IsMachineEndian()) {
      return result;
    }
    return ((result & 0xFFU) << 8) | ((result & 0xFF00U) >> 8);
  }

  const vector<ClassDefItem>& class_defs() const { return class_defs_; }
  const vector<MethodIdItem>& method_ids() const { return method_ids_; }
  const vector<TypeIdItem>& type_ids() const { return type_ids_; }
  const vector<string>& string_ids() const { return string_ids_; }

 private:
  void ParseHeader();
  void LoadStrings();
  void LoadTypes();
  void LoadProtos() {
  }
  void LoadFields() {
  }

  void LoadMethods();
  void LoadClassDefs();

  bool IsMachineEndian() const {
    return endianness_ == 0x12345678;
  }

 private:
  const string content_;
  uint32_t endianness_;

  uint32_t string_ids_offs_;
  uint32_t string_ids_size_;
  uint32_t type_ids_offs_;
  uint32_t type_ids_size_;
  uint32_t method_ids_offs_;
  uint32_t method_ids_size_;
  uint32_t class_defs_offs_;
  uint32_t class_defs_size_;
  vector<string> string_ids_;
  vector<TypeIdItem> type_ids_;
  vector<MethodIdItem> method_ids_;
  vector<ClassDefItem> class_defs_;

  static constexpr size_t kEndiannessOffset = 40;
  static constexpr size_t kStringIdsOffset = 56;
  static constexpr size_t kTypeIdsOffset = 64;
  static constexpr size_t kMethodIdsOffset = 88;
  static constexpr size_t kClassDefsOffset = 96;

  static constexpr size_t kMethodIdSize = 8;
  static constexpr size_t kClassDefSize = 32;

  DexScanner(const DexScanner&) = delete;
};

}  // namespace rev
}  // namespace egorich

#endif  // REV_DEX_SCANNER_H__
