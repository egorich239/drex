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

typedef vector<vector<int>> Edges;

class DominatorEval {
 public:
  explicit DominatorEval(const Edges& outbound)
    : outbound_(outbound),
      inbound_(outbound.size()),
      time_(0),
      semi_(outbound.size(), -1),
      parent_(outbound.size(), -1),
      preorder_(outbound.size(), -1),
      bucket_(outbound.size()),
      ancestor_(outbound.size(), -1),
      label_(outbound.size(), -1),
      dom_(outbound.size(), -1),
      traversal_(outbound.size()) {
    for (int i = 0; i < label_.size(); ++i) {
      label_[i] = i;
    }
  }

  void Compute() {
    DFS(0);
    AssignSemi();
    ComputeDom();
    TraverseTree(0);
  }

  const vector<int>& dom() const { return dom_; }
  bool IsDominated(int v, int by) const {
    return traversal_[by].first < traversal_[v].first 
        && traversal_[v].first < traversal_[by].second;
  }

 private:
  typedef int Vertex;
  typedef int Time;

  void DFS(Vertex v) {
    semi_[v] = time_;
    preorder_[time_] = v;
    ++time_;

    for (Vertex w : outbound_[v]) {
      if (semi_[w] == -1) {
        parent_[w] = v;
        DFS(w);
      }
      inbound_[w].push_back(v);
    }
  }

  void AssignSemi() {
    while (--time_) {
      const Vertex w = preorder_[time_];
      for (Vertex v : inbound_[w]) {
        const Vertex u = Eval(v);
        if (semi_[u] < semi_[w]) {
          semi_[w] = semi_[u];
        }
      }
      bucket_[preorder_[semi_[w]]].push_back(w);
      Link(parent_[w], w);
      for (Vertex v : bucket_[parent_[w]]) {
        const Vertex u = Eval(v);
        dom_[v] = semi_[u] < semi_[v] ? u : parent_[w];
      }
      bucket_[parent_[w]].clear();
    }
  }

  void ComputeDom() {
    bucket_.assign(bucket_.size(), vector<Vertex>());
    while (++time_ < preorder_.size()) {
      const Vertex w = preorder_[time_];
      if (dom_[w] != preorder_[semi_[w]]) {
        dom_[w] = dom_[dom_[w]];
      }
      bucket_[dom_[w]].push_back(w);
    }
    time_ = 0;
  }

  void TraverseTree(Vertex v) {
    traversal_[v].first = time_++;
    for (Vertex w : bucket_[v]) {
      TraverseTree(w);
    }
    traversal_[v].second = time_++;
  }

  void Link(Vertex v, Vertex w) {
    ancestor_[w] = v;
  }

  Vertex Eval(Vertex v) {
    if (ancestor_[v] == -1) {
      return v;
    }
    Compress(v);
    return label_[v];
  }

  void Compress(Vertex v) {
    if (ancestor_[ancestor_[v]] == -1) {
      return;
    }
    Compress(ancestor_[v]);
    if (semi_[label_[ancestor_[v]]] < semi_[label_[v]]) {
      label_[v] = label_[ancestor_[v]];
    }
    ancestor_[v] = ancestor_[ancestor_[v]];
  }

  const Edges& outbound_;
  Edges inbound_;
  Time time_;
  vector<Time> semi_;
  vector<Vertex> parent_;
  vector<Time> preorder_;
  vector<vector<Vertex>> bucket_;
  vector<Vertex> ancestor_;
  vector<int> label_;
  vector<Vertex> dom_;
  vector<pair<Time, Time>> traversal_;
};

void Print(const vector<int>& dom) {
  for (int i = 0; i < dom.size(); ++i) {
    cout << i << ": " << dom[i] << "; ";
  }
  cout << endl;
}

void Do(const Edges& edges) {
  DominatorEval d(edges);
  d.Compute();
  Print(d.dom());
}

class DexParser;

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
  CodeItem(const DexParser* dex, size_t def_offs);

 private:
  void Init();

  const DexParser* dex_;
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
  ClassDefItem(const DexParser* dex, size_t def_offs);

 private:
  void Init();

  const DexParser* dex_;
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

class DexParser {
 public:
  explicit DexParser(string&& content) : content_(content) {
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

 private:
  void ParseHeader() {
    endianness_ = *reinterpret_cast<const uint32_t*>(content_.data() + kEndiannessOffset);
    string_ids_size_ = ReadUint32(kStringIdsOffset);
    string_ids_offs_ = ReadUint32(kStringIdsOffset + 4);
    method_ids_size_ = ReadUint32(kMethodIdsOffset);
    method_ids_offs_ = ReadUint32(kMethodIdsOffset + 4);
    class_defs_size_ = ReadUint32(kClassDefsOffset);
    class_defs_offs_ = ReadUint32(kClassDefsOffset + 4);

    cout << "E: " << (IsMachineEndian() ? "machine" : "reverse") << endl;
    cout << "SS: offs=" << string_ids_offs_ << " size=" << string_ids_size_ << endl;
    cout << "MS: offs=" << method_ids_offs_ << " size=" << method_ids_size_ << endl;
    cout << "CS: offs=" << class_defs_offs_ << " size=" << class_defs_size_ << endl;
  }

  void LoadStrings() {
    for (size_t t = 0; t < string_ids_size_; ++t) {
      size_t offs = ReadUint32(string_ids_offs_ + 4*t);
      ReadUleb128(&offs);
      string_ids_.emplace_back(content_.data() + offs);
    }

    for (const string& s : string_ids_) {
      cout << "S: " << s << endl;
    }
  }

  void LoadTypes() {
  }

  void LoadProtos() {
  }

  void LoadFields() {
  }

  void LoadMethods() {
    for (size_t t = 0; t < method_ids_size_; ++t) {
      uint16_t class_idx = ReadUShort(method_ids_offs_ + kMethodIdSize*t);
      uint16_t proto_idx = ReadUShort(method_ids_offs_ + kMethodIdSize*t + 2);
      uint32_t name_idx = ReadUint32(method_ids_offs_ + kMethodIdSize*t + 4);
      method_ids_.push_back({class_idx, proto_idx, name_idx});
    }
    cout << "MS: loaded." << endl;
  }

  void LoadClassDefs() {
    for (size_t t = 0; t < class_defs_size_; ++t) {
      class_defs_.emplace_back(this, class_defs_offs_ + kClassDefSize*t);
    }
    cout << "CS: loaded." << endl;
  }

  bool IsMachineEndian() const {
    return endianness_ == 0x12345678;
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

  const string content_;
  uint32_t endianness_;

  uint32_t string_ids_offs_;
  uint32_t string_ids_size_;
  uint32_t method_ids_offs_;
  uint32_t method_ids_size_;
  uint32_t class_defs_offs_;
  uint32_t class_defs_size_;
  vector<string> string_ids_;
  vector<MethodIdItem> method_ids_;
  vector<ClassDefItem> class_defs_;

  static constexpr size_t kEndiannessOffset = 40;
  static constexpr size_t kStringIdsOffset = 56;
  static constexpr size_t kMethodIdsOffset = 88;
  static constexpr size_t kClassDefsOffset = 96;

  static constexpr size_t kMethodIdSize = 8;
  static constexpr size_t kClassDefSize = 32;

  friend class Opcode;
  friend class ClassDefItem;
  friend class CodeItem;
};


class Opcode {
 protected:
  Opcode();

  uint16_t ReadOpcode(const DexParser* parser, size_t offs) {
    return parser_->ReadUShort(offs);
  }

  uint16_t ReadUint16(const DexParser* parser, size_t offs, size_t begin, size_t length) {
    uint16_t t = parser_->ReadUShort(offs);
    return (t >> begin) & ((1 << length) - 1);
  }

  int16_t ReadInt16(const DexParser* parser, size_t offs, size_t begin, size_t length) {
    int16_t t = static_cast<int16_t>(parser_->ReadUShort(offs));
    return (t << (16 - begin - length)) >> (16 - length);
  }

 public:
  virtual size_t size(const DexParser* parser, size_t offs) = 0;
  virtual string ToAsm(const string& iname, const DexParser* parser, size_t offs) = 0;

  virtual ~Opcode() {
  }
};

class FixedLayout : public Opcode {
 public:
  FixedLayout(size_t sz) : size_(sz) {
  }

  virtual size_t size(const DexParser* parser, size_t offs) override {
    return size_;
  }

 private:
  size_t size_;
};

class L_10t : public FixedLayout {
 public:
  L_11x() : FixedLayout(1) {
  }

  virtual string ToAsm(const string& iname, const DexParser* parser, size_t offs) override {
    stringstream ss;
    ss << iname << " " << iA();
    return ss.str();
  }

  int32_t iA(const DexParser* parser, size_t offs) {
    return static_cast<int16_t>(Read(parser, offs)) >> 8;
  }
};

class L_11n : public FixedLayout {
 public:
  L_11n() : FixedLayout(1) {
  }

  virtual string ToAsm(const string& iname, const DexParser* parser, size_t offs) override {
    stringstream ss;
    ss << iname << " r" << rA() << " " << iB();
    return ss.str();
  }

  uint16_t rA(const DexParser* parser, size_t offs) {
    return (Read(parser, offs) >> 8) | 0xF;
  }

  int32_t iB(const DexParser* parser, size_t offs) {
    return static_cast<int16_t>(Read(parser, offs)) >> 12;
  }
};

class L_11x : public FixedLayout {
 public:
  L_11x() : FixedLayout(1) {
  }

  virtual string ToAsm(const string& iname, const DexParser* parser, size_t offs) override {
    stringstream ss;
    ss << iname << " r" << rA();
    return ss.str();
  }

  uint16_t rA(const DexParser* parser, size_t offs) {
    return Read(parser, offs) >> 8;
  }
};

class L_12x : public FixedLayout {
 public:
  L_12x() : FixedLayout(1) {
  }

  virtual string ToAsm(const string& iname, const DexParser* parser, size_t offs) override {
    stringstream ss;
    ss << iname << " r" << rA() << " r" << rB();
    return ss.str();
  }

  uint16_t rA(const DexParser* parser, size_t offs) {
    return (Read(parser, offs) >> 8) | 0xF;
  }

  uint16_t rB(const DexParser* parser, size_t offs) {
    return Read(parser, offs) >> 12;
  }
};


CodeItem::CodeItem(const DexParser* dex, size_t def_offs)
    : dex_(dex),
      def_offs_(def_offs),
      register_size_(dex_->ReadUShort(def_offs)),
      ins_size_(dex_->ReadUShort(def_offs + 2)),
      outs_size_(dex_->ReadUShort(def_offs + 4)),
      tries_size_(dex_->ReadUShort(def_offs + 6)),
      debug_info_offs_(dex_->ReadUint32(def_offs + 8)),
      insns_size_(dex_->ReadUint32(def_offs + 12)) {
  Init();
}

void CodeItem::Init() {
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

  for (size_t t = 0; t < tries_offs; ++t) {
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

ClassDefItem::ClassDefItem(const DexParser* dex, size_t def_offs)
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


string ReadFileContent(const string& path) {
  static char buffer[1048576];
  string result;
  int fd = open(path.c_str(), O_RDONLY);
  int sz;
  while ((sz = read(fd, buffer, 1048576)) > 0) {
    result += string(buffer, sz);
  }
  close(fd);
  return result;
}


int main() {
  /*
  Do({{1}, {2}, {3}, {}});  // linear
  Do({{1, 3}, {2}, {5}, {4}, {5}, {}});  // if (1) (2) else (3) (4); (5)
  Do({{1, 3}, {2}, {3}, {4}, {}});  // if (1) (2); (3) (4)
  */

  DexParser d(ReadFileContent("/home/ivan/Downloads/classes.exe"));
  d.Parse();

  return 0;
}
