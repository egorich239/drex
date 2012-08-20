#ifndef REV_DEX_ASM_H__
#define REV_DEX_ASM_H__

#include "dex_scanner.h"

#include <sstream>

using std::stringstream;

namespace egorich {
namespace rev {

class ILayout {
 public:
  uint16_t ReadUint16(const DexScanner* scanner, size_t offs, size_t begin, size_t length) const {
    uint16_t t = scanner->ReadUShort(offs);
    return (t >> begin) & ((1 << length) - 1);
  }

  int16_t ReadInt16(const DexScanner* scanner, size_t offs, size_t begin, size_t length) const {
    int16_t t = static_cast<int16_t>(scanner->ReadUShort(offs));
    return (t << (16 - begin - length)) >> (16 - length);
  }

  uint16_t opcode(const DexScanner* scanner, size_t offs) const {
    return ReadUint16(scanner, offs, 0, 8);
  }

  string dasm(const DexScanner* scanner, size_t offs) const { return "<unimpl>"; }
};

class UnknownLayout : public ILayout {
 public:
  size_t size(const DexScanner* scanner, size_t offs) const {
    return 1;
  }
};

class VarSizeBlock : public ILayout {
 public:
  size_t size(const DexScanner* scanner, size_t offs) const {
    switch (mode(scanner, offs)) {
    case 1:
      // packed-switch-payload
      return scanner->ReadUShort(offs + 2) * 2 + 4;
    case 2:
      // sparse-switch-payload
      return scanner->ReadUShort(offs + 2) * 4 + 2;
    case 3:
      // fill-array-data-payload
      return (scanner->ReadUShort(offs + 2) * scanner->ReadUint32(offs + 4) + 1) / 2 + 4;

    default:
      return 1;
    }
  }

  uint16_t mode(const DexScanner* scanner, size_t offs) const {
    return ReadUint16(scanner, offs, 8, 8);
  }
};

template <size_t Size>
class FixedLayout : public ILayout {
 public:
  size_t size(const DexScanner* scanner, size_t offs) const {
    return Size;
  }
};

class L_10x : public FixedLayout<1> {
};

class L_12x : public FixedLayout<1> {
};

class L_11n : public FixedLayout<1> {
};

class L_11x : public FixedLayout<1> {
};

class L_10t : public FixedLayout<1> {
 public:
  int16_t A(const DexScanner* scanner, size_t offs) const {
    return ReadInt16(scanner, offs, 8, 8);
  }

  string dasm(const DexScanner* s, size_t o) const {
    stringstream ss;
    ss << A(s, o);
    return ss.str();
  }
};

class L_20t : public FixedLayout<2> {
 public:
  int16_t A(const DexScanner* scanner, size_t offs) const {
    return ReadInt16(scanner, offs + 2, 0, 16);
  }

  string dasm(const DexScanner* s, size_t o) const {
    stringstream ss;
    ss << A(s, o);
    return ss.str();
  }
};

class L_20bc : public FixedLayout<2> {
};

class L_22x : public FixedLayout<2> {
};

class L_21t : public FixedLayout<2> {
 public:
  uint16_t vA(const DexScanner* scanner, size_t offs) const {
    return ReadUint16(scanner, offs, 8, 8);
  }

  int16_t B(const DexScanner* scanner, size_t offs) const {
    return ReadInt16(scanner, offs + 2, 0, 16);
  }

  string dasm(const DexScanner* s, size_t o) const {
    stringstream ss;
    ss << "v" << vA(s, o) << ", " << B(s, o);
    return ss.str();
  }
};

class L_21s : public FixedLayout<2> {
};

class L_21h : public FixedLayout<2> {
};

class L_21c : public FixedLayout<2> {
};

class L_23x : public FixedLayout<2> {
};

class L_22b : public FixedLayout<2> {
};

class L_22t : public FixedLayout<2> {
 public:
  uint16_t vA(const DexScanner* scanner, size_t offs) const {
    return ReadUint16(scanner, offs, 8, 4);
  }

  uint16_t vB(const DexScanner* scanner, size_t offs) const {
    return ReadUint16(scanner, offs, 12, 4);
  }

  int16_t C(const DexScanner* scanner, size_t offs) const {
    return ReadInt16(scanner, offs + 2, 0, 16);
  }

  string dasm(const DexScanner* s, size_t o) const {
    stringstream ss;
    ss << "v" << vA(s, o) << ", v" << vB(s, o) << ", " << C(s, o);
    return ss.str();
  }
};

class L_22s : public FixedLayout<2> {
};

class L_22c : public FixedLayout<2> {
};

class L_22cs : public FixedLayout<2> {
};

class L_30t : public FixedLayout<3> {
 public:
  int32_t A(const DexScanner* scanner, size_t offs) const {
    return static_cast<int32_t>(ReadUint16(scanner, offs + 2, 0, 16))
        | (static_cast<int32_t>(ReadInt16(scanner, offs + 4, 0, 16)) << 16);
  }

  string dasm(const DexScanner* s, size_t o) const {
    stringstream ss;
    ss << A(s, o);
    return ss.str();
  }
};

class L_32x : public FixedLayout<3> {
};

class L_31i : public FixedLayout<3> {
};

class L_31t : public FixedLayout<3> {
 public:
  uint16_t vA(const DexScanner* scanner, size_t offs) const {
    return ReadUint16(scanner, offs, 8, 8);
  }

  int32_t B(const DexScanner* scanner, size_t offs) const {
    return static_cast<int32_t>(ReadUint16(scanner, offs + 2, 0, 16))
        | (static_cast<int32_t>(ReadInt16(scanner, offs + 4, 0, 16)) << 16);
  }

  string dasm(const DexScanner* s, size_t o) const {
    stringstream ss;
    ss << "v" << vA(s, o) << ", " << B(s, o);
    return ss.str();
  }
};

class L_31c : public FixedLayout<3> {
};

class L_35c : public FixedLayout<3> {
};

class L_35ms : public FixedLayout<3> {
};

class L_35mi : public FixedLayout<3> {
};

class L_3rc : public FixedLayout<3> {
};

class L_3rms : public FixedLayout<3> {
};

class L_3rmi : public FixedLayout<3> {
};

class L_51l : public FixedLayout<5> {
};

class IDefBase {
 public:
  virtual ~IDefBase() {}
  virtual const ILayout* Get() const = 0;
  virtual size_t size(const DexScanner* scanner, size_t offs) const = 0;
  virtual const char* name() const = 0;

  virtual string dasm(const DexScanner* scanner, size_t offs) const = 0;
};

template <typename Layout>
class IDef : public IDefBase {
 public:
  IDef(const char *const name) : name_(name), layout_(new Layout()) {
  }

  ~IDef() {
    delete layout_;
  }

  virtual const ILayout* Get() const {
    return this->layout_;
  }

  virtual size_t size(const DexScanner* scanner, size_t offs) const {
    return this->layout_->size(scanner, offs);
  }

  virtual const char* name() const { return name_; }
  virtual string dasm(const DexScanner* scanner, size_t offs) const { 
    return string(name()) + " " + this->layout_->dasm(scanner, offs);
  }

 private:
  const char *const name_;
  const Layout* const layout_;
};

extern const IDefBase* iTable[256];

}  // namespace rev
}  // namespace egorich

#endif  // REV_DEX_ASM_H__
