#ifndef REV_JAVA_BLOCKS_H__
#define REV_JAVA_BLOCKS_H__

#include <cstddef>
#include <cstdint>
#include <new>
#include <vector>

#include "log.h"

using std::vector;

namespace egorich {
namespace rev {

class Zone {
 public:
  Zone(size_t capacity) : capacity_(capacity), zone_(new char[capacity]), head_(0) {
  }

  ~Zone() {
    delete[] zone_;
  }

  void* Allocate(size_t sz) {
    void* const result = 
      head_ + sz <= capacity_ ? zone_ + head_ : 0;
    if (result) {
      head_ += sz + 7;
      head_ &= ~static_cast<size_t>(0) << 3;
    }
    return result;
  }

 private:
  const size_t capacity_;
  char *const zone_;
  size_t head_;

  Zone(const Zone&) = delete;
};

class JavaBlock {
 public:
  static void* operator new(size_t sz, Zone* zone) {
    void* result = zone->Allocate(sz);
    ASSERT(result != NULL) << "OOMing...";
    return result;
  }
  static void* operator new(size_t sz) {
    ASSERT(false) << "Use placement new.";
    throw std::bad_alloc();
  }

  enum Kind {
    BASIC = 1,
    COMPOUND,
    BRANCH,
    SWITCH,
    DO_FOREVER,  // synthetic
    WHILE_LOOP,
    DO_LOOP,
    BREAK,
    CONTINUE,
    RETURN,
    THROW,
  };

  JavaBlock(Kind kind, JavaBlock* parent, uint32_t head)
      : kind_(kind), parent_(parent), head_(head) {
  }

  Kind kind() const { return kind_; }
  JavaBlock* parent() const { return parent_; }
  uint32_t head() const { return head_; }

 private:
  Kind kind_;
  JavaBlock* parent_;
  uint32_t head_;
};

template <JavaBlock::Kind K>
class TypedBlock : public JavaBlock {
 public:
  TypedBlock(JavaBlock* parent, uint32_t head) : JavaBlock(K, parent, head) {
  }
};

class BasicBlock : public TypedBlock<JavaBlock::BASIC> {
 public:
  BasicBlock(JavaBlock* parent, uint32_t head) : TypedBlock(parent, head) {
  }
};

class BreakBlock : public TypedBlock<JavaBlock::BREAK> {
 public:
  BreakBlock(JavaBlock* parent, uint32_t head, JavaBlock* _target) 
      : TypedBlock(parent, head), target(_target) {
  }

  JavaBlock* target;
};

class ContinueBlock : public TypedBlock<JavaBlock::CONTINUE> {
 public:
  ContinueBlock(JavaBlock* parent, uint32_t head, JavaBlock* _target) 
      : TypedBlock(parent, head), target(_target) {
  }

  JavaBlock* target;
};

class ReturnBlock : public TypedBlock<JavaBlock::RETURN> {
 public:
  ReturnBlock(JavaBlock* parent, uint32_t head) : TypedBlock(parent, head) {
  }
};

class ThrowBlock : public TypedBlock<JavaBlock::THROW> {
 public:
  ThrowBlock(JavaBlock* parent, uint32_t head) : TypedBlock(parent, head) {
  }
};

class BranchBlock : public TypedBlock<JavaBlock::BRANCH> {
 public:
  BranchBlock(JavaBlock* parent, uint32_t head)
      : TypedBlock(parent, head), invert(false), cond(NULL), on_true(NULL), on_false(NULL) {
  }

  bool invert;
  BasicBlock* cond;
  JavaBlock* on_true;
  JavaBlock* on_false;
};

/*
class SwitchBlock : public TypedBlock<JavaBlock::SWITCH> {
};
*/

class WhileBlock : public TypedBlock<JavaBlock::WHILE_LOOP> {
 public:
  WhileBlock(JavaBlock* parent, uint32_t head)
      : TypedBlock(parent, head), invert(false), cond(NULL), body(NULL) {
  }

  bool invert;
  BasicBlock* cond;
  JavaBlock* body;
};

class DoBlock : public TypedBlock<JavaBlock::DO_LOOP> {
 public:
  DoBlock(JavaBlock* parent, uint32_t head)
      : TypedBlock(parent, head), invert(false), cond(NULL), body(NULL) {
  }

  bool invert;
  BasicBlock* cond;
  JavaBlock* body;
};

class DoForeverBlock : public TypedBlock<JavaBlock::DO_FOREVER> {
 public:
  DoForeverBlock(JavaBlock* parent, uint32_t head)
      : TypedBlock(parent, head), body(NULL) {
  }

  JavaBlock* body;
};

class CompoundBlock : public TypedBlock<JavaBlock::COMPOUND> {
 public:
  CompoundBlock(JavaBlock* parent, uint32_t head)
      : TypedBlock(parent, head) {
  }
  vector<JavaBlock*> child;
};

}  // namespace rev
}  // namespace egorich

#endif  // REV_JAVA_BLOCKS_H__
