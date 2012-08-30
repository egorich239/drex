#ifndef REV_METHOD_DASM_H__
#define REV_METHOD_DASM_H__

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <memory>

#include "dex_asm.h"
#include "dex_scanner.h"
#include "dominator_eval.h"
#include "java_blocks.h"

using std::unique_ptr;

namespace egorich {
namespace rev {

class MethodDasm {
 public:
  MethodDasm(Zone* zone, const DexScanner& scanner, const EncodedMethod& method, uint32_t* method_idx)
    : zone_(zone), scanner_(scanner), method_(method), method_idx_(*method_idx + method.method_idx_diff), ast_(NULL) {
    *method_idx = method_idx_;
  }

  void Run();
  void ReconstructAst();
  const JavaBlock* ast() const { return ast_; }

  void PrintRaw();

 private:
  Zone* zone() const { return zone_; }
  uint32_t block_last(uint32_t head) const {
    return prev_instr_[head + block_size_[head] - 1];
  }

  void ReconstructBlock(uint32_t head, bool ignore_loop);
  void ReconstructBlock(uint32_t head) {
    ReconstructBlock(head, false);
  }
  void ReconstructContinuation(uint32_t to);

  void PutEdge(uint32_t to);
  void PrintBlockBody(uint32_t head, size_t indent);
  void PrintInstruction(uint32_t pc, size_t indent);

  template <typename T, typename... Args>
  T* MakeNode(JavaBlock* parent, uint32_t head, Args&&... args) {
    return new(zone()) T(parent, head, args...);
  }

  template <typename T, typename... Args>
  T* AttachNode(uint32_t head, Args&&... args) {
    T* result = MakeNode<T>(current_compound_, head, args...);
    current_compound_->child.push_back(result);
    return result;
  }

  Zone* const zone_;
  const DexScanner& scanner_;
  const EncodedMethod& method_;
  const uint32_t method_idx_;

  uint32_t current_pc_;
  uint32_t current_block_;
  uint32_t next_pc_;

  Edges edges_;
  unique_ptr<CodeItem> code_;
  unique_ptr<DominatorEval> doms_;
  size_t indent_;
  // previous instr offset for offsets in range [1, code_->instr_size()].
  // To obtain the prev instr for offset K, read prev_instr_[K - 1]
  vector<uint32_t> prev_instr_;
  // Given an start offset of a block, returns its size, or zero if not a start of
  // a block.
  vector<uint32_t> block_size_;
  
  // Used by TopoSort(), defined by ReconstructBlock().
  Edges edges_r0_;
  vector<int> times_r0_;
  int time_r0_;

  CompoundBlock* current_compound_;
  JavaBlock* ast_;

 private:
  MethodDasm(const MethodDasm&) = delete;
};

}  // namespace rev
}  // namespace egorich

#endif
