#include "method_dasm.h"

#include <algorithm>
#include <iostream>
#include <iterator>

#include "log.h"

using std::cout;
using std::cerr;
using std::endl;
using std::sort;
using std::unique;

namespace egorich {
namespace rev {
namespace {

template <typename Layout>
const Layout* layout(const IDefBase* base) {
  return static_cast<const Layout*>(base->Get());
}

bool IsReturn(uint16_t opcode) { return 0xE <= opcode && opcode <= 0x11; }
bool IsBBranch(uint16_t opcode) { return 0x32 <= opcode && opcode <= 0x37; }
bool IsUBranch(uint16_t opcode) { return 0x38 <= opcode && opcode <= 0x3D; }
bool IsGoto(uint16_t opcode) { return 0x28 <= opcode && opcode <= 0x2A; }
bool IsThrow(uint16_t opcode) { return opcode == 0x27; }
bool IsBranch(uint16_t opcode) { return IsBBranch(opcode) || IsUBranch(opcode); }

}  // namespace


void MethodDasm::Run() {
  const MethodIdItem& method_item = scanner_.method_ids()[method_idx_];
  const uint32_t name_idx = method_item.name_idx;
  cout << "  " << scanner_.string_ids()[name_idx] << endl;
  if (!method_.code_offs) {
    return;
  }

  bool cont = false;
  code_.reset(new CodeItem(&scanner_, method_.code_offs));
  edges_.assign(code_->instr_size(), {0});
  prev_instr_.assign(code_->instr_size(), 0);
  edges_[0].clear();
  current_pc_ = 0;
  current_block_ = 0;
  next_pc_ = 0;
  while (next_pc_ <= code_->instr_size()) {
    for (uint32_t q = current_pc_ + 1; q < next_pc_; ++q) {
      edges_[q][0] = -static_cast<int>(current_block_) - 1;
      prev_instr_[q - 1] = current_pc_;
    }
    if (next_pc_) prev_instr_[next_pc_ - 1] = current_pc_;
    current_pc_ = next_pc_;
    if (current_pc_ == code_->instr_size()) {
      break;
    }

    if (edges_[current_pc_].empty()) {
      if (cont && edges_[current_block_].empty()) {
        edges_[current_block_].push_back(current_pc_);
      }
      current_block_ = current_pc_;
    } else {
      edges_[current_pc_][0] = -static_cast<int>(current_block_) - 1;
    }

    cont = false;
    const size_t offs = code_->instr_offs() + 2*current_pc_;
    const uint16_t opcode = scanner_.ReadUShort(offs) & 0xff;
    const IDefBase* const instr = iTable[opcode];
    next_pc_ = current_pc_ + instr->size(&scanner_, offs);

    if (IsReturn(opcode) || IsThrow(opcode)) {
      if (next_pc_ < code_->instr_size()) edges_[next_pc_].clear();
    } else if (IsBBranch(opcode)) {
      PutEdge(layout<L_22t>(instr)->C(&scanner_, offs) + current_pc_);
      PutEdge(next_pc_);
    } else if (IsUBranch(opcode)) {
      PutEdge(layout<L_21t>(instr)->B(&scanner_, offs) + current_pc_);
      PutEdge(next_pc_);
    } else if (IsGoto(opcode)) {
      int32_t target;
      switch (opcode) {
      case 0x28:
        target = layout<L_10t>(instr)->A(&scanner_, offs);
        break;
      case 0x29:
        target = layout<L_20t>(instr)->A(&scanner_, offs);
        break;
      case 0x2A:
        target = layout<L_30t>(instr)->A(&scanner_, offs);
        break;
      }
      PutEdge(target + current_pc_);
      if (next_pc_ < code_->instr_size()) edges_[next_pc_].clear();
    } else {
      cont = true;
    }

  }

  block_size_.assign(code_->instr_size(), 0);
  current_block_ = 0;
  current_pc_ = 0;
  while (current_pc_ <= code_->instr_size()) {
    if (current_pc_ == code_->instr_size()
        || !(edges_[current_pc_].size() == 1 && edges_[current_pc_][0] < 0)) {
      block_size_[current_block_] = current_pc_ - current_block_;
      current_block_ = current_pc_;
    }
    if (current_pc_ == code_->instr_size()) break;
    const size_t offs = code_->instr_offs() + 2*current_pc_;
    const uint16_t opcode = scanner_.ReadUShort(offs) & 0xff;
    const IDefBase* const instr = iTable[opcode];
    current_pc_ += instr->size(&scanner_, offs);
  }

  doms_.reset(new DominatorEval(edges_));
  doms_->Compute();
}

void MethodDasm::ReconstructAst() {
  DLOG() << "Reconstructing...";
  if (code_ == NULL) return;
  indent_ = 0;
  ast_ = current_compound_ = new(zone()) CompoundBlock(NULL, 0);
  ReconstructBlock(0);
}

void MethodDasm::PrintRaw() {
  if (code_ == NULL) {
    return;
  }
  uint32_t pc = 0;
  while (pc < code_->instr_size()) {
    PrintInstruction(pc, 0);

    const size_t offs = code_->instr_offs() + 2*pc;
    const uint16_t opcode = scanner_.ReadUShort(offs) & 0xff;
    const IDefBase* const instr = iTable[opcode];
    pc += instr->size(&scanner_, offs);
    if (pc == code_->instr_size() || block_size_[pc]) cout << endl;
  }

}

void MethodDasm::ReconstructBlock(uint32_t head, bool ignore_loop) {
  DLOG() << "Head: " << head;
  CompoundBlock* const prev_compound = current_compound_;
  const uint8_t opcode = code_->opcode(block_last(head));
  const auto& inbound = doms_->inbound()[head];
  const auto& outbound = doms_->outbound()[head];

  vector<int> cyclic;
  std::copy_if(
      inbound.begin(), inbound.end(), std::back_inserter(cyclic),
      [&doms_, head] (int v) -> bool { return doms_->IsDominated(v, head); });
  if (!ignore_loop && !cyclic.empty()) {
    const bool precond = IsBranch(code_->opcode(block_last(head)))
        && (cyclic.size() != 1
            || !IsBranch(code_->opcode(block_last(cyclic[0]))));
    if (precond) {
      // while (cond) { body; } cont;
      const uint32_t then_block = outbound[0];
      const uint32_t else_block = outbound[1];
      WhileBlock* loop = AttachNode<WhileBlock>(head);
      loop->cond = MakeNode<BasicBlock>(loop, head);
      loop->invert = !doms_->IsDominated(then_block, head)
          || !doms_->IsDominated(cyclic[0], then_block);
      const uint32_t body_block = loop->invert ? else_block : then_block;
      ASSERT(doms_->IsDominated(body_block, head)
             && doms_->IsDominated(cyclic[0], body_block))
          << "THEN: " << then_block << "; ELSE: " << else_block
          << "; BODY: " << body_block;
      ReconstructContinuation(then_block + else_block - body_block);
      loop->body = current_compound_ = MakeNode<CompoundBlock>(loop, body_block);
      ReconstructBlock(body_block);
    } else if (IsBranch(code_->opcode(block_last(cyclic[0])))) {
      // do { body; } while (cond); cont;
      DoBlock* loop = AttachNode<DoBlock>(head);
      loop->cond = MakeNode<BasicBlock>(loop, cyclic[0]);
      loop->invert = doms_->outbound()[cyclic[0]][0] != head;
      ReconstructContinuation(
          doms_->outbound()[cyclic[0]][0] + doms_->outbound()[cyclic[0]][1] - head);
      if (cyclic[0] != head) {
        loop->body = current_compound_ = MakeNode<CompoundBlock>(loop, head);
        ReconstructBlock(head, true);
      }
    } else {
      // do { body; } while (true);
      ASSERT(IsGoto(code_->opcode(block_last(cyclic[0]))));
      DoForeverBlock* loop = AttachNode<DoForeverBlock>(head);
      loop->body = current_compound_ = MakeNode<CompoundBlock>(loop, head);
      ReconstructBlock(head, true);
    }
  } else if (IsReturn(opcode)) {
    ASSERT(outbound.empty());
    AttachNode<ReturnBlock>(head);
  } else if (IsThrow(opcode)) {
    ASSERT(outbound.empty());
    AttachNode<ThrowBlock>(head);
  } else if (IsBranch(opcode)) {
    ASSERT(outbound.size() == 2);
    BranchBlock* branch = AttachNode<BranchBlock>(head);
    branch->cond = MakeNode<BasicBlock>(branch, head);

    vector<int> dominated;
    std::copy_if(
        doms_->dom_tree()[head].begin(), doms_->dom_tree()[head].end(),
        std::back_inserter(dominated),
        [this] (int v) -> bool { return !this->doms_->outbound()[v].empty(); });
    switch (dominated.size()) {
    case 0: {
      branch->on_true = current_compound_ = MakeNode<CompoundBlock>(branch, head);
      ReconstructContinuation(outbound[0]);
      branch->on_false = current_compound_ = MakeNode<CompoundBlock>(branch, head);
      ReconstructContinuation(outbound[1]);
      break;
    }
    case 1: {
      ASSERT(dominated[0] == outbound[0] || dominated[0] == outbound[1]);
      branch->invert = dominated[0] != outbound[0];
      branch->on_true = current_compound_ = MakeNode<CompoundBlock>(branch, dominated[0]);
      ReconstructBlock(dominated[0]);
      branch->on_false = current_compound_ = MakeNode<CompoundBlock>(branch, head);
      ReconstructContinuation(outbound[0] + outbound[1] - dominated[0]);
      break;
    }
    case 2: {
      const bool has_else_block = std::all_of(
          doms_->inbound()[dominated[1]].begin(),
          doms_->inbound()[dominated[1]].end(),
          [this, &dominated] (int v) -> bool { 
              return !this->doms_->IsDominated(v, dominated[0]); });
      if (has_else_block) {
        branch->on_true = current_compound_ = MakeNode<CompoundBlock>(branch, outbound[0]);
        ReconstructBlock(outbound[0]);
        branch->on_false = current_compound_ = MakeNode<CompoundBlock>(branch, outbound[1]);
        ReconstructBlock(outbound[1]);
      } else {
        ReconstructBlock(dominated[1]);
        branch->invert = dominated[0] != outbound[0];
        branch->on_true = current_compound_ = MakeNode<CompoundBlock>(branch, dominated[0]);
        ReconstructBlock(dominated[0]);
      }
      break;
    }
    case 3: {
      ReconstructBlock(dominated[2]);
      branch->on_true = current_compound_ = MakeNode<CompoundBlock>(branch, outbound[0]);
      ReconstructBlock(outbound[0]);
      branch->on_false = current_compound_ = MakeNode<CompoundBlock>(branch, outbound[1]);
      ReconstructBlock(outbound[1]);
      break;
    }
    default:
      DLOG() << "doms = ";
      for (uint32_t v : dominated) {DLOG() << v;}
      UNREACHABLE();
    }
  } else if (IsGoto(opcode)) {
    ASSERT(outbound.size() == 1);
    ReconstructContinuation(outbound[0]);
  } else {
    ASSERT(outbound.size() == 1);
    AttachNode<BasicBlock>(head);
    ReconstructContinuation(outbound[0]);
  }

  current_compound_ = prev_compound;
}

void MethodDasm::ReconstructContinuation(uint32_t to) {
}

void MethodDasm::PutEdge(uint32_t to) {
  edges_[current_block_].push_back(to);
  if (to > current_pc_) {
    edges_[to].clear();
    return;
  }
  if (edges_[to].size() == 1 && edges_[to][0] < 0) {
    const int32_t marker = edges_[to][0];
    const uint32_t b_start = -marker - 1;
    edges_[to].swap(edges_[b_start]);
    edges_[b_start][0] = to;
    if (b_start == current_block_) {
      current_block_ = to;
    }
    const int32_t new_marker = -to - 1;
    ++to;
    while (edges_[to].size() == 1 && edges_[to][0] == marker) {
      edges_[to][0] = new_marker;
      ++to;
    }
  }
}

void MethodDasm::PrintBlockBody(uint32_t head, size_t indent) {
  const int marker = -static_cast<int>(head) - 1;
  do {
    PrintInstruction(head, indent);
    head += code_->opsize(head);
  } while (head < code_->instr_size() 
           && edges_[head].size() == 1
           && edges_[head][0] == marker);
}

void MethodDasm::PrintInstruction(uint32_t pc, size_t indent) {
  const size_t offs = code_->instr_offs() + 2*pc;
  const uint16_t opcode = scanner_.ReadUShort(offs) & 0xff;
  const IDefBase* const instr = iTable[opcode];

  cout << pc << "\t";
  for (int t = 0; t < indent; ++t) {
    cout << "  ";
  }
  cout << instr->dasm(&scanner_, offs) << " [" << instr->size(&scanner_, offs) << "]";
  if (block_size_[pc]) {
    cout << " { ";
    for (int edge : edges_[pc]) {
      cout << edge << " ";
    }
    cout << "}";
  }
  cout << endl;
}

}  // namespace rev
}  // namespace egorich

