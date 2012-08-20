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
#include "dex_scanner.h"
#include "dominator_eval.h"

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

using namespace egorich::rev;

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

bool IsReturn(uint16_t opcode) { return 0xE <= opcode && opcode <= 0x11; }
bool IsBBranch(uint16_t opcode) { return 0x32 <= opcode && opcode <= 0x37; }
bool IsUBranch(uint16_t opcode) { return 0x38 <= opcode && opcode <= 0x3D; }
bool IsGoto(uint16_t opcode) { return 0x28 <= opcode && opcode <= 0x2A; }
bool IsThrow(uint16_t opcode) { return opcode == 0x27; }

void PutEdge(uint32_t current_pc, Edges* edges, uint32_t* current_block, uint32_t to) {
  edges->at(*current_block).push_back(to);
  if (to > current_pc) {
    edges->at(to).clear();
    return;
  }
  if (edges->at(to).size() == 1 && edges->at(to)[0] < 0) {
    const int32_t marker = edges->at(to)[0];
    const uint32_t b_start = -marker - 1;
    edges->at(to).swap(edges->at(b_start));
    edges->at(b_start)[0] = to;
    if (b_start == *current_block) {
      *current_block = to;
    }
    const int32_t new_marker = -to - 1;
    ++to;
    while (edges->at(to).size() == 1 && edges->at(to)[0] == marker) {
      edges->at(to)[0] = new_marker;
      ++to;
    }
  }
}

template <typename Layout>
const Layout* layout(const IDefBase* base) {
  return static_cast<const Layout*>(base->Get());
}

void AnalyzeMethod(const DexScanner& scanner, const EncodedMethod& method, uint32_t* method_idx) {
  *method_idx += method.method_idx_diff;
  const MethodIdItem& method_item = scanner.method_ids()[*method_idx];
  const uint32_t name_idx = method_item.name_idx;
  cout << "  " << scanner.string_ids()[name_idx] << endl;
  if (!method.code_offs) {
    return;
  }

  CodeItem code(&scanner, method.code_offs);
  Edges edges(code.instr_size(), {0});
  edges[0].clear();
  uint32_t current_pc = 0;
  uint32_t current_block = 0;
  uint32_t next_pc = 0;
  while (next_pc <= code.instr_size()) {
    for (uint32_t q = current_pc + 1; q < next_pc; ++q) {
      edges[q][0] = -static_cast<int>(current_block) - 1;
    }
    current_pc = next_pc;
    if (current_pc == code.instr_size()) {
      break;
    }

    if (edges[current_pc].empty()) {
      current_block = current_pc;
    } else {
      edges[current_pc][0] = -static_cast<int>(current_block) - 1;
    }

    const size_t offs = code.instr_offs() + 2*current_pc;
    const uint16_t opcode = scanner.ReadUShort(offs) & 0xff;
    const IDefBase* const instr = iTable[opcode];
    next_pc = current_pc + instr->size(&scanner, offs);

    if (IsReturn(opcode) || IsThrow(opcode)) {
      if (next_pc < code.instr_size()) edges[next_pc].clear();
    } else if (IsBBranch(opcode)) {
      PutEdge(current_pc, &edges, &current_block, next_pc);
      PutEdge(current_pc, &edges, &current_block,
              layout<L_22t>(instr)->C(&scanner, offs) + current_pc);
    } else if (IsUBranch(opcode)) {
      PutEdge(current_pc, &edges, &current_block, next_pc);
      PutEdge(current_pc, &edges, &current_block,
              layout<L_21t>(instr)->B(&scanner, offs) + current_pc);
    } else if (IsGoto(opcode)) {
      int32_t target;
      switch (opcode) {
      case 0x28:
        target = layout<L_10t>(instr)->A(&scanner, offs);
        break;
      case 0x29:
        target = layout<L_20t>(instr)->A(&scanner, offs);
        break;
      case 0x2A:
        target = layout<L_30t>(instr)->A(&scanner, offs);
        break;
      }
      PutEdge(current_pc, &edges, &current_block, target + current_pc);
      if (next_pc < code.instr_size()) edges[next_pc].clear();
    }
  }

  current_pc = 0;
  next_pc = 0;
  while (next_pc <= code.instr_size()) {
    /*
    for (uint32_t q = current_pc + 1; q < next_pc; ++q) {
      cout << "[" << q << "]\t{ ";
      for (int edge : edges[q]) {
        if (edge < 0) {
          cout << "B" << (-edge - 1) << " ";
        } else {
          cout << edge << " ";
        }
      }
      cout << "}" << endl;
    }
    */
    current_pc = next_pc;
    if (current_pc == code.instr_size()) {
      break;
    }

    const size_t offs = code.instr_offs() + 2*current_pc;
    const uint16_t opcode = scanner.ReadUShort(offs) & 0xff;
    const IDefBase* const instr = iTable[opcode];
    next_pc = current_pc + instr->size(&scanner, offs);

    cout << current_pc << "\t" << instr->dasm(&scanner, offs) << " [" << instr->size(&scanner, offs) << "] { ";
    for (int edge : edges[current_pc]) {
      if (edge < 0) {
        cout << "B" << (-edge - 1) << " ";
      } else {
        cout << edge << " ";
      }
    }
    cout << "}" << endl;
  }

  for (auto& v : edges) {
    if (v.size() == 1 && v[0] < 0) {
      v.clear();
    }
  }
  DominatorEval eval(edges);
  eval.Compute();

}

int main() {
  Do(Edges(1));
  /*
  Do({{1}, {2}, {3}, {}});  // linear
  Do({{1, 3}, {2}, {5}, {4}, {5}, {}});  // if (1) (2) else (3) (4); (5)
  Do({{1, 3}, {2}, {3}, {4}, {}});  // if (1) (2); (3) (4)
  */

  DexScanner d(ReadFileContent("/home/ivan/Downloads/classes.exe"));
  d.Parse();

  const auto& class_defs = d.class_defs();
  for (const ClassDefItem& class_def : class_defs) {
    cout << "== " << d.string_ids()[d.type_ids()[class_def.type_idx()].descriptor_idx] << endl;
    uint32_t method_idx = 0;
    for (const EncodedMethod& method : class_def.direct_methods()) {
      AnalyzeMethod(d, method, &method_idx);
    }

    method_idx = 0;
    for (const EncodedMethod& method : class_def.virtual_methods()) {
      AnalyzeMethod(d, method, &method_idx);
    }
  }

  return 0;
}
