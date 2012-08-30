#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <sstream>
#include <string>
#include <vector>

#include "dex_asm.h"
#include "dex_scanner.h"
#include "dominator_eval.h"
#include "log.h"
#include "method_dasm.h"

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

void ReconstructBlock(const DexScanner& scanner, const EncodedMethod& method, const DominatorEval& dom, uint32_t head) {
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
  
  Zone zone(1048576 * 16);

  const auto& class_defs = d.class_defs();
  for (const ClassDefItem& class_def : class_defs) {
    cout << "== " << d.string_ids()[d.type_ids()[class_def.type_idx()].descriptor_idx] << endl;
    uint32_t method_idx = 0;
    for (const EncodedMethod& method : class_def.direct_methods()) {
      MethodDasm dasm(&zone, d, method, &method_idx);
      dasm.Run();
      dasm.PrintRaw();
      dasm.ReconstructAst();
    }

    method_idx = 0;
    for (const EncodedMethod& method : class_def.virtual_methods()) {
      MethodDasm dasm(&zone, d, method, &method_idx);
      dasm.Run();
      dasm.PrintRaw();
      dasm.ReconstructAst();
    }
  }

  return 0;
}
