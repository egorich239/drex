#ifndef REV_DOMINATOR_EVAL_H__
#define REV_DOMINATOR_EVAL_H__

#include <utility>
#include <vector>

using std::pair;
using std::vector;

namespace egorich {
namespace rev {

typedef vector<vector<int>> Edges;

class DominatorEval {
 public:
  typedef int Vertex;

  explicit DominatorEval(const Edges& outbound);
  ~DominatorEval();

  void Compute();
  const vector<int>& dom() const { return dom_; }
  const Edges& inbound() const { return inbound_; }
  const Edges& outbound() const { return outbound_; }
  const vector<vector<Vertex>>& dom_tree() const { return bucket_; }
  bool IsDominated(int v, int by) const;
  // Returns true iff v is earlier than w in topological sort.
  bool IsBefore(int v, int w) const;

 private:
  typedef int Time;

  void DFS(Vertex v);
  void AssignSemi();
  void ComputeDom();
  void TraverseTree(Vertex v);
  void RearrangeTree();
  void Link(Vertex v, Vertex w);
  Vertex Eval(Vertex v);
  void Compress(Vertex v);

 private:
  const Edges& outbound_;
  Edges inbound_;
  Time time_;
  int reachable_count_;
  vector<Time> semi_;
  vector<Vertex> parent_;
  vector<Time> preorder_;
  vector<Vertex> postorder_;
  vector<Time> postorder_index_;
  vector<vector<Vertex>> bucket_;
  vector<Vertex> ancestor_;
  vector<int> label_;
  vector<Vertex> dom_;
  vector<pair<Time, Time>> traversal_;
  
  DominatorEval(const DominatorEval&) = delete;
};

}  // namespace rev
}  // namespace egorich
#endif  // REV_DOMINATOR_EVAL_H__
