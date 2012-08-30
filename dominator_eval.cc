#include "dominator_eval.h"

#include <algorithm>

#include "log.h"

using std::sort;

namespace egorich {
namespace rev {

DominatorEval::DominatorEval(const Edges& outbound)
  : outbound_(outbound),
    inbound_(outbound.size()),
    time_(0),
    semi_(outbound.size(), -1),
    parent_(outbound.size(), -1),
    preorder_(outbound.size(), -1),
    postorder_(),
    postorder_index_(outbound_.size()),
    bucket_(outbound.size()),
    ancestor_(outbound.size(), -1),
    label_(outbound.size(), -1),
    dom_(outbound.size(), -1),
    traversal_(outbound.size()) {
  for (int i = 0; i < label_.size(); ++i) {
    label_[i] = i;
  }
}

DominatorEval::~DominatorEval() {
}

void DominatorEval::Compute() {
  DFS(0);
  for (int i = 0; i < postorder_.size(); ++i) {
    postorder_index_[postorder_[i]] = i;
  }
  AssignSemi();
  ComputeDom();
  TraverseTree(0);
  RearrangeTree();
}

bool DominatorEval::IsDominated(int v, int by) const {
  return traversal_[by].first <= traversal_[v].first 
      && traversal_[v].first < traversal_[by].second;
}

bool DominatorEval::IsBefore(int v, int w) const {
  return postorder_index_[v] > postorder_index_[w];
}

void DominatorEval::DFS(Vertex v) {
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
  postorder_.push_back(v);
}

void DominatorEval::AssignSemi() {
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

void DominatorEval::ComputeDom() {
  bucket_.assign(bucket_.size(), vector<Vertex>());
  while (++time_ < postorder_.size()) {
    const Vertex w = preorder_[time_];
    if (dom_[w] != preorder_[semi_[w]]) {
      dom_[w] = dom_[dom_[w]];
    }
    bucket_[dom_[w]].push_back(w);
  }
  time_ = 0;
}

void DominatorEval::TraverseTree(Vertex v) {
  traversal_[v].first = time_++;
  for (Vertex w : bucket_[v]) {
    TraverseTree(w);
  }
  traversal_[v].second = time_++;
}

void DominatorEval::RearrangeTree() {
  for (vector<Vertex>& children : bucket_) {
    sort(children.begin(), children.end(),
         [this] (Vertex l, Vertex r) -> bool {
             return this->IsBefore(l, r); });
  }
}

void DominatorEval::Link(Vertex v, Vertex w) {
  ancestor_[w] = v;
}

DominatorEval::Vertex DominatorEval::Eval(Vertex v) {
  if (ancestor_[v] == -1) {
    return v;
  }
  Compress(v);
  return label_[v];
}

void DominatorEval::Compress(Vertex v) {
  if (ancestor_[ancestor_[v]] == -1) {
    return;
  }
  Compress(ancestor_[v]);
  if (semi_[label_[ancestor_[v]]] < semi_[label_[v]]) {
    label_[v] = label_[ancestor_[v]];
  }
  ancestor_[v] = ancestor_[ancestor_[v]];
}

}  // namespace rev
}  // namespace egorich
