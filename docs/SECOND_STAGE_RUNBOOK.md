# 第二部分：Sigma 检索与条件对照的独立运行

在项目根目录运行；先安装 `python -m pip install -r config/requirements.txt`，并确保 `data/sigma` 子模块已初始化，Ollama 已启动且有 `qwen3:4b`。输入 `data/annotations/aa25_266a_gold_draft.json` 虽保留旧文件名，其现有四条行为及映射均为 `confirmed`。

## 1. 规则召回（不需要模型）

```powershell
python -m threat2detect.sigma.retrieval data/annotations/aa25_266a_gold_draft.json artifacts/runs/aa25_266a_rule_candidates_poc.json --limit 10
python -m threat2detect.contracts artifacts/runs/aa25_266a_rule_candidates_poc.json --handoff data/annotations/aa25_266a_gold_draft.json
```

输出 `kind: rule_candidates`。候选以对应 `attack.tXXXX` 标签为入口，再执行以下排序与过滤：

- 从行为引句、action、object 推断 Windows/Linux/macOS 平台；已知平台不兼容的 `logsource.product` 不进入 Top-K。
- 对规则标题、description、完整 detection 使用 IDF 加权词项，不再由长标题或大量泛用词直接占优。
- 行为引句与 detection 的精确重叠获得额外权重。
- `logsource.category` 与行为类型一致时加分。
- `stable` 规则小幅加分，`deprecated` 规则降权。
- 必需 `CommandLine`、User、ParentImage 等 selector 无法由报告证据支持时降权；可能被 negative filter 排除的规则也降权。

`candidate_id` 使用 `mapping_id + Sigma rule ID 前缀`，不再包含排名，因此重新排序不会破坏下游 `coverage_assessments`、trace 或事件执行引用。输出同时保存 `rank`、`retrieval_score`、`retrieval_components` 和 `platform_exclusions`。

召回仍不代表规则适用；父进程、参数、排除项和覆盖结论必须在下一步检查。黄金候选清单 `data/annotations/aa25_266a_rule_candidates.json` 用于核对有没有召回已知规则，不参与检索算法。

## 1.1 Recall@K / MRR 对比

保存优化前输出后，再运行同一输入和 Sigma commit：

```powershell
python -m threat2detect.sigma.retrieval data/annotations/aa25_266a_gold_draft.json artifacts/runs/sigma_retrieval_optimized.json --limit 10
python tools/evaluate_sigma_retrieval.py data/annotations/aa25_266a_gold_draft.json data/annotations/aa25_266a_rule_candidates.json artifacts/runs/sigma_retrieval_baseline.json artifacts/runs/sigma_retrieval_optimized.json artifacts/runs/sigma_retrieval_comparison.json
```

评价器按 `behavior_id + rule_id` 对齐人工候选，输出 Recall@1/3/5/10、MRR、平均排名、错误平台候选和候选 ID 稳定性。

## 2. 条件对照（需要 Ollama）

先用 4 条人工挑选的规则进行受控演示：

```powershell
python -m threat2detect.sigma.coverage data/annotations/aa25_266a_gold_draft.json data/annotations/aa25_266a_rule_candidates.json artifacts/runs/aa25_266a_coverage_poc.json --max-items 4
python -m threat2detect.contracts artifacts/runs/aa25_266a_coverage_poc.json --handoff data/annotations/aa25_266a_gold_draft.json --candidates data/annotations/aa25_266a_rule_candidates.json
```

成功后可把第二个参数换成上一步的检索输出；大量候选会产生多次模型调用，先用 `--max-items` 限制规模。输出 `kind: coverage_assessments`，每条 `review_status: draft`。与 `data/annotations/coverage_gold_template.json` 比对时，按 `candidate_id` 连接，不能把人工答案放进模型输入。

`matches_procedure` 只表示报告描述的做法符合规则条件；实际规则运行与命中要由后续日志模块负责。任何未支持的 Sigma 语法、缺失字段或规则库更新都应记入 `docs/DEVELOPMENT_LOG.md`，不要自动当作规则 `miss`。
