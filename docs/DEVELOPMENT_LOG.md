# Threat2Detect 开发日志

本文件记录**已做的改动、验证证据和遗留问题**。新增工作按日期追加，不覆盖旧结果。版本、输入文件和输出路径要一起记；模型实验不要只记一个分数。完整目标与字段约定分别见 `docs/PROJECT_HANDOFF.md`、`docs/INTERFACE_CONTRACT.md`。

## 截至 2026-11-07 的既有基线

以下是前期工作的状态汇总，并非逐日原始记录。

| 模块 | 已有内容 | 验证与限制 |
|---|---|---|
| 报告 → 行为 → ATT&CK | `threat2detect/report_agent.py`，本地 Ollama `qwen3:4b`；三篇 CISA PDF 的去答案输入和报告级参考 ID | AA25-266A 的早期实验见 `docs/BASELINE_REVIEW.md`；原型输出还不是正式 `case_handoff`，行为提取和映射需要调优 |
| 人工答案 | AA25-266A 的 4 条行为及技术映射已确认；4 条报告 × Sigma 规则适用性已确认 | 样本只抽选第 8–9 页，不能据此声称全篇行为召回率 |
| 数据与规则 | Enterprise ATT&CK v20.0；SigmaHQ commit `05d1031f537e830b76da53bae2400c5814c89165`；OTRF LSASS_campaign_06 | 6 组 OTRF 事件 × 规则人工条件推演已确认；尚未用 Sigma 引擎执行；背景候选未获独立良性真值 |
| 版本管理 | 初始项目提交 `dbeb487` 已推送到 GitHub `main`；SigmaHQ 与 OTRF 作为子模块 | 之后的阅读指引简化改动在本机工作树中，尚未同步到远端；OTRF 解压 JSON 是子模块内的本地未跟踪文件 |

## 2026-11-07：第二部分拆分为独立模块

**改动**

- 新增 `threat2detect/sigma/retrieval.py`：读取正式 `case_handoff` 中已确认的行为与 ATT&CK 映射，扫描固定提交的 SigmaHQ `rules/` YAML；先按精确技术 tag 召回，再按行为文字与标题、检测条件、描述的词重叠排序。输出 `rule_candidates`，记录 Sigma 规则 ID、路径、SHA-256、logsource、规则字段和召回理由。`required_fields` 是规则涉及字段清单，OR 分支不要求它们同时出现。
- 新增 `threat2detect/sigma/coverage.py`：独立读取 `case_handoff`、候选列表和对应完整 YAML，经本地 Ollama 逐条提出 `coverage_assessments`。每条输出为 `draft`，仅判断**报告做法与规则条件**；不运行规则，不声称日志命中。规则文件哈希变化会中止运行。每完成一条就保存进度。
- `config/requirements.txt` 增加 PyYAML 固定版本。

**已完成验证**

- 规则召回命令：`python -m threat2detect.sigma.retrieval data/annotations/aa25_266a_gold_draft.json artifacts/runs/aa25_266a_rule_candidates_poc.json --limit 10`。输出 35 个候选，YAML 解析跳过 0 条，契约验证通过；人工黄金中的 4 条 Sigma 规则均在对应行为的前 10 个候选中。
- 条件对照命令：`python -m threat2detect.sigma.coverage data/annotations/aa25_266a_gold_draft.json data/annotations/aa25_266a_rule_candidates.json artifacts/runs/aa25_266a_coverage_poc.json --max-items 4`。输出通过契约校验；与人工黄金的逐项比较见下表。

| 规则样本 | 人工答案 | 首轮模型 | 提示词修订后 | 结论 |
|---|---|---|---|---|
| C001：普通 whoami 分支 | `matches_procedure` | 同 | 同 | 正确，但解释错误地把另一个 WMI 分支也说成满足 |
| C002：whoami `/all` | `does_not_match`（针对报告列出的命令） | `matches_procedure` | `matches_procedure` | 错误；模型承认报告未给 `/all`，仍判匹配 |
| C003：whoami 父进程异常 | `insufficient_detail` | `matches_procedure` | `matches_procedure` | 错误；模型把父进程未知当成排除条件已通过 |
| C004：`ipconfig /all` 正则 | `matches_procedure` | 同 | 同 | 正确 |

提示词修订明确了目标命令、OR 分支、否定过滤条件和未知字段规则；第二轮输出位于 `artifacts/runs/aa25_266a_coverage_poc_v2.json`，仍是 2/4。两轮结果均为 `draft`，不能当自动覆盖结论。当前样本很小，不能把 2/4 当系统整体准确率。

**已知问题与下一步**

1. 召回排序只用 tag 与词重叠，`whoami` 的 Linux 规则排得靠前；需要结合报告主机平台、`logsource` 和过滤条件做重排，不能把高排名当覆盖结论。
2. 条件对照模型仍无法可靠处理必需参数与否定过滤条件。下一轮应考虑把 Sigma YAML 先解析为结构化布尔条件，再让模型只填报告中已知的字段，未知值由确定性逻辑保留；扩大样本前不能把模型输出自动升级为 `confirmed`。
3. `threat2detect/report_agent.py` 仍只给每个行为一个技术 ID，且输出结构与正式契约不同；A 阶段需支持一对多映射和稳定引用。
4. 报告适用性和日志实际命中仍是两层。下一独立模块是 OTRF 字段标准化和选中 Sigma 子集的真实执行；必须保留事件 ID、跳过数、不支持语法及引擎版本。
5. 误报率需要独立、可靠标注的良性数据。现有 OTRF 背景候选只能用于条件检查和具体误命中案例。

## 2026-11-07：OTRF 标准化与离线执行

**改动**：新增 `threat2detect/telemetry/otrf.py` 和 `threat2detect/sigma/executor.py`。前者直接读取 OTRF ZIP/JSONL，输出符合 `normalized_events` 契约的 Sysmon 1/10/11 字段；后者按选中 Sigma YAML 的检测条件对本地静态事件逐条求值，输出 `rule_tests`。命令、支持语法和边界见 `docs/OFFLINE_SIGMA_RUNBOOK.md`。

**验证**：OTRF 共保留 33,729 条事件、0 条解析错误。LSASS memdump 与 dump keyword 规则各命中 L33808、L34151；Local Accounts Discovery 命中 L20542、L20570。已复核的 E01–E06 正反例与执行结果一致。标准化文件约 45 MB，可重建，因此不纳入 Git。

**仍有问题**：执行器只实现本次选中规则所需的 Sigma 子集。规则在 OTRF 上命中不等于检测到 CISA 报告中的事件；需要继续完善跨模块汇总、更多规则语法和独立良性样本验证。

## 2026-11-07：目录整理与后续结构

**改动**：将原 `data/runs/` 移至 `artifacts/runs/`，同步更新运行说明、阅读入口和 Git 忽略规则；新增 `docs/PROJECT_STRUCTURE.md` 与 `artifacts/README.md`。固定输入、子模块及人工答案仍集中在 `data/`。当时的后续迁移计划已在 2026-11-22 完成为 `threat2detect/` Python 包。

**后续整理**：将 `inspect_dataset.py`、`analyze_otrf_background.py`、`check_lsass_rule.py`、`build_cisa_cases.py`、`make_contract_examples.py` 移入 `tools/`，并更新文档命令。主流程命令暂留根目录。

**验证**：30 个测试通过；移动后的离线 `rule_tests` 及事件引用通过契约校验；`tools/` 中三个读取或补建脚本运行正常，其余脚本通过语法编译检查；阅读入口链接有效。约 45 MB 的标准化日志仍是本地可重建产物，不纳入 Git。

**仍有问题**：根目录仍有历史原型与新模块脚本。待主控编排接口稳定后逐个迁移，届时同步更新导入路径、命令与测试。本地工作树含此前未同步到 GitHub 的文档和代码改动。

## 2026-11-07 / 固定接口串联

**改动**：新增 `threat2detect/pipeline.py`，把报告 Agent 的实验 JSON 转为 `case_handoff`（行为、映射均为 `draft`），再通过 `rule_candidates`、`coverage_assessments`、`normalized_events`、`rule_tests` 汇总到 `case_result`。每步校验契约与外键；规则召回和条件对照增加只供流水线显式使用的草稿输入开关。新增 `docs/PIPELINE_RUNBOOK.md` 与转换、矛盾判断测试。

**输入与版本**：AA25-266A 已确认的 4 条行为；ATT&CK Enterprise 20.0；SigmaHQ commit `05d1031f537e830b76da53bae2400c5814c89165`；OTRF LSASS_campaign_06；条件对照模型 `qwen3:4b`。A 阶段旧预测另用作适配器检查，不作为人工答案。

**运行与验证**：使用 `--limit 1 --max-coverage 1 --max-rules 1` 的完整演示，得到 4 个候选、1 条条件判断和 1 条 OTRF 规则运行记录。模型把含未知必需字段的结果说成 `matches_procedure`；新增保守校验后输出 `insufficient_detail` 并保留原判。离线规则在 77 条兼容 OTRF 事件上为 `miss`。旧 A 预测中的 89 条行为、63 条映射通过转换契约，作为草稿进入检索，得到 54 个候选。`case_result` 外键校验通过；全部 33 个测试通过。

**仍有问题**：当前 A 原型每行为只输出一个 ATT&CK ID，尚未支持一对多；覆盖判断仍有模型错误，需人工复核和继续调优。首轮仅执行有限候选，未运行的状态保留为未知。OTRF 与报告属于不同事件，日志命中不能证明报告中的攻击被检测。

## 2026-11-08 / Sigma 条件分析 Agent 首版

**改动**：新增 `threat2detect/sigma/agent.py`，将单次条件判断改为有步骤上限的工具决策循环。可选择查看 YAML、读取报告上下文、查看所需字段，再提交 `coverage_assessments`。每个候选生成 JSONL 决策轨迹；统一入口 `threat2detect/pipeline.py` 加入 `--agent-coverage`。禁止重复工具调用，无法形成合格判断时以 `insufficient_detail` 停止。

**验证与发现**：在人工确认的 R001、R003 案例上运行。R001 经 `inspect_rule → finish` 得到 `matches_procedure`。R003 初次将缺失的 `ParentImage` 错当成排除条件不成立；加入否定过滤字段反馈后，轨迹为 `inspect_rule → 被退回的 finish → 修正的 finish`，最终 `insufficient_detail`，与人工判定一致。统一流水线加 Agent 选项后成功生成覆盖、日志规则运行和 `case_result`。这些只是首轮功能验证，不代表总体准确率。

**仍有问题**：当前字段护栏主要处理否定过滤中的 `ParentImage`；复杂 Sigma 条件仍可能误解。R001 解释曾混淆选择器列表中的 OR 与字段内 AND，需下一轮调优。暂未对全部人工判定样本和封存报告做量化评估。

## 2026-11-16 / Sigma 检索与排序优化

**改动**

- `threat2detect/sigma/retrieval.py` 加入行为平台与事件类别推断；已知 Windows 行为不再把 Linux、macOS、Cisco、OpenCanary 等规则列入 Top-K。
- 词项排序改为 IDF 加权，并分别记录 title、detection、description 和 quote 命中；保留 proxy、network、process、discovery 等领域词。
- 加入规则状态信号与完整 detection 的必要条件检查。缺失必需参数、User、ParentImage，或可能被 negative filter 排除的规则会降权。
- `candidate_id` 从排序编号改为 `mapping_id + rule_id 前缀`，重新排序不再破坏下游引用。
- 新增 `tools/evaluate_sigma_retrieval.py`，计算 Recall@1/3/5/10、MRR、平均排名、错误平台候选和候选 ID 稳定性。

**验证**

- 同一 AA25-266A `case_handoff`、同一 SigmaHQ commit、同一每映射 Top-10 预算。
- Recall@1 从 0.25 提升到 0.50；Recall@3 从 0.25 提升到 0.50；Recall@5 从 0.25 提升到 0.75；Recall@10 保持 1.00。
- MRR 从 0.3385 提升到 0.5875；平均正确规则排名从 6.75 降到 4.00。
- Top-10 错误平台候选从 7 个降到 0；候选 ID 稳定性从 0% 提升到 100%。
- `AA25-266A-G001` 的 Local Accounts Discovery 从第 10 名升到第 1；`AA25-266A-G002` 的 Suspicious Network Command 保持第 1；`Whoami.EXE Execution Anomaly` 从第 9 升至第 4。

**证据**

- `artifacts/runs/sigma_retrieval_baseline.json`
- `artifacts/runs/sigma_retrieval_optimized.json`
- `artifacts/runs/sigma_retrieval_comparison.json`

**仍有问题**

- 人工候选只覆盖 4 条规则，Recall@10 已达上限，不能据此计算 precision 或总体准确率。
- `whoami /all` 因缺少必需参数被降到第 10；它仍作为需覆盖分析的候选保留，不应在检索阶段直接删除。
- 条件降权是保守启发式，不等同于完整 Sigma 语义求值；最终覆盖判断仍需确定性三值逻辑或人工复核。

## 2026-11-22 / 代码包化、根目录清理与检索优化复核

**改动**

- 将根目录运行脚本迁入 `threat2detect/` 包：报告 Agent、契约校验、Sigma 检索/覆盖/Agent/执行器、OTRF 标准化和统一流水线按职责放入子包。
- 根目录只保留 `README.md`、`.gitignore`、`.gitmodules` 和功能目录；`READING_GUIDE.md`、`DEVELOPMENT_LOG.md` 移入 `docs/`，依赖清单移入 `config/requirements.txt`。
- 所有 CLI 改为模块入口，例如 `python -m threat2detect.pipeline`、`python -m threat2detect.sigma.retrieval` 和 `python -m threat2detect.contracts`。
- 同步修改测试、工具脚本、README、运行手册和项目结构说明，避免保留根目录兼容脚本。

**检索优化复核**

- `threat2detect/sigma/retrieval.py` 最新版本已加入平台/类别推断、IDF 加权、规则状态、选择器条件降权和稳定候选 ID。
- 在 AA25-266A 同一输入和 Sigma commit 上，Recall@5 从 0.25 提升到 0.75，Recall@10 保持 1.00，MRR 从 0.3385 提升到 0.5875，平均正确规则排名从 6.75 降到 4.00。
- Top-10 错误平台候选从 7 降到 0；候选 ID 稳定性从 0% 提升到 100%。
- 评估集仍只有 4 条人工规则，不能据此计算 precision 或总体准确率；`whoami /all` 因缺少必需参数被降权但仍保留为分析候选。

**验证边界**

- 本轮整理只改变包位置、导入和文档入口，不改变检索分数、规则内容或人工标签。
- 需要重新运行完整 pytest、契约校验和一条 Sigma 检索命令，确认包化后行为不变。

## 每次新改动的记录格式

```text
日期 / 模块：
改动：涉及文件、接口字段、原因
输入与版本：报告哈希、ATT&CK 版本、Sigma commit、模型与提示词版本
运行命令与输出：
验证：契约、测试、人工黄金差异、日志事件 ID
仍有问题：具体失败例、影响范围、下一步负责人
```
