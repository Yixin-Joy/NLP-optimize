# Threat2Detect

课程项目：从威胁报告提取有原文证据的行为，映射 ATT&CK，检索并逐条件分析 Sigma 规则；对另行取得的静态日志运行所选规则，分别报告“做法适用”与“日志实际命中”。目前已有通过固定 JSON 接口串联的命令行原型和小规模已确认样本，判断仍需人工复核。

## 从这里开始

先读[阅读指引](docs/READING_GUIDE.md)，再按角色读[项目总说明](docs/PROJECT_HANDOFF.md)、[接口契约](docs/INTERFACE_CONTRACT.md)和[组员启动清单](docs/TEAM_START.md)。[目录约定](docs/PROJECT_STRUCTURE.md)说明文件归属；[三段流水线](docs/PIPELINE_RUNBOOK.md)给出统一运行命令，[Sigma Agent](docs/SIGMA_AGENT_RUNBOOK.md)说明工具决策循环。[开发日志](docs/DEVELOPMENT_LOG.md)记录每轮改动与遗留问题。

## 获取数据与运行

```powershell
git clone --recurse-submodules https://github.com/Yixin-Joy/NLP-optimize.git
cd NLP-optimize
python -m pip install -r config/requirements.txt
python -m pytest -q
python -m threat2detect.contracts data/annotations/aa25_266a_gold_draft.json
python tools/inspect_dataset.py
python tools/analyze_otrf_background.py
```

`data/sigma` 和 `data/Security-Datasets` 是锁定提交的 Git 子模块；普通 `git clone` 后还需运行 `git submodule update --init --recursive`。OTRF 上游 ZIP 已在子模块中；盘点脚本会在本地未解压时直接读 ZIP。`data/attack/enterprise-attack-20.0.json`、CISA PDF 与已处理的文本在本仓库中。Ollama 原型的模型下载与运行见[原型说明](docs/POC_RUNBOOK.md)。

目前确认的样本：AA25-266A 的 4 条行为映射、4 条报告 × Sigma 规则条件判断，以及 6 组 OTRF 事件 × 规则人工条件推演。所选 3 条 Sigma 规则现可在 OTRF 静态日志上[离线执行](docs/OFFLINE_SIGMA_RUNBOOK.md)；背景候选事件不等于已证实良性。CISA 官方映射只用于盲标后的报告级对照，不作为行为级理由。

## 目录

根目录只保留 README、Git 配置和功能目录。主流程源码位于 `threat2detect/`，运行入口为 `python -m threat2detect.pipeline`；依赖位于 `config/`，人工输入位于 `data/`，实验结果位于 `artifacts/`，操作文档位于 `docs/`。

Sigma 检索当前采用精确 ATT&CK tag 召回、平台和事件类别过滤、IDF 词项重排、选择器条件降权与稳定候选 ID。最新回归结果见 `artifacts/runs/sigma_retrieval_comparison.json`。
