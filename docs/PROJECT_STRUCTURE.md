# 项目目录约定

根目录只保留 README、Git 配置和功能目录，不再放运行脚本、依赖清单或个人说明。

```text
NLP-optimize/
├─ README.md
├─ .gitignore
├─ .gitmodules
├─ artifacts/                  # 可重建的预测、评估、规则候选和运行结果
│  ├─ README.md
│  └─ runs/
├─ config/
│  └─ requirements.txt         # Python 运行依赖
├─ data/                       # 固定输入与人工答案
│  ├─ reports/                 # CISA PDF、去答案正文、报告级对照
│  ├─ attack/                  # 固定 ATT&CK 目录
│  ├─ sigma/                   # SigmaHQ 子模块
│  ├─ Security-Datasets/       # OTRF 子模块
│  └─ annotations/             # 已审核样本、候选规则与请求示例
├─ docs/                       # 阅读指引、开发日志、契约和运行说明
├─ tests/                      # 回归测试
├─ threat2detect/              # 主流程 Python 包
│  ├─ pipeline.py              # 统一编排入口
│  ├─ report_agent.py          # 报告行为提取与 ATT&CK 映射
│  ├─ contracts.py             # JSON 契约和跨模块引用校验
│  ├─ sigma/
│  │  ├─ retrieval.py          # 规则召回与排序
│  │  ├─ coverage.py           # 报告做法与规则条件对照
│  │  ├─ agent.py              # 有界工具决策 Agent
│  │  └─ executor.py           # Sigma 受限静态执行器
│  └─ telemetry/
│     └─ otrf.py               # OTRF/Sysmon 标准化
└─ tools/                      # 数据准备、盘点和一次性评估脚本
```

统一入口：

- 完整流水线：`python -m threat2detect.pipeline`
- 契约校验：`python -m threat2detect.contracts`
- Sigma 检索：`python -m threat2detect.sigma.retrieval`
- Sigma 覆盖：`python -m threat2detect.sigma.coverage`
- Sigma Agent：`python -m threat2detect.sigma.agent`
- 离线执行：`python -m threat2detect.sigma.executor`

`data/` 只放可追溯输入、版本锁定的上游仓库与人工标注；模型输出和可重建结果放 `artifacts/`。依赖统一从 `config/requirements.txt` 安装。
