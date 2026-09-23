# Unicode 双向文本安全审计 API

基于 **FastAPI + SQLite + Docker** 的服务，检测文本中的 Unicode 双向控制字符（Trojan Source / CVE-2021-42574 类攻击面），按 [UAX #9](https://www.unicode.org/reports/tr9/) 的显式嵌入/隔离配对嵌套规则解析，报告每个控制符的码点、逻辑索引、影响范围与未闭合错误，并对危险区段生成**保持逻辑可读顺序**的转义预览。

> 原始文本永远不会被改写：危险区段同时返回 `raw`（原文逐字保留）与 `escaped_preview`（可读转义形式）。

## 检测的字符

| 码点 | 缩写 | 名称 | 配对方式 |
|---|---|---|---|
| U+200E / U+200F / U+061C | LRM / RLM / ALM | 左右/右左/阿拉伯字母标记 | 无配对（info） |
| U+202A / U+202B | LRE / RLE | 左向/右向嵌入 | PDF 弹出 |
| U+202D / U+202E | LRO / **RLO** | 左向/右向**覆盖** | PDF 弹出 |
| U+202C | PDF | 弹出方向格式 | 匹配最近的 LRE/RLE/LRO/RLO |
| U+2066 / U+2067 / U+2068 | LRI / RLI / FSI | 左向/右向/首强字符隔离 | PDI 弹出 |
| U+2069 | PDI | 弹出隔离 | 匹配最近的 LRI/RLI/FSI |
| U+2061–U+2064 | FSA/ITS/ISS/IPF | 隐形数学运算符 | 无配对（info） |

同时在转义预览中暴露零宽空格（U+200B）、BOM/ZWJ 等不可见格式字符。

## 配对与嵌套规则（UAX #9 X1–X9 子集）

1. LRE/RLE/LRO/RLO 入栈，由最近的 PDF 闭合；LRI/RLI/FSI 入栈，由最近的 PDI 闭合。
2. PDF 会跳过尚未终止的隔离层，向下找到属于自己的嵌入层（X7/X9）。
3. PDI 关闭隔离时，隔离内部**未显式闭合的嵌入层会被隐式终止**并报告错误。
4. 只有 PDF/PDI 而无对应开启符 → 孤立闭合符错误。
5. 文本结束时栈中仍有开启符 → 未闭合错误（未闭合的 RLO/LRO 为 **critical**，因为重排效果延伸到文本结尾）。
6. 显式嵌套深度超过上限（125，BD13 相关）→ critical 错误。

## 风险级别

| 级别 | 含义 |
|---|---|
| `info` | 仅有 LRM/RLM/ALM 等标记或无控制符 |
| `low` | 已正确闭合的 LRE/LRI/FSI 等 |
| `medium` | RLE/RLI、未闭合的隔离/嵌入、孤立 PDF/PDI |
| `high` | 存在 RLO/LRO 方向覆盖（无论是否闭合） |
| `critical` | RLO/LRO **未闭合**，或嵌套深度超限 |

记录的整体风险级别取全部控制符中的最高级别。

## 快速开始

### Docker Compose（推荐）

```bash
docker compose up --build
```

服务在 <http://localhost:8000> 启动，交互式文档：<http://localhost:8000/docs>。
SQLite 数据文件保存在命名卷 `bidi-audit-data`（容器内 `/data/audit.db`）。
启动方式无需改动，新增的 `POST /api/v1/audits/diff` 随服务一起可用。

### 仅用 Docker

```bash
docker build -t bidi-audit .
docker run -p 8000:8000 -v "$PWD/data:/data" bidi-audit
```

容器启动时会自动执行 schema 初始化（`python -m app.init_db`）。

### 本地运行（无 Docker）

```bash
pip install -r requirements.txt
./run.sh                     # 初始化 DB 并在 8000 端口启动
# 或：
BIDI_DB_PATH=./data/audit.db python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## API

### `POST /api/v1/audits` — 提交审计

请求体：

```json
{
  "text": "‮malware.exe‬",
  "filename": "patch.diff"
}
```

`filename` 可选；`text` 必填，原样存储不做任何改写。

```bash
curl -s -X POST http://localhost:8000/api/v1/audits \
  -H 'Content-Type: application/json' \
  -d '{"text": "x‮evil.exe‬", "filename": "patch.diff"}' | jq
```

响应（节选）：

```json
{
  "id": 1,
  "risk_level": "high",
  "stored": true,
  "result": {
    "length": 12,
    "max_depth": 1,
    "risk_level": "high",
    "error_count": 0,
    "errors": [],
    "controls": [
      {
        "codepoint": "U+202E",
        "abbreviation": "RLO",
        "name": "RIGHT-TO-LEFT OVERRIDE",
        "kind": "override",
        "logical_index": 1,
        "position": {"line": 1, "column": 2},
        "depth_after": 1,
        "scope_end": 10,
        "paired_with": "U+202C",
        "is_orphan": false,
        "risk": "high"
      }
    ],
    "dangerous_spans": [
      {
        "start": 1,
        "end": 10,
        "reason": "RLO override forces visual reordering of enclosed characters",
        "opener": "RLO",
        "risk": "high",
        "raw": "‮evil.exe",
        "escaped_preview": "⟨RLO⟩evil.exe"
      }
    ],
    "stats": {
      "total_control_chars": 2,
      "by_abbreviation": {"RLO": 1, "PDF": 1},
      "unclosed_openers": 0,
      "orphan_closers": 0,
      "dangerous_span_count": 1
    }
  }
}
```

说明：

- `logical_index` 是 Python/Unicode 码点偏移；`position.line/column` 按换行切分（1 起始）。
- `scope_end` 是配对闭合符的逻辑索引（未闭合时等于文本长度）。
- `escaped_preview` 保持**逻辑顺序**，把控制符渲染为 `⟨RLO⟩` 这类可读占位符，零宽字符渲染为 `⟨U+200B⟩`，换行/Tab 渲染为 `\n` / `\t`。

未闭合 RLO 示例（攻击字符串不以 PDF 结尾，重排延伸至文本末尾）：

```bash
curl -s -X POST http://localhost:8000/api/v1/audits \
  -H 'Content-Type: application/json' \
  -d '{"text": "‮end.js", "filename": "x.js"}' | jq '.result.risk_level, .result.errors'
# "critical"
# ["RLO at logical index 0 (line 1, col 1) is never closed by PDF"]
```

### `POST /api/v1/audits/diff` — 统一 diff 审计

接收一段 **unified diff** 文本（`git diff` / `diff -u` 风格，支持多文件、多 hunk、
重命名、模式变更、二进制补丁以及 `\ No newline at end of file` 标记），**只审计
各 hunk 中以 `+` 开头的新增行**：文件头、删除行（`-`）、上下文行（前导空格）与
No-newline 标记只参与结构解析，不参与分析。

对每个**含新增内容的文件**，按新文件行号顺序重建新增文本并运行 bidi 解析器，再把
命中的**控制符、错误与危险区段**回映射到：

- 新文件路径（`path`，删除文件 `/dev/null` 不产生记录）、新文件的行/列（`position`，
  1 起始，按 hunk 头的 `+起始行,行数` 推进，删除行不推进）；
- 对应 diff 的行/列（`diff_position`，diff 行号 1 起始，列因前导 `+` 整体 +1）；
- 原解析结果中的逻辑索引与数组下标（`logical_index` / `start_logical_index` /
  `end_logical_index` 与 `result_index`），解析结果本身保持不变。

成功后为每个含新增内容的文件**各保存一条审计记录**（`filename` 为新文件路径，
重建的新增文本存入 `raw_text`，映射信息存入记录的 `meta` 字段，可通过
`GET /api/v1/audits/{id}` 取回），返回各记录 ID 与跨文件汇总的最高风险。

```bash
cat > evil.diff <<'PATCH'
diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,3 @@
 import sys
-old = 1
+name = '‮evil.exe‬'
+print(name)
PATCH

curl -s -X POST http://localhost:8000/api/v1/audits/diff \
  -H 'Content-Type: application/json' \
  --data-binary @evil.diff | jq
```

响应（节选）：

```json
{
  "stored": true,
  "file_count": 1,
  "risk_level": "high",
  "items": [
    {
      "id": 13,
      "stored": true,
      "path": "src/app.py",
      "old_path": "src/app.py",
      "text_length": 51,
      "risk_level": "high",
      "max_depth": 1,
      "error_count": 0,
      "control_count": 2,
      "dangerous_span_count": 1,
      "added_line_count": 2,
      "added_lines": [
        {"new_line": 2, "diff_line": 6, "no_newline": false},
        {"new_line": 3, "diff_line": 7, "no_newline": false}
      ],
      "locations": {
        "controls": [
          {
            "result_index": 0,
            "logical_index": 9,
            "path": "src/app.py",
            "position": {"line": 2, "column": 9},
            "diff_position": {"line": 6, "column": 10}
          }
        ],
        "errors": [],
        "dangerous_spans": [
          {
            "result_index": 0,
            "start_logical_index": 9,
            "end_logical_index": 18,
            "path": "src/app.py",
            "position": {"start": {"line": 2, "column": 9},
                         "end": {"line": 2, "column": 18}},
            "diff_position": {"start": {"line": 6, "column": 10},
                              "end": {"line": 6, "column": 19}}
          }
        ]
      },
      "result": { "risk_level": "high", "controls": ["…同 /audits 的原始解析结果…"] }
    }
  ]
}
```

说明：

- `position` 的行是**新文件行号**（跨 hunk 按各 hunk 头推进，不依赖旧文件行号）；
  `diff_position` 行是该字符所在 `+` 行在**整个 diff 文本中的行号**，列含前导 `+`
  的 1 列偏移。`result_index` 可直接索引到 `result.controls[]` / `result.errors[]` /
  `result.dangerous_spans[]` 的对应元素，`logical_index` 与其保持一致。
- `result` 是对**重建后新增文本**（无新增行之间的空行拼接问题：按新文件顺序逐行
  连接，行末按 No-newline 标记决定是否补 `\n`）的原始解析结果，结构与
  `POST /api/v1/audits` 完全一致，因此该记录同样支持 `verify` 与 `sarif`。
- 纯删除文件、二进制补丁（`Binary files … differ` / `GIT binary patch` Base85 段）、
  空文件与无新增行的文件不产生记录（仍计入合法 diff）；所有文件都无新增内容时
  返回 201、`file_count: 0`、`risk_level: "info"`。
- git 的 `a/` `b/` 路径前缀与 C 风格引号路径（如 `"src/a b.txt"`）会被还原。

错误情况：

| 状态码 | 条件 |
|---|---|
| `422` | diff 结构非法（无文件段、hunk 头格式错误、hunk 出现在文件头之外、hunk 体行首字符非法、No-newline 标记位置/文本错误），或 hunk 体行数与头部声明的旧/新行数不一致 |
| `422` | 请求体缺少 `diff` 字段（Pydantic 校验） |

行数不一致时（超出在越界行、截断在 hunk 头）都定位到**首个错误的 diff 行号**：

```json
{
  "detail": {
    "error": "invalid_unified_diff",
    "line": 4,
    "message": "hunk body exceeds the 1 new line(s) declared by its header"
  }
}
```

校验在任何写入之前完成：解析或 hunk 计数失败时**不写入任何记录**（多文件 diff 中
后置文件出错，前面的文件同样不会落库）。

### `GET /api/v1/audits` — 查询历史记录

支持按风险级别精确过滤、按文件名（大小写不敏感子串）过滤与分页：

```bash
curl 'http://localhost:8000/api/v1/audits?risk_level=critical&filename=patch&limit=20&offset=0'
```

```json
{
  "total": 1,
  "limit": 20,
  "offset": 0,
  "items": [
    {"id": 7, "created_at": 1737540000.12, "filename": "patch.diff",
     "text_length": 12, "risk_level": "critical", "max_depth": 1,
     "error_count": 1, "control_count": 1}
  ]
}
```

`risk_level` 取值：`info | low | medium | high | critical`。

### `GET /api/v1/audits/{id}` — 单条详情

返回摘要、原始文本 `raw_text` 和完整解析结果 `result`。

### `GET /api/v1/audits/{id}/verify` — 重算校验

用记录中保存的 `raw_text` **重新运行 bidi 解析**，与已存储的 `result` 逐字段比较，
用于检测存储结果是否被篡改、损坏或与当前解析器版本产生漂移。接口**只读**：
只报告差异，绝不修复或改写记录。

```bash
curl -s http://localhost:8000/api/v1/audits/1/verify | jq
```

响应（存储结果被篡改过的示例）：

```json
{
  "id": 1,
  "consistent": false,
  "diff_count": 2,
  "diffs": [
    {
      "path": "/controls/0/logical_index",
      "stored": 5,
      "recomputed": 1,
      "stored_present": true,
      "recomputed_present": true
    },
    {
      "path": "/stats/orphan_closers",
      "stored": null,
      "recomputed": 0,
      "stored_present": false,
      "recomputed_present": true
    }
  ]
}
```

说明：

- `consistent` 为 `true` 且 `diffs` 为空数组表示重算结果与存储结果完全一致。
- 每条差异的 `path` 是 [RFC 6901](https://datatracker.ietf.org/doc/html/rfc6901)
  JSON Pointer，数组元素定位到下标（如 `/controls/0/logical_index`、
  `/errors/2`）；`diffs` 按 JSON Pointer 字符串排序。
- `stored` / `recomputed` 分别是保存值与重算值；`stored_present` /
  `recomputed_present` 标记该侧字段是否存在——字段缺失时对应值为 `null` 且
  `present` 为 `false`，与「字段存在但值为 `null`」（`present` 为 `true`）区分开。
- 数组长度不一致时，多出的元素按自身下标逐条报告，缺失一侧
  `present` 为 `false`。

错误情况：记录不存在返回 `404`（`{"detail": "audit record not found"}`）。

### `GET /api/v1/audits/{id}/sarif` — 导出 SARIF 2.1.0

把**已存储**的审计转换为 [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) JSON（`Content-Type: application/sarif+json`），可直接导入 GitHub code scanning、Azure DevOps、Mend 等支持 SARIF 的代码扫描平台。

- 为每个**控制符错误**（未闭合开启符、孤立 PDF/PDI、嵌套深度超限）生成一条 result，定位到该控制符本身；
- 为每个**危险区段**（RLO/LRO 覆盖范围、未闭合区段）生成一条 result，定位到整个 `[start, end)` 区段；
- 每条 result 的 `level` 由其 `risk` 映射：`critical/high → error`、`medium → warning`、`low/info → note`（规则 `defaultConfiguration.level` 与 `properties.security-severity` 同步设置）；
- `region` 的行列均为 1 起始，**列按 UTF-16 码元逐行计算**（SARIF 规范要求），使用存储的原文重算，含 astral 字符（如 emoji，占 2 个 UTF-16 码元）时列号正确偏移；跨多行的区段同时给出 `startLine/endLine`；
- location 的 `artifactLocation.uri` 取记录中的 `filename`；缺失文件名时回退为 `audit-{id}`；
- 每条 result 带稳定 `partialFingerprints`：对「规则 id | 码点 | 起止码点范围」取 SHA-256，**不含数据库行 id**，因此同一内容重复审计产生相同指纹，便于平台做去重/回归匹配；
- `rules` 去重并按 id 排序，`results` 按（起始行、起始列、规则 id）排序，输出完全确定。

```bash
curl -s http://localhost:8000/api/v1/audits/1/sarif -o bidi-audit.sarif
```

响应（节选）：

```json
{
  "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "bidi-audit", "version": "1.0.0",
                        "semanticVersion": "1.0.0",
                        "rules": [
      {"id": "bidi/span-RLO", "name": "DangerousRLOSpan",
       "shortDescription": {"text": "Dangerous RLO bidirectional scope (U+202E)"},
       "defaultConfiguration": {"level": "error"},
       "properties": {"tags": ["security", "unicode", "bidi",
                               "dangerous-span", "override"],
                      "security-severity": "high"}}
    ]}},
    "invocations": [{"executionSuccessful": true}],
    "results": [{
      "ruleId": "bidi/span-RLO",
      "level": "error",
      "message": {"text": "RLO override forces visual reordering of enclosed characters"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "patch.diff"},
        "region": {"startLine": 1, "startColumn": 2,
                   "endLine": 1, "endColumn": 10,
                   "snippet": {"text": "⟨RLO⟩evil.exe"}}}}],
      "partialFingerprints": {
        "bidi-audit/v1/sha256": "…sha256(rule|codepoint|start|end)…"
      }
    }]
  }]
}
```

规则 id 一览：

| ruleId | 触发条件 | 默认 level |
|---|---|---|
| `bidi/unclosed-{LRE,RLE,LRO,RLO,LRI,RLI,FSI}` | 开启符到文本结束未闭合（RLO/LRO 为 critical） | error / warning |
| `bidi/orphan-PDF` / `bidi/orphan-PDI` | 孤立闭合符，找不到对应开启符 | warning |
| `bidi/nesting-depth-limit` | 显式嵌套深度超过 125 上限（BD13） | error |
| `bidi/span-{opener}` | 危险区段（覆盖范围或未闭合区段，opener 为 RLO/LRO/LRE…） | error（RLO/LRO）/ warning |

错误情况：记录不存在返回 `404`（`{"detail": "audit record not found"}`）。清洁文本（无错误、无危险区段）导出的文档 `results` 与 `rules` 均为空数组，是合法的 SARIF「零发现」报告。

Docker 方式导出（服务在容器 8000 端口运行）：

```bash
# 宿主机直接请求并落盘
docker compose up -d --build
curl -s http://localhost:8000/api/v1/audits/1/sarif -o bidi-audit.sarif

# 或在容器内请求（与 compare 一节相同的方式）
docker compose exec bidi-audit python -c "
import json, urllib.request
doc = json.load(urllib.request.urlopen(
    'http://127.0.0.1:8000/api/v1/audits/1/sarif'))
print(json.dumps(doc, ensure_ascii=False, indent=2))
" > bidi-audit.sarif

# 仅用 docker run 时（参见上文“仅用 Docker”），把请求指向映射的 8000 端口：
docker run --rm --network host curlimages/curl \
    -s http://localhost:8000/api/v1/audits/1/sarif -o bidi-audit.sarif
```

把 `bidi-audit.sarif` 上传到代码扫描平台即可，例如 GitHub Actions：

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bidi-audit.sarif
```

> 提交审计时若带上仓库内相对路径作为 `filename`（如 `src/patch.diff`），SARIF location 的 `uri` 会与仓库路径一致，平台可直接在对应文件行内展示告警。

### `POST /api/v1/audits/compare` — 结果回归比较

把两条**已存储**的审计记录作为 before / after 做回归比较。控制符按
**缩写 + 出现次序**配对（例如 before 的第 2 个 RLO 对 after 的第 2 个 RLO），
多出来的出现次数分别计入新增 / 消失。

请求体：

```json
{
  "before_id": 7,
  "after_id": 12
}
```

Docker Compose 启动后直接调用（先 `docker compose up --build`）：

```bash
curl -s -X POST http://localhost:8000/api/v1/audits/compare \
  -H 'Content-Type: application/json' \
  -d '{"before_id": 7, "after_id": 12}' | jq
```

响应（节选）：

```json
{
  "before_id": 7,
  "after_id": 12,
  "changed": true,
  "risk": {
    "before": "high",
    "after": "critical",
    "changed": true,
    "direction": "escalated",
    "order_delta": 1
  },
  "error_count": {"before": 0, "after": 1, "changed": true, "delta": 1},
  "control_changes": {
    "added": [
      {
        "abbreviation": "PDF",
        "occurrence": 1,
        "control": {
          "codepoint": "U+202C",
          "abbreviation": "PDF",
          "logical_index": 8,
          "position": {"line": 1, "column": 9},
          "scope_end": null,
          "paired_with": "U+202E",
          "is_orphan": false
        }
      }
    ],
    "removed": [],
    "position_changed": [
      {
        "abbreviation": "RLO",
        "occurrence": 1,
        "logical_index": {"before": 3, "after": 1, "delta": -2},
        "position": {"before": {"line": 1, "column": 4},
                     "after": {"line": 1, "column": 2}},
        "before": {"codepoint": "U+202E", "logical_index": 3},
        "after": {"codepoint": "U+202E", "logical_index": 1}
      }
    ],
    "pairing_changed": [
      {
        "abbreviation": "RLO",
        "occurrence": 1,
        "scope_end": {"before": 10, "after": 12},
        "scope_length": {"before": 7, "after": 11},
        "paired_with": {"before": "U+202C", "after": null},
        "is_orphan": {"before": false, "after": true}
      }
    ]
  },
  "summary": {
    "before": {"id": 7, "created_at": 1737540000.12, "filename": "patch.diff",
               "text_length": 12, "risk_level": "high", "max_depth": 1,
               "error_count": 0, "control_count": 2},
    "after": {"id": 12, "created_at": 1737626400.34, "filename": "patch.diff",
              "text_length": 13, "risk_level": "critical", "max_depth": 1,
              "error_count": 1, "control_count": 2}
  }
}
```

注：上例中 `before` / `after` 子对象是对应控制符的完整信息
（与 `GET /api/v1/audits/{id}` 中 `result.controls[]` 同构，仅多一个
`occurrence` 字段），节选展示时省略了其余字段。

比较规则：

- `control_changes.added` / `removed` — 在某一侧多出来的控制符出现（含该缩写下的第几次出现，
  以及完整控制符信息），按文档逻辑顺序排列。
- `position_changed` — 配对两侧的同一出现，但 `logical_index` 不同（含行列与位移 `delta`）。
- `pairing_changed` — 配对两侧的同一出现，但 `paired_with`（配对对象）、`is_orphan`（孤立状态）
  或影响跨度长度 `scope_length = scope_end - logical_index` 发生变化。整对控制符整体平移时
  跨度不变，只会出现在 `position_changed` 中。
- `risk.direction` 为 `escalated` / `de-escalated` / `unchanged`，`order_delta` 为风险级序差。
- `summary.before` / `summary.after` 返回两侧记录的持久化摘要（id、创建时间、文件名、
  文本长度、风险级别、最大深度、错误数、控制符数）。
- 任一项不同则顶层 `changed` 为 `true`；两条记录的解析结果完全一致时为 `false`。

错误情况：

| 状态码 | 条件 |
|---|---|
| `404` | `before_id` 或 `after_id` 指向的记录不存在（detail 标明是哪一侧） |
| `422` | 两个 ID 相同，或请求体字段缺失 / 非法 |

在容器内执行（服务已在容器 8000 端口运行）：

```bash
docker compose exec bidi-audit python -c "
import json, urllib.request
req = urllib.request.Request(
    'http://127.0.0.1:8000/api/v1/audits/compare',
    data=json.dumps({'before_id': 7, 'after_id': 12}).encode(),
    headers={'Content-Type': 'application/json'})
print(json.dumps(json.load(urllib.request.urlopen(req)), ensure_ascii=False, indent=2))
"
```

### 其他

- `GET /health` — 健康检查（容器 HEALTHCHECK 使用）
- `GET /docs` / `/openapi.json` — Swagger UI 与 OpenAPI 模式

## 项目结构

```
.
├── app/
│   ├── __init__.py
│   ├── bidi.py        # UAX#9 控制符解析、配对栈、风险评级、转义预览
│   ├── diff_audit.py  # unified diff 解析（多文件/多 hunk/No-newline）+ 新增内容回映射
│   ├── compare.py     # 两条已存审计记录的回归比较（按缩写+出现次序配对）
│   ├── verify.py      # 重算校验：从原文重新解析并与存储结果逐字段 diff
│   ├── sarif.py       # 已存审计 -> SARIF 2.1.0（rule/result、UTF-16 列、指纹）
│   ├── database.py    # SQLite schema / CRUD / 查询（含可选 meta_json）
│   ├── schemas.py     # Pydantic 请求模型
│   ├── main.py        # FastAPI 路由
│   └── init_db.py     # 独立初始化入口（容器启动调用）
├── tests/
│   ├── conftest.py    # 共享的临时 DB / TestClient fixture
│   ├── test_bidi.py   # 解析器单元测试 + API 冒烟测试
│   ├── test_diff_audit.py # unified diff 审计（解析/回映射/422/落库）
│   ├── test_compare.py # 回归比较接口测试（新增/消失/位移/配对范围/404/422）
│   ├── test_verify.py  # 重算校验接口测试（一致/篡改/缺失 vs null/只读/404）
│   └── test_sarif.py  # SARIF 导出测试（level 映射/UTF-16 列/指纹/排序/404）
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── run.sh             # 本地启动脚本
└── README.md
```

## 测试

```bash
pip install pytest httpx
python -m pytest tests/ -q
```

覆盖：清洁文本、RLO 高风险、未闭合 RLO critical、LRE/PDF 配对、孤立 PDF/PDI、
LRI/PDI 隔离配对、隔离内嵌入隐式关闭、PDF 跳过隔离层（X9）、行列定位、
嵌套深度、转义预览，以及 API 的创建/详情/过滤/404；比较接口覆盖相同结果、
新增/消失、仅位置平移、配对范围变化（孤立/配对对象/跨度）、按缩写与出现次序
配对、标记配对、风险升级与错误数、以及 404 / 422 错误分支；重算校验接口覆盖
一致记录、标量/嵌套字段/数组元素篡改定位、缺失键与 null 的区分、数组长度
不一致、差异按 JSON Pointer 排序、只读性（校验不改写记录、结果幂等）与 404；
SARIF 导出覆盖
SARIF 信封与工具元数据、清洁/仅标记零发现、文件名与 `audit-{id}` 回退、
risk→level 映射（error/warning）、未闭合/平衡/孤立/隐式终止各类 rule/result、
astral 字符与跨行区段的 UTF-16 列、规则去重排序、结果确定性排序、
partialFingerprints 的稳定性与随范围/规则变化、重复审计同指纹、以及 404；
unified diff 审计覆盖多文件/多 hunk 解析、仅分析新增行（删除行与上下文行被忽略）、
按新文件行号推进与列映射、diff 行/列映射与逻辑索引保留、未闭合/孤立/隐式终止错误
与跨行危险区段回映射、每文件一条记录与汇总最高风险、No-newline 标记（行末/行中）、
CRLF、git 前缀与引号路径、重命名/删除/新增/空文件、`Binary files` 与
`GIT binary patch` 段跳过、记录 `meta` 可取回且 verify 仍一致、以及 422 分支
（空/垃圾输入、hunk 头畸形、缺文件头、体行首非法、标记非法/悬空、头部无 hunk、
hunk 行数越界指向首个越界行、截断指向 hunk 头、错误落在后续文件时全行不落库）。

## 设计说明

- 审计只做**检测与呈现**，绝不返回"净化后"的文本，避免调用方误以为原文可安全渲染；
  需要人工复核时使用 `escaped_preview`。
- 控制符使用显式 Unicode 占位符（`⟨RLO⟩`）而非 `‮` 转义，使预览在终端/日志中一眼可见。
- SQLite 通过 WAL 友好的单文件方式持久化，位置由环境变量 `BIDI_DB_PATH` 控制。
