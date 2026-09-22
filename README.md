# 选择性 JSON 事实披露服务（Selective JSON Disclosure）

提交一份嵌套 JSON 文档，服务会把所有 **叶事实**（标量、`null`、空对象 `{}`、空数组 `[]`）
按 [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) 路径展开，用「长度前缀 + 路径 +
规范 JSON 值」计算每个叶哈希，按路径排序构建可复现的 Merkle 根。之后可以只披露其中任意
若干条事实，并附带 Merkle 包含证明；验证方**完全不需要原始文档**，仅凭「根 + 所选值 +
证明」即可校验，且任何对路径、值或兄弟哈希的篡改都会导致根不匹配，错误带有精确定位。

## 一条命令启动

```bash
docker compose up --build
```

启动时容器内会自动执行 `pip install -r requirements.txt`（**依赖随启动安装**），
随后在 `0.0.0.0:8000` 启动 uvicorn。

- API 地址与端口：<http://localhost:8000>（容器内固定监听 `8000`）
- 交互式文档（Swagger UI）：<http://localhost:8000/docs>
- 健康检查：<http://localhost:8000/healthz>

如需改用宿主机其他端口：

```bash
HOST_PORT=9000 docker compose up --build      # => http://localhost:9000
```

停止：`Ctrl+C` 或 `docker compose down`。

## 必要配置

所有配置通过环境变量提供，均为可选项：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `HOST_PORT`（仅 Compose） | `8000` | 宿主机发布端口，容器内始终是 `8000` |
| `APP_HOST` | `0.0.0.0` | uvicorn 监听地址 |
| `APP_PORT` | `8000` | uvicorn 监听端口 |
| `MAX_BODY_BYTES` | `10485760`（10 MiB） | 请求体大小上限，超限返回 `413` |
| `DEFAULT_PROOF_MODE` | `standard` | `/commit` 未显式传 `proofMode` 时的默认格式，可选 `standard` / `compact` |
| `SKIP_PIP_INSTALL` | `0` | 设为 `1` 可跳过启动时的依赖安装 |
| `REQUIREMENTS_FILE` | `/app/requirements.txt` | 启动时安装的依赖清单路径 |

可复制 `.env.example` 为 `.env` 后按需修改。

## 密码学构造（完整规范）

哈希算法：**SHA-256**（32 字节），输出均以小写十六进制（64 字符）传输。

### 1. 叶展开

- 标量（字符串、数字、布尔、`null`）是叶子；
- 空对象 `{}` 与空数组 `[]` 也是叶子；
- 非空对象/数组递归展开，不出现在叶子集合中；
- 每个叶子的路径是 RFC 6901 指针字符串（如 `/subject/age`、`/a/0`、
  根标量为 `""`；键中的 `~` 编码为 `~0`、`/` 编码为 `~1`）。

### 2. 规范 JSON 值

同一逻辑值必须有唯一字节表示，采用如下规范形式：

- UTF-8 编码、无多余空白；
- 对象成员按键名的 Unicode 码点序排列（递归）；
- 整数最短十进制；浮点使用最短往返表示（Python `repr`）；
  拒绝 `NaN` / `Infinity`（不是合法 JSON 值）；
- 字符串仅做必要转义（`"`、`\`、控制字符，及 `\b \f \n \r \t`）；
- 空容器的规范值就是 `{}` 或 `[]`。

### 3. 叶哈希（长度前缀编码）

```
leaf_digest = SHA256(
    0x00                                  # 叶子域分隔标签
 || u32be(len(pointer_utf8)) || pointer_utf8
 || u32be(len(canonical_value_utf8)) || canonical_value_utf8
)
```

长度均为 4 字节大端无符号整数。标签 `0x00`/`0x01` 做域分隔，
防止叶子与内部节点作为哈希原像互相混淆。

### 4. 可复现 Merkle 根

1. 全部叶哈希按**路径字符串排序**（Unicode 码点序）；
2. 自左向右两两配对：`parent = SHA256(0x01 || left || right)`；
3. 某层节点数为**奇数时复制末节点**再配对（如 3 个叶子 →
   `H(L0,L1)` 与 `H(L2,L2)`，再向上配对）；
4. 恰有一个叶子时，根即为该叶哈希本身（不存在配对层）；
5. 根只取决于文档内容，与披露哪些路径无关（同一文档两次提交根相同）。

### 5. 包含证明（标准格式）

每个被披露叶子附带从叶到根的兄弟节点序列，每步为
`{"side": "left"|"right", "sibling": "<hex32>"}`：

- `side="right"`：`h = H(h, sibling)`；
- `side="left"`：`h = H(sibling, h)`；
- 单叶树证明为空数组 `[]`。

验证时由「提交的路径 + 提交的值」**重新计算叶哈希**，再按证明逐层折叠，
与提交的根比较。因此：

- 篡改**值** → 叶哈希变 → 根不匹配；
- 篡改**路径** → 叶哈希变（路径在原像中）→ 根不匹配；
- 篡改/替换任意**兄弟哈希**或其方向 → 折叠结果变 → 根不匹配；
- 篡改**根** → 与重算结果不相等。

验证接口不接收也无法接触原始文档。

### 6. 紧凑多叶证明（`proofMode: "compact"`）

多路径披露时，标准格式会在各叶的 `proof` 里**重复携带相同的上层兄弟节点**
（相邻叶子还会把彼此当作 level 0 的兄弟）。紧凑格式把每个非披露树节点
按其树坐标**全局唯一化**：

- `/commit` 请求加 `"proofMode": "compact"`；
- 响应顶层给出 `leafCount`（建树时的叶子总数，验证方据此知道每层宽度）；
- 每个被披露叶只有 `{"path", "index", "value"}`，`index` 是该叶在
  **按路径排序后的叶集合中的下标**（即建树下标）；
- 兄弟节点集中放在顶层 `proofNodes`，每项
  `{"level": <int>, "index": <int>, "hash": "<hex32>"}`，
  以 `(level, index)` 唯一标识并按 level、再按 index 排序；
  **同一节点只出现一次**，不再为各叶重复；
- `level` 从叶层起算为 0；根所在的最后一层不会出现在 `proofNodes` 中；
- 奇数层末节点与自身配对（`H(L,L)`），该节点**不需要**也**不允许**
  出现在 `proofNodes`；
- 披露全部叶子时 `proofNodes` 为空数组；单叶文档同样为空。

验证方仅凭「根 + 披露值 + 紧凑证明」**自底向上**重建根：每层已知节点
（披露叶、proof 节点、或由两个已知子节点折出的父节点）两两配对，
奇数层复制末节点，逐层向上直到根。结构校验失败返回 `400 BAD_PROOF` 并带
精确 `loc`：

| 结构错误 | `loc` 示例 |
| --- | --- |
| 叶下标越界 / 重复 | `leaves[1].index` |
| 节点层级越界（含给出根层） | `proofNodes[2].level` |
| 节点层内下标越界 | `proofNodes[2].index` |
| 奇数层末节点被携带 | `proofNodes[2]` |
| 节点与披露叶重合 | `proofNodes[2]` |
| `(level,index)` 重复 | `proofNodes[2]` |
| 缺少必需节点 | `proofNodes`（`detail.missing` 列出全部缺失项） |
| 携带多余节点 | `proofNodes[2]`（`detail.extraneous` 列出全部多余项） |
| 哈希不是 64 位十六进制 | `proofNodes[0].hash` |

结构合法但折叠出的根 ≠ 提交根（篡改路径、值或节点哈希）仍返回
`422 ROOT_MISMATCH`。`/verify` 根据请求体**自动识别**两种格式：
含 `proofNodes`/`leafCount` 即为紧凑格式，否则按标准格式逐叶验证。

## API

所有请求/响应均为 JSON。错误响应统一形如：

```json
{ "error": { "code": "ERROR_CODE", "message": "…", "loc": "leaves[0].proof[1].sibling" } }
```

`loc` 指向出错字段（含数组下标），用于定位篡改或非法输入；部分错误还带 `detail`。

### `POST /commit` — 提交并生成证明

请求：

```json
{
  "document": {
    "subject": { "name": "Ada", "age": 36, "isAdult": true, "nickname": null },
    "emails": ["ada@example.com", "ada@analytical.engine"],
    "empty": {},
    "deep": { "a/b": { "tilde~key": [7] } }
  },
  "reveal": ["/subject/age", "/emails/1", "/empty", "/deep/a~1b/tilde~0key/0"]
}
```

响应（**仅含所选值及证明**，不会回显文档其他部分）：

```json
{
  "root": "9f0c…（64 位十六进制）",
  "leaves": [
    { "path": "/deep/a~1b/tilde~0key/0", "value": 7,
      "proof": [ {"side": "right", "sibling": "…"}, … ] },
    { "path": "/emails/1", "value": "ada@analytical.engine", "proof": [ … ] },
    { "path": "/empty", "value": {}, "proof": [ … ] },
    { "path": "/subject/age", "value": 36, "proof": [ … ] }
  ]
}
```

不带 `proofMode`（或显式 `"standard"`）时响应保持上述形状不变。

#### 紧凑模式（`"proofMode": "compact"`）

请求：

```json
{
  "document": {
    "subject": { "name": "Ada", "age": 36, "isAdult": true, "nickname": null },
    "emails": ["ada@example.com", "ada@analytical.engine"],
    "empty": {}
  },
  "reveal": ["/subject/age", "/emails/1", "/empty"],
  "proofMode": "compact"
}
```

响应（7 个叶子按路径排序；兄弟节点按 `(level,index)` 去重后只有 2 个，
标准格式需要 3×若干步）：

```json
{
  "root": "f066f677ef752e68f8924da8a10ba44b2beb5a4e3ff9793e20cd38c3a3120607",
  "proofMode": "compact",
  "leafCount": 7,
  "leaves": [
    { "path": "/emails/1", "index": 1, "value": "ada@analytical.engine" },
    { "path": "/empty", "index": 2, "value": {} },
    { "path": "/subject/age", "index": 3, "value": 36 }
  ],
  "proofNodes": [
    { "level": 0, "index": 0,
      "hash": "10854943caa6ff2053c8e3c9c9b183b632d3a8fd04cbe94a1f518bdb5d2ab6b9" },
    { "level": 2, "index": 1,
      "hash": "a3a2a836c671f329a313d7f9493639bc7689d2bc3a2892be6f14c3657a1223e0" }
  ]
}
```

紧凑证明直接原样发给 `/verify`（不需要 `proofMode` 字段，服务自动识别）。

### `POST /verify` — 无原文校验

请求体只需提交方给你的根与所选披露：

```json
{
  "root": "9f0c…",
  "leaves": [
    { "path": "/subject/age", "value": 36,
      "proof": [ {"side": "left", "sibling": "…"} ] }
  ]
}
```

成功（`200`）：

```json
{ "valid": true, "root": "9f0c…",
  "leaves": [ {"path": "/subject/age", "value": 36} ] }
```

紧凑格式的 `/verify` 请求体即 `/commit` 紧凑响应去掉 `proofMode`
（保留 `root`、`leafCount`、`leaves`、`proofNodes`），成功时响应多一个
`"proofMode": "compact"`：

```json
{
  "root": "f066f677ef752e68f8924da8a10ba44b2beb5a4e3ff9793e20cd38c3a3120607",
  "leafCount": 7,
  "leaves": [
    { "path": "/emails/1", "index": 1, "value": "ada@analytical.engine" },
    { "path": "/empty", "index": 2, "value": {} },
    { "path": "/subject/age", "index": 3, "value": 36 }
  ],
  "proofNodes": [
    { "level": 0, "index": 0, "hash": "108549…b9" },
    { "level": 2, "index": 1, "hash": "a3a2a8…e0" }
  ]
}
```

紧凑证明的**结构错误**（缺节点、多节点、下标越界/重复、奇数层末节点等）
是 `400 BAD_PROOF`，例如漏掉一个必需节点：

```json
{ "error": {
    "code": "BAD_PROOF",
    "message": "compact proof is missing the required sibling node at level 0, index 3 …",
    "loc": "proofNodes",
    "detail": { "missing": [ {"level": 0, "index": 3} ] }
} }
```

任一条证明内容失败（`422`，其余结构性输入错误为 `400/413`）：

```json
{ "error": {
    "code": "ROOT_MISMATCH",
    "message": "proof for path '/subject/age' failed: recomputed root does not match …",
    "loc": "leaves[0]",
    "detail": { "path": "/subject/age", "committedRoot": "…",
                "hint": "the path, the value, a sibling hash or the root was tampered with" }
} }
```

### 错误码一览

| HTTP | code | 触发场景（示例） |
| --- | --- | --- |
| 400 | `INVALID_JSON` | 请求体不是合法 JSON、含重复对象键 |
| 400 | `INVALID_REQUEST` | 缺字段、类型错误 |
| 400 | `POINTER_SYNTAX` | 指针非法（如尾随 `~`、不以 `/` 开头） |
| 400 | `PATH_NOT_FOUND` | 文档中不存在该路径（含数组越界） |
| 400 | `PATH_NOT_LEAF` | 路径是非空容器；`detail.leafChildren` 给出可选的叶路径 |
| 400 | `DUPLICATE_PATH` | 同一指针重复提交 |
| 400 | `EMPTY_REVEAL` | 披露列表为空 |
| 400 | `UNSUPPORTED_VALUE` | `NaN`/`Infinity`、孤立代理项等 |
| 400 | `BAD_HASH_ENCODING` | 根或兄弟哈希不是 64 位十六进制 |
| 400 | `BAD_PROOF` | 证明结构错误：标准格式 side 非法、兄弟长度不对；紧凑格式叶/节点下标越界或重复、节点缺失或多余、携带奇数层末节点等（均有精确 `loc`） |
| 413 | `PAYLOAD_TOO_LARGE` | 请求体超过 `MAX_BODY_BYTES` |
| 422 | `ROOT_MISMATCH` | 证明有效但重算根 ≠ 提交根（路径/值/兄弟/节点哈希/根被篡改） |

### 其他

- `GET /healthz` → `{"status":"ok"}`
- `GET /` → 服务与端点元信息
- `GET /docs` / `GET /openapi.json` → OpenAPI 文档

## 快速试用

```bash
# 1) 提交文档，只披露 /subject/age
curl -s localhost:8000/commit -H 'content-type: application/json' -d '{
  "document": {"subject": {"name": "Ada", "age": 36}, "emails": ["a@x", "b@y"]},
  "reveal": ["/subject/age"]
}' | tee /tmp/commit.json

# 2) 用返回的 root + leaves 验证（不提交 document）
curl -s localhost:8000/verify -H 'content-type: application/json' \
  -d "{\"root\": $(jq .root /tmp/commit.json), \"leaves\": $(jq .leaves /tmp/commit.json)}"

# 3) 把值改成 37 再验证 → 422 ROOT_MISMATCH，loc=leaves[0]

# 4) 紧凑多叶证明：加 "proofMode": "compact"，返回 leafCount、
#    每个叶的 index，以及按 (level,index) 去重的 proofNodes
curl -s localhost:8000/commit -H 'content-type: application/json' -d '{
  "document": {"subject": {"name": "Ada", "age": 36}, "emails": ["a@x", "b@y"]},
  "reveal": ["/subject/name", "/subject/age"],
  "proofMode": "compact"
}'
# /verify 自动识别紧凑格式：把紧凑响应的 root/leafCount/leaves/proofNodes
# 原样回传即可（无需携带 document 或 proofMode）。
```

## 本地开发与测试（不使用 Docker）

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q          # 69 个测试
python3 -m uvicorn app.main:app --reload --port 8000
```

## 项目结构

```
app/
  main.py        # FastAPI 路由：/commit、/verify、错误处理
  tree.py        # 叶展开、叶哈希/节点哈希、排序建树、标准与紧凑证明
  pointers.py    # RFC 6901 指针解析与寻址
  canonical.py   # 规范 JSON 序列化
  jsonio.py      # 严格 JSON 解析（拒绝重复键、错误定位）
  validation.py  # 提交值校验（非有限数、非 JSON 类型等）
  openapi.py     # 两种证明格式的 OpenAPI 模型与文档合并
  errors.py      # 带 code/loc 的 API 错误类型
tests/           # 哈希/树单元测试 + API 端到端（含全部篡改、去重与结构错误场景）
Dockerfile
docker-entrypoint.sh   # 启动时安装依赖并启动 uvicorn
docker-compose.yml
requirements.txt
```
