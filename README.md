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

### 5. 包含证明

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

任一条证明失败（`422`，其余结构性输入错误为 `400/413`）：

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
| 400 | `BAD_PROOF` | 证明结构错误（side 非法、兄弟长度不对） |
| 413 | `PAYLOAD_TOO_LARGE` | 请求体超过 `MAX_BODY_BYTES` |
| 422 | `ROOT_MISMATCH` | 证明有效但重算根 ≠ 提交根（路径/值/兄弟/根被篡改） |

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
```

## 本地开发与测试（不使用 Docker）

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q          # 35 个测试
python3 -m uvicorn app.main:app --reload --port 8000
```

## 项目结构

```
app/
  main.py        # FastAPI 路由：/commit、/verify、错误处理
  tree.py        # 叶展开、叶哈希/节点哈希、排序建树、证明生成与校验
  pointers.py    # RFC 6901 指针解析与寻址
  canonical.py   # 规范 JSON 序列化
  jsonio.py      # 严格 JSON 解析（拒绝重复键、错误定位）
  validation.py  # 提交值校验（非有限数、非 JSON 类型等）
  errors.py      # 带 code/loc 的 API 错误类型
tests/           # 哈希/树单元测试 + API 端到端（含全部篡改场景）
Dockerfile
docker-entrypoint.sh   # 启动时安装依赖并启动 uvicorn
docker-compose.yml
requirements.txt
```
