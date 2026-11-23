# ADR-0001　MCP Infrastructure 的设计

| 项 | 内容 |
|---|---|
| 状态 | 草案（2026-11-02），待决策人确认 |
| 范围 | `idp-mcp`：MCP 网关（数据面）与注册服务（控制面） |
| 依据 | 决策人 2026-11-02 的选择：先做 MCP；自研数据面；工程结构按《IDP TELOS Repository & Engineering Architecture v1.0》 |
| 参考 | MCP 规范 2026-07-28；《IDP TELOS System Architecture v1.0》 |

## 1. 背景

MCP 基础设施把模型可调用的工具目录、认证授权和调用审计集中到网关上。设计前先排除"外置网关产品 + 自写边界服务"这类常见方案的已知弱点：

- 两跳数据面：网关产品往往不能只绑定回环地址，要靠私有 netns、socket 中继之类的网络隔离补偿。
- 授权规则要先编译成网关产品的表达式语言才能执行；拒绝的语义只能事后从返回形态推断。
- 网关直接透传上游的 `tools/list`：审批之后上游如果改了工具描述（rug pull），网关看不到。
- SSRF 检查只在注册时做，网关连接上游时会重新解析 DNS。
- 多租户只靠应用层过滤，没有数据库层的隔离。

## 2. 决策

| # | 决策 | 理由 |
|---|---|---|
| D1 | **自研 Go 数据面**：准入、认证、授权、联邦、调用审计都在 `mcp-gateway` 一个进程内完成，单跳 | 去掉 agentgateway 带来的绑定、配置渲染和拒绝语义问题；代价是协议符合性（官方 37 项）要重新挣，放在第二阶段的门禁里 |
| D2 | **控制面与数据面通过不可变 Release 交互**：注册服务把已批准的内容编译成 Release（规范化 JSON + SHA-256）；网关拉取期望状态，或者读本地文件（离线、本地部署） | 网关不连数据库；Release 可以审计、回滚、离线分发 |
| D3 | **工具目录钉在 Release 里**：网关的 `tools/list` 直接用 Release 中审批过的工具定义，不透传上游。网关定期比对上游的实时目录摘要，出现漂移就默认封锁该目标 | 防止审批后上游篡改工具描述或参数结构 |
| D4 | **网关自证运行态**：网关心跳上报正在运行的 Release 摘要和各目标的漂移状态。注册服务据此判定 GOOD/FAILED，失败时自动把期望状态退回上一个 GOOD | 网关不暴露管理端口，运行态只能由它自己上报 |
| D5 | **授权原生执行**：Release 中的授权（租户 + 角色 + 工具）由网关直接判定；`tools/list` 按调用者过滤；未授权的调用与不存在的工具返回完全相同的错误 | 不依赖网关产品的表达式语言；防止枚举工具目录 |
| D6 | **一个网关实例只服务一个租户**：网关记录属于某个租户，Release 属于某个网关 | 隔离简单清楚；SaaS 部署按租户起多个实例 |
| D7 | **对外工具名为 `<target>__<tool>`**：target 只允许 `[a-z0-9-]`，所以第一个 `__` 一定是分隔符 | 名字可以无歧义地拆回 (target, tool)，并且符合常见客户端对函数名字符集的限制 |
| D8 | **连接上游时再检查一次地址**：在 `net.Dialer.Control` 中检查实际连接的 IP，与注册时的 SSRF 规则相同（公网 https；dev 模式允许回环；精确主机名可以解析到私有地址；metadata、link-local、CGNAT 等一律拒绝） | 补上 DNS 重绑定的缺口。**2026-11-19 补充**：“公网”的判定改为 IANA 的 IPv4 与 IPv6 Special-Purpose Address Registry（逐项取 Globally Reachable 为 False 或 N/A 的块，再加组播、保留的 224.0.0.0/3 和已弃用的 fec0::/10），与 idp-sandbox 出口代理修掉的是同一个漏洞（idp-sandbox D22）。此前的名单放过了：0.0.0.0/8 里 0.0.0.0 以外的地址，192.0.0.0/24、192.88.99.0/24，携带 IPv4 地址的 IPv6 块（NAT64 `64:ff9b::/96` 与 `64:ff9b:1::/48`、6to4 `2002::/16`、Teredo `2001::/32`、`::/96`），以及 `100::/64`、`2001::/23`（整块）、`3fff::/20`、`5f00::/16`、`fec0::/10`；带 zone 的 IPv6 地址（`fe80::1%eth0`）也会通过，因为 `netip.Prefix.Contains` 对带 zone 的地址恒为 false，现在一律拒绝。携带 IPv4 的块整块拒绝，不看里面的 IPv4 是什么；IPv4 映射地址（`::ffff:a.b.c.d`）仍按它携带的 IPv4 判定。私网名单上的主机仍只能解析到 RFC 1918 / ULA，dev 模式下回环仍只给回环名字：这几类的区分没有变，注册时与连接时用同一个函数（`policy.Classify`）。测试：`internal/policy/addresses_test.go`（在改动前的代码上 3 个测试失败，24 个应拒绝的地址被判为公网） |
| D9 | **多租户隔离由 PostgreSQL RLS（FORCE）执行**：每个事务设置 `app.tenant_id`，所有租户表上都有策略；只有网关凭据表在租户确定之前查询，因此不加 RLS。服务以非超级用户、非 BYPASSRLS 的角色运行，启动时检查，不满足就拒绝启动；审计表和调用记录表对服务角色只授予 INSERT/SELECT | 隔离不依赖每条 SQL 都记得写租户条件。**注意：目前 RLS 是唯一的一层**，应用层 SQL 没有再写 `WHERE tenant_id`（集成测试中关闭 RLS 后，跨租户读取立即出现）；是否补应用层条件作为第二层，待定 |
| D10 | **四眼原则**：服务器审批、授权审批、Release 审批，审批人都不能是创建人 | 创建与审批分离是最低限度的制衡 |
| D11 | **调用审计不记录参数原文**：每次 `tools/call` 记录主体、目标、工具、判定、结果、耗时、trace_id，以及参数的规范化摘要；网关批量推送给注册服务 | 可以关联，又不留存业务数据 |
| D12 | **只支持 MCP 2026-07-28 modern 模式**：只接受 `POST /mcp`；`MCP-Protocol-Version` 必须是 2026-07-28；`_meta` 信封必须完整；拒绝旧握手 | 旧握手与旧传输只增加攻击面，没有业务需要。**2026-11-19 补充**（传输规范 2026-07-28 的三项硬性要求，此前未满足）：①`Mcp-Method` 在每个请求上都必须有，缺失即 400 / -32020（此前只在出现时才校验；检查过平台上所有网关的客户端都会发送它：idp-host 的 `mcpclient`、`deploy/compose/egress_check.py`、idp-sandbox 的 `tests/e2e/gateway_test.go`）；②`Mcp-Name` 可以是 Base64 形式 `=?base64?…?=`，先解码再与 `params` 比较，网关作为客户端向上游发送时，不能原样作为头值的名字（非 ASCII、控制字符、首尾空白）按此形式编码；`Mcp-Param-*` 的值网关不解释、不比较，所以没有解码的对象；③中间方必须转发不认识的 `Mcp-Param-*` 请求头：网关转发它们（且只转发它们，`Authorization`、`Cookie` 等其余客户端头仍不发给上游），数量最多 16 个、名字最长 128 字节、每个值最长 1024 字节，超出即 400 / -32020 拒绝，不截断转发 |
| D13 | **依赖尽量少**：pgx、golang-jwt，其余用标准库（JWKS 解析、迁移、规范化 JSON 都自己实现） | 供应链面小，离线构建容易 |

## 3. 第一阶段范围（M1）

**包含**
- `mcp-gateway`：modern 准入、API Key 与 JWT（JWKS、RFC 9728 资源元数据与 401 挑战）、授权、工具联邦（`tools/list` 来自 Release、`tools/call` 路由与流式透传）、本地应答 `server/discover` 与 `ping`、漂移检测、心跳、调用审计推送、连接时地址检查。
- `registry-service`：租户、服务器注册与发现快照、授权、网关与凭据、Release 编译/审批/部署/回滚、审计查询、内部接口（期望状态、心跳、调用记录）。
- PostgreSQL 迁移与 RLS；单元测试；带真实上游的集成测试。

**不包含（后续阶段）**
- resources / prompts / completion / subscriptions / tasks 的联邦。未实现的方法返回 `-32601`，因此**官方符合性套件在 M1 不会是 37/37**，这一项放在 M2 的门禁里。
- 参数级策略（Cedar/CEL）、OpenTelemetry 导出、mTLS、生产级凭据轮换、Helm 与 Kubernetes 清单。

## 4. 工程结构

仓库名按决策人 2026-11-02 的要求定为 `idp-mcp`（v1.0 文档中叫 `idp-mcp-infrastructure`），Go module 路径同为 `idp-mcp`。内部目录按 v1.0 文档中该仓库的目录树：`cmd/mcp-gateway`、`cmd/registry-service`、`internal/{gateway,client,server,registry,routing,federation,authorization,policy,transport,invocation,audit,observability}`、`adapters/`、`api/`、`migrations/`、`tests/`、`deploy/`。增加了 `internal/release`，因为 Release 是两个进程之间的核心契约；单元测试按 Go 惯例放在被测包旁边，`tests/` 只放集成和端到端测试。

## 5. 后果

- 正面：单跳数据面；工具目录防篡改；授权可读、可测；连接时检查地址；RLS 兜底；Release 可以离线分发。
- 负面：协议符合性要从零做起；自研网关要自己负责性能和协议演进。

## 6. M1 实施结果（2026-11-02，WSL 实测）

**通过**
- 单元测试：13 个包（`make test`，`-race`）。
- 集成测试（`make test-integration`，真实 PostgreSQL 17，进程内运行注册服务、网关和上游）覆盖：注册、发现、四眼审批（服务器、授权、Release）、部署后网关自证 GOOD、MCP 调用、调用审计（不存参数原文）、租户隔离（另一租户看不到数据；不设租户时 0 行；服务角色删不了审计记录；超级用户连接被拒绝）、上游篡改工具描述后被检测并封锁、带旧快照的新 Release 部署失败并自动退回、重新发现与审批后恢复。
- compose 端到端（`deploy/e2e.sh`，镜像约 27 MB，基于 scratch，非 root，只读根文件系统，丢弃全部 capability）：上游是真实的 Node SDK 服务器（minimal）和 Python SDK 的 Everything Server（28 个工具，含复杂的 JSON Schema 2020-12），**9/9**；部署到 GOOD 用时 3.8 s；宿主机只开放 3320 和 8250。
- 变异检查：分别去掉授权判定、四眼原则和 RLS，相应测试都会失败。

**实测发现并修复的问题**
- `cmd/mcp-gateway` 没有把网关实例交给同步器，一拉取就空指针崩溃。进程内测试是手工接线的，所以没发现；compose 端到端跑真实二进制时发现。
- 连接池里的连接用过事务级 `app.tenant_id` 后，这个值会变成空字符串而不是 NULL，`''::uuid` 报错。结果仍然是拒绝访问，但不是预期的返回 0 行。RLS 策略已改用 `nullif`。
- 工具目录和 Release 原来打算存成 jsonb，但 jsonb 会改写数字写法，摘要可能对不上。改为 text，原样保存规范化 JSON。
- 部署失败的判定原来依赖网关的 `LastError`，这个值可能是之前网络错误的残留。改为网关上报"最近拒绝的 Release 摘要和原因"。

**未完成（M2 及以后）**
- resources / prompts / completion / subscriptions / tasks 的联邦；官方符合性套件（37 项）作为 M2 门禁，目前未测。
- 按钉住的 `inputSchema` 校验 `tools/call` 参数；参数级策略。
- 租户隔离目前只有 RLS 一层（见 D9），是否补应用层条件待定。
- API Key 属于 Release，轮换要走一次发布；生产凭据轮换、mTLS、OpenTelemetry 导出、`api/` 下的 OpenAPI 文档、Helm 与 Kubernetes 清单。
- JWT 模式只有单元测试（真实 Keycloak 联调未做）；参数原文以外的隐私策略（例如对 subject 做假名化）未定义。

## 7. M2：prompts / resources / completion 联邦与官方符合性（2026-11-02，WSL 实测）

**新增决策**

| # | 决策 | 理由 |
|---|---|---|
| D14 | **工具命名可选 `prefixed`（默认）或 `native`**：native 直接暴露上游名字，要求所有目标之间不重名，编译 Release 时检查 | 单一上游或名字不冲突时，客户端看到的就是原名；官方套件按原名调用 |
| D15 | **工具定义完整钉住**：`icons`、`execution`、`_meta` 等网关不解释的字段也保留，并计入快照摘要 | M1 只保留已知字段，审批过的定义不完整；新增字段同样属于需要审批的内容 |
| D16 | **prompts 与 resources 实时透传，不钉住**；授权扩展为 `prompts`（名字或 `*`）和 `resources`（布尔），并且要求目标在审批时声明了对应能力 | 它们是动态内容，钉住没有意义；但谁能用必须有授权 |
| D17 | **列表请求并发拉取后合并**（按调用者的授权过滤）；单个请求按归属路由：prompt 按名字（前缀模式下名字里带目标）；resource 的 URI 不改写，按各目标的列表确定归属（先精确匹配，再匹配 URI 模板，缓存 30 秒），有歧义时一律视为不存在 | 改写 URI 会破坏客户端对 scheme 的预期 |
| D18 | **未授权的 prompt 或资源与不存在的返回完全相同**（-32602；资源的错误在 `data.uri` 中带上 URI），并且未授权的请求从不转发给上游 | 与 D5 相同：不允许借此枚举 |
| D19 | **调用审计扩展到 `prompts/get`、`resources/read`、`completion/complete`**，新增 `method` 字段 | 这些请求同样把数据交给模型 |
| D20 | **`ping` 不在本地应答**：2026-07-28 已移除 ping（SEP-2575），返回 404 与 -32601 | 官方套件实测发现：M1 在本地应答 ping，违反规范 |

**符合性测试的方法**：官方运行器（`@modelcontextprotocol/conformance` 0.2.0-alpha.12，冻结的 2026-07-28 需求，37 个服务器场景）→ 测试夹具代理 → 网关（进程内）→ Python SDK 的 Everything Server。运行器不能携带凭据，所以夹具代理代为加上数据面 API Key，其余逐字节转发：Host 和 Origin 不改，流式响应即时转发。网关走的是正常的认证与授权路径，**产品中没有免认证模式**。Release 为单一目标、native 命名，所有工具、prompts 和 resources 都授权给该 Key 的角色。计分规则：出现 FAILURE、未知状态或没有任何 SUCCESS 都不计为通过。

**结果**
- 官方符合性：**37/37**（`make conformance`，运行器退出码 0）。第一次运行是 36/37，唯一的失败就是上面的 D20。
- compose 端到端：**13/13**（新增：prompts 联邦并带前缀、`prompts/get` 路由、`resources/read` 路由、资源不存在时返回 -32602 和 `data.uri`）；注册服务拒绝在不提供 prompts 的上游上授权 prompts。
- 集成测试在迁移 0002 上通过；单元测试新增联邦测试（双上游前缀模式下的合并、过滤、路由、伪装、URI 模板归属、歧义拒绝，以及 completion 引用改写）。
- 变异检查：去掉 `prompts/get` 路由中的授权判定后，两个联邦测试失败。

**局限（不标 PASS）**
- 符合性只在单一目标、native 命名下测得。前缀模式会改名，官方场景按原名调用，所以前缀模式按设计不能通过这套测试；多目标的行为由单元测试覆盖。
- prompts 和 resources 不钉住，审批后上游修改 prompt 模板不会被漂移检测发现。
- `subscriptions/listen`、`resources/subscribe/unsubscribe`、`tasks/*`、`logging/setLevel` 尚未联邦（返回 -32601），能力声明中也相应设为 `listChanged: false` 和 `subscribe: false`。冻结的 37 个场景不涉及这些方法。
- 网关自己给出的"不存在"错误用 HTTP 200，Python SDK 上游用 HTTP 400。未授权的请求总是得到网关的答复，所以这不泄露授权信息，但两者不一致。
- JWT 模式仍未与真实 IdP 联调。

**2026-11-19 复核：重跑、进 CI、仍未覆盖的**

M6、M7 改了转发路径（调用者转发与签名）之后，官方符合性没有重跑过；2026-11-03 的结果（`build/conformance/20261103T075913Z`）是那之前的。2026-11-19 在没有改动任何代码的情况下重跑一次，再在补上下面三项传输要求（D12 的 2026-11-19 补充）后又跑一次。运行器同为 0.2.0-alpha.12。

| | 计分的 37 个场景 | 计分场景里的 WARNING | “待定”场景（不计分） |
|---|---|---|---|
| 2026-11-03 | 37/37 | 2：订阅流上没有 `tools/list_changed`、`prompts/list_changed`（SHOULD；目录钉在 Release 里，上游变目录是漂移，不是列表变化，见 D29，故意如此） | `json-schema-2020-12` 通过；`http-header-validation` 失败 2 项（缺 `Mcp-Method` 仍放行；带空白的 `Mcp-Name`），`http-custom-header-server-validation` 失败 3 项（`Mcp-Param-*` 被丢弃） |
| 2026-11-19，代码未改 | 37/37 | 同样 2 个 | 与 11-03 相同 |
| 2026-11-19，补上 D12 的三项后 | 37/37 | 同样 2 个 | `http-custom-header-server-validation` 通过；`http-header-validation` 只剩 `sep-2243-server-accepts-whitespace-header-value` 一项 |

剩下的那一项不是网关的问题：该场景取 `tools/list` 的第一个工具（Everything Server 的 `json_schema_2020_12_tool`）并以 `arguments: {}` 调用，而这个工具有必填参数，网关按钉住的参数定义返回 -32602；头里的空白网关已经正确地忽略了（HTTP 200，没有 `Mcp-Name` 的错误）。换一个没有必填参数的第一个工具，这一项就会通过。另外，运行器对 Everything Server 也会跑 tasks 扩展的场景，它没有 tasks 的夹具，这些场景按设计失败；tasks 扩展用专门的夹具另测（`tests/conformance/tasks_test.go`），直连与经网关都是 8/8。

**现在进了 CI**：`.github/workflows/ci.yml` 的 `conformance` 作业运行 `make conformance`，本地与 CI 是同一条命令。运行器与参考服务器都固定了版本，不再依赖某个人的主目录：运行器是 npm 包 `@modelcontextprotocol/conformance@0.2.0-alpha.12`（`tests/conformance/runner/package-lock.json`，`npm ci`，带完整性哈希）；参考服务器是 Python SDK 的提交 `754254c08fe1c3eda18b69da3d336106fe8d72d6`（`tests/conformance/fetch.sh`），依赖按该提交自带的 `uv.lock` 安装（`uv sync --frozen`）。`CONFORMANCE_ROOT`、`REFERENCE_SERVER` 仍可用环境变量指向自己的构建。计分的 37 个场景有 FAILURE 就让作业失败；上面那 2 个 WARNING 保持为警告；“待定”与扩展场景只打印，不影响结果；证据（每个场景的 `checks.json` 与运行器日志）作为构件上传。**没有在 GitHub Actions 上跑过这个作业**，只在本机跑通了同一条命令。

**仍然没有覆盖的**：
- 网关作为客户端去连上游的那一面（发现、列表、转发）：官方套件只测服务器一侧。
- OAuth：套件的运行器不能带凭据，测试夹具代理加了 API Key，JWT 与受保护资源元数据不在其中。
- 带前缀的工具命名（官方场景按原名调用，见上）。
- 多个目标。
- 旧版本的客户端与服务，真实的第三方服务。

## 8. M3：钉住 prompts、参数校验、与真实 Keycloak 联调（2026-11-02，WSL 实测）

**新增决策**

| # | 决策 | 理由 |
|---|---|---|
| D21 | **prompts 与工具一样钉住**：快照摘要改为 `CatalogDigest = digest({tools, prompts})`；`prompts/list` 由 Release 生成；只有钉住的 prompt 才能 `get`；漂移检测同时比对 prompts，发现漂移后对 prompt 请求同样封锁；授权中的 prompt 名必须在已审批的快照里（迁移 0003） | M2 的主要缺口：prompt 定义会影响模型，审批后被改写同样是 rug pull。prompt 渲染后的内容仍是动态的，只钉住定义 |
| D22 | **按钉住的 `inputSchema` 校验 `tools/call` 参数**（JSON Schema 2020-12，`$schema` 声明的方言优先），校验在授权之后、转发之前；不合格返回 -32602，调用记为 `DENY / INVALID_ARGUMENTS`，不会到达上游 | 审批时没看到的参数（多出来的 path、recipient）和不合格的值都不能送到上游 |
| D23 | **schema 中只有内部引用能解析**：远程和 `file:` 的 `$ref` 一律不加载（会导致编译失败）；`format` 只作注解；schema 编译不过的目录在发现阶段即被拒绝（422），网关激活 Release 时再编译一次 | schema 不能让网关去访问 URL 或读取文件；网关无法执行的 schema 不能进入审批 |
| D24 | **校验错误只报告位置和关键字**（例如 `/text: maxLength`），不回显参数值；只有已通过授权的调用者才会收到校验错误，未授权的调用者仍然只收到"未知工具" | 错误信息可以安全地返回给调用者并写入日志；也不借此泄露 schema |
| D25 | **依赖增加 `github.com/santhosh-tekuri/jsonschema/v6`**（对 D13 的有意例外） | 自己实现完整的 2020-12 校验器风险更大；该库支持 2020-12 和 draft-07，并且可以禁用外部加载 |

**Keycloak 联调方法**：compose 增加 Keycloak 26.8.1（profile `jwt`，`start-dev --import-realm`）。`deploy/keycloak/realm.py` 每次运行生成一个 realm 和随机密钥，其中有 6 个 service-account 客户端：管理员 alice（operator）、bob（reviewer）、carol（admin），受众为 `idp-mcp-registry`；以及代理身份 allowed（operator）、viewer、foreign（另一个租户），受众为网关的资源 URI。每个客户端都带固定的 `tenant_id` 和 `roles` 声明。issuer 是客户端访问的 `http://127.0.0.1:7080/realms/idp`，容器通过 `keycloak:7080` 取 JWKS（backchannel）。注册服务在这个模式下以生产方式运行，管理令牌只用 JWKS 校验。

**结果**
- 与真实 Keycloak 的 JWT 端到端（`MODE=jwt bash deploy/e2e.sh`）：**17/17**：
  - 管理 API：拒绝开发用 HS256 令牌、拒绝受众为网关的令牌；用 Keycloak 身份完成注册、四眼审批和部署（GOOD）。
  - 授权发现：匿名请求得到 401 和 `resource_metadata` 挑战；RFC 9728 资源元数据中 `authorization_servers` 为 issuer；授权服务器元数据可以发现。
  - 按身份：allowed 只看到并能调用授权的工具；viewer 和外租户的目录为空、调用被拒；受众为注册服务的令牌和被篡改的令牌得到 401；超长参数被校验拒绝；审计中记录的是 Keycloak 主体。
- API Key 模式的 compose 端到端仍为 **13/13**（Everything Server 的 5 个 prompts 由注册服务钉住）；官方符合性在钉住 prompts、开启参数校验后仍为 **37/37**；集成测试在迁移 0003 上通过。
- 新增单元测试：prompt 被篡改后列表仍返回钉住的定义、漂移被检测、`prompts/get` 被封锁、审批后新增的 prompt 无法路由；参数校验（类型、必填、长度、多余字段，`$defs/$ref`、`if/then/else`、draft-07），拒绝远程和 file 引用，错误不回显参数值，未授权者拿不到校验信息。
- 变异检查：去掉参数校验调用后，相应测试失败。
- 实测发现：Keycloak 会把导入目录中的所有 `.json` 都当作 realm 导入，客户端密钥文件因此必须放在导入目录之外。

**局限（不标 PASS）**
- 与 Keycloak 联调用的是 `start-dev`（H2、无 TLS），令牌都是 client_credentials 签发的。没有测试用户授权码流程、RFC 8693 委派换发，也没有测试 JWKS 轮换（轮换只有单元测试）。
- 参数校验不覆盖 `inputResponses` 和 `requestState`（它们由上游 SDK 校验，官方场景也是这样要求的）；`outputSchema` 不校验上游的返回。
- resources 仍是实时透传，不钉住（资源本身是数据，不是能力定义）。

## 9. M4：生产前提（2026-11-03，WSL 实测）

分支 `m4-remaining`，五次提交：OpenAPI；TLS/mTLS；`subscriptions/listen`；OpenTelemetry；tasks 扩展与 Kubernetes 清单。

**新增决策**

| # | 决策 | 理由 |
|---|---|---|
| D26 | **`api/openapi.yaml` 与路由器由测试保持一致**：`API.Routes()` 列出实际路由，测试要求文档恰好覆盖这些路由、YAML 可解析、所有 `$ref` 可解析 | 文档漂移和代码漂移一样是缺陷 |
| D27 | **网关凭据绑定到客户端证书**（`IDP_GATEWAY_CLIENT_CA_FILE`）：开启后 `/internal/v1` 要求 mTLS，证书的 URI SAN `spiffe://idp-mcp/gateway/<id>` 必须等于令牌所属的网关；管理 API 同一监听器上不要求客户端证书 | 凭据泄露后单独不可用；一个监听器同时服务两类客户端，无需第二个端口 |
| D28 | **自定义 CA 按用途分开配置**：注册服务/网关、上游 MCP 服务器、JWKS 端点、OTLP 采集器各一个；TLS 1.2 起 | 内网 https 常用私有 CA，但不应把一个 CA 信任到所有出口 |
| D29 | **`subscriptions/listen`（SEP-2575）**：首帧 `notifications/subscriptions/acknowledged` 回显网关实际承诺的过滤器；每个通知的 `_meta` 带订阅 id。`tools`/`prompts` 的列表变化由网关在**激活新 Release 时**发出（目录是钉住的，上游自己改目录是漂移，不是列表变化）；`resources` 的列表变化、资源更新和 task 通知从拥有它们的目标中继，按调用者的授权和归属过滤后重新打标。**流不超过凭据的寿命**：JWT 到期即以最终结果结束；新 Release 不再认证该调用者时也结束。每网关最多 1000 条流 | 把订阅做成联邦的同时不扩大任何权限 |
| D30 | **`ping` 之外，所有 2026-07-28 删除的方法返回 404/-32601**，包括 `resources/subscribe`、`tasks/list`、`tasks/result` | 与官方套件一致 |
| D31 | **OpenTelemetry 只用 SDK，OTLP/HTTP JSON 导出器自写**（约 150 行），不引入 gRPC 和 protobuf；W3C Trace Context 传播；每个 MCP 请求一个 server span，每次上游调用一个 client span，注册服务按路由命名 span；span 属性只有方法、工具名、目标、判定、结果，**不含参数、令牌和主体**；没有配置端点时仍生成 span（trace id 用于关联审计记录），不导出 | 供应链小；scratch 镜像仍约 27 MB；隐私边界与调用记录一致 |
| D32 | **tasks 扩展（SEP-2663 v2）按"谁创建谁可用"路由**：`tools/call` 返回 `resultType:"task"` 时网关记住 taskId → 目标、租户、主体、工具、到期时间（`ttlMs`，上限 7 天，null 记 24 小时，总数上限 10 万）；`tasks/get`/`tasks/cancel` 只对创建者路由，其他人和不存在的 id 得到完全相同的 -32602；两个目标签发同一个 id 时该 id 视为不存在（fail closed）；流式响应也会被检查（最多缓存 1 MiB）；漂移封锁不影响已创建任务的读取与取消 | task id 由上游指定、不可改写，所以归属只能由网关记录；不记录归属就会让任何人读到别人的任务结果 |
| D33 | **Kubernetes：一个网关记录一个副本**（Deployment `replicas: 1`、`Recreate`）；横向扩展等于多个网关记录；NetworkPolicy 默认拒绝，再逐条放行；清单由 `tests/deploy` 做一致性检查 | 注册服务按网关 id 保存一份自证状态，共享 id 的副本会互相覆盖心跳 |

**结果**
- 完整矩阵在最终代码上重跑：单元（`-race`）通过；集成测试通过（新增 `TestTLSEverywhere`：管理 API 经 TLS、网关与注册服务经 mTLS 且证书绑定凭据、私有 CA 的 https 上游、https 数据面）；官方符合性 **37/37**，其中 `subscriptions/listen` 的三项检查由原来"不适用"变为 SUCCESS，两项"上游列表变化应通知"的 SHOULD 检查为 WARNING（见局限）；compose 端到端 API Key 模式 **13/13**、Keycloak 模式 **17/17**。
- 变异检查：去掉内部接口的证书绑定、去掉 task 的归属判定、把清单的只读根文件系统改成可写并挪动一个挂载路径，相应测试都失败。
- 实测发现：Go 客户端不会向服务器出示 CA 不在服务器"可接受 CA 列表"里的证书，所以"外部 CA 签发的证书"这条测试要强制出示才能验证握手被拒绝；OTel 的 `trace.TraceID` 是数组类型，没有 `Bytes()`。

**局限（不标 PASS）**
- Kubernetes 清单**没有在集群上应用过**；参考主机没有集群，安装 kubeconform 这类第三方二进制也被拒绝，只做了清单之间的一致性检查（标签/选择器、Secret 与 ConfigMap 引用、`*_FILE` 设置必须落在挂载卷内、加固项、NetworkPolicy 形态）。
- 官方套件中"上游改了工具列表应通知订阅者"两项为 WARNING：网关按设计不转发上游的列表变化（那是漂移），只在激活新 Release 时通知。这是有意的偏离，不是遗漏。
- tasks 扩展没有真实上游可测：夹具中的 Everything Server 不实现该扩展，官方的 tasks 场景也属于扩展（不在冻结的 37 项内），只有自写夹具的单元测试；`notifications/tasks` 的订阅过滤键 `taskIds` 按 SDK 注释实现，套件本身标注该场景待重写。
- 一个网关记录一个副本；多副本的自证状态合并尚未设计。
- 没有指标（metrics）导出；调用记录和 span 已包含判定、结果和时延，聚合在采集器一侧完成。
- 用户授权码流程和 RFC 8693 委派换发仍只在 IdP 侧，网关只校验令牌；生产 Keycloak（TLS、用户登录）未联调。

## 10. M5：五项遗留（2026-11-03，WSL 实测）

决策人 2026-11-03 指定的五项：resources 钉住；多副本自证合并；指标导出；tasks 扩展的真实上游；身份侧（用户授权码流程、RFC 8693 委派换发、生产级 Keycloak）。

**新增决策**

| # | 决策 | 理由 |
|---|---|---|
| D34 | **resources 与资源模板钉住**：快照摘要改为 `Catalog{tools, prompts, resources, resourceTemplates}` 的摘要；`resources/list`、`resources/templates/list` 由 Release 生成；`resources/read` 只接受钉住的 URI 或匹配钉住模板的 URI（归属有歧义即视为不存在）；漂移检测覆盖资源列表，封锁同样作用于读取（迁移 0004） | 这是 M2 以来最大的安全缺口：审批后上游增减资源，网关此前看不到 |
| D35 | **多副本自证合并**：每个副本以实例 id（Pod 名，`IDP_GATEWAY_INSTANCE`，默认主机名）上报；注册服务按（网关, 实例）保存状态（迁移 0005）；部署只有在**所有存活实例**（心跳在 `IDP_INSTANCE_STALE_AFTER`，默认 30 s 之内，且晚于部署开始）都运行该 Release 且目标全部 OK 时才判 GOOD；任一实例拒绝即立即失败；落后的实例在超时时被点名；静默一天的实例被遗忘。Kubernetes 清单改为 2 副本滚动更新 | 一个记录一个副本在生产里站不住；合并规则必须写死且可检验 |
| D36 | **指标用 Prometheus 文本格式，自写导出（无客户端库），在独立监听器 `IDP_METRICS_LISTEN` 上**：网关有按方法/判定/结果的决策计数、按方法的时延直方图、HTTP 按路由/状态的计数、监听流数、task 绑定数、目标健康、运行中的 Release；注册服务有按路由/状态的 HTTP 计数与部署结果计数。标签只含方法、路由模式、目标、判定、结果，**不含主体、令牌、参数、URI** | 与 D31 同一取舍：供应链小，隐私边界与审计一致；不放在数据面端口上 |
| D37 | **tasks 扩展用自写的 Go 参考服务器做真实上游**（`tests/fixtures/taskserver`，按 SEP-2663 v2 实现官方场景要求的六个工具），官方的 8 个 tasks 场景先直接打夹具、再经网关各跑一遍；网关补上 `tasks/update` 的路由和 **能力门控**（`_meta.clientCapabilities.extensions` 未声明该扩展时，任何 `tasks/*` 先得到 -32021，连查找都不做） | 没有现成实现：Python SDK 的类型文件明确"无运行时"，Node SDK 2.3.1 与 npm 最新的 2.4.0 的 dist 中都没有该扩展的服务端（已逐文件核对）；官方套件的场景说明足够精确，可以照着实现 |
| D38 | **身份侧按生产形态联调**：Keycloak 26.8.1 以 `start`（生产模式）运行，HTTPS、PostgreSQL、启用 `token-exchange-standard`（GA）与 `token-exchange-delegation`（预览，需同时启用 `parameterized-scopes`）；注册服务和网关也上 TLS，各自信任开发 CA；真实用户以授权码 + PKCE 经 Keycloak 的登录表单登录；代理客户端以标准令牌交换取得受众为网关资源的令牌（需要在请求方客户端上配该受众的映射），以委派取得带 `act` 的令牌（用户令牌必须带 `may_act: {"sub": <代理的服务账号 id>}`，由管理员配置）。网关校验不变（签名、issuer、受众、租户、角色），新增记录 `azp`（Client）与 `act`（Actor）进调用审计（迁移 0006），授权判定仍只看主体、租户和角色 | 对应 ADR-0001 D15 的第②条路；谁代表谁必须进审计 |

**结果**
- resources：单元测试（钉住的定义原样返回、审批后新增的资源既不列出也不可读、漂移被检测并封锁读取）；官方符合性在钉住资源后仍 **37/37**；compose 端到端 13/13。
- 多副本：集成测试 `TestReplicasMustAllAttest`：两副本都在 Release 上才 GOOD；第三个不拉取只心跳的副本让下一次部署失败并被点名，期望状态退回；该副本停止心跳超过窗口后不再计入，再次部署 GOOD；`GET /api/v1/gateways/{id}` 列出实例与存活状态。
- 指标：单元测试覆盖格式、转义、直方图分桶、按路由计数、不泄露主体和密钥。
- tasks：官方 tasks 扩展场景 **直接 8/8（42 项检查全部 SUCCESS）、经网关 8/8（42/42）**。
- 身份：`MODE=oidc bash deploy/e2e.sh` **12/12**：管理 API 经 TLS 且 JWKS 经 TLS 校验；授权码 + PKCE 登录；用户令牌的目录与调用；只读用户目录为空；标准交换的令牌（`sub`=用户、`aud`=网关资源、`azp`=代理）被接受；代理自己的令牌（`aud=account`）被拒；委派令牌（带 `act`）被接受；篡改令牌 401；调用记录区分三种来源（用户直接、代理标准交换、代理委派）。
- 完整矩阵在最终代码上重跑（见提交信息）。

**实测发现并修复**
- `COPY --chmod` 会把模式同时施加到自动创建的父目录：`/etc` 变成 0644 后 uid 10001 读不到 `/etc/resolv.conf`，Go 的解析器静默退回 `[::1]:53`，表现为"解析不到 postgres"。改为由构建上下文携带正确模式（`umask 022`、显式 chmod），Dockerfile 不再对 `/etc` 下的文件用 `--chmod`。
- 构建上下文在 `umask 077` 下拷出的 `ca-certificates.crt` 是 0600，镜像里非 root 读不到系统根证书，只有走 https 时才暴露。
- `cmd/mcp-gateway` 的注册服务客户端没有接 TLS 配置（M4 的集成测试自己构造了客户端，所以没发现）；compose 的 OIDC 模式跑真实二进制时暴露，已修。
- 生产模式的 Keycloak 服务名与开发模式不同，容器内按 `keycloak` 取 JWKS 解析失败；用网络别名统一。
- Keycloak 的委派要求 `may_act` 恰好是 `{"sub": <actor sub>}`（可带 `client_id`），数组或 `azp` 形式都被拒；带 `may_act` 的令牌不能再走标准交换（二者互斥）。

**局限（不标 PASS）**
- 委派仍是 Keycloak 的预览特性；`may_act` 要为每个代理逐个配置，生产上应由 IdP 侧的策略生成。
- 开发 CA 与自签证书、Keycloak 的 `dev-file`/单实例 PostgreSQL 只用于联调；用户登录只测了密码表单，没有 MFA、会话注销和刷新令牌。
- tasks 的真实上游是自写的参考实现，不是第三方实现；`notifications/tasks` 的订阅中继仍只有单元测试（官方场景自己标注待重写）。
- 指标没有带上租户维度（避免高基数），按租户的用量要从调用记录聚合。
- 多副本合并只处理"全部存活副本一致"，没有做分批发布（canary）语义。

## 11. 契约发布：idp.telos.mcp 1.0.0（2026-11-03）

决策人 2026-11-03 确认：各模块的机器契约统一登记在 `idp-contracts`（命名空间 `idp.telos.<模块>`，各自独立版本），登记的前提是实现侧的一致性测试。

| # | 决策 | 理由 |
|---|---|---|
| D39 | **本仓库是 `idp.telos.mcp` 1.0.0 的生产者**：权威副本在 `api/contracts/`（`schema.json` 手写，`examples.json` 由 Go 值生成），发布三个文档——Release（`idp.mcp.release/v1`）、Envelope、InvocationRecord——与九个组成对象；`internal/release/contract_test.go` 证明 schema 与实现一致：密封出的文档都满足 schema 且不含 `null`（`Seal` 把 nil 集合规范为空），示例都能被 `Open` 接受、记录都能无损往返 `invocation.Record`，封闭对象的属性集与 `required` 等于 Go 结构体的 JSON 字段，实现拒绝的变体 schema 也拒绝。`idp-contracts/idp.telos.mcp/1.0.0` 只是逐字节相同的发布副本，由那边的 `tools/validate.py` 核对 | 契约必须由生产者拥有并由测试钉住，否则登记只是一份会过时的文档；JSON Schema 只能表达形状与本地规则，摘要与交叉引用仍由 `Validate` 判定，所以两边都要测 |

网关与注册服务之间的内部接口（期望状态、心跳、调用批量）和管理 API 仍只由 `api/openapi.yaml` 描述，不登记为契约。

## 12. M6：向上游转发调用者身份（2026-11-06，契约 1.1.0）

起因：idp-sandbox（Agent 执行沙箱）作为网关的上游，需要知道是谁在调用，才能把工作区绑到调用者、按调用者限额。此前网关不向上游转发任何凭据或身份（`TestToolsCallIsRoutedUnderTheNativeName` 保证不转发客户端凭据），所以上游只能把工作区 id 当承载令牌。

| # | 决策 | 理由 |
|---|---|---|
| D40 | **目标有 `identity` 属性：`none`（默认）或 `forward`**。注册服务器时设定（`POST /api/v1/servers` 的 `identity`，之后不可改），编译进 Release 的 `targets[].identity`（`none` 时省略，所以已有 Release 的摘要不变）。`forward` 的目标，网关在发给它的每个请求的 `_meta["io.idp.telos/caller"]` 里放经过认证的调用者：`subject`、`tenant`、`roles`，以及 `client`（azp）与 `actor`（RFC 8693 的 act）。审计字段沿用，授权仍只看 subject、tenant、roles | 哪些服务器能知道"是谁在调用"是一个应当由审批人看见并批准的事：它在 Release 里，改它就改摘要，要经他人审批才能部署 |
| D41 | **`io.idp.telos/caller` 是网关的键：对每一个转发的请求，先删除客户端自带的同名键，再（仅对 `forward` 的目标）写入网关自己认证出的值** | 上游若信任这个键，就必须能信任它来自网关的认证，而不是调用者自己填的。测试 `TestNoIdentityIsForwardedByDefaultAndForgeryIsStripped`、`TestForwardIdentityPassesTheVerifiedCaller`（伪造的 admin 被覆盖） |
| D42 | **范围**：`tools/call`、`prompts/get`、`resources/read`、`completion/complete`、tasks 的请求都经同一个转发函数，所以都带。`subscriptions/listen` 的中继是网关自己对上游开的流、不属于某个调用者，所以不带身份（它本来就不转发客户端的 `_meta`） | 一个流服务多个订阅者时没有"那个调用者" |
| D43 | **这一跳本身仍然没有认证**：上游靠"只有网关能到达它的私网"相信网关（与此前一样）；转发身份没有改变这一点，也没有给身份签名 | 签名需要网关与上游之间的密钥分发，是另一个决策；这里只解决"上游能知道是谁"，不解决"上游能证明是网关告诉它的"（2026-11-17 起由 D44 解决：网关有密钥时给调用者签名） |

**契约**：`idp.telos.mcp` 1.0.0 → **1.1.0**，只有向后兼容的新增（Target 的可选 `identity`，枚举只有 `forward`）。OpenAPI 1.1.0 的 `identity` 同理。迁移 `0007_server_identity.sql`。

**验证**：release 的单元（省略与摘要、未知取值被拒、`IdentityOf`）；网关的单元（转发、伪造被覆盖、默认不转发、不改动输入）；契约一致性测试；idp-sandbox 的端到端经真实的注册服务与网关验证了整条链（以该服务器 `identity: forward` 注册，沙箱按调用者隔离工作区）。

## 13. M7：给转发的调用者签名（2026-11-17）

起因：D43 留下的缺口。上游只能靠"只有网关能到达它的私网"相信 `io.idp.telos/caller`；这个网络上任何别的东西（另一个被攻破的上游、一个配错的端口）都能自称任何调用者。idp-sandbox 把工作区绑在这个身份上，所以它的隔离只和网络策略一样强。

| # | 决策 | 理由 |
|---|---|---|
| D44 | **网关给转发的调用者签名**。`IDP_GATEWAY_CALLER_KEY_FILE` 是一把 P-256 私钥（PEM，PKCS #8 或 SEC 1）。设了之后，发给 `forward` 目标的每个请求在 `_meta["io.idp.telos/caller-assertion"]` 里多一个紧凑 JWS（ES256，`typ` = `idp-caller+jwt`，`kid` = 公钥的 RFC 7638 指纹）。声明：`iss` = `idp-mcp-gateway:<网关 id>`；`aud` = 这个目标在 Release 里的 `endpoint`；`sub`、`tenant_id`、`roles`、`client`、`actor` 与 `io.idp.telos/caller` 相同；`iat`、`exp`（60 秒）、`jti`（随机）；`req` = 这次请求的摘要，即 `{"method", "params"}`（`params` 去掉 `_meta`）的规范化 JSON（`release.Canonical`：键排序、无多余空白、不转义 HTML、数字照原样）的 SHA-256。`io.idp.telos/caller-assertion` 与 D41 的键一样归网关：客户端自带的一律先删除。签名失败就不发送（`NOT_DELIVERED`），不退回成不签名。没设密钥时行为与 D43 相同，启动时写一条告警 | 用非对称签名：上游只有公钥，一个上游被攻破也造不出别的调用者（共享密钥做不到）。`aud` 让发给一个上游的断言不能拿到另一个上游去用。`req`、`jti` 与一分钟的有效期让截获的断言不能换参数再用，同一个请求也只会被接受一次（由上游记 `jti`）。摘要算的是 JSON 的值而不是字节：网关重新编码 `params` 时会去掉空白、改写转义，上游按同一规则各算各的 **一致性向量（2026-11-19）**：签名方与两个验签方（idp-sandbox、idp-web）共用一份判例：平台发布的一致性向量 `idp-contracts/vectors/caller-assertion/v1.json`（格式与用例见同目录 README），含好用例与每一种拒绝（还有时钟容差、重放的边界）。网关能签出来的用例由真实的 `CallerSigner` 生成，签不出来的（5 分钟有效期、`alg` 为 `none` 或 `HS256`、P-384、伪造的签名）由测试代码构造；密钥对在生成时创建，私钥不落盘，文件里只有公钥。本仓库的副本是 `internal/gateway/testdata/caller-assertion-v1.json`，重新生成：`go test ./internal/gateway -run TestCallerVectors -update`（不带 `-update` 时同一个测试检查已提交的文件：签名、头、有效期和 `req` 摘要）。验签方的副本是各自 `internal/mcp/testdata/caller-assertion-v1.json`；四份文件必须一起改，`idp-contracts/tools/validate.py` 检查它们逐字节相同。此前靠手抄的一条向量（`TestRequestDigestIsTheOneUpstreamsCompute` 与上游的 `TestTheGatewaysAssertionIsAccepted`）保留 |
| D45 | **密钥是网关的部署属性，不进 Release；公钥由运维交给上游**（`openssl ec -in caller.key -pubout`）。同一个网关的多个副本共用一把。轮换：上游可以同时持有几把公钥（按 `kid` 选），先给上游加上新公钥，再换网关的私钥，最后去掉旧公钥。网关不提供 JWKS 端点 | 哪些目标能收到身份仍由 Release 的 `identity` 决定并经审批（D40）；用哪把钥匙签是运行环境的事。上游在启动时就该有公钥：运行时去网关取，等于又要先相信网络一次 |

**没有做的**：
- 上游的回答没有签名，网关到上游的连接可以是明文 HTTP。断言防的是伪造与重放，不防窃听与篡改回答；要防这两样，上游用 https（`IDP_UPSTREAM_CA_FILE`）。
- `subscriptions/listen` 的中继不带身份（D42），所以也没有断言。
- Kubernetes 清单里只留了注释掉的配置（`deploy/kubernetes/gateway.yaml`），没有在集群上验证过。
- 契约 `idp.telos.mcp` 没有变：断言是 `_meta` 里的约定，不是 Release、Envelope 或 InvocationRecord 的一部分。

**验证**：网关的单元测试 `TestForwardedIdentityIsSignedForTheTargetAndTheRequest`（上游用公钥验得过；`aud` 是端点、`req` 是上游实际收到的请求的摘要、有效期 60 秒、每次调用一个新的断言；客户端伪造的断言被换掉）、`TestNoAssertionWithoutApprovalAndAForgedOneIsStripped`、`TestCallerSignerTakesOnlyAP256Key`、`TestRequestDigestIsTheOneUpstreamsCompute`（同一个请求换一种写法摘要不变；这个请求与摘要也钉在 idp-sandbox 的测试里，连同本签名器为它签出的一个断言）。端到端：idp-sandbox 的 `deploy/e2e.sh`（真实的注册服务与网关，网关带密钥，沙箱只认签名）全部检查通过，沙箱网络上一个不经网关、自称 `agent-host` 的直接调用得到 403。

## 14. M8：外部客户端的准入（2026-11-19，契约 1.2.0）

起因：agent 运行时（idp-host）对"对外"的工具做三件事：成员确认、数据的敏感级别上限、把工具结果标为不可信。一个直连网关的客户端三样都没有，而网关此前只按角色授权：只要它的用户的角色允许 `web__web_open_url`，它就能调用（平台 ADR `idp-mcp-external-interop` 的缺口 C3、C4、C8，决策 D-X6 到 D-X8；本节是其中的步骤 X3，不含桥，也不含"上游的类别"，后者是 X1）。

| # | 决策 | 理由 |
|---|---|---|
| D46 | **按客户端授权，缺省什么都看不到**。令牌里的 OAuth 客户端是 `azp`（Keycloak 签发时写入，客户端自己改不了；`client_id` 不读，一个声明一个含义）。新的必填设置 `IDP_GATEWAY_CLIENTS_FILE`（YAML 或 JSON）列出网关服务的客户端，每个是 `platform`（平台自己的：角色允许什么就看见什么，同此前）或 `external`（外部的：必须写明 `servers` 和/或 `tools`）。**工具、prompt、资源对一次调用可见、可用，要同时满足角色允许、客户端允许**。没列出的客户端、没有 `azp` 的令牌：通过认证，什么都看不到、什么都用不了，并且每次都进审计。**网关没有这个文件就不启动**，错误信息写出设置名和唯一的出路：条目 `"*": platform`，它服务每一个客户端，等于关掉这项控制，网关启动时为它写一条告警。文件里的未知字段、非法的模式、种类或名字都使启动失败。API Key 没有 OAuth 客户端，它的客户端是 `api-key:<密钥 id>`，运维像别的客户端一样列出 | 控制是否生效不能取决于运维记得写一份配置：缺省关闭（所有客户端都服务）是此前的行为，也正是缺口；缺省打开而启动时拒绝，才能让"忘了配置"变成一眼可见的失败。关掉只能是运维写下的一行字。拼错字段名同样会悄悄关掉控制，所以未知字段是错误。**否决的做法**：按令牌的 scope 区分（scope 由客户端自己请求，客户端标识由 Keycloak 绑定到注册的客户端上）；用客户端 id 的前缀（`idp-*`）推断平台客户端（命名不是授权）；只告警不拒绝启动（控制悄悄不生效）；读 `client_id` 作为后备 |
| D47 | **没列出的客户端收到什么**：`tools/list`、`prompts/list`、`resources/list`、`resources/templates/list` 是 HTTP 200 的空列表；`tools/call`、`prompts/get`、`resources/read`、`completion/complete` 是与"工具不存在"逐字相同的 JSON-RPC 错误（`-32602`，HTTP 200；D5 的"一个应答"：不能靠拒绝的差别枚举目录），`tasks/*` 是"未知任务"；`server/discover` 只给最小的能力集；`subscriptions/listen` 得到一个什么都不接受的确认和流的结束（不占流的名额）。**不用 401 或 403**：401 带 `WWW-Authenticate`，会让 MCP 客户端重新走授权流程，而它的凭据本来没问题。外部客户端的 `servers` 授予该服务器的工具、prompts、resources；`tools`（`path.Match` 模式，对外暴露的工具名，与 HOST 的 `externalTools`、`confirmTools` 同一种写法与校验）只授予工具，prompts 与 resources 只能按服务器授予。task 记下创建它的客户端，只有这个客户端能用这个 task id（同一个成员的另一个客户端得到"未知任务"） | 角色过滤的每一条路径（见下面的清单）都经 `internal/authorization`，客户端的规则加在那里，所以不会有哪条路径忘了它。统一的"空或不存在"让没列出的客户端无从知道网关服务什么 |
| D48 | **只许 HOST 的工具**。设置 `hostOnlyTools`（工具名模式）列出只有 HOST 能调用的工具；HOST 是客户端文件里写了 `host: true` 的平台客户端。这样的工具对其他一切客户端（平台的或外部的，不论角色、不论白名单）既不可见也不可调。**网关不内置任何缺省模式**（平台的部署写 `["web__*"]`）。判定写成"来自两个来源之一"：文件里的模式，和 Release 对整个目标的声明（`authorization.hostOnlyByRelease`，现在恒为否；X1 在这里加"所有外部上游的工具"，不用改别处）。运维的例外 `hostOnlyExcept`（模式加必填的理由，理由有长度上限）对两个来源都有效；**每次使用例外，审计记录的 `reason` 是 `host-only exception: <理由>`**，HOST 自己的调用不算使用例外。例外只解除"只许 HOST"，不扩大任何客户端的白名单 | 成员确认、敏感级别上限、不可信标记都在 HOST 里，绕过 HOST 就绕过它们（C8）；"该不该加这一道"是部署的事，所以模式由部署给。**否决的做法**：把标记写进 Release 的每个工具（要改 Release 的契约与审批，X1 才有意义）；缺省内置 `web__*`（网关不应知道哪个上游是 web）。**与平台决策的差别**：D-X7 写"缺省标上 `web__*` 与所有外部上游的工具"；这里按任务的要求不内置模式，"所有外部上游"留给 X1。`hostOnlyTools` 的模式只管工具；一个目标的 prompts 与 resources 只有在 Release 对整个目标声明时才是"只许 HOST"（见没有做的） |
| D49 | **限流与审计补全（C4）**。限流：每个客户端一个窗口、每个成员（租户加 subject）一个窗口，滑动窗口，在内存里，**每个副本各自计数**（与 idp-web 相同；多个副本时实际上限是副本数乘以设置值，重启忘记窗口）。设置 `rateLimits.perClient`、`rateLimits.perSubject`（`requests`、`window`；缺省 600 与 120 每分钟）。**缺省只套在外部客户端和没列出的客户端上；平台客户端缺省没有限制**，它的成员也没有：HOST 一个客户端替所有成员调用，服务账号（如 EER 的）在一个 subject 下跑很多次执行，对它们套对外开放用的阈值会让平台自己被限流。客户端条目可以设自己的上限：`rateLimit`（这个客户端每个窗口的请求数）与 `subjectRateLimit`（经它来的每个成员的上限），外部客户端用它覆盖缺省，平台客户端用它给自己加上限。没列出的客户端永远受缺省限制（它什么都得不到，但不能随意冲击网关和审计）。通配 `"*"` 是平台条目，所以不限流。每个通过认证的请求都计数，被拒绝的请求也计；超限得到 HTTP 429、`Retry-After`（秒）和 JSON-RPC `-32029`（数据里有 `retryAfterSeconds`），并进审计。审计补全：列表调用、订阅、认证失败、限流都有记录（此前没有：只有 `tools/call`、`prompts/get`、`resources/read`、`completion/complete`、`tasks/*` 有）；流式的应答记两条，流打开时一条（`STREAM_STARTED`），结束时一条（`STREAMED`，带时长和转发的字节数）；订阅同理。形式不变：仍是 `InvocationRecord`，仍不记令牌和参数。新增两个可选字段 `reason`（拒绝的原因，或例外的理由）和 `bytes`，三个新的结果（`STREAM_STARTED`、`RATE_LIMITED`、`UNAUTHENTICATED`）和六个新的方法名（四个列表、`subscriptions/listen`、`server/discover`，后者只在被拒绝时记）。未认证的请求记为主体 `(none)`；没有单个对象的记录的 `tool` 是 `*`。认证失败的记录每个来源地址每分钟最多 30 条，多出的只计入指标 `idp_mcp_gateway_auth_failures_total`（没有凭据的人不能用它灌满审计缓冲） | 对外开放后，限流和完整的审计是基本要求。每个副本各自计数不需要新的依赖，也不增加一个共享状态的故障点；代价是上限不精确，写在这里。**否决的做法**：只数 `tools/call`（探测哪些东西可用同样要限制）；共享计数（Redis 或 PostgreSQL，为一个防失控的阈值增加依赖）；另开一条审计流（运维要多看一处）；每次认证失败都记（审计被无凭据的人灌满） |

**契约**：`idp.telos.mcp` 1.1.0 → **1.2.0**，只有向后兼容的新增（上面的两个字段、三个结果、六个方法名）。迁移 `0008_invocation_reason_bytes.sql`。`idp-contracts/idp.telos.mcp/1.2.0` 的发布副本要与 `api/contracts/` 逐字节相同（在那个仓库里放，不在这里）。

**角色过滤的每一条路径，现在都按客户端再过滤一次**：`tools/list`（`mcp.go` 的 `VisibleTools`）、`tools/call`（`Decide`）、`prompts/list`（`AllowedPrompt`）、`prompts/get` 与 `completion/complete` 的 prompt 引用（`promptOwner`）、`resources/list`、`resources/templates/list`（`AllowedResources`）、`resources/read` 与 `completion/complete` 的资源引用与 `subscriptions/listen` 的资源订阅（`resourceOwner` 经 `ResourceTargets`）、`subscriptions/listen` 的 prompts 与 tools 的 list_changed（`PromptTargets`；tools 的通知只发给被服务的客户端）、tasks（`tasks/get|update|cancel` 与 listen 的 `taskIds`，经 `taskStore.lookup` 的创建者客户端）、`server/discover`。这些都经 `internal/authorization` 的同一个策略对象，客户端的规则在那里。

**升级说明**：
1. **网关不再在没有客户端文件时启动**。升级前先写好文件：平台部署至少要列出 HOST（`idp-host`，`host: true`）和其他调用网关的平台客户端，再加 `hostOnlyTools: ["web__*"]`；想先保持原来的行为，写 `clients: {"*": platform}`（控制关闭，启动告警）。例子见 README"客户端准入"；compose 与 Kubernetes 的配置见 `deploy/e2e.sh` 与 `deploy/kubernetes/gateway.yaml`。
2. **先升级注册服务（迁移 `0008`），再升级网关**。注册服务按 `DisallowUnknownFields` 解码网关推来的调用记录：新网关推 `reason` 与 `bytes` 给旧注册服务，整批被拒（400），网关保留该批重试，记录就堵在缓冲里。
3. 使用 API Key 数据面的部署，客户端 id 是 `api-key:<密钥 id>`，要列出，或写 `"*"`。
4. 受影响的现有检查：见平台一侧的清单（报告），主要是直接用令牌调网关的验收脚本。

**没有做的**：
- 旧版本协议的外部客户端（C1）：等有了要接的客户端清单再定；做的话与桥对称，核心仍只说新版本。
- 浏览器里的客户端（C6）：不支持，网关不开 CORS。
- 动态客户端注册：不开放；外部客户端在 Keycloak 里由运维注册，再写进客户端文件。
- 每个成员各自的第三方凭据（平台决策的选择点 2）：不在这一批。
- "所有外部上游的工具缺省只许 HOST"：X1 加上游的类别后，在 `hostOnlyByRelease` 里实现；本批只有挂载点和针对它的测试（`TestEverythingOfAHostOnlyTargetIsHostOnlyWhenTheReleaseSaysSo`）。
- `hostOnlyTools` 不管 prompts 和 resources；这些对 HOST 以外的客户端仍按 `servers` 与角色决定。
- 成功的 `server/discover` 不进审计（只有被拒绝的：认证失败、限流）。
- 列表的审计记录不含返回了多少项。
- 限流不跨副本；窗口不持久。
- 客户端文件只在启动时读，改动要重启（Kubernetes 里是滚动重启）。

**验证**（2026-11-19，WSL）：
- 单元与网关的测试：未列出的客户端（空列表、调用被拒、审计）、有白名单的外部客户端、平台客户端、"只许 HOST"（HOST 可见可调，其余不可见不可调）、例外与它的审计理由、prompts/resources/completion/tasks/subscriptions 同样按客户端、网关与注册服务的启动失败信息、`"*"` 的出路、限流（每客户端、每成员、`Retry-After`、覆盖、没列出的客户端也限）、补全后的审计（列表、订阅、认证失败及其上限、流的两条记录与字节数）。真实的 JWT（本地 JWKS）证明 `azp` 是客户端、没有 `azp` 的令牌不被服务。
- `make test`（含 `-race`）、`make test-integration`（真实 PostgreSQL：迁移 `0008` 应用，认证失败与列表记录经注册服务存下并读回）全部通过。
- 官方符合性：37/37 个计分场景通过，官方 tasks 扩展 8/8（符合性测试的客户端是一个平台客户端，不是 `"*"`）。
- compose 端到端（本仓库的 `deploy/e2e.sh`）：`MODE=apikey` 13/13，`MODE=jwt` 25/25 检查（新增：平台客户端看不到只许 HOST 的工具并被拒，HOST 可以，外部客户端只有白名单，没列出的客户端什么都没有，注册服务里的调用记录写明原因），`MODE=oidc` 12/12（`agent-app` 平台、`agent-exchange` 为 HOST，审计的 client 与 actor 不变）。

**反向验证**：每个控制手工去掉一次，对应的测试失败，再恢复：

| 去掉的控制 | 失败的测试（节选） |
|---|---|
| 没列出的客户端也被服务（`lookup` 对未知客户端回退成平台客户端） | `TestAnUnlistedClientSeesNoToolsAndEveryCallIsRefusedAndAudited`、`TestATokenWithoutAClientIsNotListed`、`TestAToolNeedsTheRoleAndTheClient`（共 15 个） |
| 没有客户端文件的策略服务所有人（nil 不是"不服务"） | `TestAPolicyCompiledWithoutClientsGrantsNothing`、`TestNothingIsServedWithoutAFile` |
| 外部客户端的白名单不起作用 | `TestAnExternalClientSeesAndCallsOnlyWhatItsAllowListNames`、`TestDecideCombines…`（共 6 个） |
| "只许 HOST"不起作用 | `TestAHostOnlyToolIsVisibleAndCallableForTheHostClientOnly`、`TestAnExternalClientsOwnPatternDoesNotLiftHostOnly`（共 5 个） |
| 例外匹配所有工具 | `TestAHostOnlyExceptionLetsOtherClientsThroughAndIsAuditedWithItsReason`、`TestDecideCombines…` |
| 例外的使用不记理由 | `TestAHostOnlyExceptionLetsOtherClientsThroughAndIsAuditedWithItsReason` |
| 例外可以不写理由 | `TestInvalidFilesAreRefusedWithAMessageThatNamesTheProblem` |
| 配置里的未知字段被接受（拼错的 `hostOnlyTool` 让控制失效） | `TestInvalidFilesAreRefusedWithAMessageThatNamesTheProblem` |
| prompts 不按客户端过滤 | `TestPromptsAndResourcesFollowTheClientToo`、`TestAnUnlistedClientGetsEmptyPromptAndResourceListsAndNoCapabilities`（共 4 个） |
| resources 不按客户端过滤 | `TestPromptsAndResourcesFollowTheClientToo`、`TestSubscriptionsHonourOnlyWhatTheClientMaySee`（共 5 个） |
| completion 与订阅用的 prompt 目标不按客户端过滤 | `TestPromptsAndResourcesFollowTheClientToo`、`TestSubscriptionsHonourOnlyWhatTheClientMaySee` |
| task 不绑定创建它的客户端 | `TestATaskBelongsToTheClientThatCreatedIt` |
| 没列出的客户端的订阅被接受 | `TestSubscriptionsHonourOnlyWhatTheClientMaySee` |
| `server/discover` 对没列出的客户端给全部能力 | `TestAnUnlistedClientGetsEmptyPromptAndResourceListsAndNoCapabilities` |
| 平台客户端也受缺省限流 | `TestPlatformClientsAreNotLimitedUnlessTheFileSaysSoAndOthersAre`、`TestPlatformClientsAndTheirSubjectsAreNotLimitedByTheDefaults` |
| 没列出的客户端不限流 | `TestAnUnlistedClientIsAlwaysLimitedByTheDefaults`、`TestPlatformClientsAreNotLimitedUnlessTheFileSaysSoAndOthersAre` |
| 每个客户端的限流去掉 | `TestTheRequestLimitOfAnExternalClientRefusesWithRetryAfterAndIsAudited`、`TestAClientsOwnRateLimitOverridesTheDefaultsForPlatformAndExternalClients`、`TestAnUnlistedClientIsAlwaysLimitedByTheDefaults` |
| 每个成员的限流去掉 | `TestTheRequestLimitOfASubjectCountsAcrossClientsWhenAPlatformEntrySetsOne` |
| 限流的拒绝不带 `Retry-After` | `TestTheRequestLimitOfAnExternalClientRefusesWithRetryAfterAndIsAudited` |
| 限流的拒绝不进审计 | `TestTheRequestLimitOfAnExternalClientRefusesWithRetryAfterAndIsAudited`、`TestTheRequestLimitOfASubjectCountsAcrossClientsWhenAPlatformEntrySetsOne` |
| 限流窗口不滑动（或把被拒的请求也计入） | `TestTheLimiterSlidesRefusesWithTheWaitAndKeepsKeysApart`、`TestTheRequestLimitOfAnExternalClientRefusesWithRetryAfterAndIsAudited` |
| 列表调用不记审计 | `TestListCallsAreRecordedForListedClientsToo`、`TestAnUnlistedClientSeesNoToolsAndEveryCallIsRefusedAndAudited` |
| 认证失败不记审计 | `TestAuthenticationFailuresAreRecordedWithoutTheCredential`、`TestAFloodOfRefusedCredentialsFromOneAddressIsCountedButNotAllRecorded` |
| 认证失败的审计不设上限 | `TestAFloodOfRefusedCredentialsFromOneAddressIsCountedButNotAllRecorded` |
| 流的开始不记 | `TestAStreamedCallRecordsItsStartItsEndAndItsBytes`、`TestASubscriptionRecordsItsOpeningAndItsEndWithBytes` |
| 流的字节数不记 | 同上两个 |
| 订阅的字节数不记 | `TestASubscriptionRecordsItsOpeningAndItsEndWithBytes` |
| API Key 不是自己的客户端 | `TestAPrincipalWithAnAPIKeyIsTheClientNamedAfterTheKey`、`TestAnAPIKeyIsTheClientNamedAfterItsID`（共 16 个） |
| `azp` 不当作客户端读 | `TestTheClientOfATokenIsItsAzpAndATokenWithoutOneHasNone`、`TestATokenWithoutAClientIsNotListed`、`TestValidTokensRSAAndECWithRotation` |
| 启动时不检查客户端文件 | `TestTheGatewayDoesNotStartWithoutTheClientsFile` |
| 注册服务丢掉 `reason` 与 `bytes` | `TestControlPlaneToDataPlane`（集成测试） |

## 15. X1：第三方的服务器（2026-11-19，契约 1.3.0）

起因：平台打算接第三方的 MCP 服务。网关此前的前提是"上游都是我们写的"：它把客户端的 `_meta` 整个转发（`clientInfo`、自定义键、追踪号），身份模式 `forward` 会把成员的主体、租户、角色交给对方，对方的结果和它自己发起的请求原样交给客户端，探测失败不拦截，评审人只看得到工具名（平台 ADR `idp-mcp-external-interop` 的缺口 S4、S5、S6、S10；决策 D-X3、D-X4、D-X7 里涉及外部上游的部分）。本节是其中的步骤 X1。**不含**：桥（D-X1、D-X2：凭据、旧版本协议、公网出口）、HOST 读标记（D-X5，在 idp-host 里）、按上游各自的限流与熔断（S8，是桥的事）。

| # | 决策 | 理由 |
|---|---|---|
| D50 | **上游有类别**：`internal`（缺省，此前的全部行为）或 `external`（第三方的）。登记时写 `class`，之后不能改（没有修改接口；要改就重新登记，等于重新评审）；它进入 Release 的目标（`class: "external"`，`internal` 不写出，已有 Release 的摘要不变），所以由审批人批准，也由网关按钉住的值执行。**桥的地址**由设置 `IDP_BRIDGE_ENDPOINTS` 给出（主机、`主机:端口` 或 http(s) 地址前缀，逗号分隔，缺省为空；注册服务与网关各读一份）：登记在这些地址上的服务器必须是 `external`，否则登记被拒绝（400，错误信息写明原因）；重新发现时再查一次（设置可能是后来加的）；网关激活 Release 时也查，有指向桥地址的目标而不是 `external` 就拒绝激活。`external` 的目标 `identity` 必须是 `none`（登记时拒绝，Release 校验也拒绝），也不能带 `tasks`、`resources.subscribe`、`resources.listChanged` 能力（它们会让网关中继上游主动推来的内容；编译 Release 时从外部目标的能力里去掉，校验再拒绝一次）。评审用的接口显示类别（`GET /api/v1/servers`、`/servers/{id}` 的 `class`，目录视图见 D53） | 类别由我们判定，不由上游自述（平台 ADR 原则 2）；"漏标"是最容易发生的错误，所以桥的地址单独列出，让它成为登记失败而不是悄悄的缺省。类别进 Release 是为了让网关只信自己钉住的东西，而不是登记表里的现状。**否决的做法**：登记后可改类别（改类别应当和第一次登记一样被评审，而审批只发生在服务器上）；按主机名猜（"看起来像第三方"）；只在注册服务里查桥地址（网关是执行的一方，两头都查才是"忘了也不行"） |
| D51-a | **身份**：对 `external` 的目标，调用者断言、`io.idp.telos/caller`、主体、租户、角色都不发，登记时的身份模式无关紧要。执行点是 `forward`：目标是 external 就走 `externalParams`，不调用 `stampCaller`，所以即使 Release 里写了 `forward`（校验会拒绝，但执行不依赖校验），也不会发出 | 第三方不该拿到这些 |
| D51-b | **`_meta` 白名单与追踪**：发给 external 目标的 `_meta` 由网关从白名单**构造**，不是从客户端的清理出来，所以没人想到的键也不会被发出。白名单三个键：`io.modelcontextprotocol/protocolVersion`（2026-07-28 每个请求的信封，没有它上游无法应答；值是网关自己的）；`io.modelcontextprotocol/clientCapabilities`（信封的另一个必填键，**固定是空对象**：客户端的能力——采样、征询、扩展——正是上游用来向客户端要更多东西的依据，而网关不为 external 目标中继任何这类请求，所以不能说"客户端支持"）；`progressToken`（上游报告这次调用进度所用的令牌；不透明，字符串且不超过 128 字节，或整数，否则丢弃）。**不发**：`clientInfo`、`io.idp.telos/caller*`、`traceparent`/`tracestate` 与任何自定义键。顶层参数里 `inputResponses`、`requestState`、`task` 也去掉（external 目标没有理由返回需要它们的应答）。W3C 追踪头不发；目录探测（网关与注册服务发现时）也不带 `clientInfo` 与追踪头（`client.Anonymized`）。`Mcp-Param-*` 头照 D12 转发（对 external 同样适用，有测试），它由客户端提供、网关不知道哪些是工具声明的，所以仍受 16 个、名字 128 字节、值 1024 字节的上限 | 平台 ADR 的草案写"缺省只有进度令牌"；规范的信封是两个必填键，所以实际的白名单是三个。把 `clientCapabilities` 固定成空，比转发客户端的更保守，也让 D51-c 成立。**否决的做法**：转发客户端的能力（上游据此发采样请求）；给 external 目标发网关自己的 `clientInfo`（暴露网关的版本，没有用处，规范不要求） |
| D51-c | **上游发起的请求**：2026-07-28 是无状态的，上游向客户端要东西有两种形式——流里的 JSON-RPC 请求（`sampling/createMessage`、`elicitation/create`、`roots/list`、`ping`），和 `resultType: "input_required"` 的结果（`inputRequests`）；还有客户端没要的 `resultType: "task"`。对 external 目标，网关**逐条判断**应答里的消息：这几种都不转发，调用以工具错误结束（"调用被网关结束：服务器向客户端发了一个请求……"），审计结果 `REVERSE_REQUEST_REFUSED`，`reason` 是网关自己的措辞（方法名只在固定的几个里取，上游编的不写进去）；客户端什么也看不到。进度通知只在令牌是客户端发的那个时转发，并且从数字重新构造（`progressToken`、`progress`、`total`），上游的 `message` 文字不转发；其他通知（日志等）丢弃 | 采样请求能让上游借客户端的模型读上下文，征询能向成员要口令。在无状态协议里网关没有回给上游的通道，所以"拒绝"就是结束这次调用并让客户端知道原因 |
| D51-d | **结果有上限**：`IDP_GATEWAY_EXTERNAL_MAX_RESULT_BYTES`（缺省 1 MiB）限一次普通应答和流里的一个事件；`IDP_GATEWAY_EXTERNAL_MAX_STREAM_BYTES`（缺省 4 MiB）限一条流读到的全部字节，**注释行和保活行也算**；上限必须在 1 到 16 MiB 之间。超过时调用以工具错误结束（写明上限，叫客户端少要一些），审计结果 `RESULT_TOO_LARGE`（`reason` 写明哪个上限）。流是逐事件解析的，网关一次只持有一个事件，读到上限就不再读：内存与上游的输出多少无关，只与上限有关（一个没有尽头的流只占那一块缓冲，直到上限或调用时限 60 秒，先到者为准）。流没有发出过事件就出错时，客户端得到普通的 JSON 应答；已经发出过的，工具错误作为流的最后一个事件发出 | **数字的来源**：HOST 读一个应答最多 8 MiB（`idp-host/internal/mcpclient` 的 `MaxResponse`），再多就失败；它交给模型的工具结果是 16 KiB（`internal/harness` 的 `ToolResultLimit`）。普通应答取 1 MiB：是模型读到的 64 倍，是 HOST 上限的八分之一，所以网关每个并发调用最多多占 1 MiB；流取 4 MiB：HOST 把一条流整个读成一个应答，取一半留出事件格式的开销。**与内部目标的差别**：内部目标仍是 16 MiB 的缓冲上限、流不设上限（此前的行为） |
| D51-e | **参数按钉住的 schema 校验**：此前就有（M3，`policy.ArgumentSchemas`）：每个目标、每次 `tools/call`，参数都按 Release 钉住的 `inputSchema` 校验，不合格的不转发。差别在**应答的形式**：内部目标仍是 JSON-RPC 错误（`-32602`，此前的行为）；external 目标改成**工具错误**（`isError: true`，文字是"工具 X 的参数无效：<位置: 关键字>；调用没有发出，请改正参数后再调"，不含参数的值），审计仍是 `INVALID_ARGUMENTS`。这回应缺口清单第 4 节"参数校验的错误应作为工具错误返回"：规范建议校验错误让模型自己纠正；协议错误是客户端自己的问题，HOST 不会把它交给模型。只对 external 改，是为了内部目标"与此前完全一致" | 恶意上游可以对探测返回批准的目录，对调用接受任何东西（D51-f 的局限），所以钉住的 schema 在网关一侧的校验才是真正拦住"多出的 `path`、`recipient`"的控制 |
| D51-f | **漂移与探测失败，宁可多扣**。对 external 目标：目录与批准的不同（漂移）**不论 Release 的 `driftAction` 是 `block` 还是 `report`**，立刻拦截调用；探测失败（不可达、应答无效、返回错误）**连续 `IDP_GATEWAY_EXTERNAL_PROBE_FAILURES` 次（缺省 3）**后拦截，探测周期是 `IDP_DRIFT_INTERVAL`（缺省 60 秒，每次探测超时 15 秒），所以对方挂了之后约 3 分钟拦截；**这个 Release 里从没有一次探测找到批准的目录的目标，也拦截**（包括刚激活的瞬间）。解除：下一次探测找到批准的目录（失败计数清零）；没有手动旁路开关。可见性：网关的状态（心跳经注册服务的 `GET /api/v1/gateways/{id}` 的 `lastStatus.targets[]`）里每个目标有 `failures`、`blocked`、`external`，指标 `idp_mcp_gateway_target_blocked{target,class}`，目标状态变化的日志，被拦的调用在审计里是 `NOT_DELIVERED` 加原因。被拦截的调用得到 HTTP 503 的 JSON-RPC 错误（"……暂不可用：……"）。拦截对 `tools/call`、`prompts/get`、`resources/read`、`completion/complete` 都生效（`completion/complete` 此前不查漂移，只对 external 目标加上，内部目标不变） | 三次、一分钟的取值：一次部署或重启上游不会拦任何东西，持续不可用或持续返回无意义内容的会被拦。**局限**（平台 ADR 也写了）：对方可以只对探测返回批准过的目录、对真实调用做别的事，探测发现不了。所以真正的控制是 D51-e（参数按钉住的 schema 校验）和"结果一律不可信"（HOST 的不可信标记、D51-c、D51-d）；漂移检测只发现诚实的变更 |
| D51-g | **`Mcp-Param-*`**：D12 起转发（SEP-2243），对 external 目标同样适用（`TestMcpParamHeadersAreForwardedToAnExternalTargetToo`）；它们由客户端提供、网关不知道哪些是工具声明的，所以只受 D12 的数量与长度上限，不能保证与参数一致 | 规范要求中间方转发 |
| D51-h | **标记**：`tools/list` 里 external 目标的每个工具的 `_meta` 带 `"io.idp.telos/external": true`（`server.MetaExternal`），由网关在 `routing.Route.Listed` 按钉住的类别写入；上游自己发的这个键（不论值）被覆盖；内部目标的工具永远没有它，上游自己发了也被删掉；`_meta` 里别的键原样保留，钉住的定义不改。prompts 与 resources 不加标记（HOST 只处理工具） | 标记是网关知道的事，不是上游声称的事；HOST 信的是这个，不是上游的标注 |
| D52 | **external 目标的一切都是"只许 HOST"**：`authorization.hostOnlyByRelease` 对 external 目标返回真（工具、prompts、资源），所以只有客户端文件里 `host: true` 的客户端能看到、调用它们；运维的 `hostOnlyExcept` 对**工具**照常有效（模式加理由，每次使用都进审计）。prompts 与 resources 没有例外机制：它们没有工具名可匹配，external 目标的 prompts 与资源永远只给 HOST | 成员确认、敏感级别上限、不可信标记都在 HOST 里，绕过 HOST 就绕过它们（C8）；"所有外部上游的工具缺省只许 HOST"是平台决策的选择点 4 |
| D53 | **评审人看到的**：此前 `GET /api/v1/servers` 只返回工具名，评审人批准一个服务器时看不到描述和参数定义。新接口 `GET /api/v1/servers/{id}/catalog` 返回最新与已批准的两个快照，每个工具的**完整**定义（名字、标题、描述、输入与输出 schema、注解、其余字段，即将被钉住的那一份），prompts、资源、资源模板同样；`changes` 是最新对已批准的差异：每一项新增、删除或改变，改变的写明哪些 JSON 键不同（`description`、`inputSchema`、`annotations`……）；还没有已批准的快照时全是新增。**批准 external 服务器的请求必须带 `{"digest": "<看过的目录摘要>"}`**（内部服务器可选）：摘要与最新快照不同就拒绝（409），所以评审之后才发现的目录不会被没看过就批准。**描述的长度**：external 服务器的目录，发现时（描述是那时才知道的）检查每个工具的 `description`、`title`，以及输入、输出 schema 与注解里每一处 `description`、`title`，上限 `IDP_EXTERNAL_MAX_DESCRIPTION` 字节（注册服务的设置，缺省 1024，约 150 个词）；含控制字符或不可见字符（零宽、方向控制、Unicode 标签字符）的也拒绝；prompts 同样。超过时发现失败（422），写明工具名与位置。内部服务器不受影响 | 描述是对模型的指令，评审人没读过全文就没评审过；schema 里的 `description` 是同样的通道，所以一并限制；不可见字符是把指令藏起来不让人看见的办法。长度上限给攻击者的空间设了上界，也给评审人要读的东西设了上界 |

### 15.1 修订 D51-a：桥的地址上的 external 目标收到网关签的调用者断言（2026-11-22，G1，契约不变）

桥（idp-mcp-bridge，见平台的 `docs/adr/idp-mcp-bridge-oauth-plan.md`）是我们自己的组件，在网关与第三方 MCP 服务之间，用**成员各自的** OAuth 令牌调用第三方。要选对令牌，桥必须知道调用者是谁；而 D51-a 对 external 一律不发身份。所以 D51-a 改为：

| 目标 | 收到的身份 | 其余 D51 规则 |
|---|---|---|
| external，**不在**桥的地址 | 什么都没有（与此前相同） | 全部照旧 |
| external，**在**桥的地址（`IDP_BRIDGE_ENDPOINTS` 匹配其 `endpoint`） | 只有 `_meta["io.idp.telos/caller-assertion"]`：网关的签名（D44 的同一把密钥、同样的声明，`aud` = 这个目标的 `endpoint`，`req` = 实际发出的 `params` 的摘要，有效期 60 秒） | 全部照旧：没有明文的 `io.idp.telos/caller`、主体、租户、角色，`_meta` 仍是 D51-b 的白名单加这一个键，没有追踪头 |
| internal | 照旧（由 `identity` 决定） | 照旧 |

- 没有签名密钥（`IDP_GATEWAY_CALLER_KEY_FILE`）或没有已验证的调用者时，对桥的调用**不发出**（`NOT_DELIVERED`）：桥得不到可信的身份，就不该收到一个会按"没人"处理的调用。
- **没有新增类别或身份模式，契约 `idp.telos.mcp` 不变（仍是 1.3.0）。** 判定用的是已经由审批人批准、进了 Release 的两个事实：目标是 `external`，端点在桥的地址上；而桥的地址早已强制"必须是 external"（D50，登记、发现、激活各查一次）。再加一个 `class: bridge` 或 `identity: assert` 只会让同一件事有两个写法，并且要升契约到 1.4.0；登记规则也因此不变：桥地址上的服务器必须是 external（仍拒绝 internal），external 的 `identity` 仍必须是 `none`（连在桥的地址上也拒绝 `forward`，因为 `forward` 会发明文的调用者）。计划原先设想的"桥地址登记为 `assert`"在代码里没有这个模式（现有的只有 `none`、`forward`），没有采用。
- **理由**：成员要用自己的令牌，要由桥来选；"不对第三方传 TELOS 的身份"这条规则改由桥在**它对第三方的那一跳**执行（桥只出示成员自己的第三方令牌和白名单内的 `_meta`）。网关这一跳仍不让身份到达任何不是我们的东西。
- **反方向的防护**（纵深防御）：桥会在工具结果的 `structuredContent` 里放"需要授权"标记 `io.idp.telos/authorizationRequired: {connection}`。对**不在**桥地址的 external 目标，网关从一个结果的 `structuredContent` 与 `_meta`（顶层）里**删除所有以 `io.idp.telos/` 开头的键**，再交给客户端（普通应答与流里的最终事件都做）；桥的目标不删；internal 目标不变。第三方因此不能伪造我们的标记（桥也要自己剥掉第三方发来的这类键）。**目录里同样**：`tools/list` 里 external 目标（桥或非桥）的每个工具，`_meta` 中除网关自己的 `io.idp.telos/external` 之外，所有以 `io.idp.telos/` 开头的键都删掉（`routing.Route.Listed`；钉住的定义不改）；internal 目标不变。以后新增的平台键，因此不会被第三方经评审、钉住的定义写进来。其余的键、没有这类键的结果，一个字节都不改。只看顶层这两个对象：平台读这些标记的地方就是这里；`content` 里各项自己的 `_meta` 不处理（HOST 不读）。

| 去掉的控制（15.1） | 失败的测试 |
|---|---|
| 桥目标不加断言 | `TestABridgeTargetReceivesTheSignedAssertionAndNothingElseOfTheCaller`、`TestABridgeTargetIsNotCalledWithoutASignerAndCarriesNoIdentityThen` |
| 断言之外还发明文 `io.idp.telos/caller` | `TestABridgeTargetReceivesTheSignedAssertionAndNothingElseOfTheCaller` |
| 所有 external 目标都发断言 | `TestAnExternalTargetThatIsNotAtABridgeAddressStillReceivesNoAssertion`、`TestTheExternalUpstreamReceivesNoIdentityNoClientInfoNoTraceAndNoCustomMeta` 等 |
| `aud` 不是桥的端点 | `TestABridgeTargetReceivesTheSignedAssertionAndNothingElseOfTheCaller` |
| 没有密钥也照发 | `TestABridgeTargetIsNotCalledWithoutASignerAndCarriesNoIdentityThen` |
| 非桥 external 的普通应答不删标记 / 流不删标记 | `TestTheKeysOfThePlatformAreRemovedFromAnExternalResultButNotFromABridges`（两个子测试各一） |
| 桥的目标也删标记（普通应答 / 流） | 同上（两个子测试各一） |
| external 工具的 `_meta` 里别的 `io.idp.telos/` 键不删 | `TestAnExternalToolCarriesNoKeyOfThePlatformButTheGatewaysMarker`、`TestTheMarkerIsSetForEveryToolOfAnExternalTargetAndNeverForAnInternalOne` |
| 只删 `structuredContent` / 只删 `_meta` | 同上、`TestStripOurKeysLeavesAnythingElseAsItWas` |

**契约**：`idp.telos.mcp` 1.2.0 → **1.3.0**，只有向后兼容的新增：Release 的目标多一个可选的 `class`（`"external"`）；调用记录多两个结果（`RESULT_TOO_LARGE`、`REVERSE_REQUEST_REFUSED`）；注册服务的 API（`openapi.yaml` 1.3.0）：登记与服务器的 `class`，`GET /api/v1/servers/{id}/catalog`，批准的可选请求体，网关状态里目标的 `failures`、`blocked`、`external`。迁移 `0009_server_class.sql`。`idp-contracts/idp.telos.mcp/1.3.0` 的发布副本要与 `api/contracts/` 逐字节相同（在那个仓库里放，不在这里）。

**对内部目标的影响**：没有（以下是全部例外）：①目标状态里多了 `failures`（探测失败计数）、`blocked` 两个字段，内部目标的 `blocked` 就是此前的"漂移且 `driftAction` 为 block"；②`tools/list` 里内部目标的工具如果上游自己带了 `io.idp.telos/external` 键，现在被删掉（此前原样转发）。每一条都有内部目标的回归测试（见验证）。

**执行点**（`file:line`）：- 登记：`internal/registry/servers.go` 的 `RegisterServer`（类别、身份）与 `checkBridge`（桥地址，登记与发现各一次）；网关激活 `internal/gateway/gateway.go:342`；Release 校验 `internal/release/release.go:386-402`；编译去掉能力 `internal/registry/catalog.go:287`（`externalCapabilities`）。
- D51-a、b：`internal/gateway/mcp.go:375-382`（`forward` 对 external 走 `externalParams`，不调 `stampCaller`）、`:412`（不发追踪头）；白名单 `internal/gateway/external.go:56`；探测不带 `clientInfo` 与追踪：`internal/gateway/gateway.go:446`（`CheckDrift`）、`internal/client/client.go`（`Anonymized`）、注册服务发现 `internal/registry/servers.go:231`。
- D51-c、d：`internal/gateway/mcp.go:427` 转入 `relayExternal`（`internal/gateway/external.go:204`）；逐条判断 `classify`（`:126`）；进度 `progressMessage`（`:168`）；普通应答上限 `:217`，流总量 `:279`，一行 `:282`，一个事件的数据 `:300`。
- D51-e：`internal/gateway/mcp.go:321-335`（校验此前就在，external 改为工具错误）。
- D51-f：`internal/gateway/gateway.go:441`（`CheckDrift` 计数）、`:523`（`blockReason`）；调用点 `internal/gateway/mcp.go:348`（`refuseBlocked`，`tools/call`、`prompts/get`、`resources/read`、`completion/complete`）。
- D51-h：`internal/routing/routing.go:90`（`Route.Listed`）。
- D52：`internal/authorization/authorization.go:60`（`hostOnlyByRelease`）。
- D53：`internal/registry/catalog.go:89`（`GetCatalog`）、`:214`（`CheckExternalDescriptions`）；`internal/registry/servers.go:329`（`ApproveServer` 的摘要）。

**升级说明**：
1. **先升级注册服务（迁移 `0009`），再升级网关，最后登记第一台 external 服务器。** 网关心跳里新的 `failures`、`blocked`、`external` 字段，旧的注册服务（按 `DisallowUnknownFields` 解码）会拒绝（只在有探测失败或有 external 目标时才出现，但不要靠这个）；旧的网关遇到带 `class` 的 Release 会因未知字段拒绝激活（部署失败并自动回到上一个 GOOD），所以 external 服务器要在所有网关升级之后再登记。
2. 在桥上线之前不用设 `IDP_BRIDGE_ENDPOINTS`；桥上线时在注册服务与网关里设成同一个值。


### 15.3 修订 D53：描述长度的上限按服务器设定（2026-11-23，契约 1.4.0）

**起因**：对真实的 GitHub 托管 MCP 服务验证时，注册服务拒绝了它的整个目录：`tool pull_request_read: inputSchema/properties/method/description is 1546 bytes, more than the 1024 allowed`。28 个工具里只有这一处超过 1024（其次是 690）。统一把部署缺省调高，等于放宽所有第三方服务器；决策人选定：**按服务器设定，由运维给出**。

| 项 | 决定 |
|---|---|
| 设定 | 登记 `class: external` 的服务器时可带 `maxDescriptionBytes`（正整数，字节）。不带：用部署缺省 `IDP_EXTERNAL_MAX_DESCRIPTION`（1024，不变）。`internal` 带它：400。 |
| 上限 | `IDP_EXTERNAL_MAX_DESCRIPTION_CAP`（缺省 8192）：超过的登记或修改被拒绝（400，写明上限与设置名）。**缺省值必须不超过上限，两者启动时都校验**，不合格则注册服务不启动。 |
| 登记后可否改 | **可以，且要被评审**：`PATCH /api/v1/servers/{id}`，请求体 `{"maxDescriptionBytes": 数字或 null}`（null = 回到部署缺省），运维可做。改成与现在相同的值什么也不变。有变化时：写审计 `server.update`（新值、旧值、改前的生命周期），服务器退回 `DRAFT`，所以必须重新发现（按新上限检查）、重新批准（四眼：批准人不是创建人）；已经做好的 Release 仍用它钉住的目录。**理由**：上限决定评审人要读多长的指令文字，放宽它与改目录同样需要评审；不让改则只能重新登记，丢掉审计与批准的连续性。 |
| 记录与展示 | 登记的值进审计 `server.register`（`maxDescriptionBytes`，缺省为 null）；服务器记录多 `maxDescriptionBytes`（null = 缺省）；评审接口 `GET /api/v1/servers/{id}/catalog` 多 `descriptionLimit {bytes, deploymentDefault, cap, serverSetting}`（"允许到 `bytes` 字节，部署缺省 `deploymentDefault`"，internal 为 null）；每个快照多 `descriptionLimit`，是它的目录被检查时用的上限，**批准即钉住**（`approved.descriptionLimit`），审计 `server.discover` 也写。 |
| 用在哪 | 描述限制只在注册服务里检查，发现与重新发现是同一处（`DiscoverServer`），都用这台服务器的上限（自己的，没有就部署缺省）。网关的漂移探测比较的是目录摘要，不检查描述长度，所以不需要这个值；一个批准后变长的描述改变摘要，被漂移检测拦截（D51-f），重新发现时又按同一上限检查。 |

**契约**：`idp.telos.mcp` 1.3.0 → **1.4.0**，只有向后兼容的新增，且只在注册服务的 API（`openapi.yaml` 1.4.0）：登记的可选 `maxDescriptionBytes`，`PATCH /api/v1/servers/{id}`，服务器的 `maxDescriptionBytes`，评审视图的 `descriptionLimit`，快照的 `descriptionLimit`。Release、Envelope、InvocationRecord 的 JSON Schema 没有变，只有版本号（`schema.json` 的 `$id`、标题与示例说明）随之升到 1.4.0。迁移 `0010_server_description_limit.sql`（两列，均可为空）。`idp-contracts/idp.telos.mcp/1.4.0` 的发布副本在那个仓库里放。升级：先升级注册服务（迁移 `0010`）；没有设置的服务器行为与此前完全一致。

| 去掉的控制（15.3） | 失败的测试 |
|---|---|
| 忽略服务器自己的上限（发现与重新发现用部署缺省） | `TestTheDescriptionLimitOfAnExternalServerIsTheOperatorsPerServerSettingUnderACap`（两种去法各一次） |
| 不检查上限 `CAP` | 同上 |
| internal 也接受该字段 | 同上 |
| 修改不使批准失效 | 同上 |
| 快照不记录上限 / 评审接口没有上限 | 同上 |
| 登记的审计没有值 / 修改不写审计 | 同上 |
| 启动时不校验缺省不超过上限 | 同上 |

**15.2 补正（2026-11-22，平台验收 PATH O 发现）：桥的端点不以 `/mcp` 结尾。** 桥每条连接一个端点 `<桥的地址>/mcp/<连接 id>`，而登记与重新发现用的 `CheckEndpoint` 要求路径以 `/mcp` 结尾，所以任何一条连接都登记不了（`endpoint must end in /mcp`）。现在：登记在桥的地址上的端点（`IDP_BRIDGE_ENDPOINTS` 匹配，`policy.Upstream.Bridges`）免于**这一条**路径规则，其余检查不变（主机白名单、开发模式外要 https、地址分类、不许有查询串；类别必须是 external 仍由注册服务单独强制）。没有指名桥的地址时，规则与此前相同。测试：`TestABridgeEndpointNeedNotEndInMcp`。契约、迁移、网关的行为都不变。

**没有做的**：
- **桥**（D-X1、D-X2）：凭据的引用与保管、旧版本协议、公网出口与地址规则、第三方地址形式（不以 `/mcp` 结尾）。本节只做网关里对"外部"这一类上游的强制；没有桥，现在也没有任何方式让网关连到公网上的第三方服务。
- **按上游各自的限流、并发上限与熔断**（S8）：是桥的事（对第三方服务的出口在桥上）。网关侧只有 D49 的按客户端、按成员的限流。
- **HOST 读标记**（D-X5）：idp-host 的下一个任务；标记的形式见 D51-h 与本仓库的报告。
- **旧版本协议**与**凭据**：不在网关核心里（原则 1）。
- **漂移检测的局限**：见 D51-f；一个上游可以诚实地回答探测、对调用另做别的事。所以真正的控制是 D51-e 和"结果一律不可信"（HOST 的不可信标记、D51-c、D51-d），不是探测。
- external 目标的 `tasks` 与资源订阅（D50）：不支持，需要时另行设计。
- 描述与 schema 文字的**语义**检查（"这段话像不像指令"）：不做；只限长度和不可见字符，其余靠评审人读。
- 目录视图只在注册服务的接口里，没有网页界面。
- external 目标的 prompts 与 resources 的标记，以及对它们的参数校验。
- 登记时（而不是发现时）的描述长度检查：登记时还不知道描述。

**验证**（2026-11-19，WSL）：
- 测试用的恶意上游 `tests/fixtures/hostileserver`：记录收到的一切（头和正文），可以在描述里放指令、批准后改目录（描述、schema、新工具）、对探测返回批准的目录而对调用接受任何东西、返回超大结果与没有尽头的流（注释行、一行不换行、一个事件由很多短行组成）、发采样与征询请求（流里的、整个应答的、`input_required`）、自己发标记、慢、不可达、探测返回 503、垃圾或错误。
- 网关的测试（`internal/gateway/external_test.go`）：上游收到的内容里没有主体、租户、角色、客户端信息、追踪号、自定义 `_meta` 键，探测也一样；内部目标仍然收到（回归）；不合格的参数不转发，external 是工具错误、内部仍是协议错误（回归）；超大结果与无尽的流被截断并写审计，网关停止读取，堆没有随上游的输出增长，内部目标的同样大小的结果完整通过（回归）；反向请求被拒绝并写审计，客户端什么也看不到，内部目标仍然中继（回归）；漂移（描述、schema、新工具；`driftAction` 的 block 与 report 两种）拦截并在改回后恢复，内部目标仍只在 block 时拦截且审计记录没有多出 `reason`（回归）；探测失败（不可达、无效应答、错误应答）在阈值后拦截、状态里看得到、一次成功的探测解除，内部目标不被拦（回归）；从没核对过的目标被拦；标记（上游自带、写反了、与自己的键并存）；只有 HOST 客户端看得到、调得到，运维的例外有理由并进审计；桥地址；`Mcp-Param-*`。
- 注册服务与 Release 的测试：类别的往返与摘要不变，桥地址的匹配，描述限制，差异。集成测试（`tests/integration/external_test.go`，真实 PostgreSQL）：登记规则、发现时的描述限制、评审视图、批准必须带摘要、Release 钉住类别并去掉 tasks 能力、网关里只有 HOST 的客户端看得到并带标记、超大结果的审计经注册服务存下、漂移后的拦截在注册服务的网关状态里看得到、新目录的差异显示改变的描述。
- `make test`（含 `-race`、gofmt、vet）与 `make test-integration` 通过；官方符合性 37/37 个计分场景通过，tasks 扩展 8/8（参考服务器用的是主检出里已构建的那份，只读）。

**反向验证**：每个控制手工去掉一次，对应的测试失败，再恢复（共 39 项；第一次去掉时有五项没有测试失败或没能编译，补了测试后重做）：

| 去掉的控制 | 失败的测试 |
|---|---|
| D52 hostOnlyByRelease | `TestEverythingOfAnExternalTargetIsHostOnlyBecauseOfItsClassAndNothingElseIs`、`TestOnlyTheHostClientSeesAnExternalTargetsToolsUnlessTheOperatorSaysOtherwise` |
| D51a identity for external (stampCaller used) | `TestProgressIsRelayedForTheCallsOwnTokenAsNumbersOnly`、`TestTheExternalClassForcesNoIdentityEvenWhenTheTargetSaysForward`、`TestTheExternalUpstreamReceivesNoIdentityNoClientInfoNoTraceAndNoCustomMeta` |
| D51b _meta allow-list (client _meta kept) | `TestTheExternalClassForcesNoIdentityEvenWhenTheTargetSaysForward`、`TestTheExternalUpstreamReceivesNoIdentityNoClientInfoNoTraceAndNoCustomMeta` |
| D51b clientCapabilities forwarded as sent | `TestTheExternalClassForcesNoIdentityEvenWhenTheTargetSaysForward`、`TestTheExternalUpstreamReceivesNoIdentityNoClientInfoNoTraceAndNoCustomMeta` |
| D51b trace headers sent | `TestTheExternalUpstreamReceivesNoIdentityNoClientInfoNoTraceAndNoCustomMeta` |
| D51b probe carries clientInfo and trace | `TestTheExternalUpstreamReceivesNoIdentityNoClientInfoNoTraceAndNoCustomMeta`、`TestTheProbeOfAnExternalTargetCarriesNoClientInfoAndNoTrace` |
| D51b registry discovery carries clientInfo | `TestAThirdPartysServerIsRegisteredReviewedPinnedAndRestricted` |
| D51 e arguments not validated for external (tool error removed) | `TestExternalArgumentsThatDoNotMatchThePinnedSchemaAreNotForwardedAndTheModelGetsAToolError` |
| D51 e arguments not validated at all | `TestArgumentsAreValidatedBeforeDelivery`、`TestExternalArgumentsThatDoNotMatchThePinnedSchemaAreNotForwardedAndTheModelGetsAToolError`、`TestInternalArgumentsThatDoNotMatchAreStillAProtocolError` |
| D51 c input_required result accepted | `TestRequestsFromTheExternalServerAreRefusedAuditedAndNeverReachTheClient` |
| D51 d plain result limit | `TestAnOversizedPlainResultIsCutWithAToolErrorAndAnAuditRecord` |
| D51 d stream total limit | `TestAStreamThatNeverEndsIsCutAtTheTotalAndTheGatewayStopsReading` |
| D51 f drift blocks only per driftAction (external) | `TestADriftedExternalCatalogBlocksCallsWhateverTheDriftActionSaysAndRecovers` |
| D51 f failed probes never block | `TestProbeFailuresBlockAnExternalTargetAfterTheThresholdAndASuccessfulProbeClearsIt` |
| D51 f unverified/pending target not blocked | `TestAnExternalTargetThatWasNeverVerifiedIsBlockedUntilItIs` |
| D51 f block at threshold 1 (counts wrongly: never clears) | `TestProbeFailuresBlockAnExternalTargetAfterTheThresholdAndASuccessfulProbeClearsIt` |
| D51 f completion not blocked for external | `TestCompletionOfABlockedExternalTargetIsRefusedToo` |
| D51 h marker set for external | `TestTheExternalMarkerIsTheGatewaysAloneForAnyUpstream`、`TestTheMarkerIsSetForEveryToolOfAnExternalTargetAndNeverForAnInternalOne` |
| D51 h upstream's own marker kept for internal | `TestTheExternalMarkerIsTheGatewaysAloneForAnyUpstream`、`TestTheMarkerIsSetForEveryToolOfAnExternalTargetAndNeverForAnInternalOne` |
| D51 h upstream's own marker value kept for external | `TestTheExternalMarkerIsTheGatewaysAloneForAnyUpstream`、`TestTheMarkerIsSetForEveryToolOfAnExternalTargetAndNeverForAnInternalOne` |
| D50 gateway refuses an internal target at a bridge address | `TestAReleaseWithAnInternalTargetAtABridgeAddressIsRefusedAtActivation` |
| D50 release refuses external with identity | `TestTheReleaseRefusesAnExternalTargetWithIdentityOrRelayedCapabilities` |
| D50 release refuses external with tasks/subscribe | `TestTheReleaseRefusesAnExternalTargetWithIdentityOrRelayedCapabilities` |
| D50 registry: class required at a bridge address | `TestAThirdPartysServerIsRegisteredReviewedPinnedAndRestricted` |
| D50 registry: external with identity forward | `TestAThirdPartysServerIsRegisteredReviewedPinnedAndRestricted` |
| D53 registry: description limit | `TestAThirdPartysServerIsRegisteredReviewedPinnedAndRestricted`、`TestTheDescriptionsOfAnExternalCatalogAreBoundedAndHaveNoInvisibleText` |
| D53 registry: schema descriptions not checked | `TestTheDescriptionsOfAnExternalCatalogAreBoundedAndHaveNoInvisibleText` |
| D53 registry: approval of external needs the digest | `TestAThirdPartysServerIsRegisteredReviewedPinnedAndRestricted` |
| D53 registry: stale digest refused | `TestAThirdPartysServerIsRegisteredReviewedPinnedAndRestricted` |
| D53 registry: catalog shows full tools (annotations dropped) | `TestAThirdPartysServerIsRegisteredReviewedPinnedAndRestricted` |
| D51 g Mcp-Param headers forwarded | `TestMcpParamHeadersAreForwardedToAnExternalTargetToo`、`TestToolsCallIsRoutedUnderTheNativeName` |
| D51 c reverse request in stream relayed | `TestRequestsFromTheExternalServerAreRefusedAuditedAndNeverReachTheClient` |
| D51 c reverse request / input_required as whole answer relayed | `TestRequestsFromTheExternalServerAreRefusedAuditedAndNeverReachTheClient` |
| D51 d event/line limit | `TestTheLimitOfOneEventHoldsWhateverShapeTheEventHas` |
| D51 d event data limit | `TestTheLimitOfOneEventHoldsWhateverShapeTheEventHas` |
| D51 c foreign progress tokens relayed | `TestProgressIsRelayedForTheCallsOwnTokenAsNumbersOnly` |
| D50 compile keeps tasks/subscribe capabilities | `TestAThirdPartysServerIsRegisteredReviewedPinnedAndRestricted` |
| D53 registry: invisible characters | `TestAThirdPartysServerIsRegisteredReviewedPinnedAndRestricted`、`TestTheDescriptionsOfAnExternalCatalogAreBoundedAndHaveNoInvisibleText` |
| D53 registry: diff reports changes | `TestAThirdPartysServerIsRegisteredReviewedPinnedAndRestricted`、`TestTheDiffOfTwoCatalogsNamesWhatChanged` |

