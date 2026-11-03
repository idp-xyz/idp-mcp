# ADR-0001　MCP Infrastructure 的 Go 重新设计

| 项 | 内容 |
|---|---|
| 状态 | 草案（2026-11-02），待决策人确认 |
| 范围 | `idp-telos-go/idp-mcp`：MCP 网关（数据面）与注册服务（控制面） |
| 依据 | 决策人 2026-11-02 的选择：先做 MCP；重新设计，不受 Python 版约束；工程结构按《IDP TELOS Repository & Engineering Architecture v1.0》；完全重构 |
| 参考 | Python 版 `idp-telos/idp-mcp`（只作为经验来源，不是兼容目标）；MCP 规范 2026-07-28 |

## 1. 背景

Python 版由 FastAPI 控制面、Python 写的 Modern Boundary 和 agentgateway 1.6.0 组成。实测留下的教训：

- 两跳数据面（Boundary → agentgateway）。agentgateway 不能只绑定回环地址，为此先后做了私有 netns、Unix socket 中继和 pod-guard 三层补偿。
- 授权规则要先编译成 agentgateway 的 CEL 才能执行；拒绝的语义只能事后从网关的返回形态去推断（"Unknown tool"）。
- 网关直接透传上游的 `tools/list`：审批之后上游如果改了工具描述（rug pull），网关看不到。
- SSRF 检查只在注册时做，网关连接上游时会重新解析 DNS（文档里承认的缺口）。
- 多租户只靠应用层过滤，没有 RLS。

## 2. 决策

| # | 决策 | 理由 |
|---|---|---|
| D1 | **自研 Go 数据面**：准入、认证、授权、联邦、调用审计都在 `mcp-gateway` 一个进程内完成，单跳 | 去掉 agentgateway 带来的绑定、配置渲染和拒绝语义问题；代价是协议符合性（官方 37 项）要重新挣，放在第二阶段的门禁里 |
| D2 | **控制面与数据面通过不可变 Release 交互**：注册服务把已批准的内容编译成 Release（规范化 JSON + SHA-256）；网关拉取期望状态，或者读本地文件（离线、本地部署） | 网关不连数据库；Release 可以审计、回滚、离线分发 |
| D3 | **工具目录钉在 Release 里**：网关的 `tools/list` 直接用 Release 中审批过的工具定义，不透传上游。网关定期比对上游的实时目录摘要，出现漂移就默认封锁该目标 | 防止审批后上游篡改工具描述或参数结构 |
| D4 | **网关自证运行态**：网关心跳上报正在运行的 Release 摘要和各目标的漂移状态。注册服务据此判定 GOOD/FAILED，失败时自动把期望状态退回上一个 GOOD | 替代 Python 版通过 admin.sock 读 `/config_dump`；网关不暴露管理端口 |
| D5 | **授权原生执行**：Release 中的授权（租户 + 角色 + 工具）由网关直接判定；`tools/list` 按调用者过滤；未授权的调用与不存在的工具返回完全相同的错误 | 不依赖网关产品的表达式语言；防止枚举工具目录 |
| D6 | **一个网关实例只服务一个租户**：网关记录属于某个租户，Release 属于某个网关 | 隔离简单清楚；SaaS 部署按租户起多个实例 |
| D7 | **对外工具名为 `<target>__<tool>`**：target 只允许 `[a-z0-9-]`，所以第一个 `__` 一定是分隔符 | 名字可以无歧义地拆回 (target, tool)，并且符合常见客户端对函数名字符集的限制 |
| D8 | **连接上游时再检查一次地址**：在 `net.Dialer.Control` 中检查实际连接的 IP，与注册时的 SSRF 规则相同（公网 https；dev 模式允许回环；精确主机名可以解析到私有地址；metadata、link-local、CGNAT 等一律拒绝） | 补上 DNS 重绑定的缺口 |
| D9 | **多租户隔离由 PostgreSQL RLS（FORCE）执行**：每个事务设置 `app.tenant_id`，所有租户表上都有策略；只有网关凭据表在租户确定之前查询，因此不加 RLS。服务以非超级用户、非 BYPASSRLS 的角色运行，启动时检查，不满足就拒绝启动；审计表和调用记录表对服务角色只授予 INSERT/SELECT | 隔离不依赖每条 SQL 都记得写租户条件。**注意：目前 RLS 是唯一的一层**，应用层 SQL 没有再写 `WHERE tenant_id`（集成测试中关闭 RLS 后，跨租户读取立即出现）；是否补应用层条件作为第二层，待定 |
| D10 | **四眼原则**：服务器审批、授权审批、Release 审批，审批人都不能是创建人 | 沿用 Python 版行之有效的规则 |
| D11 | **调用审计不记录参数原文**：每次 `tools/call` 记录主体、目标、工具、判定、结果、耗时、trace_id，以及参数的规范化摘要；网关批量推送给注册服务 | 可以关联，又不留存业务数据 |
| D12 | **只支持 MCP 2026-07-28 modern 模式**：只接受 `POST /mcp`；`MCP-Protocol-Version` 必须是 2026-07-28；`_meta` 信封必须完整；拒绝旧握手 | 与 Python 版 G1 的结论一致 |
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
- 负面：协议符合性要从零做起；自研网关要自己负责性能和协议演进；与 Python 版的 API 和数据不兼容，没有迁移路径（按决策不需要）。

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

**符合性测试的方法**：官方运行器（`@modelcontextprotocol/conformance` 0.2.0-alpha.12，冻结的 2026-07-28 需求，37 个服务器场景）→ 测试夹具代理 → 网关（进程内）→ Python SDK 的 Everything Server。运行器不能携带凭据，所以夹具代理代为加上数据面 API Key，其余逐字节转发：Host 和 Origin 不改，流式响应即时转发。网关走的是正常的认证与授权路径，**产品中没有免认证模式**。Release 为单一目标、native 命名，所有工具、prompts 和 resources 都授权给该 Key 的角色。计分规则与 Python 版相同：出现 FAILURE、未知状态或没有任何 SUCCESS 都不计为通过。

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
