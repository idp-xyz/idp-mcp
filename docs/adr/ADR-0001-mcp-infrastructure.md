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
| D8 | **连接上游时再检查一次地址**：在 `net.Dialer.Control` 中检查实际连接的 IP，与注册时的 SSRF 规则相同（公网 https；dev 模式允许回环；精确主机名可以解析到私有地址；metadata、link-local、CGNAT 等一律拒绝） | 补上 DNS 重绑定的缺口 |
| D9 | **多租户隔离由 PostgreSQL RLS（FORCE）执行**：每个事务设置 `app.tenant_id`，所有租户表上都有策略；只有网关凭据表在租户确定之前查询，因此不加 RLS。服务以非超级用户、非 BYPASSRLS 的角色运行，启动时检查，不满足就拒绝启动；审计表和调用记录表对服务角色只授予 INSERT/SELECT | 隔离不依赖每条 SQL 都记得写租户条件。**注意：目前 RLS 是唯一的一层**，应用层 SQL 没有再写 `WHERE tenant_id`（集成测试中关闭 RLS 后，跨租户读取立即出现）；是否补应用层条件作为第二层，待定 |
| D10 | **四眼原则**：服务器审批、授权审批、Release 审批，审批人都不能是创建人 | 创建与审批分离是最低限度的制衡 |
| D11 | **调用审计不记录参数原文**：每次 `tools/call` 记录主体、目标、工具、判定、结果、耗时、trace_id，以及参数的规范化摘要；网关批量推送给注册服务 | 可以关联，又不留存业务数据 |
| D12 | **只支持 MCP 2026-07-28 modern 模式**：只接受 `POST /mcp`；`MCP-Protocol-Version` 必须是 2026-07-28；`_meta` 信封必须完整；拒绝旧握手 | 旧握手与旧传输只增加攻击面，没有业务需要 |
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
| D43 | **这一跳本身仍然没有认证**：上游靠"只有网关能到达它的私网"相信网关（与此前一样）；转发身份没有改变这一点，也没有给身份签名 | 签名需要网关与上游之间的密钥分发，是另一个决策；这里只解决"上游能知道是谁"，不解决"上游能证明是网关告诉它的" |

**契约**：`idp.telos.mcp` 1.0.0 → **1.1.0**，只有向后兼容的新增（Target 的可选 `identity`，枚举只有 `forward`）。OpenAPI 1.1.0 的 `identity` 同理。迁移 `0007_server_identity.sql`。

**验证**：release 的单元（省略与摘要、未知取值被拒、`IdentityOf`）；网关的单元（转发、伪造被覆盖、默认不转发、不改动输入）；契约一致性测试；idp-sandbox 的端到端经真实的注册服务与网关验证了整条链（以该服务器 `identity: forward` 注册，沙箱按调用者隔离工作区）。
