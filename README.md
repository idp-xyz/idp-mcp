# idp-mcp

IDP TELOS 的 MCP 基础设施：`mcp-gateway`（数据面）和 `registry-service`（控制面）。只支持 MCP 2026-07-28 modern 模式。设计决策见 [`docs/adr/ADR-0001-mcp-infrastructure.md`](docs/adr/ADR-0001-mcp-infrastructure.md)。

状态：**M1–M5 已完成并实测**：工具 / prompts / resources 全部钉住并联邦，completion / subscriptions / tasks 联邦，参数校验，TLS/mTLS，OpenTelemetry 与 Prometheus 指标，多副本自证，OpenAPI，Kubernetes 清单；官方符合性 37/37，官方 tasks 扩展场景 8/8；与生产模式 Keycloak 联调（授权码 + PKCE、RFC 8693 标准交换与委派）。Kubernetes 清单未在集群上应用过。

## 组成

```
注册服务 registry-service（/api/v1 管理 API，/internal/v1 网关接口，PostgreSQL + RLS）
   │  不可变 Release（规范化 JSON + SHA-256）：期望状态 ↓   心跳自证、调用记录 ↑
网关 mcp-gateway（/mcp）：准入 → 认证（API Key / JWT+JWKS）→ 授权 → 钉住的工具目录 / 路由 → 上游
```

- **Release** 由已批准的服务器快照、已批准的授权和网关的认证配置编译而成，必须经他人审批后才能部署。网关只运行通过摘要校验的 Release。
- **工具、prompts、resources 的定义钉在 Release 里**：列表不透传上游，只有钉住的名字和 URI 可用。网关定期比对上游的实时目录，发现漂移（rug pull）后默认封锁该目标。
- **参数按钉住的 `inputSchema` 校验**（JSON Schema 2020-12，不加载外部引用），不合格的调用不会到达上游。
- **部署要有网关的证明**：网关上报正在运行的摘要和各目标状态，全部 OK 才判为 GOOD；否则判为 FAILED，期望状态自动退回上一个 Release。
- **租户隔离**由 PostgreSQL RLS（FORCE）执行。服务角色不能是超级用户或 BYPASSRLS（启动时检查）。审计和调用记录对服务角色只能追加。
- **连接上游时再检查一次地址**（防 DNS 重绑定），并且只允许 Release 中批准的网络类别（公网 / 私网 / 回环）。
- **订阅与任务不扩大权限**：`subscriptions/listen` 只中继调用者有权看到的通知，流不超过凭据寿命；tasks 只对创建者路由。
- **全链路 TLS**：管理 API 与数据面可配 HTTPS；网关对注册服务可用 mTLS，证书绑定到网关凭据；各出口的 CA 分开配置。
- **多副本**：同一网关记录的副本各自自证，部署只有在所有存活副本都运行该 Release 时才判 GOOD。
- **谁代表谁**：JWT 的 `azp` 与 `act`（RFC 8693 委派）进调用审计。
- **按客户端授权，缺省什么都看不到**：令牌里的 OAuth 客户端（`azp`）要列在网关的客户端文件里，工具对一次调用可见，要同时满足角色允许、客户端允许；没列出的客户端通过了认证也看不到任何东西。见下面"客户端准入"。

## 客户端准入（ADR-0001 第 14 节）

网关**不带客户端文件就不启动**（`IDP_GATEWAY_CLIENTS_FILE`，YAML 或 JSON）。文件列出网关服务的 OAuth 客户端（令牌的 `azp`），说明谁是 HOST、哪些工具只许 HOST 调用、限流是多少：

```yaml
clients:
  idp-host: {kind: platform, host: true}                    # HOST：按成员的角色看见和调用，也是唯一能调用"只许 HOST"的工具的客户端
  idp-workspace: {kind: platform}                           # 平台自己的客户端：看见其用户的角色允许的一切（"只许 HOST"的除外）
  partner-docs:                                             # 外部客户端：角色允许、并且这里列了才可见
    kind: external
    servers: [docs]                                         # 这些服务器的全部工具、prompts、resources
    tools: ["wiki__search*"]                                # 再加这些工具（path.Match 语法，对外暴露的工具名；与 HOST 的 externalTools 同一种写法）
hostOnlyTools: ["web__*"]                                   # 只许 HOST 调用的工具；网关不内置任何缺省，由部署写
hostOnlyExcept:                                             # 运维对个别工具的例外；理由必填，每次使用都写进审计
  - {pattern: "web__web_search", reason: "安全组 2026-11 批准，工单 SEC-17"}
rateLimits:                                                 # 只套在外部客户端和没列出的客户端上，每个副本各自计数；下面是缺省值
  perClient: {requests: 600, window: 1m}
  perSubject: {requests: 120, window: 1m}
```

- 没列出的客户端、没有 `azp` 的令牌：`tools/list`、`prompts/list`、`resources/list` 给空列表，所有调用得到与"工具不存在"相同的应答，每一次都进审计（原因 `client not listed`）。
- 想保持原来的行为（服务每一个客户端）：写 `"*": platform`。**这等于关掉这项控制**，网关启动时会告警；只用于开发和还没有清单的过渡期。
- API Key 的客户端是 `api-key:<密钥 id>`，要像别的客户端一样列出（或用上面的 `"*"`）。
- 外部客户端的 `tools` 只授予工具；prompts 和 resources 只能按服务器授予（`servers`）。
- 文件里写错一个字段名、模式或种类，网关拒绝启动，并说明哪一项错了：拼错的 `hostOnlyTool` 不会悄悄让控制失效。
- 限流：平台客户端缺省没有任何限制（HOST 替所有成员调用，服务账号在一个 subject 下跑很多执行）；外部客户端用 `rateLimits` 的缺省，可用条目里的 `rateLimit`（每客户端）、`subjectRateLimit`（每成员）覆盖，平台客户端也可以用它们给自己加上限；没列出的客户端永远受缺省限制。
- 被限流的请求得到 HTTP 429、`Retry-After` 和 JSON-RPC 错误 -32029，并进审计（`RATE_LIMITED`）。

升级说明：见 ADR-0001 第 14 节。先升级注册服务（迁移 `0008`，契约 1.2.0），再升级网关；**网关没有客户端文件就不再启动**。

## 第三方的服务器（ADR-0001 第 15 节）

登记服务器时可以写 `class: external`（缺省 `internal`，行为与此前相同）。它表示这是第三方的、不是我们写的服务器；类别在登记时定下，进入 Release、由审批人批准，要改就重新登记。`IDP_BRIDGE_ENDPOINTS`（注册服务与网关各设一份，缺省为空）列出桥的地址（主机、`主机:端口` 或 http(s) 地址前缀，逗号分隔）：登记在这些地址上的服务器必须写 `external`，否则登记被拒绝。

对 `external` 的目标，网关无论登记里怎么写，都强制做下面这些：

| 设置 | 缺省 | 作用 |
|---|---|---|
| `IDP_GATEWAY_EXTERNAL_MAX_RESULT_BYTES` | 1048576 | 一次应答、流里的一个事件的上限；超过则调用以工具错误结束并进审计（`RESULT_TOO_LARGE`） |
| `IDP_GATEWAY_EXTERNAL_MAX_STREAM_BYTES` | 4194304 | 一条流一共能传多少字节（注释行和保活行也算） |
| `IDP_GATEWAY_EXTERNAL_PROBE_FAILURES` | 3 | 连续这么多次目录探测失败（不可达、应答无效），或目录从未核对过，就拦截对它的调用，直到一次探测找到批准的目录；探测周期是 `IDP_DRIFT_INTERVAL`（缺省 60 秒），即约 3 分钟 |
| `IDP_EXTERNAL_MAX_DESCRIPTION`（注册服务） | 1024 | 目录里每一处描述（工具、prompt、输入与输出 schema 里的 `description` 与 `title`）的字节上限；含零宽、方向控制等不可见字符的也拒绝。超过则发现失败，并写明是哪个工具 |

- 不转发调用者：身份模式必须是 `none`（登记时拒绝 `forward`，网关发送时再强制一次）；`_meta` 只放行协议版本、空的客户端能力和进度令牌，`clientInfo`、自定义键、追踪上下文一律不发，探测也不带。
- 上游发来的采样、征询等请求不转发给客户端，调用以工具错误结束并进审计（`REVERSE_REQUEST_REFUSED`）；调用参数先按评审时钉住的输入 schema 校验，不合格的不发送，客户端得到模型能读懂并改正的工具错误。
- `tools/list` 里每个这类工具的 `_meta` 都带 `"io.idp.telos/external": true`，由网关按钉住的类别写入，上游自己发的同名键被覆盖或删除；内部的工具永远没有。这类目标的工具、prompts、资源缺省只许 HOST 调用。
- 评审人用 `GET /api/v1/servers/{id}/catalog` 看每个工具的完整描述、输入 schema、注解，以及与已批准目录的差异（新增、删除、哪些字段变了）；批准外部服务器的请求必须带上看过的目录摘要（`{"digest": ...}`）。

升级说明：见 ADR-0001 第 15 节。契约 1.3.0，迁移 `0009`；先升级注册服务，再升级网关，最后登记第一台外部服务器。

## 目录

| 路径 | 内容 |
|---|---|
| `cmd/mcp-gateway`、`cmd/registry-service` | 两个可执行程序（配置见各自文件头部的注释） |
| `internal/server`、`transport`、`client` | MCP 2026-07-28 协议、Streamable HTTP、上游客户端 |
| `internal/release`、`federation`、`routing` | Release 契约、目录规范化与摘要、工具路由 |
| `internal/authorization`、`policy` | 授权判定、上游网络策略 |
| `internal/gateway` | 数据面主体、漂移检测、与注册服务的同步 |
| `internal/registry`、`audit` | 控制面领域逻辑与 HTTP API、审计 |
| `internal/invocation`、`observability` | 调用审计批量推送、日志、OpenTelemetry（自写的 OTLP/HTTP JSON 导出器，无 gRPC） |
| `api/openapi.yaml` | 注册服务的 OpenAPI 3.1（测试保证与路由一致） |
| `api/contracts/` | 对外发布的契约 `idp.telos.mcp` 1.0.0（Release、Envelope、InvocationRecord 的 JSON Schema；示例由 Go 值生成）。`go test ./internal/release -run TestContract` 保证它与实现一致；发布副本在 `idp-contracts/idp.telos.mcp/1.0.0`，必须与这里逐字节相同 |
| `adapters/identity`、`adapters/store/postgres` | 身份（API Key、JWT/JWKS、管理令牌）、数据库与迁移执行 |
| `migrations/` | 数据库结构（含 RLS 策略） |
| `tests/integration`、`tests/e2e` | 真实 PostgreSQL 上的进程内全链路测试；compose 拓扑上的端到端测试 |
| `deploy/` | 镜像（scratch，约 27 MB）、compose 拓扑、端到端驱动脚本、Kubernetes 清单（`deploy/kubernetes`，由 `tests/deploy` 做一致性检查） |

## 使用

```bash
make test               # gofmt、vet、单元测试（-race）
make test-integration   # 在 Docker 中起一个临时 PostgreSQL，跑全链路集成测试
make conformance        # 官方 MCP 符合性套件（2026-07-28，37 个服务器场景），经网关运行
bash deploy/e2e.sh      # 构建镜像，起 compose 拓扑（真实 MCP SDK 上游），跑端到端测试；KEEP=1 保留环境
MODE=jwt bash deploy/e2e.sh   # 同上，身份来自 Keycloak：管理 API 走 JWKS，数据面走 OAuth bearer JWT
MODE=oidc bash deploy/e2e.sh  # 生产模式 Keycloak（TLS、PostgreSQL）+ 全链路 TLS：真实用户授权码 + PKCE 登录，RFC 8693 标准交换与委派
go test ./internal/release -run TestContract -update   # 改了 Release / InvocationRecord 后重新生成契约示例（api/contracts/examples.json）
```

CI 与 `deploy/e2e.sh` 里的第三方镜像（PostgreSQL、Keycloak、trivy、测试替身的基础镜像）先由 `deploy/pull-image.sh` 显式拉取并重试（最多 5 次，间隔 15、30、60、120 秒；本机已有则跳过），因为公共 registry 对匿名拉取按来源地址限流，而 CI 的 runner 与许多项目共用地址。

`deploy/e2e.sh` 需要 `idp-fixture-upstream:local` 镜像（两个真实 MCP SDK 上游的测试替身），由 `bash deploy/fixtures/build.sh` 构建；来源见该脚本头部。

## 实测结果（2026-11-02，WSL，Go 1.26.8）

| 项 | 结果 |
|---|---|
| 单元测试 | 13 个包全部通过（`-race`） |
| 集成测试（真实 PostgreSQL 17） | 通过：注册 → 发现 → 四眼审批 → 授权 → 部署后网关自证 GOOD → MCP 调用 → 调用审计；租户隔离；上游篡改后被封锁，部署失败并自动退回，重新审批后恢复 |
| compose 端到端（Node SDK 与 Python SDK 的真实服务器） | **13/13**（含 prompts / resources 联邦）；部署到 GOOD 用时 3.8 s；宿主机只开放 3320 和 8250 |
| 官方符合性（2026-07-28，37 个服务器场景） | **37/37**，走正常的 API Key 认证路径（见 ADR 第 7 节的测试方法） |
| 官方 tasks 扩展场景（SEP-2663，8 个场景 42 项检查） | 直接打 Go 参考任务服务器 **8/8**，经网关 **8/8** |
| 生产模式 Keycloak 联调（`MODE=oidc`） | **12/12**：全链路 TLS；授权码 + PKCE；标准令牌交换与委派（`act`）；审计区分用户直接、代理交换、代理委派 |
| 多副本自证（集成测试） | 全部存活副本一致才 GOOD；落后副本被点名并回退；过期副本不计入 |
| 与真实 Keycloak 26.8.1 的 JWT 端到端 | **17/17**：管理 API 用 JWKS 校验；RFC 9728 发现；按身份、租户和受众正确放行或拒绝；拒绝篡改的令牌；参数校验（ADR 第 8 节） |
| TLS 全链路（集成测试） | 管理 API 经 TLS；网关 ↔ 注册服务 mTLS，证书与凭据绑定（只有令牌、或别的网关的证书都被拒）；私有 CA 的 https 上游；https 数据面 |
| Kubernetes 清单 | 一致性检查通过；**未在集群上应用** |
| 变异检查 | 分别关闭工具授权、prompt 授权、参数校验、四眼原则、RLS、证书绑定、task 归属判定，以及削弱清单加固，相应测试都会失败 |
| 指标 | `IDP_METRICS_LISTEN` 上的 Prometheus 文本格式；标签不含主体、令牌、参数、URI |

## 尚未完成

见 ADR 第 6–10 节。主要是：Kubernetes 清单未在集群上实测；委派是 Keycloak 的预览特性，`may_act` 需逐个代理配置；tasks 的真实上游是自写的参考实现；多副本合并没有分批发布语义；指标不含租户维度。

## 许可证

本仓库采用 [PolyForm Noncommercial License 1.0.0](LICENSE)：允许非商业用途，禁止任何商业使用。
