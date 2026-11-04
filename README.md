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
