# idp-mcp on Kubernetes

状态：**清单已写出并做了一致性检查（`go test ./tests/deploy/`），没有在集群上应用过**：参考主机没有集群。下一步是 `kubectl apply --dry-run=server -k deploy/kubernetes`。

## 拓扑

| 对象 | 说明 |
|---|---|
| `idp-mcp-registry` Deployment（2 副本）+ Service `:8250` | 控制面。HTTPS；`/internal/v1` 另要求网关的客户端证书（mTLS），证书的 URI SAN `spiffe://idp-mcp/gateway/<gateway id>` 必须与凭据对应的网关一致 |
| `idp-mcp-gateway-edge-1` Deployment（**1 副本**）+ Service `:3220` | 数据面。注册服务按网关 id 记录一份自证状态，两个副本共用一个 id 会互相覆盖心跳；要横向扩展就再建一个网关记录（一个 Deployment），放在同一个 Ingress 之后 |
| `idp-mcp-migrate` Job | 以 schema 所有者运行迁移；注册服务启动时检查 schema 版本，不匹配就拒绝启动，所以先跑 Job 再滚动更新 |
| NetworkPolicy | 默认拒绝，再逐条放行：网关 ↔ 注册服务、注册服务 → PostgreSQL、二者 → 上游 MCP 服务器（命名空间标签 `idp-mcp/mcp-upstream=true`）、二者 → IdP 的 JWKS、二者 → 采集器。网关入口只开放 3220，来自标签 `idp-mcp/mcp-clients=true` 的命名空间或 ingress 命名空间；metadata 地址没有任何放行 |
| Secrets（`secrets.example.yaml`） | 数据库连接、证书、网关 id 与凭据。只是占位，用你的密钥管理创建；不在 kustomization 里 |

## 步骤

1. 构建并推送镜像（`deploy/build.sh`），把 `kustomization.yaml` 的 `images` 改成镜像的 digest。
2. 创建 Secrets：数据库的两个连接串（服务角色、所有者）；注册服务的服务器证书与其 CA；签发网关客户端证书的 CA；上游 CA（可选）。证书用 cert-manager 更省事。
3. `kubectl apply -k deploy/kubernetes`，等 Job 完成、注册服务就绪。
4. 用管理员令牌 `POST /api/v1/gateways`（`authMode: jwt`，`resource` 为客户端访问网关的公开 URL），把返回的 `gatewayId` 和 `token` 写入 `idp-mcp-gateway-edge-1` Secret；给这个网关签发客户端证书（URI SAN 用 `gatewayId`）。网关 Pod 起来后会拉取期望状态并上报心跳。
5. 注册上游、审批、授权、编译并部署 Release（`api/openapi.yaml`）。

## 已知限制

- 没有集群实测，`kubeconform` 之类的 schema 校验也没有运行（参考主机上安装第三方二进制被拒绝）；`tests/deploy` 只检查清单之间的一致性与加固项。
- 一个网关记录一个副本。
- NetworkPolicy 中 IdP 和 PostgreSQL 的选择器是示例，要按实际部署改。
