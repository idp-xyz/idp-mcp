# 开发指南：在 IDP TELOS 网关之后建一个领域 MCP 服务（以 CargoPai FIN 为例）

读者：自己开发并运维领域 MCP 服务的业务团队。目标：照本文做完，服务能被 idp-mcp 网关登记、评审、上线，并且不需要再问平台团队。

本文是指南，不是决策记录。每条规则都出自下面"来源"一节列出的文件；与来源不一致时以来源为准，并请告诉我们改本文。来源没有定的事写在最后的"未决问题"里，本文不替平台猜。

状态说明（2026-11-25）：

- 调用者断言（第 3 节）、客户端准入、工具白名单、登记与评审流程已经实现。
- 结果敏感级别（第 5 节，idp-mcp D54、idp-host D64）**只是规则，尚未实施**。登记接口里还没有对应字段。
- FIN 的接口（`fin-eii.md`）目前只接受开发令牌，见第 4.1 节与未决问题 1。

## 0. 来源

| 简称 | 文件 |
|---|---|
| MCP-ADR | `idp-mcp/docs/adr/ADR-0001-mcp-infrastructure.md`（第 12、13、14、15、16 节：D40–D54） |
| 规范化与摘要 | `idp-mcp/internal/release/canonical.go`（`Canonical`、`Digest`） |
| 签名器 | `idp-mcp/internal/gateway/caller.go`（`CallerSigner.sign`、`RequestDigest`、`KeyID`、`stampCaller`） |
| Release 与目标 | `idp-mcp/internal/release/release.go`（`Target`：`Endpoint`、`Network`、`Identity`、`Class`、`Tools`；`Grant`） |
| 登记接口 | `idp-mcp/api/openapi.yaml`（`/api/v1/servers`、`/grants`、`/releases`） |
| 客户端准入、`hostOnlyTools` | `idp-mcp/README.md` 的"客户端准入"；MCP-ADR D46–D49 |
| 网关发往上游的请求 | `idp-mcp/internal/client/client.go`（`Headers`、`Meta`）、`idp-mcp/internal/gateway/mcp.go`（转发与超时）、`idp-mcp/internal/server/protocol.go`（`ProtocolVersion`） |
| 参考验签实现 | `idp-sandbox/internal/mcp/assertion.go`（`CallerVerifier.Verify`）、`idp-sandbox/internal/mcp/mcp.go`（`call`：403、豁免）、`idp-sandbox/docs/adr/ADR-0001-sandbox-design.md` D18 |
| 一致性向量 | `idp-contracts/vectors/caller-assertion/v1.json` 与同目录 `README.md`；各仓库副本 `idp-sandbox/internal/mcp/testdata/caller-assertion-v1.json`、`idp-web/internal/mcp/testdata/caller-assertion-v1.json`、`idp-mcp/internal/gateway/testdata/caller-assertion-v1.json`（逐字节相同） |
| 钉住的单条向量 | `idp-sandbox/internal/mcp/assertion_test.go`（`vectorKey`、`vectorAssertion`、`vectorDigest`、`vectorParams`、`TestTheGatewaysAssertionIsAccepted`） |
| 一阶上游示例 | `idp-web/docs/adr/ADR-0001-web-design.md` D2、D3、D15、D20、D24；`idp-web/internal/tools/tools.go`；`idp-web/internal/mcp/mcp.go`（结果的形状） |
| HOST 规则 | `idp-host/docs/adr/ADR-0001-host-design.md`：D7（确认）、D27（工具结果不可信）、D43/D44/D44-9（敏感上限、强制确认）、D47（中断后重发）、D63-9、D63-11、D64 |
| FIN 接口 | `/home/tops/workspace/idp-cargo/go_cargo/docs/api/fin-eii.md` |
| Go SDK | 见第 2 节的链接 |

## 1. 网关替你做什么，不替你做什么

### 1.1 网关做的

| 事项 | 说明 | 来源 |
|---|---|---|
| 认证成员 | 数据面的令牌（JWT）或 API Key；上游看不到这些凭据，网关不转发客户端凭据 | MCP-ADR D12、D40 |
| 客户端准入 | 令牌里的 `azp` 必须在网关的客户端文件里；没列出的客户端什么也看不到 | D46、D47 |
| 角色授权与工具白名单 | Release 的 `grants`：租户 + 角色 + 工具名。一个调用要同时通过角色与客户端两道 | D5、D46 |
| 钉住的目录与参数校验 | `tools/list` 只给评审时钉住的定义；每次 `tools/call` 的参数先按钉住的 `inputSchema` 校验，不合格的不转发（内部上游得到 JSON-RPC `-32602`） | D3、D51-e |
| 漂移封锁 | 上游的实时目录与批准的不同，网关封锁这个目标（`driftAction` 缺省 `block`） | D3 |
| 给转发的调用者签名 | 目标登记为 `identity: forward`，网关就在每个请求的 `_meta["io.idp.telos/caller-assertion"]` 里放它签的断言 | D40、D41、D44 |
| 抹掉伪造 | 客户端自带的 `io.idp.telos/caller` 与 `io.idp.telos/caller-assertion` 一律先删除 | D41、D44 |
| 审计与限流 | 每次调用记元数据与参数摘要，不记参数原文 | D11、D49 |
| 把你的工具标为"只许 HOST"（部署决定） | 由网关的 `hostOnlyTools` 模式决定；这样成员确认、敏感上限、不可信包装（都在 HOST）就绕不过 | D48 |
| HOST 一侧（不是网关，也不是你） | 工具结果包成不可信内容再交给模型；写工具调用等成员确认；按敏感级别筛选结果 | idp-host D27、D7、D44-9、D64 |

### 1.2 你的服务仍然必须做的

网关到你的这一跳可以是内网明文 HTTP（D45 后的"没有做的"一节）。网络上任何别的东西也能连到你的端口。所以：

1. **验签。** 没有有效断言的 `tools/call` 一律拒绝（第 3 节）。这是你的服务唯一知道"这是网关说的"的办法。
2. **按断言里的租户、主体、角色授权。** 网关的角色授权只决定"这个角色能不能调用这个工具"，不决定"这个人能看这家法人的哪些数据"。后者是领域规则，只有你知道。
3. **执行领域规则。** 金额、状态、幂等、不能自己批自己的申请，都在你和 FIN 一侧执行；不要指望模型或 HOST 的确认来保证。
4. **不信任网关之外的一切输入**，包括参数的类型、长度、范围（网关校验过一次，你仍要自己校验：网关的 schema 校验只覆盖 JSON Schema 能表达的部分，而且你要能脱离网关测试）。
5. **不泄露内部细节**（第 4.5 节）。

## 2. 推荐的技术栈

推荐用官方 Go SDK：`github.com/modelcontextprotocol/go-sdk`，**v1.7.0 或更高**。理由只有一个：它替你处理协议（`server/discover`、`tools/list`、`tools/call` 的信封、输入 schema 的生成与校验、`resultType`、错误形状）。写协议层容易错，而且网关的符合性要求很细（2026-07-28，MCP-ADR D12）。idp-sandbox 与 idp-web 是手写协议层的（各自的 ADR D1/D10），那是它们先于 SDK 支持新版本时的选择，不是你的建议。

**SDK 里没有的东西，本文第 3、4、5 节讲的全是**：调用者断言的验证、租户与主体的授权、`io.idp.telos/*` 的 `_meta` 键、结果敏感级别、平台的登记流程。这些要你自己写，不要去 SDK 里找。

要点（均为 v1.7.0 的实际 API，下面的链接可核对；本指南没有把 SDK 加进任何仓库）：

- 协议版本：网关只说 `2026-07-28`（`idp-mcp/internal/server/protocol.go` 的 `ProtocolVersion`；每个请求有 `MCP-Protocol-Version` 头与完整的 `_meta` 信封；**没有 initialize 握手**）。SDK README 的兼容表：v1.7.0 起支持 2026-07-28。
- 传输：Streamable HTTP，**只在 `StreamableHTTPOptions.Stateless = true` 时接受 2026-07-28**。源码注释：Stateless 服务器不读不写 `Mcp-Session-Id`，每个请求一个临时会话，GET 与 DELETE 返回 405；"新协议（>= 2026-07-28）只有在 Stateless 为 true 时才在 HTTP 传输上受支持"（`mcp/streamable.go`，v1.7.0）。网关总是用 `POST /mcp`，正好是这个模式。
- 创建：`mcp.NewServer(&mcp.Implementation{Name: "fin-mcp", Version: "…"}, nil)`；注册：泛型函数 `mcp.AddTool[In, Out](s, &mcp.Tool{…}, handler)`，处理函数形状是 `func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error)`。`In` 的 JSON Schema 由结构体推断并在调用时校验；`Out` 不是 `any` 时推断出 `outputSchema`，`Out` 的值成为 `structuredContent`。处理函数返回 `error` 时，SDK 自动把 `isError` 设为真并把错误文字放进 `content`（`ToolHandlerFor` 的文档）。底层的 `(*Server).AddTool(t, h)` 不做这些，不推荐。
- HTTP 处理器：`mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true})`。请求体上限缺省 4 MiB（`MaxRequestBodyBytes`）。
- 读 `_meta`：`req.Params.GetMeta()`（`CallToolParamsRaw` 内嵌 `Meta`），键如 `io.idp.telos/caller-assertion`。`req.Params.Arguments` 是原始 JSON。`req.Extra.Header` 给 HTTP 头。
- 工具标注：`mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: …, DestructiveHint: *bool, OpenWorldHint: *bool}`；注意 `DestructiveHint`、`OpenWorldHint` 是 `*bool`，缺省语义是"真"，所以只读的内部工具要显式写 `OpenWorldHint: ptr(false)`。

**不要用 `req.Params` 重组出请求再去算摘要**：`req.Params` 是 SDK 解出来的结构，可能丢字段或改写。摘要要对网关发来的原始 JSON-RPC 体算，所以验签放在 HTTP 中间件里，在 SDK 处理器之前（第 3.3 节）。

链接：

- https://github.com/modelcontextprotocol/go-sdk （README 的兼容表）
- https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk@v1.7.0/mcp （API）
- https://github.com/modelcontextprotocol/go-sdk/blob/v1.7.0/mcp/streamable.go （`StreamableHTTPOptions.Stateless` 的注释与 2026-07-28 的限制）

## 3. 验证调用者断言

### 3.1 断言是什么

登记时 `identity: forward`（第 6 节），网关给发往你的每个请求的 `_meta` 加两个键：

- `io.idp.telos/caller`：明文的 `{subject, tenant, roles, client?, actor?}`。**不要用它**。它没有签名；有签名的断言才可信（MCP-ADR D43、D44；idp-sandbox D18："通过后调用者取自断言，没签名的那份不再看"）。
- `io.idp.telos/caller-assertion`：一个紧凑 JWS（`header.payload.signature`，base64url 无填充）。

头：`alg` = `ES256`，`typ` = `idp-caller+jwt`，`kid` = 网关公钥的 RFC 7638 指纹。

声明（`idp-mcp/internal/gateway/caller.go` 的 `sign`）：

| 声明 | 含义 |
|---|---|
| `iss` | `idp-mcp-gateway:<网关 id>` |
| `aud` | 你在 Release 里的 `endpoint`，**字符串逐字相同**（登记时写的 URL，如 `http://fin-mcp:8600/mcp`） |
| `sub` | 成员的主体 |
| `tenant_id` | 租户 |
| `roles` | 角色列表，没有时是空列表 |
| `client`、`actor` | 可选：OAuth 客户端（`azp`）；RFC 8693 的委派方。用于你的审计，不用于授权 |
| `iat`、`exp` | 签发与过期，`exp - iat` = 60 秒 |
| `jti` | 随机 id，每次调用一个新的 |
| `req` | 这次请求的摘要（3.2） |

### 3.2 请求摘要 `req`

`req = "sha256:" + hex(SHA-256(规范化 JSON({"method": <方法>, "params": <params 去掉 _meta>})))`。

规范化（`idp-mcp/internal/release/canonical.go` 的 `Canonical`）：把值按通用 JSON 重新解码（数字保留原文，`UseNumber`）；再编码：对象键排序、无多余空白、**不转义 HTML**（`<`、`>`、`&` 保持原样，`SetEscapeHTML(false)`）、数字照原样（`5.0` 仍是 `5.0`）；去掉末尾换行。它不是 RFC 8785。摘要算的是 JSON 的**值**，不是字节：换空白、换键序、换字符转义写法，摘要不变（向量里有对应用例）。

只去掉 `params` 顶层的 `_meta`。`method` 是你正在处理的方法（`tools/call`），不是从别处读的。

### 3.3 逐步检查

下面每一步对应 `idp-sandbox/internal/mcp/assertion.go` 的 `Verify`，顺序与那里一致。**任何一步失败：拒绝，工具不运行**；不说明原因给调用者，原因只写日志（idp-sandbox D18）。

1. 有断言，长度不超过 8192 字节，恰好三段，三段都是 base64url（无填充）。
2. 头：`alg == "ES256"` 且 `typ == "idp-caller+jwt"`。别的 `alg`（含 `none`、`HS256`、`ES384`）一律拒绝。**不要让 JWT 库按头里的 `alg` 选算法。**
3. `kid` 在你持有的公钥里；没有就拒绝（不去别处取）。
4. 签名恰好 64 字节（r‖s，各 32 字节），用对应公钥验 ES256（对 `base64url(头) + "." + base64url(声明)` 的 SHA-256）。
5. 声明是 JSON 对象。
6. `aud`（字符串，或列表时含它）等于你自己的端点。
7. `exp` 存在，且现在不晚于 `exp + 30 秒`；`iat` 存在，且不晚于现在 `+ 30 秒`；`exp ≥ iat` 且 `exp - iat ≤ 5 分钟`（网关自己签的是 60 秒；容差与上限是 idp-sandbox 的取值，向量也按它）。
8. `sub` 与 `jti` 非空。
9. `req` 等于你对**这个请求**算出的摘要。
10. `jti` 没出现过；出现过就拒绝。只在前面所有检查都通过之后才记录，记到 `exp + 30 秒` 之后可以忘。
11. 通过后：调用者 = `{sub, tenant_id, roles, client, actor}`，**只取自断言**。

`tools/list` 与 `server/discover` 不需要调用者（网关的漂移检查没有调用者；idp-sandbox D18、idp-web D2）。所以中间件对这两个方法放行，对其余方法一律要求断言。（idp-sandbox 与 idp-web 只对 `tools/call` 检查，因为它们只有工具；FIN 服务没有 prompts 与 resources，把其余方法也要求断言是更严的做法，是本文的建议，不是沙箱的行为。）

`iss` 的检查：idp-sandbox 不检查 `iss`。见未决问题 4。

### 3.4 代码草图（Go，只用标准库）

下面是 `idp-sandbox/internal/mcp/assertion.go` 的精简改写，规则相同。可以直接复制那个文件，它有自己的测试。

```go
package finmcp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	MetaCallerAssertion = "io.idp.telos/caller-assertion"
	assertionType       = "idp-caller+jwt"
	skew                = 30 * time.Second
	maxTTL              = 5 * time.Minute
	maxAssertion        = 8192
)

type Caller struct {
	Subject, Tenant, Client, Actor string
	Roles                          []string
}

type Verifier struct {
	keys     map[string]*ecdsa.PublicKey // kid（RFC 7638 指纹）-> 公钥
	audience string                      // 本服务在 idp-mcp 里登记的 endpoint，逐字
	now      func() time.Time
	mu       sync.Mutex
	seen     map[string]int64 // jti -> 可以忘记的时刻（unix 秒）
}

// NewVerifier 读一个或多个 PKIX PEM 公钥（P-256）。轮换期间文件里放几把。
func NewVerifier(pemBytes []byte, audience string) (*Verifier, error) {
	if audience == "" {
		return nil, errors.New("no audience")
	}
	v := &Verifier{keys: map[string]*ecdsa.PublicKey{}, audience: audience, now: time.Now, seen: map[string]int64{}}
	for rest := pemBytes; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		k, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		pub, ok := k.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, errors.New("not an EC key on P-256")
		}
		kid, err := keyID(pub)
		if err != nil {
			return nil, err
		}
		v.keys[kid] = pub
	}
	if len(v.keys) == 0 {
		return nil, errors.New("no public key") // 没有公钥就不启动：失败关闭
	}
	return v, nil
}

func keyID(pub *ecdsa.PublicKey) (string, error) { // RFC 7638，与网关的 KeyID 相同
	raw, err := pub.Bytes() // 0x04 || X || Y
	if err != nil || len(raw) != 65 {
		return "", errors.New("not an uncompressed P-256 point")
	}
	enc := base64.RawURLEncoding.EncodeToString
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + enc(raw[1:33]) + `","y":"` + enc(raw[33:]) + `"}`))
	return enc(sum[:]), nil
}

// canonical：键排序、无多余空白、不转义 HTML、数字照原样（idp-mcp 的 release.Canonical）。
func canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil { // map 按键排序编码
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func requestDigest(method string, params map[string]json.RawMessage) (string, error) {
	p := make(map[string]json.RawMessage, len(params))
	for k, v := range params {
		if k != "_meta" {
			p[k] = v
		}
	}
	b, err := canonical(map[string]any{"method": method, "params": p})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type claims struct {
	Aud     any      `json:"aud"`
	Iat     int64    `json:"iat"`
	Exp     int64    `json:"exp"`
	Jti     string   `json:"jti"`
	Sub     string   `json:"sub"`
	Tenant  string   `json:"tenant_id"`
	Roles   []string `json:"roles"`
	Client  string   `json:"client"`
	Actor   string   `json:"actor"`
	Req     string   `json:"req"`
}

func (c claims) forAudience(aud string) bool {
	switch a := c.Aud.(type) {
	case string:
		return a == aud
	case []any:
		for _, x := range a {
			if s, _ := x.(string); s == aud {
				return true
			}
		}
	}
	return false
}

// Verify 返回断言所说的调用者。错误只供写日志，不要交给调用者。
func (v *Verifier) Verify(assertion, method string, params map[string]json.RawMessage) (Caller, error) {
	parts := strings.Split(assertion, ".")
	if assertion == "" || len(parts) != 3 || len(assertion) > maxAssertion {
		return Caller{}, errors.New("not a compact JWS")
	}
	dec := base64.RawURLEncoding.DecodeString
	h, e1 := dec(parts[0])
	c, e2 := dec(parts[1])
	sig, e3 := dec(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return Caller{}, errors.New("not base64url")
	}
	var hdr struct{ Alg, Typ, Kid string }
	if json.Unmarshal(h, &hdr) != nil || hdr.Alg != "ES256" || hdr.Typ != assertionType {
		return Caller{}, errors.New("header")
	}
	key := v.keys[hdr.Kid]
	if key == nil {
		return Caller{}, errors.New("unknown kid")
	}
	if len(sig) != 64 {
		return Caller{}, errors.New("signature length")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return Caller{}, errors.New("bad signature")
	}
	var cl claims
	if json.Unmarshal(c, &cl) != nil {
		return Caller{}, errors.New("claims are not an object")
	}
	now := v.now()
	switch {
	case !cl.forAudience(v.audience):
		return Caller{}, errors.New("audience")
	case cl.Exp == 0 || now.After(time.Unix(cl.Exp, 0).Add(skew)):
		return Caller{}, errors.New("expired")
	case cl.Iat == 0 || time.Unix(cl.Iat, 0).After(now.Add(skew)):
		return Caller{}, errors.New("issued in the future")
	case cl.Exp < cl.Iat || cl.Exp-cl.Iat > int64(maxTTL/time.Second):
		return Caller{}, errors.New("lifetime")
	case cl.Sub == "" || cl.Jti == "":
		return Caller{}, errors.New("no subject or jti")
	}
	if want, err := requestDigest(method, params); err != nil || cl.Req != want {
		return Caller{}, errors.New("another request")
	}
	if !v.first(cl.Jti, cl.Exp+int64(skew/time.Second), now.Unix()) {
		return Caller{}, errors.New("replay")
	}
	roles := cl.Roles
	if roles == nil {
		roles = []string{}
	}
	return Caller{Subject: cl.Sub, Tenant: cl.Tenant, Roles: roles, Client: cl.Client, Actor: cl.Actor}, nil
}

func (v *Verifier) first(id string, forget, now int64) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, dup := v.seen[id]; dup {
		return false
	}
	if len(v.seen) >= 4096 { // 到上限时清掉已过期的
		for k, t := range v.seen {
			if t < now {
				delete(v.seen, k)
			}
		}
	}
	v.seen[id] = forget
	return true
}

type callerKey struct{}

// CallerFrom 在工具处理函数里取验过的调用者。取不到就拒绝，不要有缺省值。
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// Require 是放在 SDK 处理器之前的中间件：对原始的 JSON-RPC 体验签。
func (v *Verifier) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body)) // 还给 SDK
		var msg struct {
			Method string                     `json:"method"`
			Params map[string]json.RawMessage `json:"params"`
		}
		if json.Unmarshal(body, &msg) != nil {
			http.Error(w, "bad request", http.StatusBadRequest) // 含批请求：2026-07-28 网关不发
			return
		}
		if msg.Method == "server/discover" || msg.Method == "tools/list" {
			next.ServeHTTP(w, r) // 网关的漂移检查没有调用者
			return
		}
		var meta map[string]json.RawMessage
		_ = json.Unmarshal(msg.Params["_meta"], &meta)
		var assertion string
		_ = json.Unmarshal(meta[MetaCallerAssertion], &assertion)
		caller, err := v.Verify(assertion, msg.Method, msg.Params)
		if err != nil {
			// 原因只写日志：slog.Warn("caller assertion refused", "method", msg.Method, "reason", err.Error())
			http.Error(w, "forbidden", http.StatusForbidden) // idp-sandbox 回 403，工具不运行
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, caller)))
	})
}
```

用法：`http.Handle("/mcp", verifier.Require(mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{Stateless: true})))`。

两点要在你自己的测试里确认（本文没有在 SDK 上运行过这段代码，见未决问题 2）：验过的 `Caller` 经 `r.Context()` 确实到达工具处理函数的 `ctx`；还回去的请求体 SDK 能照常读。

### 3.5 密钥的分发与轮换

- 网关用一把 P-256 私钥（`IDP_GATEWAY_CALLER_KEY_FILE`）签名；同一网关的副本共用一把；私钥是网关的部署属性，不进 Release（D45）。
- **公钥由运维给你**（`openssl ec -in caller.key -pubout`，PKIX PEM）。你在启动时从文件读，不在运行时去网关取：网关没有 JWKS 端点（D45）。
- 你可以同时持有几把公钥，按 `kid` 选。轮换的顺序（D45）：先把新公钥加给你，再换网关的私钥，最后去掉旧公钥。所以你的服务要支持"文件里有多把"，并且改文件后能重启或重载。
- `kid` 是公钥的 RFC 7638 指纹；启动时把持有的 `kid` 写进日志，便于运维核对。
- 公钥文件缺失、无法解析、不是 P-256：**启动失败**，不要退化成不验签。不要提供"关闭验签"的开关；idp-sandbox 有这样的开关（两个变量都不设时只告警），是它的过渡期做法（D18），领域服务不应照抄。

### 3.6 失败关闭，租户与主体只来自断言

- 没有断言、验不过：拒绝，工具不运行（HTTP 403）。
- 处理函数里 `CallerFrom(ctx)` 取不到调用者：拒绝，不使用空租户或"默认租户"。
- 所有向 FIN 的调用、日志里的租户与主体，取自断言。**工具的输入里不能有租户或人的字段**（第 4.2 节）；FIN 自己也拒绝这样的字段（`fin-eii.md` Conventions）。
- 明文的 `io.idp.telos/caller` 不看。
- 限制（来自 idp-sandbox 的 ADR）：`jti` 表在内存里，重启后一分钟内同一个断言能再用一次；多个副本各有各的表，重放可以落在另一个副本上。写工具要靠 FIN 的幂等键（第 4.7 节）兜底，不要只靠 `jti`。

## 4. 工具设计：FIN 的例子

### 4.1 FIN 的接口给了什么

`fin-eii.md` 定义的路由（基路径 `/v1/fin/`）：

| 路由 | 权限 | 备注 |
|---|---|---|
| `GET legal-entities/{legalEntityId}/job-profits` | `fin:ReadProfit` | 参数 `loss_only`、`limit`（1–500，缺省 100）、`after`；**`loss_only=true` 时一页最多看 2000 个 job，一页可能不满，下一页可能为空：`next_after` 非空就继续，不是页短就停** |
| `GET jobs/{jobId}/profit` | `fin:ReadProfit` | 一个 job 的利润与组成，含 `profit_version`；不接受任何查询参数 |
| `GET jobs/{jobId}/cost-review-requests` | `fin:ReadProfit` | 参数 `state`、`limit`、`after`；未知 job 返回空列表 |
| `GET cost-review-requests/{requestId}` | `fin:ReadProfit` | |
| `POST cost-review-requests` | `fin:RequestCostReview` | 必须带 `Idempotency-Key`；体 `{job_id, profit_version, reason}` |
| `POST cost-review-requests/{id}/resolution` | `fin:ResolveCostReview` | 本指南不包含：不让本服务提供"处理"工具 |

约定：金额是 `{"currency": "CNY", "minor": 10001}`（整数，最小货币单位，不用小数）；错误是 RFC 9457 的 `application/problem+json`，程序读 `code`；租户与操作人只来自令牌，体或查询里出现租户/人的字段是 `400 MALFORMED_REQUEST`；`profit_version` 是不透明文本，只比较相等。

**FIN 的令牌（未决问题 1）**：该文档写明现在只有开发令牌，"IDP 身份平台接入之前"没有生产接口。你的服务用什么令牌代表断言里的成员去调 FIN，本文没有来源可依，不替你定。设计上必须满足的是：FIN 看到的"操作人"应当是断言里的成员（FIN 自己的规则"处理人不是申请人"依赖这一点），而不是你的服务账号。

### 4.2 只读工具先做

目标名（登记时的 `targetName`）用 `fin`，对外的工具名就是 `fin__<原名>`（D7）；原名用 `[A-Za-z0-9_.-]`，最长 128。

| 原名 | 作用 | FIN 路由 |
|---|---|---|
| `list_loss_jobs` | 列一个法人下亏损的 job，分页，有总行数上限 | `job-profits?loss_only=true` |
| `get_job_profit` | 一个 job 的利润与组成 | `jobs/{jobId}/profit` |
| `list_job_cost_reviews` | 一个 job 的成本复核申请 | `jobs/{jobId}/cost-review-requests` |

所有工具的标注：`readOnlyHint: true`，`openWorldHint: false`（内部系统）。HOST 读 `readOnlyHint`、`idempotentHint` 决定中断后能不能重发（idp-host D47-1）；标对它。

**输入 schema 的规则**（idp-web D3 的做法）：

- `additionalProperties: false`；每个字段有类型，字符串有 `minLength`/`maxLength` 与 `pattern`，整数有 `minimum`/`maximum`，枚举用 `enum`。
- **没有 `tenant_id`、`actor_id`、`requested_by` 之类的字段。** 租户与人来自断言。
- 描述写给模型读：说清用途、什么时候不该用，不写指令性的话，不写内部系统名与地址。
- 参数严格解码：未知字段是错误（Go：`json.Decoder.DisallowUnknownFields`；用 SDK 泛型 `AddTool` 时 schema 推断 + `additionalProperties:false` 已经做了校验，但结构体上自己再校验一遍范围）。

```json
{
  "name": "list_loss_jobs",
  "description": "List freight jobs of one legal entity whose profit is below zero, with revenue, cost and profit in minor units. Returns at most `limit` jobs per call; pass the returned `next_cursor` to continue. Use get_job_profit for the parts of one job.",
  "inputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["legal_entity_id"],
    "properties": {
      "legal_entity_id": {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[A-Za-z0-9._:-]+$", "description": "The legal entity."},
      "limit": {"type": "integer", "minimum": 1, "maximum": 50, "description": "Jobs per call (default 20)."},
      "cursor": {"type": "string", "maxLength": 512, "description": "The next_cursor of the previous call, unchanged."}
    }
  },
  "annotations": {"readOnlyHint": true, "openWorldHint": false}
}
```

`legal_entity_id` 是领域对象的标识，不是租户。要不要再核对"这个成员能看这个法人"，见未决问题 3。

**`list_loss_jobs` 的分页与总量上限**：

- 单次返回 ≤ `limit` 行（≤ 50）。原因：HOST 交给模型的单个工具结果是 16 KiB（idp-mcp D51-d 引用的 `idp-host/internal/harness` 的 `ToolResultLimit`），行数多了模型读不全。
- 向 FIN 取页时用 FIN 的 `limit` 与 `after`；**继续的条件是 `next_after` 非空**，不是页短（FIN 文档）。单次调用最多向 FIN 取 5 页，到了就带着游标返回（`truncated: true`），不要在一次调用里无限扫。（5 页是本文的建议值，按 FIN 的实测调整。）
- **总行数上限**：一条游标链最多交付 200 行（建议值）。游标里记已交付的行数，到上限就不再给 `next_cursor`，并在结果里写 `row_cap_reached: true`，叫模型缩小范围（换法人、问某个 job）。目的：模型一次对话里不能靠翻页把整个法人的财务拉走。
- 游标是不透明的、**绑定调用者**：内容 = 编码的 `{FIN 的 after, 已交付行数, 法人, 过期时间}` + 对（租户、主体、这些内容）的 HMAC（密钥来自你的部署，从文件读）。别的成员或过期的游标一律拒绝。idp-web 的 `ref` 是同样的做法（ADR D16）。
- 同一页内所有行来自 FIN 的一次只读快照；跨页不保证一致。结果里带 FIN 的 `as_of`，让模型知道数字是什么时候的。

### 4.3 结果：`structuredContent` 加一句短文字

idp-web 的做法（`idp-web/internal/mcp/mcp.go`、ADR D20）：`content` 是一段给模型读的短文字，`structuredContent` 是机器可读的对象，出错时 `isError: true`。2026-07-28 的结果还带 `resultType: "complete"`（SDK 会写）。

```json
{
  "resultType": "complete",
  "content": [{"type": "text", "text": "3 loss-making jobs of legal entity LE (as of 2026-11-25T13:33:06Z). Worst: JOB-H03, profit -80.01 CNY. More: pass next_cursor."}],
  "structuredContent": {
    "legal_entity_id": "LE",
    "as_of": "2026-11-25T13:33:06.752086Z",
    "profit_basis_note": "Figures under SEPARATE and INCLUDED_MARKED are not comparable.",
    "rows": [
      {"job_id": "JOB-H03", "shipment_id": "SH-H03", "state": "OPEN",
       "revenue": {"currency": "CNY", "minor": 12000},
       "cost":    {"currency": "CNY", "minor": 20001},
       "profit":  {"currency": "CNY", "minor": -8001},
       "profit_basis": "SEPARATE", "profit_version": "6c3bfbcf…"}
    ],
    "next_cursor": "…",
    "truncated": false,
    "row_cap_reached": false
  }
}
```

规则：

- **金额只有整数 `minor` 加 `currency`**，从 FIN 原样取，不换算、不四舍五入、不用浮点。文字里的"-80.01 CNY"是给人读的，由整数格式化出来，只在 `content` 里；任何计算用 `structuredContent`。
- `profit_version` 原样带回，**只做相等比较**，不解析、不排序（FIN 文档）。写工具要用它（4.7）。
- 同时声明 `outputSchema`（SDK 泛型 `AddTool` 会按 `Out` 推断），让钉住的定义说明结果的形状。变更 schema 要重新评审（见第 6 节），所以第一次就定准。
- 不返回 FIN 没给的字段，不拼接内部地址、SQL、堆栈。
- 结果大小：保持在几 KiB 到十几 KiB。网关对内部上游的缓冲上限是 16 MiB（D51-d 的"与内部目标的差别"），HOST 一次最多读 8 MiB；但模型读到的只有 16 KiB，实际约束是后者。

### 4.4 工具描述的长度

网关强制的描述上限（D53：`IDP_EXTERNAL_MAX_DESCRIPTION`，缺省 1024 字节，覆盖 `description`、`title` 以及 schema 里每一处 `description`/`title`，并拒绝控制字符与不可见字符）**只对第三方上游（`class: external`）生效；"内部服务器不受影响"**。FIN 的服务是内部上游，网关不会替你卡长度。

仍然建议你自己守同样的上限：每个 `description` 与 `title` ≤ 1024 字节，不含控制字符、零宽字符、方向控制字符、Unicode 标签字符，并在单元测试里检查。理由：描述是对模型的指令，评审人要读全文（D53 的理由）；以后若平台把内部上游也纳入检查，你不需要改。这是本文的建议，不是网关今天的规则（未决问题 5）。

### 4.5 错误：映射成 MCP 工具错误，不泄露内部

两类错误要分开：

- **工具错误**（`isError: true`，`content` 是一句模型能据以行动的话）：参数不合理、业务规则拒绝、FIN 暂时不可用。模型读得到，可以改正后重试。idp-web D15、D24 的做法：每个已知错误一句固定的小写句子；**不在表里的错误：详情写日志，模型只读到一句通用的话**。
- **协议错误**（JSON-RPC error）：请求本身畸形、未知工具。客户端自己的问题，HOST 不会把它交给模型。

不要把 FIN 的 `detail`、`correlation_id` 以外的原文、URL、令牌、堆栈、SQL 放进错误文字。`detail` 里可能带内部拼接的文字（FIN 文档的示例里就有 `fin: rejected by business rules: …`），也不要原样转交；用你自己的固定句子，必要时带 FIN 的 `code`。`correlation_id` 可以写进日志，并可放进错误文字（它本来就是给追踪用的）。

| FIN 的结果 | 工具错误的文字（示例） |
|---|---|
| `400 MALFORMED_REQUEST` | 这是你的 bug（你自己该先校验过）：日志记原因；文字 `the request to FIN was malformed` |
| `401 UNAUTHENTICATED`、`403 FORBIDDEN` | `you are not allowed to do this in FIN`（不透露是缺哪个权限） |
| `404 NOT_FOUND` | `no such job or request` |
| `422 FIN_REVIEW_JOB_NOT_OPEN` | `the job is cancelled; ask about the shipment's open job` |
| `422 FIN_REVIEW_NOT_A_LOSS` | `the job's profit is not below zero; no review is needed` |
| `422 FIN_REVIEW_STALE` | `the profit changed since you read it; read it again with get_job_profit, show the member, and ask again` |
| `422 FIN_REVIEW_OPEN` | `the job already has an open review request` + 申请号（`CRR-n`，这是业务标识，可以给） |
| `422 BUSINESS_RULE_VIOLATION` | `FIN refused the request; reason or note is empty or too long` |
| `409 IDEMPOTENCY_MISMATCH` | `this command id was used for a different request; use a new one`（对写工具） |
| `503 COMMIT_UNCERTAIN`、超时、连接失败 | 对读：`FIN is not available now; try again later`。对写：见 4.7，**结果不明** |
| 其他、无法解析的应答 | `the FIN tool failed to complete the request`，详情写日志 |

对 FIN 的调用要设超时。网关对一次 `tools/call` 的上限是 60 秒（`IDP_CALL_TIMEOUT`，缺省 60 秒；`idp-mcp/internal/gateway/gateway.go`）。超时之后网关把结果记为 `UNKNOWN`（"上游没有应答；结果不明"，`mcp.go`），HOST 同样会把中断的调用记为"结果不明"。所以你对 FIN 的超时应明显短于 60 秒（建议 ≤ 20 秒，写工具要留出一次重试），并且在自己这一层决定结果，而不是等网关超时。

### 4.6 限额

- 单次返回行数（≤ 50）、总行数（≤ 200）、对 FIN 的取页数（≤ 5）、请求体（SDK 缺省 4 MiB；你可以收紧）。
- 按调用者的限流（滑动窗口，内存里，按副本）和并发上限：参照 idp-web D22。网关对平台客户端缺省不限流（D49），所以你自己必须有。
- FIN 文档写明现在 FIN 没有限流，每页 500 个 job 且多合并时可能慢。你的 `limit ≤ 50` 本来就远低于 500；也不要为"快"去并发地打 FIN 的多页。
- 审计：每次调用一行结构化日志，记工具、结果、耗时、调用者的**短哈希**（租户与主体的 SHA-256 前 4 字节），不记参数原文，不记金额（idp-web D4 的做法）。网关已记参数的摘要（D11）。

### 4.7 写工具：成本复核申请（后一步）

**先说什么时候不用这个工具。** idp-host D63-9 把业务写入分两类：

1. 只调用一次、不需要回执与对账的简单写入：HOST 的成员确认加一个 MCP 工具。
2. 需要权威回执、结果不明时按原命令号对账、幂等或补偿的业务命令：交给 EER 执行；EII 的界面只发起意图，经 HOST 审批后由 EER 按步骤语义执行，回执再回到界面。

D63-9 明写："GA 要求的成本复核申请属于这一类"。所以**FIN 的成本复核申请按平台的决定走 EER，不是一个让模型直接调的 MCP 写工具**。下面的设计是两种情形都需要的部分：

- 若决策人把某个写入判为第 1 类，工具就是下面这个样子，HOST 负责确认。
- 若走 EER，EER 的步骤去调用同样的 FIN 命令；你的 MCP 服务提供的是**读**工具（让界面与审批人看到申请前的利润与版本、申请后的状态），以及（如果 EER 的步骤选择经网关调用）这个写工具。EER 如何调用（经网关还是直接）本文没有来源，见未决问题 6。

工具形状（`request_cost_review`）：

```json
{
  "name": "request_cost_review",
  "description": "Ask finance to review the costs of a loss-making job. Needs the profit_version you read with get_job_profit and a command_id; the member must confirm. Sending the same command_id with the same arguments again returns the same receipt.",
  "inputSchema": {
    "type": "object", "additionalProperties": false,
    "required": ["command_id", "job_id", "profit_version", "reason"],
    "properties": {
      "command_id": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9._:-]+$"},
      "job_id": {"type": "string", "minLength": 1, "maxLength": 64},
      "profit_version": {"type": "string", "pattern": "^[0-9a-f]{64}$", "description": "The profit_version the member saw, unchanged."},
      "reason": {"type": "string", "minLength": 1, "maxLength": 500}
    }
  },
  "annotations": {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
}
```

规则：

- **`command_id`**：映射为 FIN 的 `Idempotency-Key`（1–128 个字母数字与 `. _ : -`）。FIN 的语义：同键同体同人返回**第一次的回执**，同键不同体或不同人是 `409 IDEMPOTENCY_MISMATCH`，业务规则拒绝的不存储（原因消除后同键同体可再用）。**谁生成 `command_id`**：必须在 HOST 确认之前就定下并随参数一起被确认（HOST 的确认绑定参数摘要，idp-host D7），这样确认后重发的是同一个命令。不要在你的服务里替调用者生成键，否则重发就成了新命令。由谁（模型、HOST 还是界面）生成见未决问题 7。
- **`profit_version`**：用户看到的那一版。原样传给 FIN；FIN 在一个事务里重算并比较，不一致是 `FIN_REVIEW_STALE`，你把它翻成"再读一次、给成员看、再申请"。**不要自己重读利润再替换版本重试**：那等于替成员确认了他没见过的数字。
- **成员确认在 HOST**：确认请求的方式见 idp-host D7（确认策略要求的调用让 Run 进入 `awaiting_input`，只有 Run 的所有者能确认或拒绝，确认绑定参数摘要，过期视为拒绝）与 D44-9（网关的 `confirmTools` 模式匹配的工具一律强制确认，不看发布件的设置）。要让它强制，运维在 HOST 配置里把 `fin__request_cost_review` 写进该网关的 `confirmTools`。**你的服务不做确认，也不假设确认发生过**：FIN 的权限（`fin:RequestCostReview`）与规则（一个 job 一个未处理申请）才是最终防线。
- **回执与"结果不明"**：成功返回 FIN 的 `{command_id, request_id, new_revision, request_no}`，放进 `structuredContent`，文字写申请号。以下情形**结果不明**，不得当作失败也不得当作成功：FIN 的 `503 COMMIT_UNCERTAIN`、超时、连接中断。处理：同一个 `command_id` 对 FIN 原样重发（FIN 文档：不要换键）；仍然不明就返回工具错误，文字明说"申请可能已提交，也可能没有；用 list_job_cost_reviews 查，不要换 command_id 重新申请"。这与 D63-9 对"结果不明按原命令号对账"的要求，和 HOST D47-2 对中断调用的措辞（"结果未知，先核实再做"）一致。
- **`idempotentHint`**：HOST 在中断后只对"现在的目录里带 `readOnlyHint` 或 `idempotentHint`"的工具重发（D47-1），其余记为失败并告诉模型"结果不明"（D47-2）。写 `idempotentHint: true` 就是对 HOST 说"重发安全"。只有在你确定 `command_id` 对 FIN 重发返回同一回执时才写，上面的设计满足；运维还可以用 `neverResendTools` 强制不重发（D47-4）。
- 网关把写工具与只读工具一样登记；"这个工具只许 HOST"（`hostOnlyTools`）是部署决定（D48）。写工具的确认、不可信包装、敏感上限都在 HOST，所以建议 `fin__*` 写入 `hostOnlyTools`（运维的决定，不是你的）。

## 5. 结果的敏感级别（D54）

**状态：只是规则，尚未实施**（MCP-ADR 第 16 节标题；idp-host D64 标题同样写明）。登记接口今天没有这个字段。本节写的是规则，字段名以后以 `idp-mcp/api/openapi.yaml` 为准。

规则（MCP-ADR D54、idp-host D64）：

- 级别四档：`public`、`internal`、`confidential`、`restricted`（与 idp-cmi、idp-host D43 相同）。
- **登记时声明**：每个目标有缺省级别 `resultSensitivity`，可以按工具名模式覆盖。网关把每个工具的级别写进 `tools/list` 里工具的 `_meta["io.idp.telos/resultSensitivity"]`。声明与工具白名单、"只许 HOST"在同一处评审。
- **你可以在单个结果里调高**：在结果的 `_meta`（`io.idp.telos/resultSensitivity`）里给出更高的级别，或者按字段标出级别。网关原样转交，**只许调高，不许调低**（D54）。HOST 取声明与单个结果中较高者（D64-1）。**按字段标记的具体格式没有定义**，见未决问题 8；在它定下之前，要用就只用整个结果的级别。
- HOST 怎么用：运行可能用外部模型或有对外工具时，级别高于租户 `externalModelCeiling` 的工具结果**不进模型的上下文**，换成一句说明；HOST 自己仍可用这个结果（例如 D63-11 的界面绑定取数）。有自有模型路由时，高于上限的结果只交给自有模型（D64-2、D64-4）。
- **没有声明就按超限处理**（D64-5，失败关闭）：HOST 扣留整个结果。所以没登记级别的目标，在 HOST 启用 D64 之后，模型什么也读不到。这是有意的：少一个声明不应等于放行。

对 FIN 的建议（供评审人与负责人确认，不是平台已定）：

- 目标缺省 `confidential`：利润、成本、收入都是财务数据。
- 工具列表里没有 `restricted` 的需要；若某个结果带客户的个人信息或银行信息，在这个结果里调到 `restricted`。
- 缺省定得过低（比如 `internal`）的后果是财务数字可能被送到外部模型；定得过高的后果是模型读不到数据、分析任务做不了。负责人在登记时逐个确认（D54："逐个由负责人确认"）。

另见 idp-host D63-11：在 EII 的界面生成路径上，业务数据根本不进模型，数据由 HOST 按绑定声明调用你的工具取回。你的工具因此要同时好用于"模型调用"与"HOST 按绑定调用"：结果的字段名稳定、类型严格，`structuredContent` 能被界面直接绑定。这条不是平台对所有路径的规则（D63-11 写明了适用范围）。

## 6. 向网关登记

整条路径是：运维登记服务器 → 发现目录 → 另一个人批准 → 提授权 → 另一个人批准 → 编译 Release → 另一个人批准 → 部署。四眼原则：批准人不是创建人（D10）。接口见 `idp-mcp/api/openapi.yaml`；你不直接操作，但要知道每一步会评审什么。

### 6.1 你要交给运维的

| 项 | 内容 |
|---|---|
| `targetName` | `^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`，如 `fin`。工具对外名为 `fin__<原名>` |
| `endpoint` | http(s) URL，**以 `/mcp` 结尾**。它同时是断言的 `aud`：你配置的 audience 必须与登记的字符串逐字相同 |
| 网络 | 登记时的地址策略（SSRF 规则，D8）：公网 https；内网要由运维把精确主机放进 `IDP_PRIVATE_UPSTREAM_HOSTS`（与 `IDP_ALLOWED_UPSTREAM_HOSTS`）；回环只在开发模式。连接时网关再检查一次实际 IP |
| TLS | 网关到你可以是明文 HTTP；断言防伪造与重放，不防窃听与篡改回答（D44 的"没有做的"）。要防这两样，你用 https，并由运维把你的 CA 放进网关与注册服务的 `IDP_UPSTREAM_CA_FILE` |
| `identity` | `forward`（FIN 需要知道是谁；缺省 `none` 时网关不发任何身份）。登记后不可改 |
| `class` | `internal`（缺省）。FIN 是自己的服务。`external` 是第三方，网关对它不发身份，所以你不能是 external |
| 工具清单与授权 | 哪些工具给哪些角色（Release 的 `grants`：`tools` 数组 + `roles`，租户是网关的租户）。授权提案里的工具名必须在已批准的目录里 |
| 网关公钥 | 运维给你（第 3.5 节） |
| 结果敏感级别 | 目标缺省与按工具的覆盖（第 5 节；实施后） |

### 6.2 评审人看到什么、什么会让评审重来

- 评审人用 `GET /api/v1/servers/{id}/catalog` 看每个工具的**完整**定义：名字、描述、输入输出 schema、标注（D53）。批准内部服务器时摘要是可选的，external 必须带。
- **批准后目录被钉住**。你之后改任何一个工具的描述、schema、标注，目录摘要就变了，网关视为漂移，默认**封锁该目标**（D3；内部目标按 Release 的 `driftAction`，缺省 `block`）。所以：**先把工具的声明定准，处理函数以后再换**（idp-web D3 的做法，并有测试钉住声明的摘要）。改声明要走一遍：重新发现 → 批准 → 新 Release → 批准 → 部署。
- 要加工具：同样要重新发现、批准、改授权、出新 Release。
- 部署后网关心跳上报运行的 Release 与各目标的漂移状态；失败会自动退回上一个 GOOD 的 Release（D4）。

### 6.3 网关和 HOST 一侧的部署决定（运维做，你要知道）

- 网关的客户端文件（`IDP_GATEWAY_CLIENTS_FILE`）要列出调用者客户端；没列的客户端什么也看不到（D46）。
- `hostOnlyTools`：是否把 `fin__*` 设为只许 HOST 调用（D48）。建议设（第 4.7 节）。
- HOST 的 `gateways[].confirmTools`（写工具强制确认）、`externalTools`（FIN 是内部上游，不应出现在这里）、`neverResendTools`（idp-host D44、D47）。
- 网关要配 `IDP_GATEWAY_CALLER_KEY_FILE`；**没配时网关不签名**，只发明文的 `io.idp.telos/caller`（D44），你的验签会拒绝所有 `tools/call`。这是对的：不要为了"能跑起来"而退让。

## 7. 测试

### 7.1 单元测试

**必做：一致性向量。** 平台发布的向量 `idp-contracts/vectors/caller-assertion/v1.json`（格式与用例见同目录 `README.md`）是网关的签名器与已有上游（idp-sandbox、idp-web）共用的判例，也应当是你的判例。做法（照 `idp-sandbox/internal/mcp/caller_vectors_test.go`）：

1. 把文件复制到你仓库的 `testdata/caller-assertion-v1.json`（逐字节相同；不要重新生成，也不要改）。
2. 对每个用例：用 `keys` 里的全部公钥和 `audience` 建一个**新的**验签器（新的 `jti` 表）；按 `steps` 顺序执行：用 `now` 代替时钟，把步骤里的 `method` 与 `params`（原样，含 `_meta`）交给**你真正的中间件**（不只是 `Verify`）；`expect.outcome` 为 `accept` 时调用者要等于 `expect.caller`，为 `refuse` 时请求被拒。
3. 用例覆盖：好的断言（含参数换写法、第二把密钥、容差边界、`aud` 为列表、有效期正好 5 分钟、断言正好 8192 字节），以及每一种拒绝：无断言、畸形、`alg` 为 `none`/`HS256`/`ES384`、`typ` 不对、未知 `kid`、签名错、`aud` 不对、过期、签发在未来、有效期过长、缺 `sub`/`jti`、`req` 不符（改了参数、换了方法）、重放（同一断言两次；同一 `jti` 用在另一个请求上）。
4. 向量里的密钥只有公钥，没有人能事后再签；文件有变化时测试应当失败，所以不要自己动它。

**钉住的单条向量**（`idp-sandbox/internal/mcp/assertion_test.go`）：一个请求、它的摘要、一个由网关的真实签名器在固定时刻为它签的断言和那把公钥：

- 受众 `http://sandbox:8570/mcp`；方法 `tools/call`；参数（`vectorParams`）是 `{"name":"sandbox_run","arguments":{"workspaceId":"0123456789abcdef0123456789abcdef","language":"python","code":"print('<a> & é')","timeoutSeconds":5.0},"_meta":…}`；
- 摘要 `sha256:8851b44519b6c048088bfd66090581b433b7489257501bb2a91e17e0e84a5b33`；
- 时刻 `2026-11-17T00:00:20Z` 验签应通过，调用者 `svc-operator`、租户 `t1`、角色 `operator`、client 与 actor 都是 `idp-host`；同一断言第二次出示被拒。
- 测试 `TestTheGatewaysAssertionIsAccepted` 同时断言：同一请求换空白、键序、字符转义（`<`、`&`、`é`）与 `_meta`，摘要不变。

你的服务应当把**这个常量原样复制**进自己的测试（公钥、断言、摘要、参数，带来源注释），再加上：用你自己的 `audience` 建不出能通过它的验签器（因为它的 `aud` 是沙箱的端点）——所以对你的服务，这条单条向量主要检验**摘要的计算**（`requestDigest` 得到上面的摘要）与**换写法不变**；验签通过与否由上面的一致性向量文件测（它的 `audience` 可以直接设给你的验签器）。完整的单条断言字符串见该测试文件，这里不抄，以免抄错。

另外的单元测试：

- 每个工具的输入：缺字段、多字段（含 `tenant_id`、`actor_id`）、类型错误、越界、含控制字符——都被拒绝；工具的 schema 里**没有**租户或人的字段（遍历 schema 断言）。
- 每个描述与标题的长度与字符（4.4）。
- FIN 错误映射表的每一行；"不在表里的错误"得到通用句子且原文只在日志里；错误文字里不含 FIN 的原文、URL、令牌。
- 分页：`next_after` 非空而页为空时继续；到 5 页上限带游标返回；到 200 行上限不再给游标；别的调用者或过期的游标被拒。
- 金额：往返不经过浮点（用大于 2^53 的整数测）。
- 写工具：同一 `command_id` 重发得到同一回执；`409 IDEMPOTENCY_MISMATCH`；`COMMIT_UNCERTAIN` 后用同一个键重发；结果不明时的文字。

### 7.2 本地对着网关跑

1. 起一个开发模式的 idp-mcp 栈（`idp-mcp/deploy/e2e.sh` 起 compose 拓扑：注册服务、网关、PostgreSQL，可带 Keycloak；`KEEP=1` 保留环境）。网关加 `IDP_GATEWAY_CALLER_KEY_FILE`：用 `openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt` 生成私钥，`openssl ec -in … -pubout` 取公钥给你的服务。
2. 把你的服务登记为 `identity: forward`、`class: internal`，endpoint 写你在网关网络里可达的地址；发现、批准、授权、出 Release、批准、部署（接口见 `openapi.yaml`；`deploy/e2e.sh` 里有整套调用的写法）。
3. 用带令牌的客户端调 `fin__list_loss_jobs`，应成功；在你的日志里应看到验签通过，调用者的租户与主体与令牌一致。
4. FIN 用 `fin-eii.md` 的测试租户 `eii-test`（`tools/demo/eii-test.sh` 起来的服务）。**本文的作者没有也不会连接 FIN 的 127.0.0.1:8095**；你自己的测试里，对 FIN 的调用也应经一个可替换的接口，单元测试用假的 FIN，集成测试再用真的。

### 7.3 负面测试（必做，对着你的真实 HTTP 处理器）

| 测试 | 期望 |
|---|---|
| 不带断言，只带明文的 `io.idp.telos/caller`（伪造 admin） | 403，工具不运行 |
| 断言的 `aud` 是另一个上游的端点 | 403 |
| 过期（超过 `exp + 30 秒`） | 403 |
| 同一个断言出示两次 | 第二次 403 |
| 断言有效但 `arguments` 被改过一个字节 | 403（`req` 不符） |
| 断言有效但换了方法（拿 `resources/read` 的断言调 `tools/call`） | 403 |
| `alg: none`、`HS256`（用公钥 PEM 当密钥）、`ES384` | 403 |
| 未知 `kid` | 403 |
| 工具参数里带 `tenant_id` 或 `actor_id` | 被拒；永远不会到 FIN |
| 断言里的租户 A，参数里的法人属于租户 B | 不返回 B 的数据（由你与 FIN 的授权拒绝；FIN 对别的租户的行是 404） |
| 没有公钥文件 / 公钥不是 P-256 | 启动失败 |
| `tools/list`、`server/discover` 不带断言 | 成功（网关的漂移检查需要） |
| 对 FIN 的错误：每一行映射 | 见 4.5 |

### 7.4 平台的验收会检查什么

本文不能代表平台的验收清单（没有这份文件，见未决问题 9）。从已有的做法能推断，至少会有这些，请自己先做过：

- 经真实的注册服务与网关，用 `identity: forward` 登记，网关带密钥，你的服务只认签名；从你所在的网络**不经网关**直接发一个带调用者、不带签名的 `tools/call`，得到 403，日志里有拒绝记录，`tools/list` 仍可用（这是 idp-sandbox 的 `deploy/e2e.sh` 做的检查）。
- 目录钉住与漂移：批准后改一个描述，目标被封锁。
- 客户端准入：未列出的客户端看不到你的工具；只许 HOST 的工具对别的客户端不可见（若部署设了）。
- HOST 一侧：写工具触发确认；工具结果被包成不可信内容；敏感级别（D64 实施后）。

## 8. 检查表

验签

- [ ] 只用标准库或你审过的库；`alg` 固定为 `ES256`，不从头里选
- [ ] 公钥从文件读，按 `kid` 选，可以有多把；没有公钥就不启动
- [ ] 验 `typ`、`aud`（逐字等于登记的 endpoint）、`exp`/`iat`（30 秒容差，≤ 5 分钟）、`sub`、`jti`、`req`
- [ ] `req` 对**原始请求体**的 `{method, params 去掉 _meta}` 用规范化 JSON 计算；换空白、键序、转义不变；数字照原样；不转义 HTML
- [ ] `jti` 只收一次，通过其他检查之后才记录
- [ ] 无断言或验不过：403，工具不运行，原因只进日志
- [ ] `tools/list`、`server/discover` 放行，其余要断言
- [ ] 不看明文的 `io.idp.telos/caller`
- [ ] 过了平台向量文件的每个用例，并含钉住的单条向量

授权与规则

- [ ] 租户、主体、角色只来自断言；输入 schema 没有任何租户或人的字段
- [ ] 取不到调用者就拒绝，没有缺省租户
- [ ] 按断言的角色与领域规则授权（含法人范围，见未决问题 3）
- [ ] 对 FIN 的操作人等于断言里的成员（未决问题 1）

工具

- [ ] `additionalProperties: false`，类型、长度、范围、枚举齐全
- [ ] 标注正确：只读工具 `readOnlyHint: true`，`openWorldHint: false`；写工具 `idempotentHint` 只在确实幂等时写
- [ ] `structuredContent` 加一句短文字；`outputSchema` 已声明
- [ ] 金额是整数 `minor` + `currency`，没有浮点
- [ ] `profit_version` 只比较相等
- [ ] 分页按 `next_after` 非空继续；单次行数、取页数、总行数都有上限；游标不透明并绑定调用者
- [ ] 错误映射成工具错误，固定句子，内部细节只进日志；写工具"结果不明"单独处理
- [ ] 对 FIN 有超时，明显短于网关的 60 秒
- [ ] 描述与标题 ≤ 1024 字节，无控制与不可见字符
- [ ] 审计只记元数据与调用者的短哈希
- [ ] 限流与并发上限已设

登记与运行

- [ ] SDK：`go-sdk` ≥ v1.7.0，`Stateless: true`，只有 `POST /mcp`
- [ ] endpoint 以 `/mcp` 结尾，与 `aud` 配置逐字相同
- [ ] 目标名、`identity: forward`、`class: internal`、授权的角色与工具已交给运维
- [ ] 工具声明在第一次评审前定准；之后只改处理函数
- [ ] 结果敏感级别已与负责人确认（D54 实施后登记）
- [ ] 写工具：运维已把它放进 HOST 的 `confirmTools`；`fin__*` 是否 `hostOnlyTools` 已定
- [ ] 平台向量、负面测试都在 CI 里

## 9. 未决问题

来源没有给出答案，本文没有猜。请向对应的决策人确认，并把答案写回来源文件和本文。

**平台的答复（2026-11-25，平台维护方）**。下面几条由平台定下；其余仍未决，按原文处理。

- **第 1 条，FIN 的令牌**：MCP 服务是 CargoPai 自己的服务，它只凭网关的断言认人，生产环境不用开发令牌。它对 FIN 以哪种方式代表断言里的成员操作（内部调用时带上断言里的主体作为操作人，或在 CargoPai 内部做令牌交换），由 CargoPai 决定；主体到 CargoPai 用户的对应关系也归 CargoPai。
- **第 3 条，法人范围**：这是领域规则，由 CargoPai（MCP 服务或 FIN）执行。网关的角色只决定能不能调用这个工具，不是领域权限。
- **第 4 条，`iss`**：**要检查**，只接受配置里那个网关 id 的 `idp-mcp-gateway:<网关 id>`。这是纵深防御；平台也会给 idp-sandbox 补上同样的检查。
- **第 6 条，EER**：写入走 HOST 审批加 MCP 工具，还是走 EER，要到 EII 第 3 阶段按证据再定（idp-host D63-9）。在那之前，这个服务只做第 4.2 节的三个只读工具。
- **第 7 条，`command_id`**：**由 HOST 生成**，在成员确认的那一步生成，重试时不变；模型和界面都不生成它。它由 HOST 实施（EII 的 H7）。
- **第 5 条**：1024 字节的建议照旧。**第 8、10、11 条**随 idp-mcp D54、idp-host D64 的实施确定。**第 9 条**：第一个上游登记时，平台给出验收清单。**第 2 条**：留给你们自己的测试。

1. **FIN 的令牌。** `fin-eii.md` 说明现在只有开发令牌，"IDP 身份平台接入之前"不是生产接口。MCP 服务怎样拿到一个"操作人是断言里的成员、租户是断言里的租户"的 FIN 令牌（令牌交换？FIN 接受网关的断言？）没有来源。FIN 的"处理人不是申请人"规则要求操作人是真实的成员，不能是服务账号。
2. **SDK 的两个行为本文没有验证过。** 一是 HTTP 中间件放进 `r.Context()` 的值是否到达工具处理函数的 `ctx`（`mcp/streamable.go` 的无状态路径用 `req.Context()` 建会话，看起来是，但没有运行验证）；二是 `ToolHandlerFor` 在 `Out` 为结构体时 `isError` 与 `structuredContent` 的互动。第 3.4 节要求你的测试覆盖前者。若前者不成立，需要换一种把调用者交给处理函数的办法，请把结论告诉我们。
3. **法人范围的授权。** FIN 的权限是令牌里的三个 `fin:*`；`fin-eii.md` 没有说成员能访问哪些法人。路径里的 `legalEntityId` 由谁限定：FIN、你的服务，还是网关的角色？没有来源。在定下之前，不要假设"调用者能访问任意 `legal_entity_id`"。
4. **`iss` 要不要检查。** 网关签的 `iss` 是 `idp-mcp-gateway:<网关 id>`；idp-sandbox 与向量都不检查它。多网关部署时你是否要限定只接受某个网关 id，没有决定。
5. **内部上游的描述上限。** D53 只对 external 生效，内部不受影响。你的任务说明里写"网关的描述上限"：对 FIN 这样的内部上游，网关今天没有上限，本文的 1024 字节是建议值。若平台打算对内部上游也设上限，需要新的决定。
6. **EER 怎么调用 FIN。** D63-9 说成本复核申请由 EER 执行，但 EER 的步骤是经 idp-mcp 网关调用你的 MCP 写工具，还是直接调 FIN，本文读到的来源没有写明（`idp-eer` 的规范没有在本次核对范围内）。这决定你是否需要提供 `request_cost_review` 这个 MCP 工具。
7. **`command_id` 由谁生成。** HOST 的确认绑定参数摘要，所以 `command_id` 必须在确认前就在参数里；是模型生成、HOST 注入，还是界面生成，没有来源。模型生成的键有被重复使用或猜测的风险。
8. **字段级敏感级别的格式。** D54 只写"可以按字段标出级别"，D64-3 写"结果里标了字段级别的，高于上限的字段换成占位"；标记放在结果的哪里、用什么形状没有定义。
9. **平台验收清单。** 没有一份"上游服务的验收标准"文件；第 7.4 节是从已有的验收做法推断的，不是平台规定。
10. **HOST 对 `structuredContent` 的处理。** idp-mcp 的 D51-d 写的是 HOST 交给模型的工具结果 16 KiB；`content` 与 `structuredContent` 各占多少、谁被截断，来源没有说明。第 4.2 节的行数上限是按保守取的。
11. **D54 与 D64 的实施时间。** 两者都写"尚未实施"；登记字段名、`_meta` 键的最终样子以实施后的 `openapi.yaml` 与 Release 契约为准。
