# hass-proxy-relay

`hass-proxy-relay` 为 Home Assistant 提供一个小型、受控的 HTTPS TCP relay。它只代理明确列入白名单的 TLS SNI，并通过上游 HTTP CONNECT 代理连接真实目标。

relay 不终止 TLS、不解密流量，也不修改 Home Assistant Core。Home Assistant 仍然访问原始 HTTPS 域名，目标服务器仍然提供并签署 TLS 证书。

## 背景

从 Home Assistant 2026.9 开始，地图底图请求改由 Home Assistant Server 端拉取并提供给前端，而不再全部由浏览器直接访问 OpenStreetMap。

这意味着，为浏览器配置的代理不再影响这些地图请求。对于必须通过代理访问 OpenStreetMap 的网络环境，地图可能因此无法加载。

可以给整个 Home Assistant 设置全局代理，但这会扩大代理影响范围。Home Assistant 内部不同组件和网络客户端的行为并不完全相同，全局代理也会增加部署复杂度、故障范围和长期维护成本。

本项目采用更窄的机制：

1. 在 Home Assistant Server 所在容器、主机或其使用的 DNS 中，将少数目标域名解析到 `hass-proxy-relay`；
2. relay 从 TLS ClientHello 中读取原始 SNI；
3. 只有 SNI 在 allowlist 中时，relay 才通过配置的上游 HTTP CONNECT 代理连接真实目标；
4. 建立隧道后，relay 只转发加密的 TCP 数据。

当前 Home Assistant 地图使用的目标域名是：

- `vector.openstreetmap.org`
- `tile.openstreetmap.org`

本项目与 Home Assistant 的接口只有“目标域名解析到 relay 地址”。

## 实现机制

```text
Home Assistant Server
    │
    │ DNS/hosts override
    │ vector.openstreetmap.org -> relay IP
    ▼
hass-proxy-relay:443
    │ read TLS ClientHello
    │ extract and validate SNI
    │ enforce exact allowlist
    ▼
upstream HTTP CONNECT proxy
    │ CONNECT vector.openstreetmap.org:443
    ▼
vector.openstreetmap.org:443
```

TLS 实际关系仍然是：

```text
Home Assistant <============ TLS ============> OpenStreetMap
```

一条连接的处理过程如下：

1. relay 读取带有大小上限和超时保护的 TLS ClientHello；
2. 提取并规范化 SNI；
3. 精确检查 allowlist，未知、无效或缺少 SNI 的连接默认拒绝；
4. 以 `SNI:443` 为目标向上游代理发送 HTTP CONNECT；
5. CONNECT 成功后，将之前读取的 ClientHello 原样转发；
6. 使用双向 TCP copy 转发后续数据，并尽可能保持 TCP half-close 语义。

目标域名由上游代理解析，relay 不维护 OpenStreetMap 或 CDN 的 IP 地址列表。

当前实现包括：

- 64 KiB ClientHello 上限；
- ClientHello、代理 TCP connect 和 CONNECT 握手超时；
- 精确域名 allowlist，默认拒绝；
- HTTP CONNECT 与可选的 HTTP Basic 代理认证；
- 并发连接、TCP backpressure 和 half-close；
- JSON 结构化日志；
- SIGINT/SIGTERM 优雅关闭；
- 配置严格校验和敏感信息日志保护。

当前不提供 SOCKS server、通用 HTTP proxy、TLS MITM、DNS 服务、tile cache、全局透明代理或 Home Assistant Core 补丁。

## 配置文件

仓库中的 [config.example.yaml](config.example.yaml) 只描述配置结构：

```yaml
listen: ":443"

upstream: "http://proxy.example:7890"

allowed_hosts:
  - vector.openstreetmap.org
  - tile.openstreetmap.org

timeouts:
  client_hello: 10s
  connect: 5s
  proxy_handshake: 10s
```

字段说明：

- `listen`：relay 的 TCP 监听地址；Home Assistant 访问标准 HTTPS 时必须能连接到 relay 的 443 端口；
- `upstream`：上游 HTTP CONNECT 代理 URL；
- `allowed_hosts`：允许转发的精确 SNI 列表，不支持通配符；
- `timeouts.client_hello`：等待客户端发送完整 ClientHello 的时间；
- `timeouts.connect`：连接上游代理的时间；
- `timeouts.proxy_handshake`：完成 HTTP CONNECT 握手的时间。

如果上游代理需要 HTTP Basic 认证，可以使用 URL userinfo：

```yaml
upstream: "http://username:password@proxy.example:7890"
```

用户名和密码中的 URL 特殊字符必须进行 percent-encoding。程序不会把 userinfo 或 `Proxy-Authorization` 写入日志。

配置使用严格校验。未知字段、重复域名、通配符、IP allowlist、非正数超时和非 HTTP 上游都会导致启动失败。空 allowlist 是合法的安全状态，此时拒绝所有目标。

实际配置可能包含本地网络和代理信息，应放在部署侧的 data 目录中单独维护，不要提交到项目仓库。

## 从源码编译和运行

当前暂不提供预编译二进制。需要 Go 1.23 或更高版本。

运行测试：

```bash
go test ./...
go test -race ./...
go vet ./...
```

编译：

```bash
go build -trimpath -o bin/hass-proxy-relay ./cmd/hass-proxy-relay
```

运行：

```bash
./bin/hass-proxy-relay -c /path/to/config.yaml
```

也可以直接运行源码：

```bash
go run ./cmd/hass-proxy-relay -c /path/to/config.yaml
```

开发测试时可以在本地配置中改用 `:8443`。

## Docker 部署

当前不提供预构建镜像。Docker 部署分为“构建镜像”和“准备运行配置”两部分。

### 1. 构建镜像

在仓库根目录执行：

```bash
docker build -t hass-proxy-relay:latest .
```

最终镜像基于 `scratch`，只包含静态编译的 `/hass-proxy-relay` 程序。配置文件、Compose 文件和本地开发信息不会进入镜像。

### 2. 准备 data 目录

实际运行配置由部署侧维护。以下示例使用 Compose 文件旁的 `data/` 目录：

```bash
mkdir -p data
cp config.example.yaml data/config.yaml
```

编辑 `data/config.yaml`，填写实际上游代理地址和 allowlist。容器默认读取 `/data/config.yaml`。

### 3. 准备 Compose 配置

仓库只提供 [compose.example.yaml](compose.example.yaml)。它不参与镜像构建，只引用已经构建好的 `hass-proxy-relay:latest`，并将宿主机 data 目录只读挂载到容器 `/data`：

```bash
cp compose.example.yaml compose.yaml
```

实际 `compose.yaml` 属于部署配置，不提交到项目仓库。示例会创建具名的 user-defined bridge `hass-proxy-relay-network`，并为 relay 分配固定地址 `172.30.10.2`。这样容器重建后，Home Assistant 的 hosts 覆盖仍然指向同一地址。

示例中的 `172.30.10.0/24` 和 `172.30.10.2` 只是占位值。部署前必须检查它们是否与宿主机、Docker、LAN、VPN 或其他容器网络冲突；如有冲突，应在实际 `compose.yaml` 中同时更换 subnet 和 relay 地址。项目本身不依赖这个特定网段。

如果 Home Assistant 运行在普通 Docker network 中，需要让 Home Assistant 容器加入这个网络。若 Home Assistant 由另一个 Compose 项目管理，可以在其实际 `compose.yaml` 中引用该具名网络：

```yaml
services:
  homeassistant:
    networks:
      - default
      - hass_proxy_relay

networks:
  hass_proxy_relay:
    external: true
    name: hass-proxy-relay-network
```

如果 Home Assistant 使用 `network_mode: host`，则不需要、也不能再将 HA 容器附加到这个 Docker bridge。HA 与宿主机共享网络命名空间，在常规 Linux Docker 部署中可以通过宿主机路由访问 relay 的固定 bridge 地址；仍应在实际环境中确认该地址的 TCP 443 可达。

不需要通过 `ports` 将 relay 的 443 端口发布到 LAN；Home Assistant 只需能够从其实际网络命名空间访问 relay 固定地址的 TCP 443。

启动：

```bash
docker compose -f compose.yaml up -d
```

查看日志：

```bash
docker compose -f compose.yaml logs -f hass-proxy-relay
```

修改 `data/config.yaml` 后需要重启容器：

```bash
docker compose -f compose.yaml restart hass-proxy-relay
```

relay 当前不会动态重新加载配置。

## 将 Home Assistant 指向 relay

这是 Home Assistant 与本项目之间唯一需要配置的接口：

```text
需要代理的原始域名 -> relay 的稳定 IP
```

覆盖必须对 **Home Assistant Server** 生效，而不是只对访问 Home Assistant 的浏览器生效。

### Home Assistant Container 示例

如果 Home Assistant 由 Docker Compose 管理，可以在 Home Assistant 服务中使用 `extra_hosts`。以下地址与仓库中的 relay Compose 示例对应；如果修改了 relay 地址，这里必须同步修改：

```yaml
services:
  homeassistant:
    extra_hosts:
      - "vector.openstreetmap.org:172.30.10.2"
      - "tile.openstreetmap.org:172.30.10.2"
```

确保 Home Assistant 容器能够访问 relay 所在网络和该地址的 443 端口。修改后需要重新创建或重启 Home Assistant 容器。

Home Assistant 仍然认为自己在连接：

```text
https://vector.openstreetmap.org/...
https://tile.openstreetmap.org/...
```

因此 TLS SNI 和证书主机名仍然是原始 OpenStreetMap 域名。

### 其他部署模式

如果不能使用 Compose `extra_hosts`，可以在 Home Assistant Server 实际使用的 DNS 中添加等价的域名覆盖。例如，在部署主机、容器 DNS、路由器上的本地 DNS、Pi-hole 或 AdGuard Home 中，让上述两个域名仅对相关网络解析到 relay 的可达地址。

具体配置入口取决于 Home Assistant 的部署方式，但必须满足两个条件：

1. 在 Home Assistant Server 内解析目标域名时，结果是 relay 地址；
2. Home Assistant Server 能连接该地址的 TCP 443 端口。

浏览器自身的 hosts 或代理设置不会改变 Home Assistant Server 的解析结果。

### 添加更多目标域名

新增域名必须同时修改两处：

1. 在 Home Assistant 的 DNS/hosts 覆盖中将域名指向 relay；
2. 在 relay 的 `allowed_hosts` 中加入完全相同的域名。

只修改第一处会被 relay 默认拒绝；只修改第二处不会改变 Home Assistant 的访问路径。

## 验证

仓库包含一个使用真实配置的冒烟测试程序：

```bash
go run ./cmd/relay-smoke -c /path/to/config.yaml
```

或：

```bash
make smoke CONFIG=/path/to/config.yaml
```

它会在临时回环地址启动 relay，并检查：

- 配置可以严格加载；
- allowlist 中的域名可以经上游代理完成 TLS 握手；
- 真实目标证书的主机名校验成功；
- HTTPS 请求可以收到响应；
- 非 allowlist SNI 被拒绝；
- 未发送 ClientHello 的连接按配置超时关闭。

完成 Docker 和 Home Assistant 配置后，最终验收是 Home Assistant 地图能够加载，同时其他网络请求仍保持原有直连行为。

## 日志与故障行为

日志记录：

- 接受或拒绝的 SNI；
- 上游代理连接失败；
- HTTP CONNECT 握手失败；
- ClientHello 等关键超时；
- 隧道异常终止。

日志不会记录 TLS payload、HTTP 内容、代理密码或认证头。

上游代理重启时，已有隧道可能失败。relay 不实现离线队列、会话恢复或应用层重试；代理恢复后，Home Assistant 发起的新连接会正常建立新隧道。

## 安全边界

- 未知、无效或缺少 SNI 的连接默认拒绝；
- 客户端不能指定任意 CONNECT 目标；
- relay 不是通用 HTTP 或 SOCKS 代理；
- relay 不终止或解密 TLS；
- relay 不应暴露到不受信任的 LAN 或公网；
- 实际配置、Compose 文件和 data 目录不应提交到版本库。

## License

GPL-3.0，见 [LICENSE](LICENSE)。
