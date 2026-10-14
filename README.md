# Docker 镜像代理服务

基于 Cloudflare Workers 的容器镜像仓库代理服务，用于加速 Docker Hub、GHCR、Kubernetes 等公共镜像仓库的拉取。

## ✨ 功能特性

- 支持 18 个主流容器镜像仓库（Docker Hub、GHCR、GCR、Quay、MCR、ECR、Kubernetes 等）
- 两种使用模式：**路径前缀** 与 **子域名前缀**
- 自动处理 Docker Registry V2 认证（token 自动获取）
- Docker Hub 官方镜像自动补全 `library/` 命名空间（`nginx` → `library/nginx`）
- 支持 Docker / Podman / containerd / Kubernetes 等所有兼容 Registry V2 协议的运行时
- 零依赖、低延迟，部署在 Cloudflare 全球边缘网络

## 📦 支持的镜像仓库

| 子域名 | 路径前缀 | 镜像源 |
|--------|----------|--------|
| `docker` / `dockerhub` / `hub` | `cr/docker` | Docker Hub (`registry-1.docker.io`) |
| `ghcr` | `cr/ghcr` | GitHub Container Registry |
| `gcr` | `cr/gcr` | Google Container Registry |
| `quay` | `cr/quay` | Quay.io |
| `mcr` | `cr/mcr` | Microsoft Container Registry |
| `ecr` | `cr/ecr` | Amazon ECR Public |
| `k8s` | `cr/k8s` | Kubernetes Registry (`registry.k8s.io`) |
| `gitlab` | `cr/gitlab` | GitLab Container Registry |
| `nvcr` | `cr/nvcr` | NVIDIA Container Registry |
| `redhat` | `cr/redhat` | Red Hat Registry |
| `oracle` | `cr/oracle` | Oracle Container Registry |
| `cloudsmith` | `cr/cloudsmith` | Cloudsmith |
| `digitalocean` | `cr/digitalocean` | DigitalOcean Registry |
| `vmware` | `cr/vmware` | VMware Registry |
| `heroku` | `cr/heroku` | Heroku Registry |
| `suse` | `cr/suse` | SUSE Registry |
| `opensuse` | `cr/opensuse` | openSUSE Registry |
| `gitpod` | `cr/gitpod` | Gitpod Registry |

## 🚀 使用方式

假设服务部署在 `docker.xget.example.com`（示例域名，替换为你自己的）。

### 子域名前缀模式（推荐）

每个镜像仓库对应一个子域名，拉取镜像时只需把仓库域名替换为对应子域名：

```bash
# Docker Hub 官方镜像
docker pull docker.xget.example.com/nginx:latest

# Docker Hub 用户镜像
docker pull docker.xget.example.com/bitnami/redis:latest

# GHCR
docker pull ghcr.xget.example.com/nginxinc/nginx-unprivileged:latest

# Kubernetes
docker pull k8s.xget.example.com/pause:3.9

# GCR
docker pull gcr.xget.example.com/distroless/base:latest
```

### 路径前缀模式

使用 `/cr/<registry>/` 前缀指定目标仓库：

```bash
docker pull docker.xget.example.com/cr/docker/nginx:latest
docker pull docker.xget.example.com/cr/ghcr/nginxinc/nginx-unprivileged:latest
docker pull docker.xget.example.com/cr/k8s/pause:3.9
```

### Docker Hub 镜像加速（registry-mirrors）

配置 Docker daemon 使用本服务作为 Docker Hub 的镜像加速器，之后 `docker pull nginx:latest` 等命令会自动走代理：

编辑 `/etc/docker/daemon.json`：

```json
{
  "registry-mirrors": ["https://docker.xget.example.com"]
}
```

重启 Docker：

```bash
sudo systemctl restart docker
```

### Podman

```bash
# 直接拉取
podman pull docker.xget.example.com/nginx:latest

# 配置 registries.conf 加速 Docker Hub
# /etc/containers/registries.conf
[[registry]]
location = "docker.io"
prefix = "docker.io"
[[registry.mirror]]
location = "docker.xget.example.com"
```

### containerd

编辑 `/etc/containerd/config.toml`：

```toml
[plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
  endpoint = ["https://docker.xget.example.com"]

[plugins."io.containerd.grpc.v1.cri".registry.mirrors."registry.k8s.io"]
  endpoint = ["https://k8s.xget.example.com"]
```

### Kubernetes

直接在 Pod 定义中使用代理地址，或配置 containerd 镜像加速（同上）后使用原始镜像名。

```yaml
spec:
  containers:
    - name: nginx
      image: docker.xget.example.com/nginx:latest
```

## 🛠️ 部署

### 1. 安装依赖

```bash
npm install
```

### 2. 配置 Worker 路由

编辑 `wrangler.toml`，添加自定义域名路由：

```toml
routes = [
  # 单个域名（路径前缀模式）
  { pattern = "docker.xget.example.com/*", zone_name = "example.com" }
]
```

若要使用**子域名前缀模式**，添加通配符路由：

```toml
routes = [
  { pattern = "*.xget.example.com/*", zone_name = "example.com" }
]
```

### 3. 配置 DNS 记录

#### 方式一：泛解析（推荐，覆盖所有子域名）

| 类型 | 名称 | 内容 | 代理状态 |
|------|------|------|----------|
| CNAME | `*.xget` | `<你的-worker-name>.<你的-subdomain>.workers.dev` | 已代理（橙色云朵） |

#### 方式二：逐条添加

按支持的镜像仓库表格，为每个子域名（`docker`、`ghcr`、`k8s` 等）添加 CNAME 记录，全部指向 `<你的-worker-name>.<你的-subdomain>.workers.dev`。

### 4. 部署

```bash
npm run deploy
```

## ⚙️ 环境变量

可在 `wrangler.toml` 的 `[vars]` 中配置：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `TIMEOUT_SECONDS` | `30` | 上游请求超时时间（秒） |
| `MAX_RETRIES` | `3` | 失败重试次数 |
| `RETRY_DELAY_MS` | `1000` | 重试间隔（毫秒） |
| `MAX_PATH_LENGTH` | `2048` | 允许的最大路径长度 |

## 🧪 本地开发

```bash
npm run dev      # 启动本地开发服务器
npm test         # 运行测试
npm run lint     # 代码检查
npm run format   # 代码格式化
```

## 📝 说明

- 公共仓库的镜像拉取无需认证，代理会自动获取匿名 token
- 私有仓库需在客户端配置凭证，代理会透传 `Authorization` 头
- Docker Hub 官方镜像（如 `nginx`）会自动补全为 `library/nginx`
