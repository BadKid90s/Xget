import { CONFIG, createConfig } from './config/index.js';
import { transformPath, resolveDomainPlatform, DOMAIN_PREFIX_MAP } from './config/platforms.js';

/**
 * Detects if a request is a container registry operation.
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is a container registry operation
 */
function isDockerRequest(request, url) {
  if (url.pathname.startsWith('/v2/')) {
    return true;
  }

  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.toLowerCase().includes('docker/')) {
    return true;
  }

  const accept = request.headers.get('Accept') || '';
  if (
    accept.includes('application/vnd.docker.distribution.manifest') ||
    accept.includes('application/vnd.oci.image.manifest') ||
    accept.includes('application/vnd.docker.image.rootfs.diff.tar.gzip')
  ) {
    return true;
  }

  return false;
}

/**
 * Validates the incoming request against security rules.
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @param {import('./config/index.js').ApplicationConfig} config - Configuration object
 * @returns {{valid: boolean, error?: string, status?: number}} Validation result
 */
function validateRequest(request, url, config = CONFIG) {
  // Container registry operations need GET/HEAD plus POST/PUT for uploads and auth
  const allowedMethods = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH'];

  if (!allowedMethods.includes(request.method)) {
    return { valid: false, error: 'Method not allowed', status: 405 };
  }

  if (url.pathname.length > config.SECURITY.MAX_PATH_LENGTH) {
    return { valid: false, error: 'Path too long', status: 414 };
  }

  return { valid: true };
}

/**
 * Creates a standardized error response.
 * @param {string} message - Error message
 * @param {number} status - HTTP status code
 * @returns {Response} Error response
 */
function createErrorResponse(message, status) {
  return new Response(message, {
    status,
    headers: addSecurityHeaders(
      new Headers({
        'Content-Type': 'text/plain'
      })
    )
  });
}

/**
 * Adds security headers to the response.
 * @param {Headers} headers - Headers object to modify
 * @returns {Headers} Modified headers object
 */
function addSecurityHeaders(headers) {
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('X-XSS-Protection', '1; mode=block');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Content-Security-Policy', "default-src 'none'; img-src 'self'; script-src 'none'");
  headers.set('Permissions-Policy', 'interest-cohort=()');
  return headers;
}

/**
 * Parses Docker WWW-Authenticate header.
 * @param {string} authenticateStr - The WWW-Authenticate header value
 * @returns {{realm: string, service: string}} Parsed authentication info
 */
function parseAuthenticate(authenticateStr) {
  const re = /(?<==")(?:\\.|[^"\\])*(?=")/g;
  const matches = authenticateStr.match(re);
  if (matches === null || matches.length < 2) {
    throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
  }
  return {
    realm: matches[0],
    service: matches[1]
  };
}

/**
 * Fetches an authentication token from a container registry.
 * @param {{realm: string, service: string}} wwwAuthenticate - Authentication info
 * @param {string} scope - The scope for the token
 * @param {string} authorization - Authorization header value
 * @returns {Promise<Response>} Token response
 */
async function fetchToken(wwwAuthenticate, scope, authorization) {
  const url = new URL(wwwAuthenticate.realm);
  if (wwwAuthenticate.service.length) {
    url.searchParams.set('service', wwwAuthenticate.service);
  }
  if (scope) {
    url.searchParams.set('scope', scope);
  }
  const headers = new Headers();
  if (authorization) {
    headers.set('Authorization', authorization);
  }
  return await fetch(url, { method: 'GET', headers });
}

/**
 * Returns a 401 response that passes through the upstream registry's real
 * WWW-Authenticate challenge so the Docker client can authenticate directly.
 * Falls back to a generic challenge only when no upstream header is available.
 * @param {URL} url - Request URL
 * @param {string|null} upstreamAuthenticate - The upstream WWW-Authenticate header
 * @returns {Response} 401 response
 */
function responseUnauthorized(url, upstreamAuthenticate) {
  const headers = new Headers();
  if (upstreamAuthenticate) {
    headers.set('WWW-Authenticate', upstreamAuthenticate);
  } else {
    headers.set('WWW-Authenticate', `Bearer realm="https://${url.hostname}/v2/auth",service="registry"`);
  }
  return new Response(JSON.stringify({ message: 'UNAUTHORIZED' }), {
    status: 401,
    headers
  });
}

/**
 * Infers the repository scope (e.g. `repository:library/nginx:pull`) from the
 * transformed target path. The path should already have the platform prefix
 * and any redundant registry domain stripped, and start with `/v2/`.
 * @param {string} targetPath - The upstream target path, e.g. "/v2/library/nginx/manifests/latest"
 * @returns {string} The inferred scope, or empty string
 */
function inferScope(targetPath) {
  const pathParts = targetPath.split('/').filter(Boolean);
  // targetPath always starts with /v2/, so skip it
  const scopeStart = 1;
  const opIndex = pathParts.findIndex(
    (segment, index) =>
      index >= scopeStart && ['manifests', 'blobs', 'tags', 'referrers'].includes(segment)
  );
  if (opIndex > scopeStart) {
    const repoName = pathParts.slice(scopeStart, opIndex).join('/');
    return `repository:${repoName}:pull`;
  }
  return '';
}

/**
 * Returns the HTML home page shown when the root path is visited in a browser.
 * Includes the supported registry table and usage instructions from the README,
 * with all example domains dynamically replaced by the real request hostname.
 * @param {string} hostname - The request hostname, used for usage examples
 * @returns {string} HTML content
 */
function getHomePage(hostname) {
  // Determine the base domain: if the leftmost label is a known registry prefix,
  // strip it; otherwise use the hostname as-is.
  const label = hostname.split('.')[0].toLowerCase();
  const isRegistrySubdomain = Boolean(DOMAIN_PREFIX_MAP[label]);
  const baseDomain = isRegistrySubdomain
    ? hostname.split('.').slice(1).join('.')
    : hostname;
  // The domain used for path-prefix / registry-mirror examples (the one the user is visiting)
  const currentDomain = hostname;
  // Helper to build a subdomain example
  const sub = (prefix) => `${prefix}.${baseDomain}`;

  const registries = [
    { prefixes: ['docker', 'dockerhub', 'hub'], path: 'cr/docker', source: 'Docker Hub (registry-1.docker.io)' },
    { prefixes: ['ghcr'], path: 'cr/ghcr', source: 'GitHub Container Registry' },
    { prefixes: ['gcr'], path: 'cr/gcr', source: 'Google Container Registry' },
    { prefixes: ['quay'], path: 'cr/quay', source: 'Quay.io' },
    { prefixes: ['mcr'], path: 'cr/mcr', source: 'Microsoft Container Registry' },
    { prefixes: ['ecr'], path: 'cr/ecr', source: 'Amazon ECR Public' },
    { prefixes: ['k8s'], path: 'cr/k8s', source: 'Kubernetes Registry (registry.k8s.io)' },
    { prefixes: ['gitlab'], path: 'cr/gitlab', source: 'GitLab Container Registry' },
    { prefixes: ['nvcr'], path: 'cr/nvcr', source: 'NVIDIA Container Registry' },
    { prefixes: ['redhat'], path: 'cr/redhat', source: 'Red Hat Registry' },
    { prefixes: ['oracle'], path: 'cr/oracle', source: 'Oracle Container Registry' },
    { prefixes: ['cloudsmith'], path: 'cr/cloudsmith', source: 'Cloudsmith' },
    { prefixes: ['digitalocean'], path: 'cr/digitalocean', source: 'DigitalOcean Registry' },
    { prefixes: ['vmware'], path: 'cr/vmware', source: 'VMware Registry' },
    { prefixes: ['heroku'], path: 'cr/heroku', source: 'Heroku Registry' },
    { prefixes: ['suse'], path: 'cr/suse', source: 'SUSE Registry' },
    { prefixes: ['opensuse'], path: 'cr/opensuse', source: 'openSUSE Registry' },
    { prefixes: ['gitpod'], path: 'cr/gitpod', source: 'Gitpod Registry' }
  ];

  const tableRows = registries.map(r => `
    <tr>
      <td><code>${r.prefixes.map(p => `<span class="tag">${p}</span>`).join(' ')}</code></td>
      <td><code>${r.path}</code></td>
      <td>${r.source}</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Docker 镜像代理服务</title>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      max-width: 860px; margin: 40px auto; padding: 0 20px;
      color: #1a1a1a; line-height: 1.7; background: #fafafa;
    }
    h1 { font-size: 26px; margin-bottom: 8px; }
    h2 { font-size: 20px; margin-top: 36px; border-bottom: 2px solid #e5e7eb; padding-bottom: 6px; }
    h3 { font-size: 16px; margin-top: 24px; }
    .intro { color: #4b5563; margin-bottom: 24px; }
    code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 13px; font-family: "SF Mono", Menlo, Consolas, monospace; }
    pre { background: #1e293b; color: #e2e8f0; padding: 16px 18px; border-radius: 8px; overflow-x: auto; font-size: 13px; line-height: 1.6; }
    pre code { background: none; padding: 0; color: inherit; font-size: inherit; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 14px; }
    th, td { border: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; }
    th { background: #f9fafb; font-weight: 600; }
    tr:nth-child(even) td { background: #fcfcfd; }
    .tag { display: inline-block; background: #e0e7ff; color: #4338ca; padding: 1px 8px; border-radius: 10px; font-size: 12px; margin: 1px; }
    .host { color: #2563eb; font-weight: 600; }
    .note { background: #fffbeb; border-left: 4px solid #f59e0b; padding: 10px 14px; margin: 16px 0; border-radius: 4px; font-size: 14px; }
  </style>
</head>
<body>
  <h1>Docker 镜像代理服务</h1>
  <p class="intro">基于 Cloudflare Workers 的容器镜像仓库代理，用于加速公共镜像仓库的拉取。支持 Docker Hub、GHCR、K8s、GCR、Quay 等 18 个公共镜像仓库。</p>

  <h2>📦 支持的镜像仓库</h2>
  <table>
    <thead>
      <tr><th>子域名</th><th>路径前缀</th><th>镜像源</th></tr>
    </thead>
    <tbody>${tableRows}</tbody>
  </table>

  <h2>🚀 使用方式</h2>

  <h3>子域名前缀模式（推荐）</h3>
  <p>每个镜像仓库对应一个子域名，拉取时把仓库域名替换为对应子域名：</p>
  <pre><code># Docker Hub 官方镜像
docker pull ${sub('docker')}/nginx:latest

# Docker Hub 用户镜像
docker pull ${sub('docker')}/bitnami/redis:latest

# GHCR
docker pull ${sub('ghcr')}/nginxinc/nginx-unprivileged:latest

# Kubernetes
docker pull ${sub('k8s')}/pause:3.9

# GCR
docker pull ${sub('gcr')}/distroless/base:latest

# 也支持路径中带原仓库域名
docker pull ${sub('ghcr')}/ghcr.io/nginxinc/nginx-unprivileged:latest</code></pre>

  <h3>路径前缀模式</h3>
  <p>使用 <code>/cr/&lt;registry&gt;/</code> 前缀指定目标仓库：</p>
  <pre><code>docker pull ${currentDomain}/cr/docker/nginx:latest
docker pull ${currentDomain}/cr/ghcr/nginxinc/nginx-unprivileged:latest
docker pull ${currentDomain}/cr/k8s/pause:3.9</code></pre>

  <h3>Docker Hub 镜像加速（registry-mirrors）</h3>
  <p>配置 Docker daemon 使用本服务作为 Docker Hub 镜像加速器，之后 <code>docker pull nginx:latest</code> 等命令自动走代理。</p>
  <p>编辑 <code>/etc/docker/daemon.json</code>：</p>
  <pre><code>{
  "registry-mirrors": ["https://${currentDomain}"]
}</code></pre>
  <p>重启 Docker：</p>
  <pre><code>sudo systemctl restart docker</code></pre>

  <h3>Podman</h3>
  <pre><code># 直接拉取
podman pull ${sub('docker')}/nginx:latest

# 配置 registries.conf 加速 Docker Hub
# /etc/containers/registries.conf
[[registry]]
location = "docker.io"
prefix = "docker.io"
[[registry.mirror]]
location = "${currentDomain}"</code></pre>

  <h3>containerd</h3>
  <p>编辑 <code>/etc/containerd/config.toml</code>：</p>
  <pre><code>[plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
  endpoint = ["https://${currentDomain}"]

[plugins."io.containerd.grpc.v1.cri".registry.mirrors."registry.k8s.io"]
  endpoint = ["https://${sub('k8s')}"]</code></pre>

  <h3>Kubernetes</h3>
  <p>直接在 Pod 定义中使用代理地址，或配置 containerd 镜像加速后使用原始镜像名：</p>
  <pre><code>spec:
  containers:
    - name: nginx
      image: ${sub('docker')}/nginx:latest</code></pre>

  <div class="note">
    当前访问域名：<span class="host">${hostname}</span>。子域名示例基于基础域名 <span class="host">${baseDomain}</span>，请确保已配置对应的 DNS 泛解析记录。
  </div>
</body>
</html>`;
}

/**
 * Handles incoming container registry requests with retries and authentication.
 * @param {Request} request - The incoming request
 * @param {Object} env - Environment variables
 * @param {Object} ctx - Cloudflare Workers execution context
 * @returns {Promise<Response>} The response object
 */
async function handleRequest(request, env, _ctx) {
  try {
    const config = env ? createConfig(env) : CONFIG;
    const url = new URL(request.url);
    const domainPlatform = resolveDomainPlatform(url.hostname);
    const isDocker = isDockerRequest(request, url) || Boolean(domainPlatform);

    // Docker API version check
    if (isDocker && (url.pathname === '/v2/' || url.pathname === '/v2')) {
      const headers = new Headers({
        'Docker-Distribution-Api-Version': 'registry/2.0',
        'Content-Type': 'application/json'
      });
      addSecurityHeaders(headers);
      return new Response('{}', { status: 200, headers });
    }

    if (url.pathname === '/' || url.pathname === '') {
      return new Response(getHomePage(url.hostname), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    const validation = validateRequest(request, url, config);
    if (!validation.valid) {
      return createErrorResponse(validation.error || 'Validation failed', validation.status || 400);
    }

    // Resolve platform & effective path
    let effectivePath = url.pathname;

    if (domainPlatform) {
      const registryName = domainPlatform.replace(/^cr-/, '');
      effectivePath = `/cr/${registryName}${url.pathname}`;
    } else if (url.pathname.startsWith('/v2/cr/')) {
      effectivePath = url.pathname.replace(/^\/v2/, '');
    } else if (url.pathname.startsWith('/cr/')) {
      effectivePath = url.pathname;
    } else if (url.pathname.startsWith('/v2/')) {
      effectivePath = `/cr/docker${url.pathname.replace(/^\/v2/, '')}`;
    } else {
      return createErrorResponse(
        'container registry requests must use /cr/ prefix or a /v2/ path',
        400
      );
    }

    const sortedPlatforms = Object.keys(config.PLATFORMS).sort((a, b) => {
      const pathA = `/${a.replace('-', '/')}/`;
      const pathB = `/${b.replace('-', '/')}/`;
      return pathB.length - pathA.length;
    });

    const platform =
      sortedPlatforms.find(key => {
        const expectedPrefix = `/${key.replace('-', '/')}/`;
        return effectivePath.startsWith(expectedPrefix);
      }) || effectivePath.split('/')[1];

    if (!platform || !config.PLATFORMS[platform]) {
      return createErrorResponse('unknown container registry', 400);
    }

    const targetPath = transformPath(effectivePath, platform);
    const finalTargetPath = targetPath.startsWith('/v2/') ? targetPath : `/v2${targetPath}`;
    const targetUrl = `${config.PLATFORMS[platform]}${finalTargetPath}${url.search}`;
    const authorization = request.headers.get('Authorization');

    // Handle token endpoint /v2/auth
    if (url.pathname === '/v2/auth') {
      const probeUrl = new URL(`${config.PLATFORMS[platform]}/v2/`);
      const resp = await fetch(probeUrl.toString(), { method: 'GET', redirect: 'follow' });
      if (resp.status !== 401) {
        return resp;
      }
      const authenticateStr = resp.headers.get('WWW-Authenticate');
      if (authenticateStr === null) {
        return resp;
      }
      const wwwAuthenticate = parseAuthenticate(authenticateStr);
      const scope = url.searchParams.get('scope');
      return await fetchToken(wwwAuthenticate, scope || '', authorization || '');
    }

    // Build proxy request headers (copy all for protocol compliance)
    const requestHeaders = new Headers();
    for (const [key, value] of request.headers.entries()) {
      if (!['host', 'connection', 'upgrade', 'proxy-connection'].includes(key.toLowerCase())) {
        requestHeaders.set(key, value);
      }
    }

    /** @type {RequestInit} */
    const fetchOptions = {
      method: request.method,
      headers: requestHeaders,
      redirect: 'follow'
    };

    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      fetchOptions.body = request.body;
    }

    // Retry loop
    let attempts = 0;
    let response;
    while (attempts < config.MAX_RETRIES) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.TIMEOUT_SECONDS * 1000);

        response = await fetch(targetUrl, { ...fetchOptions, signal: controller.signal });
        clearTimeout(timeoutId);

        if (response.ok || response.status === 206) {
          break;
        }

        // Handle 401 authentication challenge for public repositories
        if (response.status === 401) {
          const authenticateStr = response.headers.get('WWW-Authenticate');
          if (authenticateStr) {
            try {
              const wwwAuthenticate = parseAuthenticate(authenticateStr);
              const scope = inferScope(finalTargetPath);
              const tokenResponse = await fetchToken(wwwAuthenticate, scope, '');
              if (tokenResponse.ok) {
                const tokenData = await tokenResponse.json();
                if (tokenData.token) {
                  const retryHeaders = new Headers(requestHeaders);
                  retryHeaders.set('Authorization', `Bearer ${tokenData.token}`);
                  const retryResponse = await fetch(targetUrl, {
                    ...fetchOptions,
                    headers: retryHeaders
                  });
                  if (retryResponse.ok) {
                    response = retryResponse;
                    break;
                  }
                }
              }
            } catch (error) {
              console.warn('Token fetch failed:', error);
            }
          }
          // Pass through the upstream's real WWW-Authenticate so the Docker
          // client can authenticate directly (e.g. for private repos).
          return responseUnauthorized(url, authenticateStr);
        }

        // Don't retry on client errors
        if (response.status >= 400 && response.status < 500) {
          break;
        }

        attempts++;
        if (attempts < config.MAX_RETRIES) {
          await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
        }
      } catch (error) {
        attempts++;
        if (error instanceof Error && error.name === 'AbortError') {
          return createErrorResponse('Gateway Timeout', 504);
        }
        if (attempts >= config.MAX_RETRIES) {
          return createErrorResponse('Bad Gateway', 502);
        }
        await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
      }
    }

    return response;
  } catch {
    return createErrorResponse('Internal Server Error', 500);
  }
}

export default {
  fetch: handleRequest
};
