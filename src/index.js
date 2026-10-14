import { CONFIG, createConfig } from './config/index.js';
import { transformPath, resolveDomainPlatform } from './config/platforms.js';

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
 * @param {string} hostname - The request hostname, used for usage examples
 * @returns {string} HTML content
 */
function getHomePage(hostname) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Docker 镜像代理</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 720px; margin: 60px auto; padding: 0 20px; color: #1a1a1a; line-height: 1.6; }
    h1 { font-size: 28px; }
    code { background: #f4f4f5; padding: 2px 6px; border-radius: 4px; font-size: 14px; }
    pre { background: #f4f4f5; padding: 14px; border-radius: 8px; overflow-x: auto; font-size: 13px; }
    .host { color: #2563eb; font-weight: 600; }
  </style>
</head>
<body>
  <h1>Docker 镜像代理服务</h1>
  <p>这是一个基于 Cloudflare Workers 的容器镜像仓库代理，用于加速公共镜像仓库的拉取。</p>
  <h2>使用示例</h2>
  <pre><code># 当前域名（<span class="host">${hostname}</span>）
docker pull ${hostname}/nginx:latest

# 其他仓库通过子域名访问
docker pull ghcr.${hostname}/nginxinc/nginx-unprivileged:latest
docker pull k8s.${hostname}/pause:3.9</code></pre>
  <p>支持的仓库子域名：docker / ghcr / gcr / quay / mcr / ecr / k8s / gitlab / nvcr 等。</p>
  <p>浏览器访问此页仅作说明，镜像拉取请使用 <code>docker pull</code> 命令。</p>
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
