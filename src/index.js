import { CONFIG, createConfig } from './config/index.js';
import { transformPath } from './config/platforms.js';

/**
 * Monitors performance metrics during request processing
 */
class PerformanceMonitor {
  /**
   * Initializes a new performance monitor
   */
  constructor() {
    this.startTime = Date.now();
    this.marks = new Map();
  }

  /**
   * Marks a timing point with the given name
   * @param {string} name - The name of the timing mark
   */
  mark(name) {
    if (this.marks.has(name)) {
      console.warn(`Mark with name ${name} already exists.`);
    }
    this.marks.set(name, Date.now() - this.startTime);
  }

  /**
   * Returns all collected metrics
   * @returns {Object.<string, number>} Object containing name-timestamp pairs
   */
  getMetrics() {
    return Object.fromEntries(this.marks.entries());
  }
}

/**
 * Detects if a request is a container registry operation
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is a container registry operation
 */
function isDockerRequest(request, url) {
  // Check for container registry API endpoints
  if (url.pathname.startsWith('/v2/')) {
    return true;
  }

  // Check for Docker-specific User-Agent
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.toLowerCase().includes('docker/')) {
    return true;
  }

  // Check for Docker-specific Accept headers
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
 * Detects if a request is a Git operation
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is a Git operation
 */
function isGitRequest(request, url) {
  // Check for Git-specific endpoints
  if (url.pathname.endsWith('/info/refs')) {
    return true;
  }

  if (url.pathname.endsWith('/git-upload-pack') || url.pathname.endsWith('/git-receive-pack')) {
    return true;
  }

  // Check for Git user agents (more comprehensive check)
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.includes('git/') || userAgent.startsWith('git/')) {
    return true;
  }

  // Check for Git-specific query parameters
  if (url.searchParams.has('service')) {
    const service = url.searchParams.get('service');
    return service === 'git-upload-pack' || service === 'git-receive-pack';
  }

  // Check for Git-specific content types
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('git-upload-pack') || contentType.includes('git-receive-pack')) {
    return true;
  }

  return false;
}

/**
 * Check if the request is for an AI inference provider
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is an AI inference request
 */
function isAIInferenceRequest(request, url) {
  // Check for AI inference provider paths (ip/{provider}/...)
  if (url.pathname.startsWith('/ip/')) {
    return true;
  }

  // Check for common AI inference API endpoints
  const aiEndpoints = [
    '/v1/chat/completions',
    '/v1/completions',
    '/v1/messages',
    '/v1/predictions',
    '/v1/generate',
    '/v1/embeddings',
    '/openai/v1/chat/completions'
  ];

  if (aiEndpoints.some(endpoint => url.pathname.includes(endpoint))) {
    return true;
  }

  // Check for AI-specific content types
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('application/json') && request.method === 'POST') {
    // Additional check for common AI inference patterns in URL
    if (
      url.pathname.includes('/chat/') ||
      url.pathname.includes('/completions') ||
      url.pathname.includes('/generate') ||
      url.pathname.includes('/predict')
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Validates incoming requests against security rules
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @param {import('./config/index.js').ApplicationConfig} config - Configuration object
 * @returns {{valid: boolean, error?: string, status?: number}} Validation result
 */
function validateRequest(request, url, config = CONFIG) {
  // Allow POST method for Git, Docker, and AI inference operations
  const isGit = isGitRequest(request, url);
  const isDocker = isDockerRequest(request, url);
  const isAI = isAIInferenceRequest(request, url);

  const allowedMethods =
    isGit || isDocker || isAI
      ? ['GET', 'HEAD', 'POST', 'PUT', 'PATCH']
      : config.SECURITY.ALLOWED_METHODS;

  if (!allowedMethods.includes(request.method)) {
    return { valid: false, error: 'Method not allowed', status: 405 };
  }

  if (url.pathname.length > config.SECURITY.MAX_PATH_LENGTH) {
    return { valid: false, error: 'Path too long', status: 414 };
  }

  return { valid: true };
}

/**
 * Creates a standardized error response
 * @param {string} message - Error message
 * @param {number} status - HTTP status code
 * @param {boolean} includeDetails - Whether to include detailed error information
 * @returns {Response} Error response
 */
function createErrorResponse(message, status, includeDetails = false) {
  const errorBody = includeDetails
    ? JSON.stringify({ error: message, status, timestamp: new Date().toISOString() })
    : message;

  return new Response(errorBody, {
    status,
    headers: addSecurityHeaders(
      new Headers({
        'Content-Type': includeDetails ? 'application/json' : 'text/plain'
      })
    )
  });
}

/**
 * Adds security headers to the response
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
 * Parses Docker WWW-Authenticate header
 * @param {string} authenticateStr - The WWW-Authenticate header value
 * @returns {{realm: string, service: string}} Parsed authentication info
 */
function parseAuthenticate(authenticateStr) {
  // sample: Bearer realm="https://auth.ipv6.docker.com/token",service="registry.docker.io"
  const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
  const matches = authenticateStr.match(re);
  if (matches == null || matches.length < 2) {
    throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
  }
  return {
    realm: matches[0],
    service: matches[1]
  };
}

/**
 * Fetches authentication token from container registry
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
  return await fetch(url, { method: 'GET', headers: headers });
}

/**
 * Creates unauthorized response for container registry
 * @param {URL} url - Request URL
 * @returns {Response} Unauthorized response
 */
function responseUnauthorized(url) {
  const headers = new Headers();
  headers.set('WWW-Authenticate', `Bearer realm="https://${url.hostname}/v2/auth",service="Xget"`);
  return new Response(JSON.stringify({ message: 'UNAUTHORIZED' }), {
    status: 401,
    headers: headers
  });
}

function githubInterface() {
	const htmlPage = `
  <!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xget URL 转换器</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        }

        body {
            background: linear-gradient(135deg, #1a1c2f 0%, #2b2c3c 100%);
            color: #e6e9f0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            padding: 20px;
            position: relative;
        }

        .container {
            max-width: 800px;
            width: 100%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            flex: 1;
        }

        header {
            text-align: center;
            margin-bottom: 40px;
            padding: 20px;
            width: 100%;
            max-width: 600px;
            position: relative; /* 新增: 为GitHub图标定位做准备 */
        }

        h1 {
            font-size: 2.8rem;
            background: linear-gradient(to right, #6a7eff, #9d7bff);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            margin-bottom: 10px;
            font-weight: 700;
            text-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
        }

        .subtitle {
            font-size: 1.2rem;
            color: #a2a9c5;
            line-height: 1.6;
        }

        .converter-card {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 16px;
            padding: 30px;
            width: 100%;
            max-width: 600px;
            backdrop-filter: blur(10px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            margin-bottom: 40px;
        }

        .input-group {
            margin-bottom: 25px;
        }

        label {
            display: block;
            margin-bottom: 10px;
            font-weight: 500;
            color: #a2a9c5;
            font-size: 1.1rem;
        }

        .input-container {
            position: relative;
        }

        input {
            width: 100%;
            padding: 15px 20px;
            font-size: 1.1rem;
            background: rgba(0, 2, 29, 0.7);
            border: 1px solid rgba(90, 100, 150, 0.4);
            border-radius: 10px;
            color: #e6e9f0;
            outline: none;
            transition: all 0.3s ease;
        }

        input:focus {
            border-color: #6a7eff;
            box-shadow: 0 0 0 3px rgba(106, 126, 255, 0.2);
        }

        .detection-info {
            font-size: 0.9rem;
            margin-top: 8px;
            color: #7d87a8;
            font-style: italic;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .detection-info i {
            color: #6a7eff;
        }

        .result-container {
            display: flex;
            background: rgba(0, 2, 29, 0.7);
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid rgba(90, 100, 150, 0.4);
            opacity: 0;
            height: 0;
            transform: translateY(-10px);
            transition: all 0.3s ease;
            pointer-events: none;
        }

        .result-container.visible {
            opacity: 1;
            height: auto;
            transform: translateY(0);
            pointer-events: auto;
        }

        #converted-url {
            flex-grow: 1;
            padding: 15px 20px;
            font-size: 1.1rem;
            background: transparent;
            border: none;
            color: #e6e9f0;
            outline: none;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .copy-btn {
            background: linear-gradient(135deg, #6a7eff 0%, #9d7bff 100%);
            color: white;
            border: none;
            padding: 0 10px;
            font-size: 1.1rem;
            cursor: button;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            min-width: 160px;
        }

        .copy-btn:hover {
            background: linear-gradient(135deg, #5a6df5 0%, #8d6bf5 100%);
            box-shadow: 0 0 15px rgba(106, 126, 255, 0.4);
        }

        .copy-btn:active {
            transform: scale(0.98);
        }

        .loading-icon {
            display: inline-block;
            animation: spin 1s linear infinite;
            margin-right: 8px;
        }

        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        .output-label {
            opacity: 0;
            height: 0;
            overflow: hidden;
            transition: all 0.3s ease;
            margin-bottom: 10px;
            font-weight: 500;
            color: #a2a9c5;
            font-size: 1.1rem;
        }

        .output-label.visible {
            opacity: 1;
            height: auto;
        }

        footer {
            width: 100%;
            text-align: center;
            color: #7d87a8;
            font-size: 0.95rem;
            line-height: 1.8;
            padding: 20px;
            position: relative;
            bottom: 0;
            left: 0;
        }

        .toast {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            color: white;
            padding: 15px 30px;
            border-radius: 10px;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.3);
            transition: transform 0.3s ease;
            z-index: 100;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .toast.show {
            transform: translateX(-50%) translateY(0);
        }

        /* 新增: GitHub图标样式 */
        .github-corner {
            position: absolute;
            top: 20px;
            right: 20px;
            color: #a2a9c5;
            font-size: 1.8rem;
            transition: all 0.3s ease;
            z-index: 10;
        }

        .github-corner:hover {
            transform: scale(1.1);
            color: #e6e9f0;
        }

        /* 新增: Footer链接样式 */
        .footer-link {
            color: #6a7eff;
            text-decoration: none;
            transition: color 0.3s ease;
            margin-left: 5px;
        }

        .footer-link:hover {
            color: #9d7bff;
            text-decoration: underline;
        }

        @media (max-width: 600px) {
            h1 {
                font-size: 2.2rem;
            }

            .converter-card {
                padding: 20px;
            }

            .result-container {
                flex-direction: column;
            }

            .copy-btn {
                padding: 12px;
                width: 100%;
                min-width: auto;
            }

            /* 响应式调整：在小屏幕上调整GitHub图标位置 */
            .github-corner {
                top: 15px;
                right: 15px;
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <!-- 新增: 右上角GitHub图标链接 -->
            <a href="https://github.com/BadKid90s/Xget/" target="_blank" class="github-corner">
                <i class="fab fa-github"></i>
            </a>

            <h1>Xget URL 转换器</h1>
            <p class="subtitle">将支持平台的 URL 转换为加速的 Xget 格式</p>
        </header>

        <main class="converter-card">
            <div class="input-group">
                <label for="original-url">原始 URL</label>
                <div class="input-container">
                    <input type="url" id="original-url" placeholder="https://github.com/user/repo..." autocomplete="off">
                </div>
                <div class="detection-info" id="platform-info">
                    <i class="fas fa-magic"></i>
                    <span>正在加载支持的平台...</span>
                </div>
            </div>

            <div class="input-group">
                <label for="converted-url" class="output-label" id="output-label">转换后的 Xget URL</label>
                <div class="result-container" id="result-container">
                    <input type="text" id="converted-url" readonly>
                    <button id="copy-button" class="copy-btn" disabled>
                        <i class="fas fa-copy"></i>
                        <span class="copy-text">复制</span>
                    </button>
                </div>
            </div>
        </main>
    </div>

    <footer>
        <div>Xget URL 转换工具</div>
        <div>版权所有 © 2025。保留所有权利。更多用法请参考
            <a href="https://github.com/BadKid90s/Xget/" target="_blank" class="footer-link">GitHub</a>
        </div>
    </footer>

    <div id="toast" class="toast">
        <i class="fas fa-check-circle"></i>
        <span>已复制！</span>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            let platformsData = {};
            const originalUrlInput = document.getElementById('original-url');
            const convertedUrlInput = document.getElementById('converted-url');
            const copyButton = document.getElementById('copy-button');
            const toast = document.getElementById('toast');
            const resultContainer = document.getElementById('result-container');
            const outputLabel = document.getElementById('output-label');
            const platformInfo = document.getElementById('platform-info');

            // 获取当前域名
            const currentOrigin = window.location.origin;

            // 动态加载平台数据
            function loadPlatforms() {
                platformInfo.innerHTML = '<i class="fas fa-circle-notch loading-icon"></i> 正在加载支持的平台列表...';

                fetch('/platforms')
                    .then(response => response.json())
                    .then(data => {
                        platformsData = data;
                        updatePlatformInfo();
                    })
                    .catch(error => {
                        console.error('平台数据加载失败:', error);
                        platformInfo.innerHTML = '<i class="fas fa-exclamation-triangle"></i> 平台数据加载失败，请刷新页面重试';
                        platformsData = {};
                    });
            }

            // 更新平台信息显示
            function updatePlatformInfo() {
                const platforms = Object.keys(platformsData);
                if (platforms.length === 0) {
                    platformInfo.innerHTML = '<i class="fas fa-exclamation-circle"></i> 未加载任何平台数据';
                    return;
                }

                const platformList = platforms.join(', ').toUpperCase();
                platformInfo.innerHTML = \`<i class="fas fa-check-circle"></i> 已加载 \${platforms.length} 个平台.\`;
            }

            // 自动检测平台并转换URL
            function detectAndConvert() {
                const url = originalUrlInput.value.trim();

                if (url) {
                    resultContainer.classList.add('visible');
                    outputLabel.classList.add('visible');
                    copyButton.disabled = false;
                } else {
                    resultContainer.classList.remove('visible');
                    outputLabel.classList.remove('visible');
                    convertedUrlInput.value = '';
                    copyButton.disabled = true;
                    return;
                }

                if (Object.keys(platformsData).length === 0) {
                    convertedUrlInput.value = '平台数据未加载，请稍后重试';
                    return;
                }

                let prefix = null;
                for (const [key, domain] of Object.entries(platformsData)) {
                    if (url.startsWith(domain)) {
                        prefix = key;
                        break;
                    }
                }

                if (prefix) {
                    const path = url.substring(platformsData[prefix].length);
                    convertedUrlInput.value = \`\${currentOrigin}/\${prefix}\${path}\`;
                } else {
                    convertedUrlInput.value = '无法识别的平台URL';
                }
            }

            // 添加输入事件监听
            originalUrlInput.addEventListener('input', detectAndConvert);

            // 复制功能
            copyButton.addEventListener('click', function() {
                if (!convertedUrlInput.value || convertedUrlInput.value.includes('无法识别') ||
                    convertedUrlInput.value.includes('未加载')) {
                    showToast('没有有效内容可复制', 'error');
                    return;
                }

                convertedUrlInput.select();
                convertedUrlInput.setSelectionRange(0, 99999); // 移动设备支持

                try {
                    const successful = document.execCommand('copy');
                    if (successful) {
                        showToast('已复制！', 'success');

                        // 添加成功动画
                        const icon = this.querySelector('i');
                        const text = this.querySelector('.copy-text');

                        icon.className = 'fas fa-check';
                        text.textContent = '已复制';

                        setTimeout(() => {
                            icon.className = 'fas fa-copy';
                            text.textContent = '复制';
                        }, 2000);
                    } else {
                        showToast('复制失败，请手动复制', 'error');
                    }
                } catch (err) {
                    showToast('复制失败，请手动复制', 'error');
                }
            });

            // 显示通知
            function showToast(message, type = 'success') {
                toast.innerHTML = \`
                    <i class="fas \${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
                    <span>\${message}</span>
                \`;
                toast.classList.add('show');

                setTimeout(() => {
                    toast.classList.remove('show');
                }, 3000);
            }

            // 初始化：加载平台数据
            loadPlatforms();
        });
    </script>
</body>
</html>
  `;
	return htmlPage;
}

/**
 * Handles incoming requests with caching, retries, and security measures
 * @param {Request} request - The incoming request
 * @param {Object} env - Environment variables
 * @param {ExecutionContext} ctx - Cloudflare Workers execution context
 * @returns {Promise<Response>} The response object
 */
async function handleRequest(request, env, ctx) {
  try {
    // Create config with environment variable overrides
    const config = env ? createConfig(env) : CONFIG;
    const url = new URL(request.url);
    const isDocker = isDockerRequest(request, url);

    const monitor = new PerformanceMonitor();

	const origin = url.origin; // 获取当前域名

	if (url.pathname === '/platforms') {
		  return new Response(JSON.stringify(CONFIG.PLATFORMS), {
			  headers: { 'Content-Type': 'application/json' }
		  });
	}

	if (url.pathname === '/' || url.pathname === '') {
		  return new Response(githubInterface(), {
			  headers: { 'Content-Type': 'text/html; charset=UTF-8' }
		  });
	}

	  // Handle Docker API version check
    if (isDocker && (url.pathname === '/v2/' || url.pathname === '/v2')) {
      const headers = new Headers({
        'Docker-Distribution-Api-Version': 'registry/2.0',
        'Content-Type': 'application/json'
      });
      addSecurityHeaders(headers);
      return new Response('{}', { status: 200, headers });
    }

    const validation = validateRequest(request, url, config);
    if (!validation.valid) {
      return createErrorResponse(validation.error || 'Validation failed', validation.status || 400);
    }

    // Parse platform and path
    let platform;
    let effectivePath = url.pathname;

    // Handle container registry paths specially
    if (isDocker) {
      // For Docker requests (excluding version check which is handled above),
      // check if they have /cr/ prefix
      if (!url.pathname.startsWith('/cr/') && !url.pathname.startsWith('/v2/cr/')) {
        return createErrorResponse('container registry requests must use /cr/ prefix', 400);
      }
      // Remove /v2 from the path for container registry API consistency if present
      effectivePath = url.pathname.replace(/^\/v2/, '');
    }

    // Platform detection using transform patterns
    // Sort platforms by path length (descending) to prioritize more specific paths
    // e.g., conda/community should match before conda, pypi/files before pypi
    const sortedPlatforms = Object.keys(config.PLATFORMS).sort((a, b) => {
      const pathA = `/${a.replace('-', '/')}/`;
      const pathB = `/${b.replace('-', '/')}/`;
      return pathB.length - pathA.length;
    });

    platform = sortedPlatforms.find(key => {
        const expectedPrefix = `/${key.replace('-', '/')}/`;
        return effectivePath.startsWith(expectedPrefix);
      }) || effectivePath.split('/')[1];

    if (!platform || !config.PLATFORMS[platform]) {
      return Response.redirect(origin, 302);
    }

    // Transform URL based on platform using unified logic
    const targetPath = transformPath(effectivePath, platform);

    // For container registries, ensure we add the /v2 prefix for the Docker API
    let finalTargetPath;
    if (platform.startsWith('cr-')) {
      finalTargetPath = `/v2${targetPath}`;
    } else {
      finalTargetPath = targetPath;
    }

    const targetUrl = `${config.PLATFORMS[platform]}${finalTargetPath}${url.search}`;
    const authorization = request.headers.get('Authorization');

    // Handle Docker authentication
    if (isDocker && url.pathname === '/v2/auth') {
      const newUrl = new URL(config.PLATFORMS[platform] + '/v2/');
      const resp = await fetch(newUrl.toString(), {
        method: 'GET',
        redirect: 'follow'
      });
      if (resp.status !== 401) {
        return resp;
      }
      const authenticateStr = resp.headers.get('WWW-Authenticate');
      if (authenticateStr === null) {
        return resp;
      }
      const wwwAuthenticate = parseAuthenticate(authenticateStr);
      let scope = url.searchParams.get('scope');
      return await fetchToken(wwwAuthenticate, scope || '', authorization || '');
    }

    // Check if this is a Git operation
    const isGit = isGitRequest(request, url);

    // Check if this is an AI inference request
    const isAI = isAIInferenceRequest(request, url);

    // Check cache first (skip cache for Git, Docker, and AI inference operations)
    /** @type {Cache} */
    // @ts-ignore - Cloudflare Workers cache API
    const cache = caches.default;
    const cacheKey = new Request(targetUrl, request);
    let response;

    if (!isGit && !isDocker && !isAI) {
      response = await cache.match(cacheKey);
      if (response) {
        monitor.mark('cache_hit');
        return response;
      }
    }

    /** @type {RequestInit} */
    const fetchOptions = {
      method: request.method,
      headers: new Headers(),
      redirect: 'follow'
    };

    // Add body for POST/PUT/PATCH requests (Git/Docker/AI inference operations)
    if (['POST', 'PUT', 'PATCH'].includes(request.method) && (isGit || isDocker || isAI)) {
      fetchOptions.body = request.body;
    }

    // Cast headers to Headers for proper typing
    const requestHeaders = /** @type {Headers} */ (fetchOptions.headers);

    // Set appropriate headers for Git/Docker/AI vs regular requests
    if (isGit || isDocker || isAI) {
      // For Git/Docker/AI operations, copy all headers from the original request
      // This ensures protocol compliance
      for (const [key, value] of request.headers.entries()) {
        // Skip headers that might cause issues with proxying
        if (!['host', 'connection', 'upgrade', 'proxy-connection'].includes(key.toLowerCase())) {
          requestHeaders.set(key, value);
        }
      }

      // Set Git-specific headers if not present
      if (isGit && !requestHeaders.has('User-Agent')) {
        requestHeaders.set('User-Agent', 'git/2.34.1');
      }

      // For Git upload-pack requests, ensure proper content type
      if (isGit && request.method === 'POST' && url.pathname.endsWith('/git-upload-pack')) {
        if (!requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/x-git-upload-pack-request');
        }
      }

      // For Git receive-pack requests, ensure proper content type
      if (isGit && request.method === 'POST' && url.pathname.endsWith('/git-receive-pack')) {
        if (!requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/x-git-receive-pack-request');
        }
      }

      // For AI inference requests, ensure proper content type and headers
      if (isAI) {
        // Ensure JSON content type for AI API requests if not already set
        if (request.method === 'POST' && !requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/json');
        }

        // Set appropriate User-Agent for AI requests if not present
        if (!requestHeaders.has('User-Agent')) {
          requestHeaders.set('User-Agent', 'Xget-AI-Proxy/1.0');
        }
      }
    } else {
      // Regular file download headers
      Object.assign(fetchOptions, {
        cf: {
          http3: true,
          cacheTtl: config.CACHE_DURATION,
          cacheEverything: true,
          minify: {
            javascript: true,
            css: true,
            html: true
          },
          preconnect: true
        }
      });

      requestHeaders.set('Accept-Encoding', 'gzip, deflate, br');
      requestHeaders.set('Connection', 'keep-alive');
      requestHeaders.set('User-Agent', 'Wget/1.21.3');
      requestHeaders.set('Origin', request.headers.get('Origin') || '*');

      // Handle range requests
      const rangeHeader = request.headers.get('Range');
      if (rangeHeader) {
        requestHeaders.set('Range', rangeHeader);
      }
    }

    // Implement retry mechanism
    let attempts = 0;
    while (attempts < config.MAX_RETRIES) {
      try {
        monitor.mark('attempt_' + attempts);

        // Fetch with timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.TIMEOUT_SECONDS * 1000);

        // For Git/Docker operations, don't use Cloudflare-specific options
        const finalFetchOptions =
          isGit || isDocker
            ? { ...fetchOptions, signal: controller.signal }
            : { ...fetchOptions, signal: controller.signal };

        // Special handling for HEAD requests to ensure Content-Length header
        if (request.method === 'HEAD') {
          // First, try the HEAD request
          response = await fetch(targetUrl, finalFetchOptions);

          // If HEAD request succeeds but lacks Content-Length, do a GET request to get it
          if (response.ok && !response.headers.get('Content-Length')) {
            const getResponse = await fetch(targetUrl, {
              ...finalFetchOptions,
              method: 'GET'
            });

            if (getResponse.ok) {
              // Create a new response with HEAD method but include Content-Length from GET
              const headHeaders = new Headers(response.headers);
              const contentLength = getResponse.headers.get('Content-Length');

              if (contentLength) {
                headHeaders.set('Content-Length', contentLength);
              } else {
                // If still no Content-Length, calculate it from the response body
                const arrayBuffer = await getResponse.arrayBuffer();
                headHeaders.set('Content-Length', arrayBuffer.byteLength.toString());
              }

              response = new Response(null, {
                status: getResponse.status,
                statusText: getResponse.statusText,
                headers: headHeaders
              });
            }
          }
        } else {
          response = await fetch(targetUrl, finalFetchOptions);
        }

        clearTimeout(timeoutId);

        if (response.ok || response.status === 206) {
          monitor.mark('success');
          break;
        }

        // For container registry, handle authentication challenges more intelligently
        if (isDocker && response.status === 401) {
          monitor.mark('docker_auth_challenge');

          // For container registries, first check if we can get a token without credentials
          // This allows access to public repositories
          const authenticateStr = response.headers.get('WWW-Authenticate');
          if (authenticateStr) {
            try {
              const wwwAuthenticate = parseAuthenticate(authenticateStr);

              // Infer scope from the request path for container registry requests
              let scope = '';
              const pathParts = url.pathname.split('/');
              if (pathParts.length >= 4 && pathParts[1] === 'v2') {
                // Extract repository name from path like /v2/cr/ghcr/nginxinc/nginx-unprivileged/manifests/latest
                // Remove /v2 and platform prefix to get the repo path
                const repoPath = pathParts.slice(4).join('/'); // Skip /v2/cr/[registry]
                const repoParts = repoPath.split('/');
                if (repoParts.length >= 1) {
                  const repoName = repoParts.slice(0, -2).join('/'); // Remove /manifests/tag or /blobs/sha
                  if (repoName) {
                    scope = `repository:${repoName}:pull`;
                  }
                }
              }

              // Try to get a token for public access (without authorization)
              const tokenResponse = await fetchToken(wwwAuthenticate, scope || '', '');
              if (tokenResponse.ok) {
                const tokenData = await tokenResponse.json();
                if (tokenData.token) {
                  // Retry the original request with the obtained token
                  const retryHeaders = new Headers(requestHeaders);
                  retryHeaders.set('Authorization', `Bearer ${tokenData.token}`);

                  const retryResponse = await fetch(targetUrl, {
                    ...finalFetchOptions,
                    headers: retryHeaders
                  });

                  if (retryResponse.ok) {
                    response = retryResponse;
                    monitor.mark('success');
                    break;
                  }
                }
              }
            } catch (error) {
              console.log('Token fetch failed:', error);
            }
          }

          // If token fetch failed or didn't work, return the unauthorized response
          // Only return this if we truly can't access the resource
          return responseUnauthorized(url);
        }

        // Don't retry on client errors (4xx) - these won't improve with retries
        if (response.status >= 400 && response.status < 500) {
          monitor.mark('client_error');
          break;
        }

        attempts++;
        if (attempts < config.MAX_RETRIES) {
          await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
        }
      } catch (error) {
        attempts++;
        if (error instanceof Error && error.name === 'AbortError') {
          return createErrorResponse('Request timeout', 408);
        }
        if (attempts >= config.MAX_RETRIES) {
          const message = error instanceof Error ? error.message : String(error);
          return createErrorResponse(
            `Failed after ${config.MAX_RETRIES} attempts: ${message}`,
            500,
            true
          );
        }
        // Wait before retrying
        await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * attempts));
      }
    }

    // Check if we have a valid response after all attempts
    if (!response) {
      return createErrorResponse('No response received after all retry attempts', 500, true);
    }

    // If response is still not ok after all retries, return the error
    if (!response.ok && response.status !== 206) {
      // For Docker authentication errors that we couldn't resolve with anonymous tokens,
      // return a more helpful error message
      if (isDocker && response.status === 401) {
        const errorText = await response.text().catch(() => '');
        return createErrorResponse(
          `Authentication required for this container registry resource. This may be a private repository. Original error: ${errorText}`,
          401,
          true
        );
      }
      const errorText = await response.text().catch(() => 'Unknown error');
      return createErrorResponse(
        `Upstream server error (${response.status}): ${errorText}`,
        response.status,
        true
      );
    }

    // Handle URL rewriting for different platforms
    let responseBody = response.body;

    // Handle PyPI simple index URL rewriting
    if (platform === 'pypi' && response.headers.get('content-type')?.includes('text/html')) {
      const originalText = await response.text();
      // Rewrite URLs in the response body to go through the Cloudflare Worker
      // files.pythonhosted.org URLs should be rewritten to go through our pypi/files endpoint
      const rewrittenText = originalText.replace(
        /https:\/\/files\.pythonhosted\.org/g,
        `${url.origin}/pypi/files`
      );
      responseBody = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(rewrittenText));
          controller.close();
        }
      });
    }

    // Handle npm registry URL rewriting
    if (platform === 'npm' && response.headers.get('content-type')?.includes('application/json')) {
      const originalText = await response.text();
      // Rewrite tarball URLs in npm registry responses to go through our npm endpoint
      // https://registry.npmjs.org/package/-/package-version.tgz -> https://xget.xi-xu.me/npm/package/-/package-version.tgz
      const rewrittenText = originalText.replace(
        /https:\/\/registry\.npmjs\.org\/([^\/]+)/g,
        `${url.origin}/npm/$1`
      );
      responseBody = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(rewrittenText));
          controller.close();
        }
      });
    }

    // Prepare response headers
    const headers = new Headers(response.headers);

    if (isGit || isDocker) {
      // For Git/Docker operations, preserve all headers from the upstream response
      // These protocols are very sensitive to header changes
      // Don't add any additional headers that might interfere with protocol operation
      // The response headers from upstream should be passed through as-is
    } else {
      // Regular file download headers
      headers.set('Cache-Control', `public, max-age=${config.CACHE_DURATION}`);
      headers.set('X-Content-Type-Options', 'nosniff');
      headers.set('Accept-Ranges', 'bytes');
      addSecurityHeaders(headers);
    }

    // Create final response
    const finalResponse = new Response(responseBody, {
      status: response.status,
      headers: headers
    });

    // Cache successful responses (skip caching for Git, Docker, and AI inference operations)
    // Only cache GET and HEAD requests to avoid "Cannot cache response to non-GET request" errors
    if (
      !isGit &&
      !isDocker &&
      !isAI &&
      ['GET', 'HEAD'].includes(request.method) &&
      (response.ok || response.status === 206)
    ) {
      ctx.waitUntil(cache.put(cacheKey, finalResponse.clone()));
    }

    monitor.mark('complete');
    return isGit || isDocker || isAI
      ? finalResponse
      : addPerformanceHeaders(finalResponse, monitor);
  } catch (error) {
    console.error('Error handling request:', error);
    const message = error instanceof Error ? error.message : String(error);
    return createErrorResponse(`Internal Server Error: ${message}`, 500, true);
  }
}

/**
 * Adds performance metrics to response headers
 * @param {Response} response - The response object
 * @param {PerformanceMonitor} monitor - Performance monitor instance
 * @returns {Response} New response with performance headers
 */
function addPerformanceHeaders(response, monitor) {
  const headers = new Headers(response.headers);
  headers.set('X-Performance-Metrics', JSON.stringify(monitor.getMetrics()));
  addSecurityHeaders(headers);
  return new Response(response.body, {
    status: response.status,
    headers: headers
  });
}

export default {
  /**
   * Main entry point for the Cloudflare Worker
   * @param {Request} request - The incoming request
   * @param {Object} env - Environment variables
   * @param {ExecutionContext} ctx - Cloudflare Workers execution context
   * @returns {Promise<Response>} The response object
   */
  fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};
