/**
 * Supported container registries.
 * Each key is a platform identifier used internally; the value is the registry base URL.
 * @type {Object.<string, string>}
 */
export const PLATFORMS = {
  'cr-docker': 'https://registry-1.docker.io',
  'cr-quay': 'https://quay.io',
  'cr-gcr': 'https://gcr.io',
  'cr-mcr': 'https://mcr.microsoft.com',
  'cr-ecr': 'https://public.ecr.aws',
  'cr-ghcr': 'https://ghcr.io',
  'cr-gitlab': 'https://registry.gitlab.com',
  'cr-redhat': 'https://registry.redhat.io',
  'cr-oracle': 'https://container-registry.oracle.com',
  'cr-cloudsmith': 'https://docker.cloudsmith.io',
  'cr-digitalocean': 'https://registry.digitalocean.com',
  'cr-vmware': 'https://projects.registry.vmware.com',
  'cr-k8s': 'https://registry.k8s.io',
  'cr-heroku': 'https://registry.heroku.com',
  'cr-suse': 'https://registry.suse.com',
  'cr-opensuse': 'https://registry.opensuse.org',
  'cr-gitpod': 'https://registry.gitpod.io',
  'cr-nvcr': 'https://nvcr.io'
};

/**
 * Maps a leftmost hostname label (subdomain prefix) to a container registry platform key.
 *
 * Enables the domain-prefix mode: the registry is selected by subdomain,
 * e.g. `ghcr.example.com/v2/<repo>/manifests/<ref>` proxies to ghcr.io.
 * This matches the registry v2 API where the registry host is the domain itself,
 * so `docker pull ghcr.example.com/user/repo:tag` works out of the box.
 *
 * @type {Object.<string, string>}
 */
export const DOMAIN_PREFIX_MAP = {
  // Docker Hub
  docker: 'cr-docker',
  dockerhub: 'cr-docker',
  hub: 'cr-docker',
  // GitHub Container Registry
  ghcr: 'cr-ghcr',
  // Google Container Registry
  gcr: 'cr-gcr',
  // Quay.io
  quay: 'cr-quay',
  // Microsoft Container Registry
  mcr: 'cr-mcr',
  // Amazon ECR Public
  ecr: 'cr-ecr',
  // Kubernetes registry
  k8s: 'cr-k8s',
  // GitLab Container Registry
  gitlab: 'cr-gitlab',
  // NVIDIA
  nvcr: 'cr-nvcr',
  // Other public registries
  redhat: 'cr-redhat',
  oracle: 'cr-oracle',
  cloudsmith: 'cr-cloudsmith',
  digitalocean: 'cr-digitalocean',
  vmware: 'cr-vmware',
  heroku: 'cr-heroku',
  suse: 'cr-suse',
  opensuse: 'cr-opensuse',
  gitpod: 'cr-gitpod'
};

/**
 * Resolves the container registry platform key from a request hostname using its
 * leftmost label as the domain prefix. Returns null when the hostname does not
 * start with a known registry alias (i.e. normal path-prefix mode should be used).
 *
 * @param {string} hostname - The request hostname, e.g. "ghcr.example.com"
 * @returns {string|null} The matching platform key (e.g. "cr-ghcr") or null
 */
export function resolveDomainPlatform(hostname) {
  if (!hostname) {
    return null;
  }
  const label = hostname.split('.')[0].toLowerCase();
  return DOMAIN_PREFIX_MAP[label] || null;
}

/**
 * Container registry API operations that follow the repository name in a path.
 * @type {string[]}
 */
const REGISTRY_OPERATIONS = ['manifests', 'blobs', 'tags', 'referrers'];

/**
 * Normalizes Docker Hub image paths so that official (single-segment) images such as
 * `nginx` are rewritten to their canonical `library/nginx` repository name.
 *
 * Handles both `/nginx/manifests/<ref>` and `/v2/nginx/manifests/<ref>` forms.
 *
 * @param {string} path - The transformed path (platform prefix already removed)
 * @returns {string} The normalized path
 */
export function normalizeDockerHubImagePath(path) {
  const segments = path.split('/');
  const start = segments[1] === 'v2' ? 2 : 1;

  const operationIndex = segments.findIndex(
    (segment, index) => index >= start && REGISTRY_OPERATIONS.includes(segment)
  );
  if (operationIndex === -1) {
    return path;
  }

  const repository = segments.slice(start, operationIndex).filter(Boolean);
  if (repository.length !== 1) {
    return path;
  }

  segments.splice(start, 0, 'library');
  return segments.join('/');
}

/**
 * Strips the `/cr/<registry>/` prefix from a request path and applies registry-specific
 * path normalization (e.g. Docker Hub official image -> library/<name>).
 *
 * @param {string} path - The original path starting with `/cr/<registry>/`
 * @param {string} platformKey - The platform key, e.g. "cr-docker"
 * @returns {string} - The transformed path
 */
export function transformPath(path, platformKey) {
  if (!PLATFORMS[platformKey]) {
    return path;
  }

  const prefix = `/${platformKey.replace(/-/g, '/')}/`;
  let transformedPath = path.replace(
    new RegExp(`^${prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`),
    '/'
  );

  if (platformKey === 'cr-docker') {
    transformedPath = normalizeDockerHubImagePath(transformedPath);
  }

  return transformedPath;
}
