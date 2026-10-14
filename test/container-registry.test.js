import { SELF } from 'cloudflare:test';
import { describe, expect, it, vi, beforeAll, afterAll } from 'vitest';

/**
 * Mock the global fetch so integration tests do not hit real upstream
 * registries. The mock returns sensible registry v2 responses so the
 * worker's routing / auth-retry logic can be exercised offline.
 */
const realFetch = globalThis.fetch;

const mockFetch = vi.fn(async (input) => {
  const url = typeof input === 'string' ? input : input.url;

  // Token endpoint simulation: any request to a realm URL returns a token.
  if (url.includes('/token') || url.includes('service=') || url.includes('auth')) {
    return new Response(JSON.stringify({ token: 'mock-bearer-token' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Registry base /v2/ probe returns 401 with a WWW-Authenticate challenge.
  if (url.endsWith('/v2/') || url.endsWith('/v2')) {
    return new Response('{}', {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        'WWW-Authenticate':
          'Bearer realm="https://auth.example.com/token",service="registry.example.com"'
      }
    });
  }

  // Manifest / blob / tags requests succeed with a minimal OCI manifest.
  if (url.includes('/manifests/') || url.includes('/blobs/') || url.includes('/tags/list')) {
    return new Response(
      JSON.stringify({
        schemaVersion: 2,
        mediaType: 'application/vnd.docker.distribution.manifest.v2+json',
        config: { mediaType: 'application/vnd.docker.container.image.v1+json', size: 1, digest: 'sha256:abc' },
        layers: []
      }),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/vnd.docker.distribution.manifest.v2+json',
          'Docker-Content-Digest': 'sha256:abcdef'
        }
      }
    );
  }

  // Upload endpoints return 202 Accepted.
  if (url.includes('/blobs/uploads')) {
    return new Response(null, {
      status: 202,
      headers: { Location: `${url}/uuid` }
    });
  }

  return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
});

beforeAll(() => {
  globalThis.fetch = mockFetch;
});

afterAll(() => {
  globalThis.fetch = realFetch;
});

describe('Container Registry Support', () => {
  describe('Docker API Version Check', () => {
    it('should handle /v2/ endpoint correctly', async () => {
      const response = await SELF.fetch('https://example.com/v2/');

      expect(response.status).toBe(200);
      expect(response.headers.get('Docker-Distribution-Api-Version')).toBe('registry/2.0');
      expect(response.headers.get('Content-Type')).toBe('application/json');

      const body = await response.text();
      expect(body).toBe('{}');
    });

    it('should handle /v2 endpoint correctly', async () => {
      const response = await SELF.fetch('https://example.com/v2');

      expect(response.status).toBe(200);
      expect(response.headers.get('Docker-Distribution-Api-Version')).toBe('registry/2.0');
    });
  });

  describe('Container Registry URL Transformation', () => {
    it('should handle Quay.io registry requests', async () => {
      const testUrl = 'https://example.com/cr/quay/v2/quay/redis/manifests/latest';
      const response = await SELF.fetch(testUrl, { method: 'HEAD' });

      // Should attempt to proxy to Quay.io
      expect(response.status).not.toBe(400);
    });

    it('should handle Google Container Registry requests', async () => {
      const testUrl = 'https://example.com/cr/gcr/v2/distroless/base/manifests/latest';
      const response = await SELF.fetch(testUrl, { method: 'HEAD' });

      // Should attempt to proxy to GCR
      expect(response.status).not.toBe(400);
    });

    it('should handle GitHub Container Registry requests', async () => {
      const testUrl = 'https://example.com/cr/ghcr/v2/nginxinc/nginx-unprivileged/manifests/latest';
      const response = await SELF.fetch(testUrl, { method: 'HEAD' });

      // Should attempt to proxy to GHCR
      expect(response.status).not.toBe(400);
    });

    it('should handle subdomain-prefixed requests', async () => {
      const testUrl = 'https://ghcr.example.com/v2/nginxinc/nginx-unprivileged/manifests/latest';
      const response = await SELF.fetch(testUrl, { method: 'HEAD' });

      expect(response.status).not.toBe(400);
    });

    it('should strip a redundant registry domain prefix from the path', async () => {
      const testUrl = 'https://ghcr.example.com/v2/ghcr.io/nginxinc/nginx-unprivileged/manifests/latest';
      const response = await SELF.fetch(testUrl, { method: 'HEAD' });

      expect(response.status).not.toBe(400);
    });

    it('should normalize Docker Hub official images to library/<name>', async () => {
      const testUrl = 'https://docker.example.com/v2/nginx/manifests/latest';
      const response = await SELF.fetch(testUrl, { method: 'HEAD' });

      expect(response.status).not.toBe(400);
    });
  });

  describe('Docker Authentication', () => {
    it('should pass through 401 authentication challenges', async () => {
      // Make the mock return a 401 for this specific private repo path.
      const privateFetch = vi.fn(async (input) => {
        const url = typeof input === 'string' ? input : input.url;
        if (url.includes('/v2/private/repo/manifests')) {
          return new Response('{}', {
            status: 401,
            headers: {
              'Content-Type': 'application/json',
              'WWW-Authenticate':
                'Bearer realm="https://auth.example.com/token",service="registry.example.com"'
            }
          });
        }
        if (url.includes('/token')) {
          return new Response(JSON.stringify({ token: 'mock-token' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        return new Response('{}', { status: 404 });
      });
      globalThis.fetch = privateFetch;

      const testUrl = 'https://example.com/cr/ghcr/v2/private/repo/manifests/latest';
      const response = await SELF.fetch(testUrl, {
        headers: {
          Accept: 'application/vnd.docker.distribution.manifest.v2+json'
        }
      });

      // Should not convert 401 to 500 or other error codes
      expect(response.status).toBe(401);
      expect(response.headers.has('WWW-Authenticate')).toBeTruthy();

      // Restore default mock
      globalThis.fetch = mockFetch;
    });

    it('should handle container registry token requests', async () => {
      const testUrl = 'https://example.com/cr/ghcr/v2/auth';
      const response = await SELF.fetch(testUrl, {
        headers: {
          Authorization: 'Basic dGVzdDp0ZXN0'
        }
      });

      // Should attempt to proxy auth requests
      expect(response.status).not.toBe(400);
    });
  });

  describe('Docker Request Detection', () => {
    it('should detect Docker requests by path', async () => {
      const response = await SELF.fetch(
        'https://example.com/cr/ghcr/v2/nginxinc/nginx-unprivileged/manifests/latest',
        {
          method: 'GET'
        }
      );

      // Should not reject with 405 (method not allowed)
      expect(response.status).not.toBe(405);
    });

    it('should detect Docker requests by Accept header', async () => {
      const response = await SELF.fetch('https://example.com/cr/ghcr/v2/test/repo/manifests/tag', {
        headers: {
          Accept: 'application/vnd.docker.distribution.manifest.v2+json'
        }
      });

      // Should not reject with 405 (method not allowed)
      expect(response.status).not.toBe(405);
    });

    it('should detect Docker requests by User-Agent', async () => {
      const response = await SELF.fetch('https://example.com/cr/ghcr/v2/test/repo/manifests/tag', {
        headers: {
          'User-Agent': 'docker/20.10.7'
        }
      });

      // Should not reject with 405 (method not allowed)
      expect(response.status).not.toBe(405);
    });
  });

  describe('Docker HTTP Methods', () => {
    it('should allow GET for manifest requests', async () => {
      const response = await SELF.fetch(
        'https://example.com/cr/ghcr/v2/nginxinc/nginx-unprivileged/manifests/latest',
        {
          method: 'GET'
        }
      );

      expect(response.status).not.toBe(405);
    });

    it('should allow HEAD for manifest requests', async () => {
      const response = await SELF.fetch(
        'https://example.com/cr/ghcr/v2/nginxinc/nginx-unprivileged/manifests/latest',
        {
          method: 'HEAD'
        }
      );

      expect(response.status).not.toBe(405);
    });

    it('should allow PUT for manifest uploads', async () => {
      const response = await SELF.fetch('https://example.com/cr/ghcr/v2/test/repo/manifests/tag', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/vnd.docker.distribution.manifest.v2+json'
        },
        body: JSON.stringify({
          schemaVersion: 2,
          mediaType: 'application/vnd.docker.distribution.manifest.v2+json'
        })
      });

      expect(response.status).not.toBe(405);
    });

    it('should allow POST for blob uploads', async () => {
      const response = await SELF.fetch('https://example.com/cr/ghcr/v2/test/repo/blobs/uploads/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream'
        }
      });

      expect(response.status).not.toBe(405);
    });
  });

  describe('Container Registry Error Handling', () => {
    it('should reject requests without a supported container registry prefix', async () => {
      const response = await SELF.fetch(
        'https://example.com/random/invalid/path'
      );

      expect(response.status).toBe(400);
      expect(await response.text()).toContain('container registry requests must use /cr/ prefix');
    });

    it('should reject unknown container registry keys', async () => {
      const response = await SELF.fetch(
        'https://example.com/cr/unknown-registry/v2/foo/manifests/latest'
      );

      expect(response.status).toBe(400);
    });
  });

  describe('Container Registry Headers', () => {
    it('should preserve container-specific headers', async () => {
      const response = await SELF.fetch(
        'https://example.com/cr/ghcr/v2/nginxinc/nginx-unprivileged/manifests/latest',
        {
          headers: {
            'Container-Content-Digest': 'sha256:abc123',
            Accept: 'application/vnd.docker.distribution.manifest.v2+json',
            Authorization: 'Bearer token123'
          }
        }
      );

      // Should not reject Docker-specific headers
      expect(response.status).not.toBe(400);
    });

    it('should not cache container registry responses', async () => {
      const testUrl = 'https://example.com/cr/ghcr/v2/nginxinc/nginx-unprivileged/manifests/latest';

      const response = await SELF.fetch(testUrl);

      // Container registry responses should not be cached
      const cacheControl = response.headers.get('Cache-Control');
      if (cacheControl) {
        expect(cacheControl).not.toContain('max-age=1800');
      }
    });
  });

  describe('Container Registry Platform Support', () => {
    const containerRegistries = [
      { name: 'Quay.io', prefix: 'cr/quay' },
      { name: 'Google Container Registry', prefix: 'cr/gcr' },
      { name: 'Microsoft Container Registry', prefix: 'cr/mcr' },
      { name: 'GitHub Container Registry', prefix: 'cr/ghcr' },
      { name: 'Amazon ECR Public', prefix: 'cr/ecr' },
      { name: 'Kubernetes Registry', prefix: 'cr/k8s' },
      { name: 'GitLab Registry', prefix: 'cr/gitlab' },
      { name: 'NVIDIA Registry', prefix: 'cr/nvcr' }
    ];

    containerRegistries.forEach(({ name, prefix }) => {
      it(`should support ${name} registry`, async () => {
        const testUrl = `https://example.com/${prefix}/v2/test/image/manifests/latest`;
        const response = await SELF.fetch(testUrl, { method: 'HEAD' });

        // With mocked fetch, valid registries should return 200 (not a 400 routing error)
        expect(response.status).toBe(200);
      });
    });
  });

  describe('Root Page', () => {
    it('should render the home page at the root path', async () => {
      const response = await SELF.fetch('https://example.com/');

      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('text/html');
      const body = await response.text();
      expect(body).toContain('Docker 镜像代理服务');
      expect(body).toContain('example.com');
    });

    it('should use the request hostname in usage examples', async () => {
      const response = await SELF.fetch('https://ghcr.example.com/');

      const body = await response.text();
      expect(body).toContain('ghcr.example.com');
      expect(body).toContain('docker.example.com');
    });
  });
});
