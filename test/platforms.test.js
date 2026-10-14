import { describe, expect, it } from 'vitest';
import {
  PLATFORMS,
  transformPath,
  DOMAIN_PREFIX_MAP,
  resolveDomainPlatform,
  normalizeDockerHubImagePath
} from '../src/config/platforms.js';

describe('Container Registry Platforms', () => {
  describe('Platform Definitions', () => {
    it('should have all major container registries defined', () => {
      const containerRegistries = [
        'cr-docker',
        'cr-quay',
        'cr-gcr',
        'cr-mcr',
        'cr-ecr',
        'cr-ghcr',
        'cr-gitlab',
        'cr-redhat',
        'cr-oracle',
        'cr-cloudsmith',
        'cr-digitalocean',
        'cr-vmware',
        'cr-k8s',
        'cr-heroku',
        'cr-suse',
        'cr-opensuse',
        'cr-gitpod',
        'cr-nvcr'
      ];

      containerRegistries.forEach(registry => {
        expect(PLATFORMS).toHaveProperty(registry);
        expect(typeof PLATFORMS[registry]).toBe('string');
        expect(PLATFORMS[registry]).toMatch(/^https:\/\/.+/);
      });
    });

    it('should only contain container registry platforms', () => {
      Object.keys(PLATFORMS).forEach(key => {
        expect(key.startsWith('cr-')).toBe(true);
      });
    });
  });

  describe('Path Transformation', () => {
    it('should strip the /cr/<registry>/ prefix', () => {
      expect(transformPath('/cr/ghcr/v2/nginxinc/nginx-unprivileged/manifests/latest', 'cr-ghcr')).toBe(
        '/v2/nginxinc/nginx-unprivileged/manifests/latest'
      );
      expect(transformPath('/cr/gcr/v2/distroless/base/manifests/latest', 'cr-gcr')).toBe(
        '/v2/distroless/base/manifests/latest'
      );
    });

    it('should normalize Docker Hub official images to library/<name>', () => {
      expect(transformPath('/cr/docker/nginx/manifests/latest', 'cr-docker')).toBe(
        '/library/nginx/manifests/latest'
      );
      expect(transformPath('/cr/docker/v2/nginx/manifests/latest', 'cr-docker')).toBe(
        '/v2/library/nginx/manifests/latest'
      );
    });

    it('should preserve already-namespaced Docker Hub repositories', () => {
      expect(transformPath('/cr/docker/bitnami/redis/manifests/latest', 'cr-docker')).toBe(
        '/bitnami/redis/manifests/latest'
      );
      expect(transformPath('/cr/docker/library/nginx/manifests/latest', 'cr-docker')).toBe(
        '/library/nginx/manifests/latest'
      );
    });

    it('should transform all container registry paths correctly', () => {
      Object.keys(PLATFORMS).forEach(registry => {
        const prefix = registry.replace('cr-', 'cr/');
        const testPath = `/${prefix}/v2/test/image/manifests/latest`;
        const transformedPath = transformPath(testPath, registry);
        expect(transformedPath).toBe('/v2/test/image/manifests/latest');
      });
    });

    it('should handle unknown platform keys gracefully', () => {
      expect(transformPath('/unknown/test/path', 'unknown')).toBe('/unknown/test/path');
    });
  });

  describe('Docker Hub Official Image Normalization', () => {
    it('should rewrite single-segment repository to library/<name>', () => {
      expect(normalizeDockerHubImagePath('/nginx/manifests/latest')).toBe(
        '/library/nginx/manifests/latest'
      );
    });

    it('should handle the /v2/ prefix form', () => {
      expect(normalizeDockerHubImagePath('/v2/nginx/manifests/latest')).toBe(
        '/v2/library/nginx/manifests/latest'
      );
    });

    it('should leave multi-segment repositories untouched', () => {
      expect(normalizeDockerHubImagePath('/bitnami/redis/manifests/latest')).toBe(
        '/bitnami/redis/manifests/latest'
      );
    });

    it('should preserve an explicit library/ prefix', () => {
      expect(normalizeDockerHubImagePath('/library/nginx/manifests/latest')).toBe(
        '/library/nginx/manifests/latest'
      );
    });

    it('should return the path unchanged when no operation keyword is found', () => {
      expect(normalizeDockerHubImagePath('/nginx')).toBe('/nginx');
    });
  });

  describe('Domain-Prefix Mode', () => {
    it('should resolve known registry subdomains to platform keys', () => {
      expect(resolveDomainPlatform('ghcr.example.com')).toBe('cr-ghcr');
      expect(resolveDomainPlatform('docker.example.com')).toBe('cr-docker');
      expect(resolveDomainPlatform('k8s.example.com')).toBe('cr-k8s');
      expect(resolveDomainPlatform('quay.example.com')).toBe('cr-quay');
      expect(resolveDomainPlatform('nvcr.example.com')).toBe('cr-nvcr');
    });

    it('should accept common aliases for Docker Hub', () => {
      expect(resolveDomainPlatform('dockerhub.example.com')).toBe('cr-docker');
      expect(resolveDomainPlatform('hub.example.com')).toBe('cr-docker');
    });

    it('should be case-insensitive', () => {
      expect(resolveDomainPlatform('GHCR.example.com')).toBe('cr-ghcr');
    });

    it('should return null for the base domain and unknown subdomains', () => {
      expect(resolveDomainPlatform('example.com')).toBeNull();
      expect(resolveDomainPlatform('xget.example.com')).toBeNull();
      expect(resolveDomainPlatform('unknown.example.com')).toBeNull();
      expect(resolveDomainPlatform('')).toBeNull();
    });

    it('should map every alias to a defined container registry platform', () => {
      Object.entries(DOMAIN_PREFIX_MAP).forEach(([alias, platformKey]) => {
        expect(alias).toBe(alias.toLowerCase());
        expect(PLATFORMS).toHaveProperty(platformKey);
        expect(platformKey.startsWith('cr-')).toBe(true);
      });
    });
  });
});
