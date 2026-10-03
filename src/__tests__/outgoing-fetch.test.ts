import { describe, expect, it, vi } from 'vitest';
import { allowMetadataFetch, guardedFetch } from '../outgoing-fetch.js';

describe('guardedFetch', () => {
  it('refuses when the SSRF-guarding dispatcher is missing', async () => {
    const inner = vi.fn();
    await expect(guardedFetch(inner)('https://client.example.com/', {})).rejects.toThrow(
      /SSRF protection is not available/
    );
    await expect(guardedFetch(inner)('https://client.example.com/')).rejects.toThrow();
    expect(inner).not.toHaveBeenCalled();
  });

  it('passes the dispatcher through and never follows a redirect', async () => {
    const inner = vi.fn(() => Promise.resolve(new Response('{}')));
    const dispatcher = {};
    await guardedFetch(inner)('https://client.example.com/', { dispatcher } as RequestInit);
    expect(inner).toHaveBeenCalledWith('https://client.example.com/', {
      dispatcher,
      redirect: 'error'
    });
  });
});

describe('allowMetadataFetch', () => {
  it('allows any public host when no allowlist is set', () => {
    expect(allowMetadataFetch('https://client.example.com/meta.json')).toBe(true);
  });

  it.each([
    'https://127.0.0.1/meta.json',
    'https://169.254.169.254/latest/meta-data',
    'https://10.0.0.5/meta.json',
    'https://[::1]/meta.json',
    'https://localhost/meta.json',
    'https://api.localhost/meta.json',
    'not a url'
  ])('refuses %s before connecting', (clientId) => {
    expect(allowMetadataFetch(clientId)).toBe(false);
  });

  it('allows only listed hosts when an allowlist is set', () => {
    expect(allowMetadataFetch('https://mcp.example.com/c.json', ['mcp.example.com'])).toBe(true);
    expect(allowMetadataFetch('https://evil.example.com/c.json', ['mcp.example.com'])).toBe(false);
  });
});
