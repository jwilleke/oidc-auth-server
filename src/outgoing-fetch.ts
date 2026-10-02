import { isIP } from 'node:net';

type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/**
 * node-oidc-provider attaches an SSRF-guarding dispatcher to every outgoing request (client ID
 * metadata documents, jwks_uri, sector identifiers): it destroys a connection to a private,
 * loopback or link-local address at connect time, which also defeats DNS rebinding. If it cannot
 * set that dispatcher up it warns and fetches anyway. This refuses instead — fail closed — and
 * never follows a redirect.
 */
export function guardedFetch(fetchImpl: Fetch = globalThis.fetch): Fetch {
  return (input, init) => {
    if (!init || !('dispatcher' in init) || !init.dispatcher) {
      return Promise.reject(
        new Error('outgoing request refused: SSRF protection is not available')
      );
    }
    return fetchImpl(input, { ...init, redirect: 'error' });
  };
}

/**
 * Whether a client ID metadata document may be fetched from this URL. A literal IP address or a
 * localhost name is refused before any connection is tried; `allowedHosts`, when not empty, is
 * the only set of hosts that may be fetched at all.
 */
export function allowMetadataFetch(clientId: string, allowedHosts: string[] = []): boolean {
  let host: string;
  try {
    host = new URL(clientId).hostname.toLowerCase();
  } catch {
    return false;
  }
  const bare = host.replace(/^\[|\]$/g, '');
  if (isIP(bare) !== 0) return false;
  if (host === 'localhost' || host.endsWith('.localhost')) return false;
  return allowedHosts.length === 0 || allowedHosts.map((h) => h.toLowerCase()).includes(host);
}
