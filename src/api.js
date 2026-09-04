/**
 * Client for the DalanID API.
 *
 * The browser prototype originally computed disclosure locally. It no longer
 * does: every field shown in the interface now arrives from the Django service,
 * which decides what may be released. This module is the only place that knows
 * how to reach the API, so the components stay unaware of transport.
 *
 * Note what the browser is *not* trusted with. It never holds a signing secret
 * and cannot mint a Context-Key. It asks the service for one, naming a relying
 * party and a context, and the service signs it. In deployment the relying
 * party would sign locally and this issuance route would not exist; it is here
 * so the demonstration can run without embedding secrets in client code.
 */

const BASE = import.meta.env?.VITE_API_BASE ?? "http://127.0.0.1:8000/api/v1";

class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${BASE}${path}`, {
      // `options` is spread first: spreading it last would overwrite the
      // merged headers with its own, dropping the JSON content type on any
      // call that supplies a header of its own.
      ...options,
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    });
  } catch (cause) {
    throw new ApiError(
      "Could not reach the DalanID API. Is the Django server running?",
      0,
      null,
    );
  }

  const text = await response.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = { detail: text };
  }

  if (!response.ok) {
    throw new ApiError(
      body?.detail || body?.reason || `Request failed (${response.status})`,
      response.status,
      body,
    );
  }
  return body;
}

/** Attribute schema plus every active context and who may invoke it. */
export function listContexts() {
  return request("/contexts");
}

/** Ask the service to mint a Context-Key. Demonstration affordance. */
export function issueKey(relyingParty, context) {
  return request("/keys/issue", {
    method: "POST",
    body: JSON.stringify({ relying_party: relyingParty, context }),
  });
}

/** Request a citizen record under a context, presenting the signed key. */
export function fetchProfile(citizenId, contextKey) {
  return request(`/profile/${citizenId}`, {
    headers: { "X-Context-Key": contextKey },
  });
}

/** The unprotected baseline, for side-by-side comparison. */
export function fetchFullRecord(citizenId) {
  return request(`/profile/${citizenId}/full`);
}

/**
 * Obtain a key for a context and immediately use it.
 *
 * A context with no grant holders cannot be queried by anyone, which is a real
 * state the interface must be able to display rather than an error: a context
 * may be defined before any party is authorised to act on it.
 */
/**
 * Registered with a real signing key, but holding no grants. When a context
 * has not yet been authorised to anyone, the request is made as this party
 * rather than abandoned here. The key it presents is cryptographically
 * valid; the server still refuses it at layer 5, because a signature proves
 * only who minted a key and not that they may act under the named context.
 *
 * Refusing in this module instead would be faster and wrong: no request
 * would reach the service, nothing would enter the audit chain, and the
 * interface would be deciding disclosure - which is the one thing it does
 * not do.
 */
const UNGRANTED_PARTY = "unaffiliated-vendor";

export async function discloseUnder(citizenId, context) {
  if (context.slug === "__full__") {
    return fetchFullRecord(citizenId);
  }
  const holder = context.grant_holders?.[0] ?? UNGRANTED_PARTY;
  const { context_key } = await issueKey(holder, context.slug);
  const body = await fetchProfile(citizenId, context_key);
  return { ...body, context_key, relying_party: holder };
}

/** Create a context. Requires an administrative key and the role. */
export async function createContext({ slug, name, tier, purpose, attributes }) {
  const { context_key } = await issueKey(
    "ministry-health",
    "context-administration",
  );
  return request("/contexts/create", {
    method: "POST",
    headers: { "X-Context-Key": context_key },
    body: JSON.stringify({ slug, name, tier, purpose, attributes }),
  });
}

/** Authorise a relying party to invoke a context. */
export async function grantContext(contextSlug, relyingParty) {
  const { context_key } = await issueKey(
    "ministry-health",
    "context-administration",
  );
  return request(`/contexts/${contextSlug}/grants`, {
    method: "POST",
    headers: { "X-Context-Key": context_key },
    body: JSON.stringify({ relying_party: relyingParty }),
  });
}

/** Verify the tamper-evident disclosure log. */
export function verifyAudit() {
  return request("/audit/verify").catch((error) => {
    if (error.status === 409) return error.body;
    throw error;
  });
}

export { ApiError };
