// Thin fetch wrapper. All requests are same-origin (nginx proxies the API), so no CORS.

const TOKEN_KEY = 'access_token';
const USER_KEY = 'username';

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function getSession() {
  try {
    return { username: sessionStorage.getItem(USER_KEY), token: sessionStorage.getItem(TOKEN_KEY) };
  } catch {
    return { username: null, token: null };
  }
}

export function setSession(username, token) {
  sessionStorage.setItem(USER_KEY, username);
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearSession() {
  try { sessionStorage.clear(); } catch { /* ignore */ }
}

function friendlyMessage(status, detail) {
  if (status === 401) return typeof detail === 'string' ? detail : 'Authentication failed.';
  if (status === 403 || status === 404 || status === 409 || status === 400) {
    return typeof detail === 'string' ? detail : 'Request refused.';
  }
  if (status === 422) return 'Some of the data you entered is not valid.';
  if (status === 429) return 'Too many attempts. Please wait and try again.';
  if (status === 413) return 'The message is too large.';
  return 'Something went wrong. Please try again.';
}

export async function api(path, { method = 'GET', body, token } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const bearer = token ?? getSession().token;
  if (bearer) headers.Authorization = `Bearer ${bearer}`;

  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'omit',
      cache: 'no-store',
    });
  } catch {
    throw new ApiError(0, 'Cannot reach the server.');
  }

  let data = null;
  try { data = await response.json(); } catch { /* empty body */ }
  if (!response.ok) throw new ApiError(response.status, friendlyMessage(response.status, data?.detail));
  return data;
}
