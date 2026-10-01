const API_URL = (
  import.meta.env.VITE_API_URL || "http://localhost:5000"
).replace(/\/+$/, "");

type ApiOptions = RequestInit & {
  auth?: boolean;
};

function getToken(): string | null {
  return localStorage.getItem("cyberguard_token");
}

async function request<T>(
  endpoint: string,
  options: ApiOptions = {},
): Promise<T> {
  const token = getToken();

  const headers = new Headers(options.headers);

  if (options.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }

  if (options.auth !== false && token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  let response: Response;

  try {
    response = await fetch(`${API_URL}${endpoint}`, {
      ...options,
      headers,
    });
  } catch {
    throw new Error(
      `Serverga ulanib boвЂlmadi: ${API_URL}`,
    );
  }

  let data: unknown = null;

  const contentType =
    response.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    const text = await response.text();
    data = text ? { message: text } : null;
  }

  if (!response.ok) {
    const message =
      typeof data === "object" &&
      data !== null &&
      "message" in data &&
      typeof data.message === "string"
        ? data.message
        : `Server xatosi: ${response.status}`;

    throw new Error(message);
  }

  return data as T;
}

export async function apiGet<T>(
  endpoint: string,
  options: ApiOptions = {},
): Promise<T> {
  return request<T>(endpoint, {
    ...options,
    method: "GET",
  });
}

export async function apiPost<T>(
  endpoint: string,
  body?: unknown,
  options: ApiOptions = {},
): Promise<T> {
  return request<T>(endpoint, {
    ...options,
    method: "POST",
    body:
      body === undefined
        ? undefined
        : JSON.stringify(body),
  });
}

export async function apiPatch<T>(
  endpoint: string,
  body?: unknown,
  options: ApiOptions = {},
): Promise<T> {
  return request<T>(endpoint, {
    ...options,
    method: "PATCH",
    body:
      body === undefined
        ? undefined
        : JSON.stringify(body),
  });
}

export async function apiPut<T>(
  endpoint: string,
  body?: unknown,
  options: ApiOptions = {},
): Promise<T> {
  return request<T>(endpoint, {
    ...options,
    method: "PUT",
    body:
      body === undefined
        ? undefined
        : JSON.stringify(body),
  });
}

export async function apiDelete<T>(
  endpoint: string,
  options: ApiOptions = {},
): Promise<T> {
  return request<T>(endpoint, {
    ...options,
    method: "DELETE",
  });
}

export function saveSession(
  token: string,
  user?: unknown,
): void {
  localStorage.setItem(
    "cyberguard_token",
    token,
  );

  if (user) {
    localStorage.setItem(
      "cyberguard_user",
      JSON.stringify(user),
    );
  }
}

export function clearSession(): void {
  localStorage.removeItem("cyberguard_token");
  localStorage.removeItem("cyberguard_user");
}

export function getSessionToken(): string | null {
  return getToken();
}

export function getApiUrl(): string {
  return API_URL;
}
