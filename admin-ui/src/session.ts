const tokenKey = "admin-ui.token";

export function loadToken(): string {
  return sessionStorage.getItem(tokenKey) ?? "";
}

export function saveToken(token: string): void {
  sessionStorage.setItem(tokenKey, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(tokenKey);
}
