import { UserOut } from "./api";

export function saveSession(token: string, user: UserOut) {
  localStorage.setItem("nids_token", token);
  localStorage.setItem("nids_user", JSON.stringify(user));
}

export function getUser(): UserOut | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem("nids_user");
  return raw ? JSON.parse(raw) : null;
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("nids_token");
}

export function clearSession() {
  localStorage.removeItem("nids_token");
  localStorage.removeItem("nids_user");
}
