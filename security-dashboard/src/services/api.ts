import axios from "axios";

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "",
  withCredentials: true,
});
// LOGIN
export async function login(email: string, password: string) {
  const response = await api.post("/auth/login", {
    email,
    password,
  });

  return response.data;
}

// REGISTER
export async function register(email: string, password: string) {
  const response = await api.post("/auth/register", {
    email,
    password,
  });

  return response.data;
}

export async function forgotPassword(email: string) {
  const res = await fetch(
    `${import.meta.env.VITE_API_URL || ""}/auth/forgot-password`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify({ email }),
    },
  );

  const data = await res.json();

  if (!res.ok) {
    throw { response: { data } };
  }

  return data;
}

export async function resetPassword(token: string, password: string) {
  const res = await fetch(
    `${import.meta.env.VITE_API_URL || ""}/auth/reset-password`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify({ token, password }),
    },
  );

  const data = await res.json();

  if (!res.ok) {
    throw { response: { data } };
  }

  return data;
}

// GET CURRENT USER
export async function getMe() {
  const response = await api.get("/auth/me");
  return response.data;
}

// LOGOUT
export async function logout() {
  await api.post("/auth/logout");
}
