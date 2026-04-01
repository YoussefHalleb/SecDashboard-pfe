import axios from "axios";

export const api = axios.create({
  baseURL: "http://localhost:5000",
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

// GET CURRENT USER
export async function getMe() {
  const response = await api.get("/auth/me");
  return response.data;
}

// LOGOUT
export async function logout() {
  await api.post("/auth/logout");
}
