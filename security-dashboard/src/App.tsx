import { useEffect, useState } from "react";
import { getMe } from "./services/api";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";

function App() {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");

  useEffect(() => {
    async function checkUser() {
      try {
        const me = await getMe();
        setUser(me);
      } catch {
        setUser(null);
      } finally {
        setLoading(false);
      }
    }

    checkUser();
  }, []);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!user) {
    return authMode === "login" ? (
      <Login onSwitchToRegister={() => setAuthMode("register")} />
    ) : (
      <Register onSwitchToLogin={() => setAuthMode("login")} />
    );
  }

  return <Dashboard />;
}

export default App;
