import { useEffect, useState } from "react";
import { getMe } from "./services/api";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import ResetPassword from "./pages/ResetPassword";

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

  // Si l'utilisateur clique sur le lien reçu par email :
  // http://localhost:5173/reset-password?token=xxxx
  // on affiche la page ResetPassword
  if (window.location.pathname === "/reset-password") {
    return <ResetPassword />;
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
