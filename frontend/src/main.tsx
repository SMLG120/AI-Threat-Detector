import { StrictMode, useEffect, useState, FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { Shield } from "lucide-react";
import Dashboard from "./pages/Dashboard";
import { auth } from "./api/client";
import "./styles.css";

function Login({ onLogin }: { onLogin: () => void }) {
  const [key, setKey] = useState("");
  const [error, setError] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    const res = await fetch(`${import.meta.env.VITE_API_URL ?? ""}/api/models/status`, {
      headers: { "X-API-Key": key },
    }).catch(() => null);
    if (res?.ok) {
      auth.setKey(key);
      onLogin();
    } else {
      setError(res?.status === 401 ? "Invalid API key" : "Server unavailable");
    }
  };

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={submit}>
        <div className="brand-icon"><Shield size={22} /></div>
        <h1 className="brand-name">AI-WAF</h1>
        <input
          type="password"
          placeholder="Dashboard API key"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          autoFocus
          autoComplete="current-password"
        />
        <button className="btn-retrain" type="submit" disabled={!key}>Sign in</button>
        {error && <p className="login-error">{error}</p>}
      </form>
    </div>
  );
}

function App() {
  const [authed, setAuthed] = useState(!!auth.getKey());

  useEffect(() => {
    const onUnauthorized = () => setAuthed(false);
    window.addEventListener("aiwaf:unauthorized", onUnauthorized);
    return () => window.removeEventListener("aiwaf:unauthorized", onUnauthorized);
  }, []);

  return authed ? <Dashboard /> : <Login onLogin={() => setAuthed(true)} />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
