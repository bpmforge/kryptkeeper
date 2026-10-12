import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { Button, Input } from "../components/ops-ui";

export default function Login() {
  const navigate = useNavigate();
  // S-59: a session-expiry redirect persists its reason here — the toast
  // fired at expiry time dies with the React tree, so this banner is how
  // the notice actually reaches the user. Read-and-clear so it shows once.
  const [notice] = useState<string | null>(() => {
    const n = sessionStorage.getItem("kk_login_notice");
    if (n) sessionStorage.removeItem("kk_login_notice");
    return n;
  });
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  // Which sign-in methods this deployment offers — an OIDC/SAML-only
  // deployment previously had no way to sign in from this page at all.
  const methods = useQuery({
    queryKey: ["auth-methods"],
    queryFn: api.authMethods,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
  const sso = methods.data?.data;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = await api.login({ email: email.trim(), password });
      // Cookie is set httpOnly by the server; also store in sessionStorage
      // as a Bearer fallback for browsers that don't reliably send cookies
      // from IP-addressed origins.
      sessionStorage.setItem("kk_session", "1");
      if (result?.data?.access_token) {
        sessionStorage.setItem("auth_token", result.data.access_token);
      }
      navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center">
          <span className="text-2xl font-bold tracking-wide text-primary">
            Kryptkeeper
          </span>
          <p className="mt-2 text-sm text-muted-foreground">
            Sign in to your PKI console
          </p>
        </div>

        {notice && (
          <div
            role="status"
            className="rounded-lg border border-state-attn/50 bg-state-attn/10 px-4 py-3 text-sm text-state-attn"
          >
            {notice}
          </div>
        )}

        <form
          onSubmit={handleSubmit}
          className="rounded-2xl border border-border bg-card/60 p-6 space-y-4"
        >
          <label className="block space-y-2 text-sm text-foreground">
            <span>Email</span>
            <Input
              type="email"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="operator@example.com"
              required
            />
          </label>
          <label className="block space-y-2 text-sm text-foreground">
            <span>Password</span>
            <Input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />
          </label>
          {error ? (
            <p className="rounded-xl bg-state-over/10 border border-state-over/50 px-3 py-2 text-sm text-state-over">
              {error}
            </p>
          ) : null}
          <Button tone="primary" type="submit" disabled={loading}>
            {loading ? "Signing in…" : "Sign in"}
          </Button>
          {sso?.oidc || sso?.saml ? (
            <div className="space-y-2 border-t border-border pt-3">
              {sso.oidc ? (
                <a
                  href="/api/v1/auth/oidc/login"
                  className="block w-full rounded-xl border border-border bg-foreground/5 px-4 py-2 text-center text-sm font-medium text-foreground hover:bg-foreground/10 transition"
                >
                  Sign in with SSO (OIDC)
                </a>
              ) : null}
              {sso.saml ? (
                <a
                  href="/api/v1/auth/saml/login"
                  className="block w-full rounded-xl border border-border bg-foreground/5 px-4 py-2 text-center text-sm font-medium text-foreground hover:bg-foreground/10 transition"
                >
                  Sign in with SSO (SAML)
                </a>
              ) : null}
            </div>
          ) : null}
        </form>
      </div>
    </div>
  );
}
