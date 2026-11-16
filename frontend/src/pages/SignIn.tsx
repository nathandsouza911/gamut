// SPDX-License-Identifier: AGPL-3.0-only
import { useState, type FormEvent } from "react";
import { api, type Me } from "../api";
import ErrorText, { messageOf } from "../components/ErrorText";

export default function SignIn({ onSignedIn }: { onSignedIn: (me: Me) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const me = await api.bootstrapLogin(email, password);
      setPassword("");
      onSignedIn(me);
    } catch (err) {
      setPassword("");
      setError(messageOf(err));
      setBusy(false);
    }
  }

  return (
    <section className="card narrow">
      <h2>Sign in</h2>
      <p>
        <button type="button" onClick={() => window.location.assign("/api/auth/login")}>
          Sign in with Google
        </button>
      </p>
      <hr />
      <form onSubmit={submit}>
        <h3>Bootstrap admin</h3>
        <label>
          Email
          <input
            type="email"
            value={email}
            autoComplete="username"
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            autoComplete="current-password"
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>
        <ErrorText message={error} />
        <button type="submit" disabled={busy}>
          Sign in
        </button>
      </form>
    </section>
  );
}
