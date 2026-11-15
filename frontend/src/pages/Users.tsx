// SPDX-License-Identifier: AGPL-3.0-only
// Owners only: the panel's users. Adding a user lets them sign in (with OIDC); a tenant
// role is granted on the Tenants page. Disabling ends their sessions and blocks sign-in.
import { useEffect, useState, type FormEvent } from "react";
import { api, type PanelUser } from "../api";
import ErrorText, { messageOf } from "../components/ErrorText";

export default function Users({ meId }: { meId: string }) {
  const [users, setUsers] = useState<PanelUser[] | null>(null);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [version, setVersion] = useState(0); // bumped to reload the list

  useEffect(() => {
    let alive = true;
    api.users().then(
      (list) => {
        if (alive) setUsers(list);
      },
      (e) => {
        if (alive) setError(messageOf(e));
      },
    );
    return () => {
      alive = false;
    };
  }, [version]);
  const load = () => setVersion((n) => n + 1);

  async function create(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.createUser({
        email: email.trim(),
        display_name: displayName.trim() === "" ? null : displayName.trim(),
      });
      setEmail("");
      setDisplayName("");
      load();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  async function disable(user: PanelUser) {
    const sure = window.confirm(
      `Disable ${user.email}? They are signed out everywhere and can no longer sign in.`,
    );
    if (!sure) return;
    setBusy(true);
    setError(null);
    try {
      await api.disableUser(user.id);
      load();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h2>Users</h2>
      <form className="card" onSubmit={(e) => void create(e)}>
        <h3>Add a user</h3>
        <p className="muted">
          They sign in with their own account (OIDC). Give them a role on a tenant afterwards,
          on the Tenants page.
        </p>
        <label>
          Email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </label>
        <label>
          Display name
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </label>
        <button type="submit" disabled={busy}>
          Add user
        </button>
      </form>
      <ErrorText message={error} />
      {users === null ? null : (
        <table className="card">
          <thead>
            <tr>
              <th>Email</th>
              <th>Name</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.email}</td>
                <td>{u.display_name ?? ""}</td>
                <td>
                  {u.disabled ? (
                    <span className="status failed">disabled</span>
                  ) : u.is_owner ? (
                    "owner"
                  ) : (
                    "active"
                  )}
                </td>
                <td>
                  {!u.disabled && u.id !== meId ? (
                    <button
                      disabled={busy}
                      aria-label={`Disable ${u.email}`}
                      onClick={() => void disable(u)}
                    >
                      Disable
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
