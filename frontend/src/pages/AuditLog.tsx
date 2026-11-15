// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useState } from "react";
import { api, type AuditEvent, type VerifyResult } from "../api";
import ErrorText, { messageOf } from "../components/ErrorText";

interface Props {
  tenantId: string;
  isOwner: boolean;
}

export default function AuditLog({ tenantId, isOwner }: Props) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    api.audit(tenantId).then(
      (p) => {
        if (!alive) return;
        setEvents(p.items);
        setNext(p.next_cursor);
        setLoaded(true);
      },
      (e) => {
        if (alive) setError(messageOf(e));
      },
    );
    return () => {
      alive = false;
    };
  }, [tenantId]);

  async function more() {
    setBusy(true);
    try {
      const p = await api.audit(tenantId, next);
      setEvents((old) => [...old, ...p.items]);
      setNext(p.next_cursor);
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }

  async function runVerify() {
    setBusy(true);
    setError(null);
    try {
      setVerify(await api.verifyAudit());
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>Audit log</h2>
      {isOwner ? (
        <p>
          <button onClick={() => void runVerify()} disabled={busy}>
            Verify chain
          </button>{" "}
          {verify ? (
            verify.ok ? (
              <span>Chain intact: {verify.checked} events verified.</span>
            ) : (
              <span role="alert" className="error">
                Chain broken at event {verify.first_broken_id} ({verify.reason}).
              </span>
            )
          ) : null}
        </p>
      ) : null}
      <ErrorText message={error} />
      {loaded && events.length === 0 ? <p>No events.</p> : null}
      {events.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td>{new Date(e.time).toLocaleString()}</td>
                <td>{e.actor}</td>
                <td>{e.action}</td>
                <td>{e.target ?? ""}</td>
                <td>
                  <details>
                    <summary>Details</summary>
                    <pre>{JSON.stringify(e.details, null, 2)}</pre>
                  </details>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      {next !== null ? (
        <button onClick={() => void more()} disabled={busy}>
          Load more
        </button>
      ) : null}
    </section>
  );
}
