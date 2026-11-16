// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useState } from "react";
import { api, type Dashboard as DashboardData, type JobSummary, type Tenant } from "../api";
import ErrorText, { messageOf } from "../components/ErrorText";
import { jobHref } from "./Tenants";

const when = (t: string | null) => (t ? new Date(t).toLocaleString() : "");

function JobLink({ tenantId, job }: { tenantId: string; job: JobSummary }) {
  return (
    <a href={jobHref(tenantId, job.id)}>
      {job.workflow} {job.target ?? ""}
    </a>
  );
}

export default function Dashboard({ tenant }: { tenant: Tenant }) {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const id = tenant.id;

  const [version, setVersion] = useState(0);
  const load = () => setVersion((v) => v + 1);

  useEffect(() => {
    let alive = true;
    api.dashboard(id).then(
      (d) => {
        if (alive) {
          setData(d);
          setError(null);
        }
      },
      (e) => {
        if (alive) setError(messageOf(e));
      },
    );
    return () => {
      alive = false;
    };
  }, [id, version]);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      load();
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }

  if (!data) return error ? <ErrorText message={error} /> : <p>Loading...</p>;

  const t = data.tenant;
  const isAdmin = t.role === "owner" || t.role === "admin";
  const { health, credentials } = data;
  const attention = data.failed_jobs.length + data.waiting_jobs.length;

  return (
    <>
      <section className="card">
        <h2>
          {t.name} <span className={`status ${t.status}`}>{t.status}</span>
        </h2>
        <ErrorText message={error} />
        {t.status === "pending" ? (
          <p>
            <a href={`#/t/${id}/setup`}>Continue setup</a>
          </p>
        ) : null}
        <h3>Health</h3>
        {health ? (
          <>
            <p className="muted">
              Last check {when(health.finished_at)} ({health.ok ? "all passing" : "needs attention"}){" "}
              <a href={jobHref(id, health.job_id)}>details</a>
            </p>
            <ul>
              {health.checks.map((c) => (
                <li key={c.key}>
                  {c.title} <span className={`status ${c.status}`}>{c.status}</span>
                  {c.status === "failed" ? (
                    <>
                      {" "}
                      <a href={`#/t/${id}/setup`}>Fix</a>
                    </>
                  ) : null}
                </li>
              ))}
            </ul>
          </>
        ) : (
          <p className="muted">No health check has run yet.</p>
        )}
        {isAdmin ? (
          <button disabled={busy} onClick={() => void act(() => api.healthCheck(id))}>
            Run health check
          </button>
        ) : null}
      </section>

      <section className="card">
        <h3>Credentials</h3>
        {credentials ? (
          <>
            <p>
              Mode: {credentials.auth_mode === "dasa" ? "service account (DASA)" : "OAuth"}
              {credentials.sa_client_email ? ` | ${credentials.sa_client_email}` : ""}
            </p>
            {credentials.uploaded_at ? <p className="muted">Uploaded {when(credentials.uploaded_at)}</p> : null}
            {credentials.rotate_soon && credentials.age_days !== null ? (
              <div role="status" className="warning">
                Key is {credentials.age_days} days old — Google recommends you rotate service account keys.
              </div>
            ) : null}
          </>
        ) : (
          <p className="muted">No credentials uploaded.</p>
        )}
      </section>

      <section className="card">
        <h3>Needs attention</h3>
        {attention === 0 ? (
          <p>Nothing needs attention.</p>
        ) : (
          <ul>
            {data.failed_jobs.map((j) => (
              <li key={j.id}>
                <JobLink tenantId={id} job={j} /> <span className="status failed">failed</span>
              </li>
            ))}
            {data.waiting_jobs.map((j) => (
              <li key={j.id}>
                <JobLink tenantId={id} job={j} /> <span className="status waiting">waiting</span>
                {j.waiting_since ? <span className="muted"> since {when(j.waiting_since)}</span> : null}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="card">
        <h3>Upcoming deletions</h3>
        {data.scheduled.length === 0 ? (
          <p>None scheduled.</p>
        ) : (
          <ul>
            {data.scheduled.map((a) => (
              <li key={a.id}>
                {a.action} {a.target ?? ""} at {when(a.run_at)}{" "}
                {isAdmin ? (
                  <button disabled={busy} onClick={() => void act(() => api.cancelScheduled(id, a.id))}>
                    Cancel
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="card">
        <h3>Recent jobs</h3>
        {data.recent_jobs.length === 0 ? (
          <p>No jobs yet.</p>
        ) : (
          <ul>
            {data.recent_jobs.map((j) => (
              <li key={j.id}>
                <JobLink tenantId={id} job={j} /> <span className={`status ${j.status}`}>{j.status}</span>{" "}
                <span className="muted">{when(j.created_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}
