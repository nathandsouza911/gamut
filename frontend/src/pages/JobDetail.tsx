// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useState } from "react";
import { ApiError, api, type Job } from "../api";
import ErrorText, { messageOf } from "../components/ErrorText";

const ACTIVE = new Set(["queued", "running", "waiting"]);
const POLL_MS = 2000;
// Errors that will not go away by asking again: polling stops. Anything else (network
// errors, 5xx, 429) is shown and polling goes on.
const PERMANENT = new Set([401, 403, 404]);

interface Props {
  tenantId: string;
  jobId: string;
  canOperate: boolean; // technician, admin or owner
}

const when = (t: string | null) => (t ? new Date(t).toLocaleString() : "");

export default function JobDetail({ tenantId, jobId, canOperate }: Props) {
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Bumped after a retry/skip/cancel so polling restarts for the re-queued job.
  const [restart, setRestart] = useState(0);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      try {
        const j = await api.job(tenantId, jobId);
        if (!alive) return;
        setJob(j);
        setError(null);
        if (ACTIVE.has(j.status)) timer = setTimeout(() => void tick(), POLL_MS);
      } catch (e) {
        if (!alive) return;
        setError(messageOf(e));
        // Keep the last known job on screen and ask again, unless the error is final.
        if (!(e instanceof ApiError && PERMANENT.has(e.status))) {
          timer = setTimeout(() => void tick(), POLL_MS);
        }
      }
    };
    void tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [tenantId, jobId, restart]);

  async function act(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      setRestart((n) => n + 1);
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }

  if (!job) return error ? <ErrorText message={error} /> : <p>Loading...</p>;
  const failed = job.status === "failed";

  return (
    <section className="card">
      <h2>
        {job.workflow} {job.target ? <span className="muted">for {job.target}</span> : null}
      </h2>
      <p>
        Status: <span className={`status ${job.status}`}>{job.status}</span> | started by{" "}
        {job.created_by ?? "system"} | {when(job.created_at)}
        {job.finished_at ? ` | finished ${when(job.finished_at)}` : ""}
      </p>
      {failed && job.account_suspended === false ? (
        <div role="status" className="warning">
          <strong>The account is NOT suspended yet.</strong> The job stopped before its
          suspend step succeeded, so {job.target ?? "the user"} can still sign in.
          {canOperate
            ? " Retry or skip the failed step now so the job continues to the suspension."
            : " Ask a technician to retry or skip the failed step now."}
        </div>
      ) : null}
      <ErrorText message={error} />
      <ol className="steps">
        {job.steps.map((s) => (
          <li key={s.id} className="step">
            <div>
              <strong>{s.title}</strong> <span className={`status ${s.status}`}>{s.status}</span>
              {s.optional ? <span className="muted"> (optional)</span> : null}
            </div>
            {s.started_at || s.finished_at ? (
              <div className="muted">
                {s.started_at ? `started ${when(s.started_at)}` : ""}
                {s.finished_at ? ` | finished ${when(s.finished_at)}` : ""}
              </div>
            ) : null}
            {s.output ? <pre>{s.output}</pre> : null}
            {failed && canOperate && s.status === "failed" ? (
              <div className="row">
                <button
                  disabled={busy}
                  onClick={() => void act(() => api.retryStep(tenantId, jobId, s.id))}
                >
                  Retry
                </button>
                {s.optional ? (
                  <button
                    disabled={busy}
                    onClick={() => void act(() => api.skipStep(tenantId, jobId, s.id))}
                  >
                    Skip
                  </button>
                ) : null}
              </div>
            ) : null}
          </li>
        ))}
      </ol>
      {job.scheduled_actions.length > 0 ? (
        <>
          <h3>Scheduled actions</h3>
          <ul>
            {job.scheduled_actions.map((a) => (
              <li key={a.id}>
                {a.action} {a.target ?? ""} at {when(a.run_at)}{" "}
                <span className={`status ${a.status}`}>{a.status}</span>
                {a.result ? <div className="muted">{a.result}</div> : null}
                {a.status === "scheduled" && canOperate ? (
                  <button
                    disabled={busy}
                    onClick={() => void act(() => api.cancelScheduled(tenantId, a.id))}
                  >
                    Cancel
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </section>
  );
}
