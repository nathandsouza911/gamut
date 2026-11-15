// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useState } from "react";
import { api, type JobSummary } from "../api";
import ErrorText, { messageOf } from "../components/ErrorText";

export default function Jobs({ tenantId }: { tenantId: string }) {
  const [jobs, setJobs] = useState<JobSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api.jobs(tenantId).then(
      (j) => {
        if (alive) setJobs(j);
      },
      (e) => {
        if (alive) setError(messageOf(e));
      },
    );
    return () => {
      alive = false;
    };
  }, [tenantId]);

  return (
    <section className="card">
      <h2>Jobs</h2>
      <ErrorText message={error} />
      {jobs === null ? null : jobs.length === 0 ? (
        <p>No jobs yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Job</th>
              <th>Target</th>
              <th>Status</th>
              <th>By</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {jobs.map((j) => (
              <tr key={j.id}>
                <td>
                  <a href={`#/t/${tenantId}/jobs/${j.id}`}>{j.workflow}</a>
                </td>
                <td>{j.target ?? ""}</td>
                <td>
                  <span className={`status ${j.status}`}>{j.status}</span>
                </td>
                <td>{j.created_by ?? "system"}</td>
                <td>{new Date(j.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
