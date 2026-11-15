// SPDX-License-Identifier: AGPL-3.0-only
import { useRef, useState, type FormEvent } from "react";
import { api, type Tenant } from "../api";
import ErrorText, { messageOf } from "../components/ErrorText";

interface Props {
  tenants: Tenant[];
  isOwner: boolean;
  onChanged: () => void;
  onOpenJob: (jobId: string) => void;
}

type RowProps = Omit<Props, "tenants"> & { tenant: Tenant };

function TenantRow({ tenant, isOwner, onChanged, onOpenJob }: RowProps) {
  const files = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [uploaded, setUploaded] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const canCheck = isOwner || tenant.role === "admin";

  async function upload(e: FormEvent) {
    e.preventDefault();
    const chosen = Array.from(files.current?.files ?? []);
    if (chosen.length === 0) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.uploadCredentials(tenant.id, chosen);
      setUploaded(r.file_names);
      if (files.current) files.current.value = "";
      onChanged();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  async function check() {
    setBusy(true);
    setError(null);
    try {
      onOpenJob((await api.healthCheck(tenant.id)).job_id);
    } catch (err) {
      setError(messageOf(err));
      setBusy(false);
    }
  }

  return (
    <li className="card">
      <h3>
        {tenant.name} <span className={`status ${tenant.status}`}>{tenant.status}</span>
      </h3>
      <p className="muted">
        {tenant.primary_domain} | admin account: {tenant.admin_email ?? "not set"}
      </p>
      <p>
        Last check:{" "}
        {tenant.last_health_check_at
          ? `${new Date(tenant.last_health_check_at).toLocaleString()}: ${tenant.last_health_message ?? ""}`
          : "never"}
      </p>
      <p>
        Credentials: {tenant.has_credentials ? tenant.credential_files.join(", ") : "none uploaded"}
      </p>
      {canCheck ? (
        <button onClick={() => void check()} disabled={busy}>
          Run health check
        </button>
      ) : null}
      {isOwner ? (
        <form onSubmit={(e) => void upload(e)}>
          <label>
            Credential files (oauth2.txt, oauth2service.json, client_secrets.json)
            <input ref={files} type="file" multiple />
          </label>
          <button type="submit" disabled={busy}>
            Upload credentials
          </button>
          {uploaded ? <p>Stored: {uploaded.join(", ")}</p> : null}
        </form>
      ) : null}
      <ErrorText message={error} />
    </li>
  );
}

export default function Tenants({ tenants, isOwner, onChanged, onOpenJob }: Props) {
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function create(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.createTenant({
        name,
        primary_domain: domain,
        admin_email: adminEmail.trim() === "" ? null : adminEmail.trim(),
      });
      setName("");
      setDomain("");
      setAdminEmail("");
      onChanged();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h2>Tenants</h2>
      {isOwner ? (
        <form className="card" onSubmit={(e) => void create(e)}>
          <h3>Add a tenant</h3>
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} required />
          </label>
          <label>
            Primary domain
            <input value={domain} onChange={(e) => setDomain(e.target.value)} required />
          </label>
          <label>
            Admin email (for the health check)
            <input
              type="email"
              value={adminEmail}
              onChange={(e) => setAdminEmail(e.target.value)}
            />
          </label>
          <ErrorText message={error} />
          <button type="submit" disabled={busy}>
            Add tenant
          </button>
        </form>
      ) : null}
      <ul className="plain">
        {tenants.map((t) => (
          <TenantRow
            key={t.id}
            tenant={t}
            isOwner={isOwner}
            onChanged={onChanged}
            onOpenJob={onOpenJob}
          />
        ))}
      </ul>
    </section>
  );
}
