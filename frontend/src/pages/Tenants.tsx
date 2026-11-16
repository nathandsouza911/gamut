// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, type Member, type MemberRole, type Tenant } from "../api";
import ErrorText, { messageOf } from "../components/ErrorText";

interface Props {
  tenants: Tenant[];
  isOwner: boolean;
  onChanged: () => void;
  onOpenJob: (tenantId: string, jobId: string) => void;
}

type RowProps = Omit<Props, "tenants"> & { tenant: Tenant };

export const jobHref = (tenantId: string, jobId: string) => `#/t/${tenantId}/jobs/${jobId}`;

// Owners and tenant admins: who has which role on this tenant.
function Members({ tenant }: { tenant: Tenant }) {
  const [members, setMembers] = useState<Member[] | null>(null);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<MemberRole>("technician");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [version, setVersion] = useState(0); // bumped to reload the list

  useEffect(() => {
    let alive = true;
    api.members(tenant.id).then(
      (list) => {
        if (alive) setMembers(list);
      },
      (e) => {
        if (alive) setError(messageOf(e));
      },
    );
    return () => {
      alive = false;
    };
  }, [tenant.id, version]);

  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      setVersion((n) => n + 1);
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }

  function save(e: FormEvent) {
    e.preventDefault();
    void run(async () => {
      await api.setMember(tenant.id, email.trim(), role);
      setEmail("");
    });
  }

  const headingId = `members-${tenant.id}`;
  return (
    <section aria-labelledby={headingId}>
      <h4 id={headingId}>Members</h4>
      {members === null ? null : members.length === 0 ? (
        <p className="muted">No members yet. Owners can always reach every tenant.</p>
      ) : (
        <ul>
          {members.map((m) => (
            <li key={m.user_id}>
              {m.email} <span className="muted">({m.role}{m.disabled ? ", disabled" : ""})</span>{" "}
              <button
                disabled={busy}
                aria-label={`Remove ${m.email}`}
                onClick={() => void run(() => api.removeMember(tenant.id, m.user_id))}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <form onSubmit={save}>
        <label>
          Email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </label>
        <label>
          Role
          <select value={role} onChange={(e) => setRole(e.target.value as MemberRole)}>
            <option value="admin">admin (runs workflows, manages members)</option>
            <option value="technician">technician (runs workflows)</option>
            <option value="auditor">auditor (reads jobs and the audit log)</option>
          </select>
        </label>
        <button type="submit" disabled={busy}>
          Add or change
        </button>
        <p className="muted">The person must already be a panel user (an owner adds them on the Users page).</p>
      </form>
      <ErrorText message={error} />
    </section>
  );
}

// Owners: the domains whose addresses this tenant may act on (the primary is always kept).
function Domains({ tenant, onChanged }: { tenant: Tenant; onChanged: () => void }) {
  const extra = tenant.domains.filter((d) => d !== tenant.primary_domain).join(", ");
  const [value, setValue] = useState(extra);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const domains = value
        .split(/[\s,]+/)
        .map((d) => d.trim().toLowerCase())
        .filter((d) => d !== "");
      await api.updateTenant(tenant.id, { domains });
      onChanged();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void save(e)}>
      <label>
        Other domains (comma-separated; {tenant.primary_domain} is always included)
        <input value={value} onChange={(e) => setValue(e.target.value)} />
      </label>
      <button type="submit" disabled={busy}>
        Save domains
      </button>
      <ErrorText message={error} />
    </form>
  );
}

function TenantRow({ tenant, isOwner, onChanged, onOpenJob }: RowProps) {
  const files = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [uploaded, setUploaded] = useState<{ names: string[]; job: string | null } | null>(null);
  const [busy, setBusy] = useState(false);
  const canManage = isOwner || tenant.role === "admin";

  async function upload(e: FormEvent) {
    e.preventDefault();
    const chosen = Array.from(files.current?.files ?? []);
    if (chosen.length === 0) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.uploadCredentials(tenant.id, chosen);
      setUploaded({ names: r.file_names, job: r.health_job_id });
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
      onOpenJob(tenant.id, (await api.healthCheck(tenant.id)).job_id);
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
        {tenant.domains.join(", ")} | admin account: {tenant.admin_email ?? "not set"}
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
      {canManage ? (
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
          {uploaded ? (
            <p>
              Stored: {uploaded.names.join(", ")}.{" "}
              {uploaded.job ? (
                <a href={jobHref(tenant.id, uploaded.job)}>View the health check</a>
              ) : (
                "No health check was queued (set the tenant's admin email first)."
              )}
            </p>
          ) : null}
        </form>
      ) : null}
      {isOwner ? <Domains key={tenant.domains.join(",")} tenant={tenant} onChanged={onChanged} /> : null}
      <ErrorText message={error} />
      {canManage ? <Members tenant={tenant} /> : null}
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
        <p>
          <a href="#/tenants/new">Add tenant (guided)</a>
        </p>
      ) : null}
      {isOwner ? (
        <form className="card" onSubmit={(e) => void create(e)}>
          <h3>Advanced: import an existing GAM setup (OAuth)</h3>
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
            Import tenant
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
