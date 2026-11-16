// SPDX-License-Identifier: AGPL-3.0-only
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { api, type Dashboard, type Job, type Tenant } from "../api";
import ErrorText, { messageOf } from "../components/ErrorText";

interface Props {
  tenant: Tenant | null; // null: the "new tenant" page (section 1 only)
  isOwner: boolean;
  onChanged: () => void;
  onCreated: (tenantId: string) => void;
}

const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.settings.basic";
const ACTIVE = new Set(["queued", "running", "waiting"]);
const STATUS_LABEL: Record<string, string> = { succeeded: "pass", failed: "fail" };
const STATUS_CLASS: Record<string, string> = { succeeded: "active", failed: "degraded" };
const POLL_MS = 2000;

// Hash routing owns the URL fragment, so a "Fix in" link scrolls to the section itself.
function scrollToSection(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
}

function Copy({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      setCopied(false); // clipboard unavailable: the value is selectable on screen
    }
  }
  return (
    <button type="button" onClick={() => void copy()} aria-label={`Copy ${label}`}>
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function Value({ value, label }: { value: string; label: string }) {
  return (
    <p>
      <code>{value}</code> <Copy value={value} label={label} />
    </p>
  );
}

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} className="card setup-section" aria-labelledby={`${id}-h`}>
      <h3 id={`${id}-h`}>{title}</h3>
      {children}
    </section>
  );
}

const CUSTOMER_HELP = (
  <p className="muted">Find it in the Admin console: Account, Account settings, Customer ID.</p>
);

function Details({ tenant, onChanged, onCreated }: Omit<Props, "isOwner">) {
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [extra, setExtra] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [customerId, setCustomerId] = useState(tenant?.customer_id ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function create(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      // One request: the tenant is created with its domains or not at all.
      const created = await api.createTenant({
        name: name.trim(),
        primary_domain: domain.trim(),
        domains: extra
          .split(/[\s,]+/)
          .map((d) => d.trim().toLowerCase())
          .filter((d) => d !== ""),
        admin_email: adminEmail.trim() === "" ? null : adminEmail.trim(),
        auth_mode: "dasa",
        customer_id: customerId.trim(),
      });
      onChanged();
      onCreated(created.id);
    } catch (err) {
      setError(messageOf(err));
      setBusy(false);
    }
  }

  async function saveCustomerId(e: FormEvent) {
    e.preventDefault();
    if (!tenant) return;
    setBusy(true);
    setError(null);
    try {
      await api.updateTenant(tenant.id, { customer_id: customerId.trim() });
      onChanged();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  if (tenant) {
    return (
      <Section id="details" title="1. Tenant details">
        <p>
          {tenant.name} ({tenant.domains.join(", ")}), admin account {tenant.admin_email ?? "not set"}.
        </p>
        <form onSubmit={(e) => void saveCustomerId(e)}>
          <label>
            Customer ID
            <input value={customerId} onChange={(e) => setCustomerId(e.target.value)} required />
          </label>
          {CUSTOMER_HELP}
          <button type="submit" disabled={busy}>
            Save customer ID
          </button>
        </form>
        <ErrorText message={error} />
      </Section>
    );
  }
  return (
    <Section id="details" title="1. Tenant details">
      <form onSubmit={(e) => void create(e)}>
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} required />
        </label>
        <label>
          Primary domain
          <input value={domain} onChange={(e) => setDomain(e.target.value)} required />
        </label>
        <label>
          Other domains (comma-separated, optional)
          <input value={extra} onChange={(e) => setExtra(e.target.value)} />
        </label>
        <label>
          Admin email (the account the checks run as)
          <input
            type="email"
            value={adminEmail}
            onChange={(e) => setAdminEmail(e.target.value)}
            required
          />
        </label>
        <label>
          Customer ID
          <input value={customerId} onChange={(e) => setCustomerId(e.target.value)} required />
        </label>
        {CUSTOMER_HELP}
        <ErrorText message={error} />
        <button type="submit" disabled={busy}>
          Create tenant
        </button>
      </form>
    </Section>
  );
}

function Credentials({ tenant, onChanged }: { tenant: Tenant; onChanged: () => void }) {
  const file = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [stored, setStored] = useState(false);

  async function upload(e: FormEvent) {
    e.preventDefault();
    const chosen = Array.from(file.current?.files ?? []);
    if (chosen.length === 0) return;
    setBusy(true);
    setError(null);
    try {
      await api.uploadCredentials(tenant.id, chosen);
      if (file.current) file.current.value = "";
      setStored(true);
      onChanged();
    } catch (err) {
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section id="credentials" title="2. Service account key">
      <p>Get a service account key (a JSON file) in one of two ways:</p>
      <ul>
        <li>
          On any machine with GAM7, run <code>gam create project</code>.
        </li>
        <li>
          Or in the Google Cloud console: IAM, Service accounts, pick the account, Keys, Add key, JSON.
        </li>
      </ul>
      <p className="muted">
        Organizations created since May 2024 block key creation (policy{" "}
        <code>iam.disableServiceAccountKeyCreation</code>). An Organization Policy Administrator must
        allow it for this project first.
      </p>
      <form onSubmit={(e) => void upload(e)}>
        <label>
          Service account key (oauth2service.json)
          <input ref={file} type="file" accept=".json,application/json" />
        </label>
        <button type="submit" disabled={busy}>
          Upload key
        </button>
      </form>
      {stored ? <p role="status">Key stored.</p> : null}
      <ErrorText message={error} />
      {tenant.sa_client_email ? (
        <>
          <p>Service account email</p>
          <Value value={tenant.sa_client_email} label="service account email" />
        </>
      ) : null}
      {tenant.sa_client_id ? (
        <>
          <p>Client ID</p>
          <Value value={tenant.sa_client_id} label="client ID" />
        </>
      ) : null}
    </Section>
  );
}

function Roles({ tenant }: { tenant: Tenant }) {
  return (
    <Section id="roles" title="3. Admin roles">
      <p>
        In the Admin console go to Account, Admin roles. Create or open these roles: User Management
        Admin, Groups Admin, and a custom role with Services, Data Transfer. For each, choose Assign
        service accounts and paste the service account email:
      </p>
      {tenant.sa_client_email ? (
        <Value value={tenant.sa_client_email} label="service account email for roles" />
      ) : (
        <p className="muted">Upload the key first; the email appears here.</p>
      )}
      <p className="muted">Changes can take a few minutes.</p>
    </Section>
  );
}

function Delegation({ tenant }: { tenant: Tenant }) {
  return (
    <Section id="delegation" title="4. Domain-wide delegation">
      <p>
        In the Admin console go to Security, Access and data control, API controls, Manage
        domain-wide delegation, Add new. Enter this client ID and scope:
      </p>
      <p>Client ID</p>
      {tenant.sa_client_id ? (
        <Value value={tenant.sa_client_id} label="client ID for delegation" />
      ) : (
        <p className="muted">Upload the key first; the client ID appears here.</p>
      )}
      <p>OAuth scope</p>
      <Value value={GMAIL_SCOPE} label="scope" />
    </Section>
  );
}

// "Fix in" buttons need the setup sections on the same page (owners of dasa tenants).
function Check({ tenant, canFix }: { tenant: Tenant; canFix: boolean }) {
  const [dash, setDash] = useState<Dashboard | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const alive = useRef(true);
  const [version, setVersion] = useState(0); // bumped to reload the dashboard

  useEffect(() => {
    alive.current = true;
    api.dashboard(tenant.id).then(
      (d) => {
        if (alive.current) setDash(d);
      },
      (e) => {
        if (alive.current) setError(messageOf(e));
      },
    );
    return () => {
      alive.current = false;
    };
  }, [tenant.id, version]);

  async function run() {
    setRunning(true);
    setError(null);
    try {
      const { job_id } = await api.healthCheck(tenant.id);
      for (;;) {
        const j = await api.job(tenant.id, job_id);
        if (!alive.current) return;
        setJob(j);
        if (!ACTIVE.has(j.status)) break;
        await new Promise((r) => setTimeout(r, POLL_MS));
        if (!alive.current) return;
      }
      setVersion((n) => n + 1);
    } catch (e) {
      if (alive.current) setError(messageOf(e));
    } finally {
      if (alive.current) setRunning(false);
    }
  }

  const checks = dash?.health?.checks ?? [];
  return (
    <Section id="check" title="5. Run the checks">
      <button type="button" onClick={() => void run()} disabled={running}>
        {running ? "Running checks..." : "Run checks"}
      </button>
      <ErrorText message={error} />
      {checks.length === 0 ? (
        <p className="muted">No check has run yet.</p>
      ) : (
        <ul className="plain">
          {checks.map((c) => {
            const output = job?.steps.find((s) => s.key === c.key)?.output;
            const failed = c.status === "failed";
            return (
              <li key={c.key}>
                <span className={`status ${STATUS_CLASS[c.status] ?? c.status}`}>
                  {STATUS_LABEL[c.status] ?? c.status}
                </span>{" "}
                {c.title}
                {failed && canFix && c.section ? (
                  <>
                    {" "}
                    <button type="button" onClick={() => scrollToSection(c.section as string)}>
                      Fix in: {c.section}
                    </button>
                  </>
                ) : null}
                {output ? (
                  <details>
                    <summary>GAM output</summary>
                    <pre>{output}</pre>
                  </details>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
    </Section>
  );
}

export default function TenantSetup({ tenant, isOwner, onChanged, onCreated }: Props) {
  if (!isOwner && !(tenant && tenant.role === "admin")) {
    return <p>Only an owner can set up a tenant.</p>;
  }
  if (!isOwner && tenant) {
    // Tenant admins may run the checks but not change credentials.
    return (
      <section>
        <h2>Checks for {tenant.name}</h2>
        <Check tenant={tenant} canFix={false} />
      </section>
    );
  }
  if (tenant && tenant.auth_mode !== "dasa") {
    return (
      <section>
        <h2>Set up {tenant.name}</h2>
        <p role="note">
          This tenant uses an admin OAuth client (oauth2.txt). The guided setup is for
          service-account tenants. Upload or replace its GAM files with the import form on the{" "}
          <a href="#/tenants">Tenants page</a>.
        </p>
        <Check tenant={tenant} canFix={false} />
      </section>
    );
  }
  return (
    <section>
      <h2>{tenant ? `Set up ${tenant.name}` : "Add a tenant"}</h2>
      <Details tenant={tenant} onChanged={onChanged} onCreated={onCreated} />
      {tenant ? (
        <>
          <Credentials tenant={tenant} onChanged={onChanged} />
          <Roles tenant={tenant} />
          <Delegation tenant={tenant} />
          <Check tenant={tenant} canFix />
        </>
      ) : null}
    </section>
  );
}
