// SPDX-License-Identifier: AGPL-3.0-only
// The only module that talks to the server. Cookies are sent on every call; state-changing
// calls also carry the CSRF token from the gamut_csrf cookie in X-CSRF-Token.

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export type Role = "owner" | "admin" | "technician" | "auditor";

export interface Me {
  id: string;
  email: string;
  display_name: string | null;
  is_owner: boolean;
  memberships: { tenant_id: string; tenant_name: string; role: Role }[];
}

export interface Tenant {
  id: string;
  name: string;
  primary_domain: string;
  domains: string[];
  admin_email: string | null;
  status: "pending" | "active" | "degraded" | "disabled";
  last_health_check_at: string | null;
  last_health_message: string | null;
  role: Role;
  has_credentials: boolean;
  credential_files: string[];
  credentials_uploaded_at: string | null;
  auth_mode: "oauth" | "dasa";
  customer_id: string | null;
  sa_client_email: string | null;
  sa_client_id: string | null;
}

export interface OffboardParams {
  user: string;
  reset_password: boolean;
  signout: boolean;
  deprovision: boolean;
  remove_groups: boolean;
  auto_reply: { subject: string; message: string } | null;
  transfer_drive_to: string | null;
  delete_after_days: number | null;
  confirm_delete_email: string | null;
}

export interface PreviewStep {
  key: string;
  title: string;
  kind: string;
  optional: boolean;
  args_display: string;
}

export interface Preview {
  preview_token: string;
  expires_at: string;
  steps: PreviewStep[];
}

export type StepStatus = "pending" | "running" | "waiting" | "succeeded" | "failed" | "skipped";

export interface Step {
  id: string;
  position: number;
  key: string;
  title: string;
  optional: boolean;
  status: StepStatus;
  output: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface ScheduledAction {
  id: string;
  action: string;
  target: string | null;
  run_at: string;
  status: string;
  result: string | null;
}

export interface JobSummary {
  id: string;
  workflow: string;
  status: string;
  target: string | null;
  created_by: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface HealthCheck {
  key: string;
  title: string;
  status: string;
  exit_code: number | null;
  section: "credentials" | "roles" | "delegation" | null;
}

export interface Health {
  job_id: string;
  finished_at: string | null;
  ok: boolean;
  checks: HealthCheck[];
}

export interface CredentialsInfo {
  auth_mode: "oauth" | "dasa";
  file_names: string[];
  uploaded_at: string | null;
  age_days: number | null;
  rotate_soon: boolean;
  sa_client_email: string | null;
  sa_client_id: string | null;
}

export interface WaitingJob extends JobSummary {
  waiting_since: string | null;
}

export interface Dashboard {
  tenant: Tenant;
  health: Health | null;
  credentials: CredentialsInfo | null;
  failed_jobs: JobSummary[];
  waiting_jobs: WaitingJob[];
  scheduled: ScheduledAction[];
  recent_jobs: JobSummary[];
}

export interface Job extends JobSummary {
  // Offboarding jobs: whether the suspend step has succeeded (null: no such step).
  account_suspended: boolean | null;
  steps: Step[];
  scheduled_actions: ScheduledAction[];
}

export interface PanelUser {
  id: string;
  email: string;
  display_name: string | null;
  is_owner: boolean;
  disabled: boolean;
}

export type MemberRole = "admin" | "technician" | "auditor";

export interface Member {
  user_id: string;
  email: string;
  display_name: string | null;
  role: MemberRole;
  disabled: boolean;
}

export interface AuditEvent {
  id: number;
  time: string;
  actor: string;
  action: string;
  target: string | null;
  details: Record<string, unknown>;
}

export interface VerifyResult {
  ok: boolean;
  checked: number;
  first_broken_id: number | null;
  reason: string | null;
}

function csrfToken(): string {
  const match = document.cookie.split("; ").find((c) => c.startsWith("gamut_csrf="));
  return match ? decodeURIComponent(match.slice("gamut_csrf=".length)) : "";
}

function describe(detail: unknown, fallback: string): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d: { loc?: unknown[]; msg?: string }) => {
        const field = (d.loc ?? []).filter((p) => p !== "body").join(".");
        return field ? `${field}: ${d.msg ?? ""}` : (d.msg ?? "");
      })
      .join("; ");
  }
  return fallback;
}

async function request<T>(method: string, path: string, body?: unknown | FormData): Promise<T> {
  const headers: Record<string, string> = {};
  let payload: BodyInit | undefined;
  if (body instanceof FormData) {
    payload = body;
  } else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken();
  const response = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
  if (response.status === 204) return undefined as T;
  let data: unknown = null;
  try {
    data = await response.json();
  } catch {
    // not JSON
  }
  if (!response.ok) {
    const detail = (data as { detail?: unknown } | null)?.detail;
    throw new ApiError(response.status, describe(detail, `request failed (${response.status})`));
  }
  return data as T;
}

const t = (id: string) => `/api/tenants/${encodeURIComponent(id)}`;

export const api = {
  meta: () => request<{ source_url: string; version: string }>("GET", "/api/meta"),
  me: () => request<Me>("GET", "/api/me"),
  bootstrapLogin: (email: string, password: string) =>
    request<Me>("POST", "/api/auth/bootstrap-login", { email, password }),
  logout: () => request<void>("POST", "/api/auth/logout"),

  tenants: () => request<Tenant[]>("GET", "/api/tenants"),
  createTenant: (b: {
    name: string;
    primary_domain: string;
    admin_email: string | null;
    auth_mode?: "oauth" | "dasa";
    customer_id?: string | null;
  }) => request<Tenant>("POST", "/api/tenants", b),
  dashboard: (id: string) => request<Dashboard>("GET", `${t(id)}/dashboard`),
  uploadCredentials: (id: string, files: File[]) => {
    const form = new FormData();
    for (const f of files) form.append("files", f, f.name);
    return request<{ file_names: string[]; health_job_id: string | null }>(
      "PUT",
      `${t(id)}/credentials`,
      form,
    );
  },
  healthCheck: (id: string) => request<{ job_id: string }>("POST", `${t(id)}/health-check`),
  updateTenant: (id: string, b: { admin_email?: string | null; domains?: string[]; customer_id?: string | null }) =>
    request<Tenant>("PATCH", t(id), b),
  members: (id: string) => request<Member[]>("GET", `${t(id)}/members`),
  setMember: (id: string, email: string, role: MemberRole) =>
    request<{ email: string; role: MemberRole }>("POST", `${t(id)}/members`, { email, role }),
  removeMember: (id: string, userId: string) =>
    request<void>("DELETE", `${t(id)}/members/${encodeURIComponent(userId)}`),

  users: () => request<PanelUser[]>("GET", "/api/users"),
  createUser: (b: { email: string; display_name: string | null }) =>
    request<PanelUser>("POST", "/api/users", b),
  disableUser: (userId: string) =>
    request<PanelUser>("POST", `/api/users/${encodeURIComponent(userId)}/disable`),

  previewOffboarding: (id: string, p: OffboardParams) =>
    request<Preview>("POST", `${t(id)}/workflows/offboarding/preview`, p),
  // 201 for a new job, 200 for a repeat of the same preview token: both are success.
  confirmOffboarding: (id: string, params: OffboardParams, previewToken: string) =>
    request<Job>("POST", `${t(id)}/jobs`, {
      workflow: "offboarding",
      params,
      preview_token: previewToken,
    }),
  jobs: (id: string) => request<JobSummary[]>("GET", `${t(id)}/jobs`),
  job: (id: string, jobId: string) => request<Job>("GET", `${t(id)}/jobs/${jobId}`),
  retryStep: (id: string, jobId: string, stepId: string) =>
    request<Job>("POST", `${t(id)}/jobs/${jobId}/steps/${stepId}/retry`),
  skipStep: (id: string, jobId: string, stepId: string) =>
    request<Job>("POST", `${t(id)}/jobs/${jobId}/steps/${stepId}/skip`),
  cancelScheduled: (id: string, actionId: string) =>
    request<ScheduledAction>("POST", `${t(id)}/scheduled-actions/${actionId}/cancel`),

  audit: (id: string, cursor?: number | null) =>
    request<{ items: AuditEvent[]; next_cursor: number | null }>(
      "GET",
      `${t(id)}/audit?limit=50${cursor ? `&cursor=${cursor}` : ""}`,
    ),
  verifyAudit: () => request<VerifyResult>("GET", "/api/audit/verify"),
};
