// SPDX-License-Identifier: AGPL-3.0-only
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { api, type Dashboard as DashboardData, type Tenant } from "../api";
import Dashboard from "./Dashboard";

vi.mock("../api", async (orig) => {
  const real = await orig<typeof import("../api")>();
  return {
    ...real,
    api: { dashboard: vi.fn(), healthCheck: vi.fn(), cancelScheduled: vi.fn() },
  };
});

const tenant = (over: Partial<Tenant> = {}): Tenant => ({
  id: "t1",
  name: "Example",
  primary_domain: "example.com",
  domains: ["example.com"],
  admin_email: "admin@example.com",
  status: "active",
  last_health_check_at: null,
  last_health_message: null,
  role: "owner",
  has_credentials: true,
  credential_files: [],
  credentials_uploaded_at: null,
  auth_mode: "dasa",
  customer_id: "C04jm7qkb",
  sa_client_email: "sa@example.iam.gserviceaccount.com",
  sa_client_id: "123",
  ...over,
});

const job = (id: string, status: string, target = "user@example.com") => ({
  id,
  workflow: "offboarding",
  status,
  target,
  created_by: "a@example.com",
  created_at: "2030-01-01T00:00:00Z",
  finished_at: null,
});

const data = (over: Partial<DashboardData> = {}, t: Partial<Tenant> = {}): DashboardData => ({
  tenant: tenant(t),
  health: {
    job_id: "h1",
    finished_at: "2030-01-01T00:00:00Z",
    ok: false,
    checks: [
      { key: "a", title: "Directory role", status: "succeeded", exit_code: 0, section: "roles" },
      { key: "b", title: "Gmail delegation", status: "failed", exit_code: 10, section: "delegation" },
    ],
  },
  credentials: {
    auth_mode: "dasa",
    file_names: ["key.json"],
    uploaded_at: "2029-01-01T00:00:00Z",
    age_days: 100,
    rotate_soon: true,
    sa_client_email: "sa@example.iam.gserviceaccount.com",
    sa_client_id: "123",
  },
  failed_jobs: [job("jf", "failed", "failed@example.com")],
  waiting_jobs: [{ ...job("jw", "waiting", "wait@example.com"), waiting_since: "2030-01-01T00:00:00Z" }],
  scheduled: [
    { id: "s1", action: "delete_user", target: "gone@example.com", run_at: "2030-02-01T00:00:00Z", status: "scheduled", result: null },
  ],
  recent_jobs: [job("jr", "succeeded", "recent@example.com")],
  ...over,
});

beforeEach(() => {
  vi.mocked(api.dashboard).mockReset();
  vi.mocked(api.healthCheck).mockReset();
  vi.mocked(api.cancelScheduled).mockReset();
});
afterEach(() => vi.restoreAllMocks());

const show = async (d: DashboardData) => {
  vi.mocked(api.dashboard).mockResolvedValue(d);
  render(<Dashboard tenant={d.tenant} />);
  await screen.findByText("Gmail delegation");
};

test("shows status, checks and key age warning", async () => {
  await show(data());
  expect(screen.getByText("Directory role")).toBeTruthy();
  expect(screen.getByText(/rotate/i)).toBeTruthy();
  expect(screen.getByText(/100 days/)).toBeTruthy();
});

test("needs attention lists failed and waiting jobs with links to job detail", async () => {
  await show(data());
  const f = screen.getByText(/failed@example.com/).closest("a");
  expect(f?.getAttribute("href")).toBe("#/t/t1/jobs/jf");
  const w = screen.getByText(/wait@example.com/).closest("a");
  expect(w?.getAttribute("href")).toBe("#/t/t1/jobs/jw");
});

test("scheduled deletions can be cancelled by owners, admins and technicians, not auditors", async () => {
  for (const role of ["owner", "admin", "technician"] as const) {
    document.body.innerHTML = "";
    await show(data({}, { role }));
    expect(screen.getByRole("button", { name: /^Cancel delete_user gone@example.com/ })).toBeTruthy();
  }
  document.body.innerHTML = "";
  await show(data({}, { role: "auditor" }));
  expect(screen.queryByRole("button", { name: /^Cancel/ })).toBeNull();
});

test("run health check button hidden for technicians and auditors", async () => {
  await show(data({}, { role: "admin" }));
  expect(screen.getByRole("button", { name: "Run health check" })).toBeTruthy();
  for (const role of ["technician", "auditor"] as const) {
    document.body.innerHTML = "";
    await show(data({}, { role }));
    expect(screen.queryByRole("button", { name: "Run health check" })).toBeNull();
  }
});

test("pending tenant shows Continue setup", async () => {
  await show(data({}, { status: "pending" }));
  await waitFor(() => {
    const a = screen.getByText("Continue setup").closest("a");
    expect(a?.getAttribute("href")).toBe("#/t/t1/setup");
  });
});

test("setup links only for owners of dasa tenants", async () => {
  await show(data({}, { status: "pending" }));
  expect(screen.getByRole("link", { name: "Fix" }).getAttribute("href")).toBe("#/t/t1/setup");
  for (const t of [{ auth_mode: "oauth" as const }, { role: "admin" as const }, { role: "technician" as const }]) {
    document.body.innerHTML = "";
    await show(data({}, { status: "pending", ...t }));
    expect(screen.queryByText("Continue setup")).toBeNull();
    expect(screen.queryByRole("link", { name: "Fix" })).toBeNull();
  }
});
