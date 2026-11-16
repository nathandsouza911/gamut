// SPDX-License-Identifier: AGPL-3.0-only
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { api, type Job, type Me, type Tenant } from "./api";
import App from "./App";

vi.mock("./api", async (orig) => {
  const real = await orig<typeof import("./api")>();
  return {
    ...real,
    api: { meta: vi.fn(), me: vi.fn(), tenants: vi.fn(), job: vi.fn(), jobs: vi.fn(), dashboard: vi.fn() },
  };
});

const tenant = (id: string, name: string): Tenant => ({
  id,
  name,
  primary_domain: `${id}.example.com`,
  domains: [`${id}.example.com`],
  admin_email: null,
  status: "active",
  last_health_check_at: null,
  last_health_message: null,
  role: "technician",
  has_credentials: true,
  credential_files: [],
  credentials_uploaded_at: null,
  auth_mode: "oauth",
  customer_id: null,
  sa_client_email: null,
  sa_client_id: null,
});

const ownerMe: Me = { id: "o1", email: "owner@example.com", display_name: null, is_owner: true, memberships: [] };
const me: Me = {
  id: "u1",
  email: "tech@example.com",
  display_name: null,
  is_owner: false,
  memberships: [],
};

const job = (id: string): Job => ({
  id,
  workflow: "health_check",
  status: "succeeded",
  target: null,
  created_by: null,
  created_at: "2030-01-01T00:00:00Z",
  finished_at: null,
  account_suspended: null,
  steps: [],
  scheduled_actions: [],
});

beforeEach(() => {
  vi.mocked(api.meta).mockResolvedValue({ source_url: "https://example.com/src", version: "1" });
  vi.mocked(api.me).mockResolvedValue(me);
  vi.mocked(api.tenants).mockResolvedValue([tenant("t1", "First"), tenant("t2", "Second")]);
  vi.mocked(api.job).mockReset().mockImplementation(async (_t, id) => job(id));
  vi.mocked(api.jobs).mockReset().mockResolvedValue([]);
});
afterEach(() => {
  window.location.hash = "";
});

test("a job link names its tenant, so it opens under that tenant", async () => {
  window.location.hash = "#/t/t2/jobs/j9";
  render(<App />);
  await waitFor(() => expect(api.job).toHaveBeenCalledWith("t2", "j9"));
  expect(api.job).not.toHaveBeenCalledWith("t1", "j9");
  // The switcher follows the tenant in the link.
  const select = (await screen.findByRole("combobox")) as HTMLSelectElement;
  expect(select.value).toBe("t2");
});

test("switching tenant on a job page goes to that tenant's job list", async () => {
  window.location.hash = "#/t/t2/jobs/j9";
  render(<App />);
  await waitFor(() => expect(api.job).toHaveBeenCalledWith("t2", "j9"));
  const select = await screen.findByRole("combobox");
  await act(async () => {
    fireEvent.change(select, { target: { value: "t1" } });
  });
  await waitFor(() => expect(window.location.hash).toBe("#/t/t1/jobs"));
  await waitFor(() => expect(api.jobs).toHaveBeenCalledWith("t1"));
});

test("an unknown tenant in the link is reported, not fetched", async () => {
  window.location.hash = "#/t/nope/jobs/j1";
  render(<App />);
  expect(await screen.findByText(/no access to this tenant/i)).toBeTruthy();
  expect(api.job).not.toHaveBeenCalled();
});

test("the job list links to tenant-scoped job pages", async () => {
  vi.mocked(api.jobs).mockResolvedValue([
    { id: "j5", workflow: "offboarding", status: "queued", target: "a@b.com",
      created_by: null, created_at: "2030-01-01T00:00:00Z", finished_at: null },
  ]);
  window.location.hash = "#/t/t2/jobs";
  render(<App />);
  const link = await screen.findByRole("link", { name: "offboarding" });
  expect(link.getAttribute("href")).toBe("#/t/t2/jobs/j5");
});

test("#/tenants/new renders the guided setup for an owner", async () => {
  vi.mocked(api.me).mockResolvedValue(ownerMe);
  window.location.hash = "#/tenants/new";
  render(<App />);
  expect(await screen.findByRole("heading", { name: /Tenant details/i })).toBeTruthy();
});

test("#/t/<id>/setup renders the setup page for that tenant", async () => {
  vi.mocked(api.me).mockResolvedValue(ownerMe);
  vi.mocked(api.dashboard).mockResolvedValue({
    tenant: tenant("t2", "Second"), health: null, credentials: null, failed_jobs: [],
    waiting_jobs: [], scheduled: [], recent_jobs: [],
  });
  window.location.hash = "#/t/t2/setup";
  render(<App />);
  expect(await screen.findByRole("heading", { name: /Run the checks/i })).toBeTruthy();
});

test("#/t/<id>/dashboard renders the dashboard, and Dashboard is the first tenant nav link", async () => {
  vi.mocked(api.dashboard).mockResolvedValue({
    tenant: tenant("t2", "Second"),
    health: null,
    credentials: null,
    failed_jobs: [],
    waiting_jobs: [],
    scheduled: [],
    recent_jobs: [],
  });
  window.location.hash = "#/t/t2/dashboard";
  render(<App />);
  await waitFor(() => expect(api.dashboard).toHaveBeenCalledWith("t2"));
  expect(await screen.findByText("Nothing needs attention.")).toBeTruthy();
  const links = screen.getAllByRole("navigation")[0].querySelectorAll("a");
  expect(links[0].textContent).toBe("Dashboard");
  expect(links[0].getAttribute("href")).toBe("#/t/t2/dashboard");
});
