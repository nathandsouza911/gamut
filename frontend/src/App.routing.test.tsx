// SPDX-License-Identifier: AGPL-3.0-only
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { api, type Job, type Me, type Tenant } from "./api";
import App from "./App";

vi.mock("./api", async (orig) => {
  const real = await orig<typeof import("./api")>();
  return {
    ...real,
    api: { meta: vi.fn(), me: vi.fn(), tenants: vi.fn(), job: vi.fn(), jobs: vi.fn() },
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
});

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
