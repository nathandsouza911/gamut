// SPDX-License-Identifier: AGPL-3.0-only
import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { api, type Dashboard, type Tenant } from "../api";
import TenantSetup from "./TenantSetup";

vi.mock("../api", async (orig) => {
  const real = await orig<typeof import("../api")>();
  return {
    ...real,
    api: {
      createTenant: vi.fn(),
      updateTenant: vi.fn(),
      uploadCredentials: vi.fn(),
      healthCheck: vi.fn(),
      dashboard: vi.fn(),
      job: vi.fn(),
    },
  };
});

const tenant = (over: Partial<Tenant> = {}): Tenant => ({
  id: "t1",
  name: "Example",
  primary_domain: "example.com",
  domains: ["example.com"],
  admin_email: "admin@example.com",
  status: "pending",
  last_health_check_at: null,
  last_health_message: null,
  role: "owner",
  has_credentials: false,
  credential_files: [],
  credentials_uploaded_at: null,
  auth_mode: "dasa",
  customer_id: "C04jm7qkb",
  sa_client_email: null,
  sa_client_id: null,
  ...over,
});

const dashboard = (status: string): Dashboard => ({
  tenant: tenant(),
  health: {
    job_id: "j1",
    finished_at: "2030-01-01T00:00:00Z",
    ok: false,
    checks: [
      { key: "directory_role", title: "Directory role", status: "succeeded", exit_code: 0, section: "roles" },
      { key: "gmail_delegation", title: "Gmail delegation", status, exit_code: 10, section: "delegation" },
    ],
  },
  credentials: null,
  failed_jobs: [],
  waiting_jobs: [],
  scheduled: [],
  recent_jobs: [],
});

beforeEach(() => {
  for (const fn of Object.values(api)) vi.mocked(fn).mockReset();
});
afterEach(() => {
  window.location.hash = "";
});

const noop = () => undefined;

test("creates a dasa tenant and moves to credentials", async () => {
  vi.mocked(api.createTenant).mockResolvedValue(tenant({ id: "new1" }));
  const onCreated = vi.fn();
  render(
    <TenantSetup tenant={null} isOwner onChanged={noop} onCreated={onCreated} />,
  );
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Example" } });
  fireEvent.change(screen.getByLabelText("Primary domain"), { target: { value: "example.com" } });
  fireEvent.change(screen.getByLabelText(/Admin email/), { target: { value: "admin@example.com" } });
  fireEvent.change(screen.getByLabelText(/Customer ID/), { target: { value: "  C04jm7qkb " } });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Create tenant" }));
  });
  expect(api.createTenant).toHaveBeenCalledWith(
    expect.objectContaining({ auth_mode: "dasa", customer_id: "C04jm7qkb", primary_domain: "example.com" }),
  );
  expect(onCreated).toHaveBeenCalledWith("new1");
});

test("shows service account identity after upload", async () => {
  vi.mocked(api.dashboard).mockResolvedValue({ ...dashboard("failed"), health: null });
  render(
    <TenantSetup
      tenant={tenant({ sa_client_email: "sa@proj.iam.gserviceaccount.com", sa_client_id: "123456789" })}
      isOwner
      onChanged={noop}
      onCreated={noop}
    />,
  );
  expect((await screen.findAllByText("sa@proj.iam.gserviceaccount.com")).length).toBeGreaterThan(0);
  expect(screen.getAllByText("123456789").length).toBeGreaterThan(0);
  expect(screen.getByText("https://www.googleapis.com/auth/gmail.settings.basic")).toBeTruthy();
});

test("failed check links to its section", async () => {
  vi.mocked(api.dashboard).mockResolvedValue(dashboard("failed"));
  render(<TenantSetup tenant={tenant()} isOwner onChanged={noop} onCreated={noop} />);
  const fix = await screen.findByRole("button", { name: /Fix in: delegation/i });
  const target = document.getElementById("delegation") as HTMLElement;
  target.scrollIntoView = vi.fn();
  fireEvent.click(fix);
  expect(target.scrollIntoView).toHaveBeenCalled();
});

test("only owners see the setup for a new tenant", () => {
  render(<TenantSetup tenant={null} isOwner={false} onChanged={noop} onCreated={noop} />);
  expect(screen.queryByLabelText("Name")).toBeNull();
  expect(screen.getByText(/Only an owner/i)).toBeTruthy();
});
