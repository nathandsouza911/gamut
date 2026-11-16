// SPDX-License-Identifier: AGPL-3.0-only
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { api, type Tenant } from "../api";
import Tenants from "./Tenants";

vi.mock("../api", async (orig) => {
  const real = await orig<typeof import("../api")>();
  return {
    ...real,
    api: {
      createTenant: vi.fn(),
      uploadCredentials: vi.fn(),
      healthCheck: vi.fn(),
      updateTenant: vi.fn(),
      members: vi.fn(),
      setMember: vi.fn(),
      removeMember: vi.fn(),
    },
  };
});

const tenant = (over: Partial<Tenant> = {}): Tenant => ({
  id: "t1",
  name: "Acme",
  primary_domain: "acme.com",
  domains: ["acme.com", "acme.org"],
  admin_email: "admin@acme.com",
  status: "pending",
  last_health_check_at: null,
  last_health_message: null,
  role: "owner",
  has_credentials: false,
  credential_files: [],
  credentials_uploaded_at: null,
  ...over,
});

beforeEach(() => {
  for (const fn of Object.values(api)) vi.mocked(fn).mockReset();
  vi.mocked(api.members).mockResolvedValue([
    { user_id: "u1", email: "tech@example.com", display_name: null, role: "technician",
      disabled: false },
  ]);
});

const noop = () => undefined;

test("after an upload, the queued health check is linked under its tenant", async () => {
  vi.mocked(api.uploadCredentials).mockResolvedValue({
    file_names: ["oauth2.txt", "oauth2service.json"],
    health_job_id: "hj1",
  });
  const onChanged = vi.fn();
  render(<Tenants tenants={[tenant()]} isOwner onChanged={onChanged} onOpenJob={noop} />);
  const input = screen.getByLabelText(/Credential files/) as HTMLInputElement;
  const file = new File(["{}"], "oauth2.txt", { type: "application/json" });
  fireEvent.change(input, { target: { files: [file] } });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Upload credentials" }));
  });
  const link = await screen.findByRole("link", { name: /health check/i });
  expect(link.getAttribute("href")).toBe("#/t/t1/jobs/hj1");
  expect(onChanged).toHaveBeenCalled();
});

test("Run health check opens the job under its tenant", async () => {
  vi.mocked(api.healthCheck).mockResolvedValue({ job_id: "hj2" });
  const onOpenJob = vi.fn();
  render(<Tenants tenants={[tenant({ id: "t7" })]} isOwner onChanged={noop} onOpenJob={onOpenJob} />);
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Run health check" }));
  });
  expect(onOpenJob).toHaveBeenCalledWith("t7", "hj2");
});

test("owners edit the extra domains", async () => {
  vi.mocked(api.updateTenant).mockResolvedValue(tenant({ domains: ["acme.com", "acme.net"] }));
  const onChanged = vi.fn();
  render(<Tenants tenants={[tenant()]} isOwner onChanged={onChanged} onOpenJob={noop} />);
  const input = screen.getByLabelText(/Other domains/) as HTMLInputElement;
  expect(input.value).toBe("acme.org");
  fireEvent.change(input, { target: { value: "acme.net, Acme.io " } });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Save domains" }));
  });
  expect(api.updateTenant).toHaveBeenCalledWith("t1", { domains: ["acme.net", "acme.io"] });
  expect(onChanged).toHaveBeenCalled();
});

test("tenant admins manage members; technicians do not see the panel", async () => {
  vi.mocked(api.setMember).mockResolvedValue({ email: "new@example.com", role: "auditor" });
  vi.mocked(api.removeMember).mockResolvedValue(undefined);
  render(
    <Tenants tenants={[tenant({ role: "admin" })]} isOwner={false} onChanged={noop} onOpenJob={noop} />,
  );
  const panel = await screen.findByRole("region", { name: "Members" });
  expect(await within(panel).findByText("tech@example.com")).toBeTruthy();
  expect(screen.queryByLabelText(/Other domains/)).toBeNull(); // owners only

  fireEvent.change(within(panel).getByLabelText("Email"), {
    target: { value: "new@example.com" },
  });
  fireEvent.change(within(panel).getByLabelText("Role"), { target: { value: "auditor" } });
  await act(async () => {
    fireEvent.click(within(panel).getByRole("button", { name: "Add or change" }));
  });
  expect(api.setMember).toHaveBeenCalledWith("t1", "new@example.com", "auditor");

  await act(async () => {
    fireEvent.click(within(panel).getByRole("button", { name: "Remove tech@example.com" }));
  });
  expect(api.removeMember).toHaveBeenCalledWith("t1", "u1");
  await waitFor(() => expect(api.members).toHaveBeenCalledTimes(3));
});

test("technicians see no members panel", async () => {
  render(
    <Tenants
      tenants={[tenant({ role: "technician" })]}
      isOwner={false}
      onChanged={noop}
      onOpenJob={noop}
    />,
  );
  expect(screen.queryByRole("region", { name: "Members" })).toBeNull();
  expect(api.members).not.toHaveBeenCalled();
});
