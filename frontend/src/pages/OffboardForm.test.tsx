// SPDX-License-Identifier: AGPL-3.0-only
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { ApiError, api } from "../api";
import OffboardForm from "./OffboardForm";

vi.mock("../api", async (orig) => {
  const real = await orig<typeof import("../api")>();
  return {
    ...real,
    api: { previewOffboarding: vi.fn(), confirmOffboarding: vi.fn() },
  };
});

const preview = {
  preview_token: "tok",
  expires_at: "2030-01-01T00:00:00Z",
  steps: [
    {
      key: "suspend",
      title: "Suspend the account",
      kind: "run",
      optional: false,
      args_display: "gam update user a@b.com suspended on",
    },
    {
      key: "signout",
      title: "Sign out everywhere",
      kind: "run",
      optional: true,
      args_display: "gam signout user a@b.com",
    },
  ],
};

beforeEach(() => {
  vi.mocked(api.previewOffboarding).mockReset().mockResolvedValue(preview);
  vi.mocked(api.confirmOffboarding).mockReset();
});

function fillUser() {
  fireEvent.change(screen.getByLabelText("User to offboard"), { target: { value: "a@b.com" } });
}

test("suspend is always checked and cannot be unchecked", () => {
  render(<OffboardForm tenantId="t1" onCreated={() => {}} />);
  const box = screen.getByLabelText(/Suspend/) as HTMLInputElement;
  expect(box.checked).toBe(true);
  expect(box.disabled).toBe(true);
});

test("the delete-days field reveals the email confirmation", () => {
  render(<OffboardForm tenantId="t1" onCreated={() => {}} />);
  expect(screen.queryByLabelText("Type the user's email again")).toBeNull();
  fireEvent.change(screen.getByLabelText("Delete the account after (days)"), {
    target: { value: "30" },
  });
  expect(screen.getByLabelText("Type the user's email again")).toBeTruthy();
});

test("submit calls preview and shows the steps", async () => {
  render(<OffboardForm tenantId="t1" onCreated={() => {}} />);
  fillUser();
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  expect(await screen.findByText("Suspend the account")).toBeTruthy();
  expect(screen.getByText("gam update user a@b.com suspended on")).toBeTruthy();
  const sent = vi.mocked(api.previewOffboarding).mock.calls[0];
  expect(sent[0]).toBe("t1");
  expect(sent[1]).toMatchObject({ user: "a@b.com", delete_after_days: null, auto_reply: null });
});

test("confirm creates the job once, even on a double click", async () => {
  let resolve: (v: unknown) => void = () => {};
  vi.mocked(api.confirmOffboarding).mockReturnValue(
    new Promise((r) => {
      resolve = r;
    }) as never,
  );
  const onCreated = vi.fn();
  render(<OffboardForm tenantId="t1" onCreated={onCreated} />);
  fillUser();
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  const confirm = await screen.findByRole("button", { name: "Confirm and run" });
  fireEvent.click(confirm);
  fireEvent.click(confirm);
  expect((confirm as HTMLButtonElement).disabled).toBe(true);
  expect(api.confirmOffboarding).toHaveBeenCalledTimes(1);
  expect(vi.mocked(api.confirmOffboarding).mock.calls[0][2]).toBe("tok");
  resolve({ id: "job-1" });
  await waitFor(() => expect(onCreated).toHaveBeenCalledWith("job-1"));
});

test("a server error is shown and confirm can be tried again", async () => {
  vi.mocked(api.confirmOffboarding).mockRejectedValue(
    new ApiError(400, "the preview has expired"),
  );
  render(<OffboardForm tenantId="t1" onCreated={() => {}} />);
  fillUser();
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  fireEvent.click(await screen.findByRole("button", { name: "Confirm and run" }));
  expect(await screen.findByText("the preview has expired")).toBeTruthy();
  const again = screen.getByRole("button", { name: "Confirm and run" }) as HTMLButtonElement;
  expect(again.disabled).toBe(false);
});
