// SPDX-License-Identifier: AGPL-3.0-only
import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { api, type PanelUser } from "../api";
import Users from "./Users";

vi.mock("../api", async (orig) => {
  const real = await orig<typeof import("../api")>();
  return { ...real, api: { users: vi.fn(), createUser: vi.fn(), disableUser: vi.fn() } };
});

const user = (over: Partial<PanelUser>): PanelUser => ({
  id: "u1",
  email: "tech@example.com",
  display_name: "Tech",
  is_owner: false,
  disabled: false,
  ...over,
});

beforeEach(() => {
  vi.mocked(api.users).mockReset().mockResolvedValue([
    user({ id: "o1", email: "owner@example.com", is_owner: true }),
    user({}),
    user({ id: "u2", email: "gone@example.com", disabled: true }),
  ]);
  vi.mocked(api.createUser).mockReset();
  vi.mocked(api.disableUser).mockReset();
});

test("lists users; Disable only for active non-owners and not for yourself", async () => {
  render(<Users meId="o1" />);
  expect(await screen.findByText("tech@example.com")).toBeTruthy();
  expect(screen.getByText("gone@example.com")).toBeTruthy();
  expect(screen.getAllByRole("button", { name: /^Disable/ })).toHaveLength(1);
  expect(screen.getByRole("button", { name: "Disable tech@example.com" })).toBeTruthy();
});

test("creates a user", async () => {
  vi.mocked(api.createUser).mockResolvedValue(user({ id: "u3", email: "new@example.com" }));
  render(<Users meId="o1" />);
  await screen.findByText("tech@example.com");
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: "new@example.com" } });
  fireEvent.change(screen.getByLabelText("Display name"), { target: { value: "New" } });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Add user" }));
  });
  expect(api.createUser).toHaveBeenCalledWith({ email: "new@example.com", display_name: "New" });
  expect(api.users).toHaveBeenCalledTimes(2);
});

test("disabling asks for confirmation, then calls the API", async () => {
  vi.mocked(api.disableUser).mockResolvedValue(user({ disabled: true }));
  const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
  render(<Users meId="o1" />);
  const button = await screen.findByRole("button", { name: "Disable tech@example.com" });
  await act(async () => {
    fireEvent.click(button);
  });
  expect(api.disableUser).not.toHaveBeenCalled();
  await act(async () => {
    fireEvent.click(button);
  });
  expect(api.disableUser).toHaveBeenCalledWith("u1");
  expect(confirm).toHaveBeenCalledTimes(2);
  confirm.mockRestore();
});
