// SPDX-License-Identifier: AGPL-3.0-only
import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { ApiError, api } from "./api";
import App from "./App";

vi.mock("./api", async (orig) => {
  const real = await orig<typeof import("./api")>();
  return { ...real, api: { meta: vi.fn(), me: vi.fn(), tenants: vi.fn() } };
});

test("the sign-in page shows the product name and the source link", async () => {
  vi.mocked(api.meta).mockResolvedValue({ source_url: "https://example.com/src", version: "1" });
  vi.mocked(api.me).mockRejectedValue(new ApiError(401, "not signed in"));
  render(<App />);
  expect(screen.getByRole("heading", { name: "GAMUT" })).toBeTruthy();
  expect(await screen.findByRole("button", { name: "Sign in with Google" })).toBeTruthy();
  const link = await screen.findByRole("link", { name: "Source code" });
  expect(link.getAttribute("href")).toBe("https://example.com/src");
});

test("the source link still renders when /api/meta fails", async () => {
  vi.mocked(api.meta).mockRejectedValue(new ApiError(500, "boom"));
  vi.mocked(api.me).mockRejectedValue(new ApiError(401, "not signed in"));
  render(<App />);
  const link = await screen.findByRole("link", { name: "Source code" });
  expect(link.getAttribute("href")).toMatch(/^https:\/\//);
});
