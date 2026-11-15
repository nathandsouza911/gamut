// SPDX-License-Identifier: AGPL-3.0-only
import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import App from "./App";

test("renders the product name", () => {
  render(<App />);
  expect(screen.getByRole("heading", { name: "GAMUT" })).toBeTruthy();
});
