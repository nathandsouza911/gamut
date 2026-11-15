// SPDX-License-Identifier: AGPL-3.0-only
import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import Footer from "./Footer";

test("links to the configured source code", () => {
  render(<Footer sourceUrl="https://example.com/gamut" />);
  const link = screen.getByRole("link", { name: "Source code" });
  expect(link.getAttribute("href")).toBe("https://example.com/gamut");
});
