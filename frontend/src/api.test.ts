// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, expect, test, vi } from "vitest";
import { ApiError, api } from "./api";

afterEach(() => vi.unstubAllGlobals());

function stubFetch(status: number, body: unknown) {
  const fetchMock = vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

test("state-changing calls send the CSRF cookie value as X-CSRF-Token", async () => {
  document.cookie = "gamut_csrf=abc123";
  const fetchMock = stubFetch(200, { job_id: "j" });
  await api.healthCheck("t1");
  const init = fetchMock.mock.calls[0][1] as RequestInit;
  expect((init.headers as Record<string, string>)["X-CSRF-Token"]).toBe("abc123");
  expect(init.credentials).toBe("same-origin");
});

test("GET calls do not send the token", async () => {
  const fetchMock = stubFetch(200, []);
  await api.tenants();
  const init = fetchMock.mock.calls[0][1] as RequestInit;
  expect((init.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
});

test("validation errors name the field", async () => {
  stubFetch(422, { detail: [{ loc: ["body", "user"], msg: "not a valid email" }] });
  await expect(api.tenants()).rejects.toMatchObject({
    status: 422,
    message: "user: not a valid email",
  });
  expect(ApiError).toBeDefined();
});
