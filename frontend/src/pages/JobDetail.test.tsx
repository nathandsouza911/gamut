// SPDX-License-Identifier: AGPL-3.0-only
import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { api, type Job, type Step } from "../api";
import JobDetail from "./JobDetail";

vi.mock("../api", async (orig) => {
  const real = await orig<typeof import("../api")>();
  return {
    ...real,
    api: { job: vi.fn(), retryStep: vi.fn(), skipStep: vi.fn(), cancelScheduled: vi.fn() },
  };
});

const step = (over: Partial<Step>): Step => ({
  id: "s1",
  position: 1,
  key: "signout",
  title: "Sign out",
  optional: false,
  status: "pending",
  output: null,
  started_at: null,
  finished_at: null,
  ...over,
});
const job = (status: string, steps: Step[], extra: Partial<Job> = {}): Job => ({
  id: "j1",
  workflow: "offboarding",
  status,
  target: "a@b.com",
  created_by: "x@y.com",
  created_at: "2030-01-01T00:00:00Z",
  finished_at: null,
  steps,
  scheduled_actions: [],
  ...extra,
});

beforeEach(() => {
  vi.useFakeTimers();
  vi.mocked(api.job).mockReset();
});
afterEach(() => vi.useRealTimers());

async function flush(ms = 0) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

test("polls every 2 seconds while the job is running, then stops", async () => {
  vi.mocked(api.job)
    .mockResolvedValueOnce(job("running", [step({ status: "running" })]))
    .mockResolvedValueOnce(job("running", [step({ status: "running" })]))
    .mockResolvedValue(job("succeeded", [step({ status: "succeeded", output: "all good" })]));
  render(<JobDetail tenantId="t1" jobId="j1" canOperate />);
  await flush();
  expect(api.job).toHaveBeenCalledTimes(1);
  await flush(1999);
  expect(api.job).toHaveBeenCalledTimes(1);
  await flush(1);
  expect(api.job).toHaveBeenCalledTimes(2);
  await flush(2000);
  expect(api.job).toHaveBeenCalledTimes(3);
  expect(screen.getByText("all good")).toBeTruthy();
  await flush(10000);
  expect(api.job).toHaveBeenCalledTimes(3);
});

test("shows step status and output", async () => {
  vi.mocked(api.job).mockResolvedValue(
    job("waiting", [step({ status: "waiting", title: "Transfer Drive", output: "transfer pending" })]),
  );
  render(<JobDetail tenantId="t1" jobId="j1" canOperate />);
  await flush();
  expect(screen.getByText("Transfer Drive")).toBeTruthy();
  expect(screen.getByText("transfer pending")).toBeTruthy();
  expect(document.querySelector(".step .status")?.textContent).toBe("waiting");
});

test("no Retry or Skip unless the job has failed", async () => {
  vi.mocked(api.job).mockResolvedValue(job("running", [step({ status: "failed" })]));
  render(<JobDetail tenantId="t1" jobId="j1" canOperate />);
  await flush();
  expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Skip" })).toBeNull();
});

test("a failed required step offers Retry only", async () => {
  vi.mocked(api.job).mockResolvedValue(
    job("failed", [step({ id: "a", status: "failed", optional: false, output: "boom" })]),
  );
  render(<JobDetail tenantId="t1" jobId="j1" canOperate />);
  await flush();
  expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Skip" })).toBeNull();
  expect(screen.getByText("boom")).toBeTruthy();
});

test("a failed optional step offers Skip too, and Skip calls the API", async () => {
  vi.mocked(api.job).mockResolvedValue(
    job("failed", [step({ id: "b", status: "failed", optional: true })]),
  );
  vi.mocked(api.skipStep).mockResolvedValue(job("queued", []));
  render(<JobDetail tenantId="t1" jobId="j1" canOperate />);
  await flush();
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Skip" }));
  });
  expect(api.skipStep).toHaveBeenCalledWith("t1", "j1", "b");
});

test("auditors do not see Retry or Skip", async () => {
  vi.mocked(api.job).mockResolvedValue(
    job("failed", [step({ status: "failed", optional: true })]),
  );
  render(<JobDetail tenantId="t1" jobId="j1" canOperate={false} />);
  await flush();
  expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Skip" })).toBeNull();
});

test("scheduled actions can be cancelled only while scheduled", async () => {
  vi.mocked(api.job).mockResolvedValue(
    job("succeeded", [], {
      scheduled_actions: [
        { id: "x1", action: "delete_user", target: "a@b.com", run_at: "2030-02-01T00:00:00Z",
          status: "scheduled", result: null },
        { id: "x2", action: "delete_user", target: "c@d.com", run_at: "2030-02-01T00:00:00Z",
          status: "cancelled", result: null },
      ],
    }),
  );
  render(<JobDetail tenantId="t1" jobId="j1" canOperate />);
  await flush();
  expect(screen.getAllByRole("button", { name: "Cancel" })).toHaveLength(1);
});
