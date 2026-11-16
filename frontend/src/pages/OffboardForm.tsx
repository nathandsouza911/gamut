// SPDX-License-Identifier: AGPL-3.0-only
import { useRef, useState, type FormEvent } from "react";
import { api, type OffboardParams, type Preview } from "../api";
import ErrorText, { messageOf } from "../components/ErrorText";

interface Props {
  tenantId: string;
  onCreated: (jobId: string) => void;
}

export default function OffboardForm({ tenantId, onCreated }: Props) {
  const [user, setUser] = useState("");
  const [resetPassword, setResetPassword] = useState(true);
  const [signout, setSignout] = useState(true);
  const [deprovision, setDeprovision] = useState(true);
  const [removeGroups, setRemoveGroups] = useState(true);
  const [replyOn, setReplyOn] = useState(false);
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [driveTo, setDriveTo] = useState("");
  const [days, setDays] = useState("");
  const [confirmEmail, setConfirmEmail] = useState("");

  const [preview, setPreview] = useState<{ params: OffboardParams; result: Preview } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Synchronous guard: state updates lag behind a fast double click.
  const confirming = useRef(false);

  // Any edit invalidates the preview: the token is bound to the exact parameters.
  function edit<T>(setter: (v: T) => void) {
    return (v: T) => {
      setter(v);
      setPreview(null);
      setError(null);
    };
  }

  function params(): OffboardParams {
    const deleteDays = days.trim() === "" ? null : Number(days);
    return {
      user: user.trim(),
      reset_password: resetPassword,
      signout,
      deprovision,
      remove_groups: removeGroups,
      auto_reply: replyOn ? { subject, message } : null,
      transfer_drive_to: driveTo.trim() === "" ? null : driveTo.trim(),
      delete_after_days: deleteDays,
      confirm_delete_email: deleteDays === null ? null : confirmEmail.trim(),
    };
  }

  async function runPreview(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const p = params();
    try {
      setPreview({ params: p, result: await api.previewOffboarding(tenantId, p) });
    } catch (err) {
      setPreview(null);
      setError(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  async function confirm() {
    if (!preview || confirming.current) return;
    confirming.current = true;
    setBusy(true);
    setError(null);
    try {
      // 201 (new job) and 200 (same token again) both mean the job exists.
      const job = await api.confirmOffboarding(
        tenantId,
        preview.params,
        preview.result.preview_token,
      );
      onCreated(job.id);
    } catch (err) {
      setError(messageOf(err));
      setBusy(false);
      confirming.current = false;
    }
  }

  const check = (label: string, value: boolean, set: (v: boolean) => void) => (
    <label className="check">
      <input type="checkbox" checked={value} onChange={(e) => edit(set)(e.target.checked)} />
      {label}
    </label>
  );

  return (
    <section className="card">
      <h2>Offboard a user</h2>
      <form onSubmit={runPreview}>
        <label>
          User to offboard
          <input
            type="email"
            value={user}
            onChange={(e) => edit(setUser)(e.target.value)}
            required
          />
        </label>
        {check("Reset password", resetPassword, setResetPassword)}
        {check("Sign out everywhere", signout, setSignout)}
        {check("Deprovision (revoke tokens and app passwords)", deprovision, setDeprovision)}
        <label className="check">
          <input type="checkbox" checked disabled readOnly />
          Suspend the account (always)
        </label>
        {check("Remove from all groups", removeGroups, setRemoveGroups)}
        {check("Set an auto-reply", replyOn, setReplyOn)}
        {replyOn ? (
          <>
            <label>
              Auto-reply subject
              <input value={subject} onChange={(e) => edit(setSubject)(e.target.value)} required />
            </label>
            <label>
              Auto-reply message
              <textarea
                value={message}
                onChange={(e) => edit(setMessage)(e.target.value)}
                required
              />
            </label>
          </>
        ) : null}
        <label>
          Transfer Drive to (optional)
          <input type="email" value={driveTo} onChange={(e) => edit(setDriveTo)(e.target.value)} />
        </label>
        <label>
          Delete the account after (days)
          <input
            type="number"
            min={1}
            max={365}
            value={days}
            onChange={(e) => edit(setDays)(e.target.value)}
          />
        </label>
        {days.trim() !== "" ? (
          <label>
            Type the user&apos;s email again
            <input
              type="email"
              value={confirmEmail}
              onChange={(e) => edit(setConfirmEmail)(e.target.value)}
              required
            />
          </label>
        ) : null}
        <button type="submit" disabled={busy}>
          Preview
        </button>
      </form>

      {preview ? (
        <div className="preview">
          <h3>Steps that will run</h3>
          <ol>
            {preview.result.steps.map((s) => (
              <li key={s.key}>
                <strong>{s.title}</strong>
                {s.optional ? <span className="muted"> (optional)</span> : null}
                <div>
                  <code>{s.args_display}</code>
                </div>
              </li>
            ))}
          </ol>
          <button type="button" onClick={() => void confirm()} disabled={busy}>
            Confirm and run
          </button>
        </div>
      ) : null}
      <ErrorText message={error} />
    </section>
  );
}
