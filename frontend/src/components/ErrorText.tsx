// SPDX-License-Identifier: AGPL-3.0-only
export function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : "something went wrong";
}

export default function ErrorText({ message }: { message: string | null }) {
  return message ? (
    <p role="alert" className="error">
      {message}
    </p>
  ) : null;
}
