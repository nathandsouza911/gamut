// SPDX-License-Identifier: AGPL-3.0-only
export default function Footer({ sourceUrl }: { sourceUrl: string | null }) {
  return (
    <footer className="footer">
      GAMUT is free software (AGPL-3.0).{" "}
      {sourceUrl ? <a href={sourceUrl}>Source code</a> : null}
    </footer>
  );
}
