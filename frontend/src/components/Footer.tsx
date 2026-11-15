// SPDX-License-Identifier: AGPL-3.0-only

// AGPL-3.0 section 13: the link must show even when /api/meta cannot be reached. The
// value from /api/meta (GAMUT_SOURCE_URL) wins; this one is baked in at build time
// (build argument GAMUT_SOURCE_URL, see backend/Dockerfile).
export const FALLBACK_SOURCE_URL: string =
  (import.meta.env.VITE_SOURCE_URL as string | undefined) || "https://github.com/OWNER/gamut";

export default function Footer({ sourceUrl }: { sourceUrl: string | null }) {
  return (
    <footer className="footer">
      GAMUT is free software (AGPL-3.0). <a href={sourceUrl || FALLBACK_SOURCE_URL}>Source code</a>
    </footer>
  );
}
