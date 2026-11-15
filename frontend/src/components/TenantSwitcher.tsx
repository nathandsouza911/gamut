// SPDX-License-Identifier: AGPL-3.0-only
import type { Tenant } from "../api";

interface Props {
  tenants: Tenant[];
  value: string | null;
  onChange: (id: string) => void;
}

export default function TenantSwitcher({ tenants, value, onChange }: Props) {
  if (tenants.length === 0) return <span className="muted">No tenants</span>;
  return (
    <label className="inline">
      Tenant{" "}
      <select value={value ?? ""} onChange={(e) => onChange(e.target.value)}>
        {tenants.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name}
          </option>
        ))}
      </select>
    </label>
  );
}
