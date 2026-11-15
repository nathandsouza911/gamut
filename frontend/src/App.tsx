// SPDX-License-Identifier: AGPL-3.0-only
import { useCallback, useEffect, useState } from "react";
import { api, type Me, type Tenant } from "./api";
import Footer from "./components/Footer";
import TenantSwitcher from "./components/TenantSwitcher";
import AuditLog from "./pages/AuditLog";
import JobDetail from "./pages/JobDetail";
import Jobs from "./pages/Jobs";
import OffboardForm from "./pages/OffboardForm";
import SignIn from "./pages/SignIn";
import Tenants from "./pages/Tenants";
import "./styles.css";

function useHash(): string {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const on = () => setHash(window.location.hash);
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash.replace(/^#\/?/, "");
}

const go = (path: string) => {
  window.location.hash = `/${path}`;
};

export default function App() {
  const [sourceUrl, setSourceUrl] = useState<string | null>(null);
  const [me, setMe] = useState<Me | null | undefined>(undefined); // undefined: loading
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantId] = useState<string | null>(null);
  const route = useHash();

  const loadTenants = useCallback(async () => {
    try {
      const list = await api.tenants();
      setTenants(list);
      setTenantId((cur) => (cur && list.some((t) => t.id === cur) ? cur : (list[0]?.id ?? null)));
    } catch {
      setTenants([]);
    }
  }, []);

  useEffect(() => {
    api.meta().then(
      (m) => setSourceUrl(m.source_url),
      () => undefined,
    );
    api.me().then(
      (m) => {
        setMe(m);
        void loadTenants();
      },
      () => setMe(null), // 401: not signed in
    );
  }, [loadTenants]);

  function signedIn(m: Me) {
    setMe(m);
    void loadTenants();
  }

  async function signOut() {
    try {
      await api.logout();
    } finally {
      setMe(null);
      setTenants([]);
      setTenantId(null);
    }
  }

  const tenant = tenants.find((t) => t.id === tenantId) ?? null;
  const isOwner = me?.is_owner ?? false;
  const canOperate = tenant ? ["owner", "admin", "technician"].includes(tenant.role) : false;
  const [page, arg] = route.split("/");

  function body() {
    if (me === undefined) return <p>Loading...</p>;
    if (me === null) return <SignIn onSignedIn={signedIn} />;
    if (page === "tenants" || (!tenant && isOwner)) {
      return (
        <Tenants
          tenants={tenants}
          isOwner={isOwner}
          onChanged={() => void loadTenants()}
          onOpenJob={(id) => go(`jobs/${id}`)}
        />
      );
    }
    if (!tenant) return <p>You do not have access to any tenant yet.</p>;
    if (page === "jobs" && arg) {
      return <JobDetail key={arg} tenantId={tenant.id} jobId={arg} canOperate={canOperate} />;
    }
    if (page === "jobs") return <Jobs tenantId={tenant.id} />;
    if (page === "audit") return <AuditLog key={tenant.id} tenantId={tenant.id} isOwner={isOwner} />;
    if (canOperate) {
      return (
        <OffboardForm key={tenant.id} tenantId={tenant.id} onCreated={(id) => go(`jobs/${id}`)} />
      );
    }
    return <Jobs tenantId={tenant.id} />;
  }

  return (
    <>
      <header className="header">
        <h1>GAMUT</h1>
        {me ? (
          <>
            <nav>
              <a href="#/">Offboard</a>
              <a href="#/jobs">Jobs</a>
              <a href="#/audit">Audit log</a>
              <a href="#/tenants">Tenants</a>
            </nav>
            <TenantSwitcher tenants={tenants} value={tenantId} onChange={setTenantId} />
            <span className="muted">{me.email}</span>
            <button onClick={() => void signOut()}>Sign out</button>
          </>
        ) : null}
      </header>
      <main>{body()}</main>
      <Footer sourceUrl={sourceUrl} />
    </>
  );
}
