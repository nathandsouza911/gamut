// SPDX-License-Identifier: AGPL-3.0-only
import { useCallback, useEffect, useState } from "react";
import { api, type Me, type Tenant } from "./api";
import Footer from "./components/Footer";
import TenantSwitcher from "./components/TenantSwitcher";
import AuditLog from "./pages/AuditLog";
import Dashboard from "./pages/Dashboard";
import JobDetail from "./pages/JobDetail";
import Jobs from "./pages/Jobs";
import OffboardForm from "./pages/OffboardForm";
import SignIn from "./pages/SignIn";
import TenantSetup from "./pages/TenantSetup";
import Tenants from "./pages/Tenants";
import Users from "./pages/Users";
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

// Tenant pages carry their tenant in the route (#/t/<tenant>/jobs/<job>), so a link
// opens under the right tenant whatever is selected. #/jobs, #/jobs/<id> and #/audit
// still work and use the selected tenant.
interface Route {
  tenant: string | null;
  page: string;
  arg: string | undefined;
}

function parseRoute(route: string): Route {
  const parts = route.split("/");
  if (parts[0] === "t" && parts[1]) return { tenant: parts[1], page: parts[2] ?? "", arg: parts[3] };
  return { tenant: null, page: parts[0] ?? "", arg: parts[1] };
}

export default function App() {
  const [sourceUrl, setSourceUrl] = useState<string | null>(null);
  const [me, setMe] = useState<Me | null | undefined>(undefined); // undefined: loading
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantsLoaded, setTenantsLoaded] = useState(false);
  const [tenantId, setTenantId] = useState<string | null>(null);
  const route = parseRoute(useHash());

  const loadTenants = useCallback(async () => {
    try {
      const list = await api.tenants();
      setTenants(list);
      setTenantId((cur) => (cur && list.some((t) => t.id === cur) ? cur : (list[0]?.id ?? null)));
    } catch {
      setTenants([]);
    } finally {
      setTenantsLoaded(true);
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
      setTenantsLoaded(false);
      setTenantId(null);
    }
  }

  const routeKnown = route.tenant !== null && tenants.some((t) => t.id === route.tenant);
  // A tenant named in the route becomes the selected tenant (state adjusted in render).
  if (routeKnown && route.tenant !== tenantId) setTenantId(route.tenant);
  const activeId = route.tenant ?? tenantId;
  const tenant = tenants.find((t) => t.id === activeId) ?? null;
  const isOwner = me?.is_owner ?? false;
  const canOperate = tenant ? ["owner", "admin", "technician"].includes(tenant.role) : false;
  const { page, arg } = route;

  function switchTenant(id: string) {
    setTenantId(id);
    if (route.tenant !== null) {
      // A job belongs to one tenant: go to the new tenant's list instead.
      go(page === "jobs" || page === "audit" ? `t/${id}/${page}` : `t/${id}`);
    }
  }

  function body() {
    if (me === undefined) return <p>Loading...</p>;
    if (me === null) return <SignIn onSignedIn={signedIn} />;
    if (route.tenant === null && page === "users" && isOwner) return <Users meId={me.id} />;
    if (route.tenant === null && page === "tenants" && arg === "new") {
      return (
        <TenantSetup
          tenant={null}
          isOwner={isOwner}
          onChanged={() => void loadTenants()}
          onCreated={(id) => go(`t/${id}/setup`)}
        />
      );
    }
    if (route.tenant !== null && !routeKnown) {
      return tenantsLoaded ? (
        <p>You have no access to this tenant, or it does not exist.</p>
      ) : (
        <p>Loading...</p>
      );
    }
    if (route.tenant === null && (page === "tenants" || (!tenant && isOwner))) {
      return (
        <Tenants
          tenants={tenants}
          isOwner={isOwner}
          onChanged={() => void loadTenants()}
          onOpenJob={(tid, jid) => go(`t/${tid}/jobs/${jid}`)}
        />
      );
    }
    if (!tenant) return <p>You do not have access to any tenant yet.</p>;
    if (page === "dashboard") return <Dashboard key={tenant.id} tenant={tenant} />;
    if (page === "setup") {
      return (
        <TenantSetup
          key={tenant.id}
          tenant={tenant}
          isOwner={isOwner}
          onChanged={() => void loadTenants()}
          onCreated={(id) => go(`t/${id}/setup`)}
        />
      );
    }
    if (page === "jobs" && arg) {
      return (
        <JobDetail
          key={`${tenant.id}/${arg}`}
          tenantId={tenant.id}
          jobId={arg}
          canOperate={canOperate}
        />
      );
    }
    if (page === "jobs") return <Jobs key={tenant.id} tenantId={tenant.id} />;
    if (page === "audit") return <AuditLog key={tenant.id} tenantId={tenant.id} isOwner={isOwner} />;
    if (canOperate) {
      return (
        <OffboardForm
          key={tenant.id}
          tenantId={tenant.id}
          onCreated={(id) => go(`t/${tenant.id}/jobs/${id}`)}
        />
      );
    }
    return <Jobs key={tenant.id} tenantId={tenant.id} />;
  }

  return (
    <>
      <header className="header">
        <h1>GAMUT</h1>
        {me ? (
          <>
            <nav>
              {activeId ? <a href={`#/t/${activeId}/dashboard`}>Dashboard</a> : null}
              <a href={activeId ? `#/t/${activeId}` : "#/"}>Offboard</a>
              <a href={activeId ? `#/t/${activeId}/jobs` : "#/jobs"}>Jobs</a>
              <a href={activeId ? `#/t/${activeId}/audit` : "#/audit"}>Audit log</a>
              <a href="#/tenants">Tenants</a>
              {isOwner ? <a href="#/users">Users</a> : null}
            </nav>
            <TenantSwitcher
              tenants={tenants}
              value={routeKnown ? route.tenant : tenantId}
              onChange={switchTenant}
            />
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
