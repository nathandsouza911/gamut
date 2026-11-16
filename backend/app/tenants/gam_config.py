# SPDX-License-Identifier: AGPL-3.0-only
"""The gam.cfg settings a tenant needs, written by the worker into each job's directory."""

from app.gam.commands import CustomerId, DomainName, Email, dasa_config
from app.models import AuthMode, Tenant


def config_args_for(tenant: Tenant) -> list[str] | None:
    """`gam config ... save` arguments for a DASA tenant; None for OAuth tenants."""
    if tenant.auth_mode != AuthMode.dasa:
        return None
    if not tenant.admin_email or not tenant.customer_id:
        raise ValueError("set the tenant's admin email and customer ID first")
    return dasa_config(
        Email(tenant.admin_email), CustomerId(tenant.customer_id),
        DomainName(tenant.primary_domain),
    )
