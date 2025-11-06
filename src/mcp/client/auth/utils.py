import re
from urllib.parse import urljoin, urlparse

from httpx import Response

from mcp.shared.auth import ProtectedResourceMetadata


def extract_field_from_www_auth(response: Response, field_name: str) -> str | None:
    """
    Extract field from WWW-Authenticate header.

    Returns:
        Field value if found in WWW-Authenticate header, None otherwise
    """
    www_auth_header = response.headers.get("WWW-Authenticate")
    if not www_auth_header:
        return None

    # Pattern matches: field_name="value" or field_name=value (unquoted)
    pattern = rf'{field_name}=(?:"([^"]+)"|([^\s,]+))'
    match = re.search(pattern, www_auth_header)

    if match:
        # Return quoted value if present, otherwise unquoted value
        return match.group(1) or match.group(2)

    return None


def extract_scope_from_www_auth(response: Response) -> str | None:
    """
    Extract scope parameter from WWW-Authenticate header as per RFC6750.

    Returns:
        Scope string if found in WWW-Authenticate header, None otherwise
    """
    return extract_field_from_www_auth(response, "scope")


def extract_resource_metadata_from_www_auth(response: Response) -> str | None:
    """
    Extract protected resource metadata URL from WWW-Authenticate header as per RFC9728.

    Returns:
        Resource metadata URL if found in WWW-Authenticate header, None otherwise
    """
    if not response or response.status_code != 401:
        return None

    return extract_field_from_www_auth(response, "resource_metadata")


def build_protected_resource_discovery_urls(www_auth_url: str | None, server_url: str) -> list[str]:
    """
    Build ordered list of URLs to try for protected resource metadata discovery.

    Per SEP-985, the client MUST:
    1. Try resource_metadata from WWW-Authenticate header (if present)
    2. Fall back to path-based well-known URI: /.well-known/oauth-protected-resource/{path}
    3. Fall back to root-based well-known URI: /.well-known/oauth-protected-resource

    Args:
        www_auth_url: optional resource_metadata url extracted from the WWW-Authenticate header
        server_url: server url

    Returns:
        Ordered list of URLs to try for discovery
    """
    urls: list[str] = []

    # Priority 1: WWW-Authenticate header with resource_metadata parameter
    if www_auth_url:
        urls.append(www_auth_url)

    # Priority 2-3: Well-known URIs (RFC 9728)
    parsed = urlparse(server_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Priority 2: Path-based well-known URI (if server has a path component)
    if parsed.path and parsed.path != "/":
        path_based_url = urljoin(base_url, f"/.well-known/oauth-protected-resource{parsed.path}")
        urls.append(path_based_url)

    # Priority 3: Root-based well-known URI
    root_based_url = urljoin(base_url, "/.well-known/oauth-protected-resource")
    urls.append(root_based_url)

    return urls


def get_client_metadata_scopes(
    www_authenticate_scope: str | None, protected_resource_metadata: ProtectedResourceMetadata | None
) -> str | None:
    """Select scopes as outlined in the 'Scope Selection Strategy' in the MCP spec."""
    # Per MCP spec, scope selection priority order:
    # 1. Use scope from WWW-Authenticate header (if provided)
    # 2. Use all scopes from PRM scopes_supported (if available)
    # 3. Omit scope parameter if neither is available

    if www_authenticate_scope is not None:
        # Priority 1: WWW-Authenticate header scope
        return www_authenticate_scope
    elif protected_resource_metadata is not None and protected_resource_metadata.scopes_supported is not None:
        # Priority 2: PRM scopes_supported
        return " ".join(protected_resource_metadata.scopes_supported)
    else:
        # Priority 3: Omit scope parameter
        return None


def get_discovery_urls(auth_server_url: str) -> list[str]:
    """Generate ordered list of (url, type) tuples for discovery attempts."""
    urls: list[str] = []
    parsed = urlparse(auth_server_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # RFC 8414: Path-aware OAuth discovery
    if parsed.path and parsed.path != "/":
        oauth_path = f"/.well-known/oauth-authorization-server{parsed.path.rstrip('/')}"
        urls.append(urljoin(base_url, oauth_path))

    # OAuth root fallback
    urls.append(urljoin(base_url, "/.well-known/oauth-authorization-server"))

    # RFC 8414 section 5: Path-aware OIDC discovery
    # See https://www.rfc-editor.org/rfc/rfc8414.html#section-5
    if parsed.path and parsed.path != "/":
        oidc_path = f"/.well-known/openid-configuration{parsed.path.rstrip('/')}"
        urls.append(urljoin(base_url, oidc_path))

    # OIDC 1.0 fallback (appends to full URL per OIDC spec)
    oidc_fallback = f"{auth_server_url.rstrip('/')}/.well-known/openid-configuration"
    urls.append(oidc_fallback)

    return urls
