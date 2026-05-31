"""
TythanAI Platform — SSO Integration
OAuth2/OIDC: Google, GitHub, Microsoft, Okta, Auth0, any OIDC provider.
SAML2: enterprise identity providers (Okta, Azure AD, OneLogin).

Конфигурация через env vars:
  GHOST_SSO_PROVIDER=google|github|okta|saml
  GHOST_OAUTH_CLIENT_ID=...
  GHOST_OAUTH_CLIENT_SECRET=...
  GHOST_OAUTH_REDIRECT_URI=https://yourdomain.com/auth/callback
  GHOST_SAML_IDP_METADATA_URL=...   (for SAML)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, Optional


# ── OAuth2 provider configs ───────────────────────────────────────────────────

_PROVIDERS: Dict[str, Dict] = {
    "google": {
        "auth_url":    "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url":   "https://oauth2.googleapis.com/token",
        "userinfo_url":"https://www.googleapis.com/oauth2/v3/userinfo",
        "scope":       "openid email profile",
        "email_field": "email",
        "name_field":  "name",
        "id_field":    "sub",
    },
    "github": {
        "auth_url":    "https://github.com/login/oauth/authorize",
        "token_url":   "https://github.com/login/oauth/access_token",
        "userinfo_url":"https://api.github.com/user",
        "emails_url":  "https://api.github.com/user/emails",
        "scope":       "read:user user:email",
        "email_field": "email",
        "name_field":  "name",
        "id_field":    "id",
    },
    "microsoft": {
        "auth_url":    "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
        "token_url":   "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        "userinfo_url":"https://graph.microsoft.com/v1.0/me",
        "scope":       "openid email profile",
        "email_field": "mail",
        "name_field":  "displayName",
        "id_field":    "id",
    },
    "okta": {
        "auth_url":    "{okta_domain}/oauth2/default/v1/authorize",
        "token_url":   "{okta_domain}/oauth2/default/v1/token",
        "userinfo_url":"{okta_domain}/oauth2/default/v1/userinfo",
        "scope":       "openid email profile",
        "email_field": "email",
        "name_field":  "name",
        "id_field":    "sub",
    },
    "auth0": {
        "auth_url":    "https://{auth0_domain}/authorize",
        "token_url":   "https://{auth0_domain}/oauth/token",
        "userinfo_url":"https://{auth0_domain}/userinfo",
        "scope":       "openid email profile",
        "email_field": "email",
        "name_field":  "name",
        "id_field":    "sub",
    },
}


@dataclass
class SSOUser:
    provider:     str
    provider_id:  str
    email:        str
    name:         str
    avatar_url:   str = ""
    raw:          dict = None

    def __post_init__(self):
        if self.raw is None:
            self.raw = {}


class OAuth2Client:
    """
    Generic OAuth2/OIDC client.
    Works with any provider in _PROVIDERS.
    """

    def __init__(
        self,
        provider:      str = "",
        client_id:     str = "",
        client_secret: str = "",
        redirect_uri:  str = "",
        extra_params:  dict = None,
    ) -> None:
        self._provider      = provider or os.getenv("GHOST_SSO_PROVIDER", "github")
        self._client_id     = client_id or os.getenv("GHOST_OAUTH_CLIENT_ID", "")
        self._client_secret = client_secret or os.getenv("GHOST_OAUTH_CLIENT_SECRET", "")
        self._redirect_uri  = redirect_uri or os.getenv("GHOST_OAUTH_REDIRECT_URI", "")
        self._extra         = extra_params or {}
        self._cfg           = dict(_PROVIDERS.get(self._provider, {}))
        # Template substitution for Okta/Microsoft/Auth0
        domain = os.getenv("GHOST_OKTA_DOMAIN","") or os.getenv("GHOST_AUTH0_DOMAIN","")
        tenant = os.getenv("GHOST_MS_TENANT","common")
        for key in self._cfg:
            self._cfg[key] = (
                self._cfg[key]
                .replace("{okta_domain}", domain)
                .replace("{auth0_domain}", domain)
                .replace("{tenant}", tenant)
            )
        self._states: Dict[str, float] = {}  # state → expiry

    def is_configured(self) -> bool:
        return bool(self._client_id and self._client_secret)

    def authorization_url(self, extra_scopes: str = "") -> tuple[str, str]:
        """Generate OAuth2 authorization URL + CSRF state token."""
        state  = secrets.token_urlsafe(32)
        self._states[state] = time.time() + 600  # 10 min expiry

        scope  = self._cfg.get("scope","") + (" " + extra_scopes if extra_scopes else "")
        params = {
            "client_id":     self._client_id,
            "redirect_uri":  self._redirect_uri,
            "response_type": "code",
            "scope":         scope,
            "state":         state,
        }
        params.update(self._extra)
        return self._cfg["auth_url"] + "?" + urllib.parse.urlencode(params), state

    def verify_state(self, state: str) -> bool:
        expiry = self._states.pop(state, 0)
        return time.time() < expiry

    def exchange_code(self, code: str) -> Optional[str]:
        """Exchange authorization code for access token."""
        if not self._cfg.get("token_url"):
            return None
        data = {
            "client_id":     self._client_id,
            "client_secret": self._client_secret,
            "code":          code,
            "redirect_uri":  self._redirect_uri,
            "grant_type":    "authorization_code",
        }
        req = urllib.request.Request(
            self._cfg["token_url"],
            data    = urllib.parse.urlencode(data).encode(),
            headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
            method  = "POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                resp = json.loads(r.read())
            return resp.get("access_token")
        except Exception:
            return None

    def get_user(self, access_token: str) -> Optional[SSOUser]:
        """Fetch user info from provider using access token."""
        url = self._cfg.get("userinfo_url","")
        if not url:
            return None
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {access_token}",
            "User-Agent":    "GhostSecurity/3.0",
            "Accept":        "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
        except Exception:
            return None

        email = data.get(self._cfg.get("email_field","email"),"")

        # GitHub: email may be in separate /user/emails endpoint
        if not email and self._provider == "github" and self._cfg.get("emails_url"):
            email = self._fetch_github_email(access_token)

        if not email:
            return None

        return SSOUser(
            provider    = self._provider,
            provider_id = str(data.get(self._cfg.get("id_field","id"),"")),
            email       = email,
            name        = data.get(self._cfg.get("name_field","name"),"") or email.split("@")[0],
            avatar_url  = data.get("avatar_url", data.get("picture","")),
            raw         = data,
        )

    def _fetch_github_email(self, token: str) -> str:
        req = urllib.request.Request(
            self._cfg.get("emails_url","https://api.github.com/user/emails"),
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                emails = json.loads(r.read())
            # Prefer primary, verified email
            for e in emails:
                if e.get("primary") and e.get("verified"):
                    return e["email"]
            return emails[0]["email"] if emails else ""
        except Exception:
            return ""

    def full_flow(self, code: str, state: str) -> Optional[SSOUser]:
        """Complete OAuth2 flow: verify state → exchange code → get user."""
        if not self.verify_state(state):
            return None
        token = self.exchange_code(code)
        if not token:
            return None
        return self.get_user(token)

    def status(self) -> dict:
        return {
            "provider":    self._provider,
            "configured":  self.is_configured(),
            "redirect_uri": self._redirect_uri,
            "supported_providers": list(_PROVIDERS.keys()),
        }


# ── SAML2 (enterprise) ────────────────────────────────────────────────────────

class SAML2Client:
    """
    Basic SAML2 SP (Service Provider) implementation.
    Works with Okta, Azure AD, OneLogin, Ping Identity.

    Full SAML2 requires python3-saml or pysaml2.
    This class handles configuration and provides the integration
    hooks; install python3-saml for production use.
    """

    def __init__(self) -> None:
        self._idp_metadata_url = os.getenv("GHOST_SAML_IDP_METADATA_URL","")
        self._sp_entity_id     = os.getenv("GHOST_SAML_SP_ENTITY_ID","")
        self._sp_acs_url       = os.getenv("GHOST_SAML_ACS_URL","")
        self._cert_path        = os.getenv("GHOST_SAML_CERT_PATH","")
        self._key_path         = os.getenv("GHOST_SAML_KEY_PATH","")

    def is_configured(self) -> bool:
        return bool(self._idp_metadata_url and self._sp_entity_id)

    def saml_settings(self) -> dict:
        """Returns python3-saml settings dict."""
        return {
            "sp": {
                "entityId":    self._sp_entity_id,
                "assertionConsumerService": {
                    "url":     self._sp_acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "x509cert":   self._cert_path,
                "privateKey": self._key_path,
            },
            "idp": {
                "entityId":           self._idp_metadata_url,
                "singleSignOnService": {
                    "url":     self._idp_metadata_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
            },
            "security": {
                "authnRequestsSigned":     True,
                "wantAssertionsSigned":    True,
                "wantMessagesSigned":      True,
                "requestedAuthnContext":   False,
            },
        }

    def initiate_login(self) -> Optional[str]:
        """Returns SSO redirect URL (requires python3-saml)."""
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth
            auth = OneLogin_Saml2_Auth({}, self.saml_settings())
            return auth.login()
        except ImportError:
            return None

    def process_response(self, request_data: dict) -> Optional[SSOUser]:
        """Process SAML response (requires python3-saml)."""
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth
            auth = OneLogin_Saml2_Auth(request_data, self.saml_settings())
            auth.process_response()
            if auth.is_authenticated():
                attrs = auth.get_attributes()
                email = attrs.get("email",[""])[0] or attrs.get("emailAddress",[""])[0]
                name  = attrs.get("displayName",[""])[0] or attrs.get("firstName",[""])[0]
                return SSOUser(
                    provider    = "saml",
                    provider_id = auth.get_nameid(),
                    email       = email,
                    name        = name,
                )
        except Exception:
            pass
        return None

    def status(self) -> dict:
        saml_available = False
        try:
            import onelogin.saml2  # type: ignore
            saml_available = True
        except ImportError:
            pass
        return {
            "configured":      self.is_configured(),
            "saml_lib":        saml_available,
            "install_hint":    "pip install python3-saml" if not saml_available else "",
            "idp_metadata_url": self._idp_metadata_url,
        }


# ── SSO Manager ───────────────────────────────────────────────────────────────

class SSOManager:
    """
    Single entry point for all SSO operations.
    Auto-selects OAuth2 vs SAML based on configuration.
    """

    def __init__(self) -> None:
        self._oauth = OAuth2Client()
        self._saml  = SAML2Client()

    def active_provider(self) -> str:
        provider = os.getenv("GHOST_SSO_PROVIDER","")
        if provider == "saml":
            return "saml"
        return provider or "none"

    def is_enabled(self) -> bool:
        p = self.active_provider()
        if p == "saml":
            return self._saml.is_configured()
        return p != "none" and self._oauth.is_configured()

    def authorization_url(self) -> tuple[str, str]:
        return self._oauth.authorization_url()

    def handle_callback(self, code: str, state: str) -> Optional[SSOUser]:
        return self._oauth.full_flow(code, state)

    def status(self) -> dict:
        return {
            "enabled":   self.is_enabled(),
            "provider":  self.active_provider(),
            "oauth":     self._oauth.status(),
            "saml":      self._saml.status(),
        }


SSO = SSOManager()
