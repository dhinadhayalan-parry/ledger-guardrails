#!/usr/bin/env python3
"""Minimal mock of the Azure endpoints azurerm needs to *plan* without a tenant.

The azurerm provider only needs two things to produce a plan with
`-refresh=false` and no prior state:

  1. the cloud metadata document (GET /metadata/endpoints), and
  2. an OAuth2 client-credentials token whose claims it can parse.

Neither the token nor the tenant is real. Any other request gets a 501 so an
unexpected API call during planning fails loudly instead of silently
producing a misleading plan.

This exists so every pull request, including from forks without access to
cloud credentials, gets the policy gate evaluated against a real
`terraform plan` of the real code. It is a fast-feedback check only. The
authoritative gate is the OIDC plan against the real subscription.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import ssl
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOG = logging.getLogger("mock_arm")

# Fixed, obviously fake identifiers. They appear in the generated plan JSON
# (for example as tenant_id), which makes an offline plan easy to recognise.
TENANT_ID = "11111111-1111-1111-1111-111111111111"
OBJECT_ID = "22222222-2222-2222-2222-222222222222"
CLIENT_ID = "33333333-3333-3333-3333-333333333333"
SUBSCRIPTION_ID = "44444444-4444-4444-4444-444444444444"


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unsigned_jwt(audience: str) -> str:
    now = int(time.time())
    header = {"alg": "none", "typ": "JWT"}
    claims = {
        "aud": audience,
        "iss": f"https://sts.windows.net/{TENANT_ID}/",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "oid": OBJECT_ID,
        "sub": OBJECT_ID,
        "tid": TENANT_ID,
        "appid": CLIENT_ID,
        "idtyp": "app",
    }
    return f"{_b64url(header)}.{_b64url(claims)}.mock"


def metadata(base_url: str) -> dict:
    return {
        "name": "AzureCloud",
        "resourceManager": f"{base_url}/",
        "microsoftGraphResourceId": f"{base_url}/",
        "graph": f"{base_url}/",
        "authentication": {
            "loginEndpoint": base_url,
            "audiences": [
                "https://management.core.windows.net/",
                "https://management.azure.com/",
            ],
            "tenant": "common",
            "identityProvider": "AAD",
        },
        "suffixes": {
            "storage": "core.windows.net",
            "keyVaultDns": "vault.azure.net",
            "mhsmDns": "managedhsm.azure.net",
            "acrLoginServer": "azurecr.io",
            "sqlServerHostname": "database.windows.net",
            "postgresqlServerEndpoint": "postgres.database.azure.com",
            "mysqlServerEndpoint": "mysql.database.azure.com",
            "mariadbServerEndpoint": "mariadb.database.azure.com",
            "storageSyncEndpointSuffix": "afs.azure.net",
            "attestationEndpoint": "attest.azure.net",
            "synapseAnalytics": "dev.azuresynapse.net",
            "azureDatalakeStoreFileSystem": "azuredatalakestore.net",
            "azureDatalakeAnalyticsCatalogAndJob": "azuredatalakeanalytics.net",
        },
    }


def make_handler(base_url: str) -> type[BaseHTTPRequestHandler]:
    meta = metadata(base_url)

    class Handler(BaseHTTPRequestHandler):
        server_version = "mock-arm/1.0"

        def _send(self, status: int, body: dict) -> None:
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _unexpected(self) -> None:
            LOG.error("unexpected request %s %s", self.command, self.path)
            self._send(501, {"error": {"code": "MockNotImplemented", "message": f"mock_arm: {self.command} {self.path}"}})

        def do_GET(self) -> None:  # noqa: N802 (http.server naming)
            if self.path.startswith("/metadata/endpoints"):
                LOG.info("metadata served")
                self._send(200, meta)
                return
            self._unexpected()

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            if "/oauth2/" in self.path and form.get("grant_type") == ["client_credentials"]:
                scope = form.get("scope", [f"{base_url}/.default"])[0]
                audience = scope.removesuffix("/.default")
                LOG.info("token issued for audience %s", audience)
                self._send(200, {
                    "token_type": "Bearer",
                    "expires_in": 3599,
                    "ext_expires_in": 3599,
                    "access_token": unsigned_jwt(audience),
                })
                return
            self._unexpected()

        def do_PUT(self) -> None:  # noqa: N802
            self._unexpected()

        def do_PATCH(self) -> None:  # noqa: N802
            self._unexpected()

        def do_DELETE(self) -> None:  # noqa: N802
            self._unexpected()

        def log_message(self, fmt: str, *args: object) -> None:
            LOG.debug(fmt, *args)

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", type=Path, required=True, help="PEM certificate for localhost")
    parser.add_argument("--key", type=Path, required=True, help="PEM private key")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    for path in (args.cert, args.key):
        if not path.is_file():
            parser.error(f"{path} does not exist")
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")

    base_url = f"https://localhost:{args.port}"
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(base_url))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(args.cert), keyfile=str(args.key))
    server.socket = context.wrap_socket(server.socket, server_side=True)

    LOG.info("listening on %s", base_url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
