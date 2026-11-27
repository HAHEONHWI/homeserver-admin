import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _validate_health_origin(value: str, name: str, service_host: str, service_port: int) -> None:
    if not value:
        return
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"{name} must use HTTPS or its internal service URL") from error
    internal_http = (
        parsed.scheme == "http" and parsed.hostname == service_host and port == service_port
    )
    if (
        parsed.scheme != "https"
        and not internal_http
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{name} must use HTTPS or its internal service URL")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    app_env: str = "development"
    app_mode: str = "mock"
    app_data_dir: Path = Path("./.data")
    audit_retention_days: int = Field(default=365, ge=1, le=3650)
    web_origin: str = ""
    webauthn_bootstrap_token: SecretStr = SecretStr("")
    cf_access_issuer: str = ""
    cf_access_aud: str = ""
    cf_access_jwks_url: str = ""
    owner_emails: str = ""
    operator_emails: str = ""
    host_agent_url: str = ""
    host_agent_token: SecretStr = SecretStr("")
    n8n_url: str = ""
    n8n_api_key: SecretStr = SecretStr("")
    openclaw_url: str = ""
    netdata_url: str = ""
    netdata_api_token: SecretStr = SecretStr("")
    scrutiny_url: str = ""
    portainer_url: str = ""
    portainer_api_key: SecretStr = SecretStr("")
    portainer_actions_api_key: SecretStr = SecretStr("")
    portainer_endpoint_id: int = Field(default=0, ge=0)
    mailcow_url: str = ""
    mailcow_api_key: SecretStr = SecretStr("")
    postgres_url: SecretStr = SecretStr("")
    redis_url: SecretStr = SecretStr("")
    ntfy_url: str = ""
    ntfy_topic: str = ""
    ntfy_token: SecretStr = SecretStr("")
    github_api_token: SecretStr = SecretStr("")
    github_repositories: str = ""
    cloudflare_api_token: SecretStr = SecretStr("")
    cloudflare_dns_write_token: SecretStr = SecretStr("")
    cloudflare_zone_id: str = ""
    cloudflare_zone_name: str = ""

    @model_validator(mode="after")
    def validate_security_mode(self):
        if self.app_env not in {"development", "production"}:
            raise ValueError("APP_ENV must be development or production")
        if self.app_mode not in {"mock", "live"}:
            raise ValueError("APP_MODE must be mock or live")
        if self.app_mode == "mock" and self.app_env != "development":
            raise ValueError("Mock mode is allowed only in development")
        if self.web_origin:
            web_origin = urlsplit(self.web_origin)
            try:
                origin_port = web_origin.port
            except ValueError as error:
                raise ValueError("WEB_ORIGIN must be an HTTPS origin or localhost") from error
            local_http = web_origin.scheme == "http" and web_origin.hostname in {
                "localhost",
                "127.0.0.1",
                "::1",
            }
            if (
                web_origin.scheme != "https"
                and not local_http
                or not web_origin.hostname
                or not web_origin.hostname.isascii()
                or web_origin.hostname.endswith(".")
                or web_origin.netloc != web_origin.netloc.lower()
                or origin_port == (443 if web_origin.scheme == "https" else 80)
                or web_origin.username
                or web_origin.password
                or web_origin.path not in {"", "/"}
                or web_origin.query
                or web_origin.fragment
            ):
                raise ValueError("WEB_ORIGIN must be an HTTPS origin or localhost")
            if self.web_origin != f"{web_origin.scheme}://{web_origin.netloc}":
                raise ValueError("WEB_ORIGIN must not contain a path or trailing slash")
        bootstrap_token = self.webauthn_bootstrap_token.get_secret_value()
        if bootstrap_token and not re.fullmatch(r"[0-9a-f]{64}", bootstrap_token):
            raise ValueError("WEBAUTHN_BOOTSTRAP_TOKEN must be 32 random bytes encoded as lowercase hex")
        token = self.host_agent_token.get_secret_value()
        if bool(self.host_agent_url) != bool(token):
            raise ValueError("HOST_AGENT_URL and HOST_AGENT_TOKEN must be configured together")
        if self.host_agent_url:
            agent = urlsplit(self.host_agent_url)
            if (
                agent.scheme != "http"
                or agent.hostname != "agent"
                or agent.port != 9000
                or agent.path != "/v1/metrics"
                or agent.username
                or agent.password
                or agent.query
                or agent.fragment
            ):
                raise ValueError("HOST_AGENT_URL must target the internal read-only agent")
            if not re.fullmatch(r"[0-9a-f]{64}", token):
                raise ValueError(
                    "HOST_AGENT_TOKEN must be 32 random bytes encoded as lowercase hex"
                )
        _validate_health_origin(self.n8n_url, "N8N_URL", "n8n", 5678)
        _validate_health_origin(self.openclaw_url, "OPENCLAW_URL", "openclaw", 18789)
        _validate_health_origin(self.netdata_url, "NETDATA_URL", "netdata", 19999)
        _validate_health_origin(self.scrutiny_url, "SCRUTINY_URL", "scrutiny", 8080)
        n8n_api_key = self.n8n_api_key.get_secret_value()
        if n8n_api_key and not self.n8n_url:
            raise ValueError("N8N_API_KEY requires N8N_URL")
        if n8n_api_key and (
            len(n8n_api_key) < 16
            or len(n8n_api_key) > 512
            or not n8n_api_key.isascii()
            or not n8n_api_key.isprintable()
            or any(char.isspace() for char in n8n_api_key)
        ):
            raise ValueError("N8N_API_KEY is invalid")
        netdata_token = self.netdata_api_token.get_secret_value()
        if netdata_token and not self.netdata_url:
            raise ValueError("NETDATA_API_TOKEN requires NETDATA_URL")
        if netdata_token and (
            len(netdata_token) < 16
            or len(netdata_token) > 512
            or not netdata_token.isascii()
            or not netdata_token.isprintable()
            or any(char.isspace() for char in netdata_token)
        ):
            raise ValueError("NETDATA_API_TOKEN is invalid")
        portainer_key = self.portainer_api_key.get_secret_value()
        portainer_actions_key = self.portainer_actions_api_key.get_secret_value()
        if bool(self.portainer_url) != bool(portainer_key):
            raise ValueError("PORTAINER_URL and PORTAINER_API_KEY must be configured together")
        if portainer_actions_key and not self.portainer_url:
            raise ValueError("PORTAINER_ACTIONS_API_KEY requires PORTAINER_URL")
        if portainer_actions_key and (
            len(portainer_actions_key) < 16
            or len(portainer_actions_key) > 512
            or not portainer_actions_key.isascii()
            or not portainer_actions_key.isprintable()
            or any(char.isspace() for char in portainer_actions_key)
        ):
            raise ValueError("PORTAINER_ACTIONS_API_KEY is invalid")
        if bool(self.portainer_url) != (self.portainer_endpoint_id > 0):
            raise ValueError("Portainer URL, API key, and endpoint ID must be configured together")
        if self.portainer_url:
            portainer = urlsplit(self.portainer_url)
            internal_http = (
                portainer.scheme == "http"
                and portainer.hostname == "portainer"
                and portainer.port == 9000
            )
            if (
                portainer.scheme != "https"
                and not internal_http
                or not portainer.hostname
                or portainer.username
                or portainer.password
                or portainer.path not in {"", "/"}
                or portainer.query
                or portainer.fragment
            ):
                raise ValueError(
                    "PORTAINER_URL must use HTTPS or the internal Portainer HTTP service"
                )
            if len(portainer_key) < 16:
                raise ValueError("PORTAINER_API_KEY is too short")
        mailcow_key = self.mailcow_api_key.get_secret_value()
        if bool(self.mailcow_url) != bool(mailcow_key):
            raise ValueError("MAILCOW_URL and MAILCOW_API_KEY must be configured together")
        if self.mailcow_url:
            mailcow = urlsplit(self.mailcow_url)
            if (
                mailcow.scheme != "https"
                or not mailcow.hostname
                or mailcow.username
                or mailcow.password
                or mailcow.path not in {"", "/"}
                or mailcow.query
                or mailcow.fragment
            ):
                raise ValueError("MAILCOW_URL must be an HTTPS origin")
            if (
                len(mailcow_key) < 16
                or len(mailcow_key) > 512
                or not mailcow_key.isascii()
                or not mailcow_key.isprintable()
                or any(char.isspace() for char in mailcow_key)
            ):
                raise ValueError("MAILCOW_API_KEY is invalid")
        postgres_url = self.postgres_url.get_secret_value()
        if postgres_url:
            try:
                postgres = urlsplit(postgres_url)
                _ = postgres.port
                postgres_options = [
                    (key.lower(), value)
                    for key, value in parse_qsl(
                        postgres.query, keep_blank_values=True, strict_parsing=True
                    )
                ]
            except ValueError as error:
                raise ValueError("POSTGRES_URL must be a valid PostgreSQL connection URL") from error
            if (
                postgres.scheme not in {"postgres", "postgresql"}
                or not postgres.hostname
                or postgres.fragment
            ):
                raise ValueError("POSTGRES_URL must be a PostgreSQL connection URL")
            sslmodes = [value for key, value in postgres_options if key == "sslmode"]
            if sslmodes != ["verify-full"] or any(
                key in {"service", "servicefile", "ssl", "requiressl"}
                for key, _ in postgres_options
            ):
                raise ValueError("POSTGRES_URL must set sslmode=verify-full")
        redis_url = self.redis_url.get_secret_value()
        if redis_url:
            redis = urlsplit(redis_url)
            if (
                redis.scheme not in {"redis", "rediss"}
                or not redis.hostname
                or redis.query
                or redis.fragment
                or redis.path not in {"", "/"}
                and not re.fullmatch(r"/(?:0|[1-9][0-9]{0,3})", redis.path)
            ):
                raise ValueError("REDIS_URL must be a Redis connection URL without options")
            if redis.scheme == "redis" and redis.hostname not in {
                "redis",
                "localhost",
                "127.0.0.1",
                "::1",
            }:
                raise ValueError("REDIS_URL must use rediss:// for remote hosts")
        ntfy_token = self.ntfy_token.get_secret_value()
        if bool(self.ntfy_url) != bool(self.ntfy_topic) or (ntfy_token and not self.ntfy_url):
            raise ValueError("NTFY_URL and NTFY_TOPIC must be configured together")
        if self.ntfy_url:
            ntfy = urlsplit(self.ntfy_url)
            internal_http = ntfy.scheme == "http" and ntfy.hostname == "ntfy" and ntfy.port == 80
            if (
                ntfy.scheme != "https"
                and not internal_http
                or not ntfy.hostname
                or ntfy.username
                or ntfy.password
                or ntfy.path not in {"", "/"}
                or ntfy.query
                or ntfy.fragment
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.ntfy_topic)
            ):
                raise ValueError("NTFY_URL must be HTTPS or the internal ntfy service")
            if ntfy_token and (
                len(ntfy_token) < 16
                or len(ntfy_token) > 512
                or not ntfy_token.isascii()
                or not ntfy_token.isprintable()
                or any(char.isspace() for char in ntfy_token)
            ):
                raise ValueError("NTFY_TOKEN is invalid")
        github_token = self.github_api_token.get_secret_value()
        repositories = self.github_repo_list
        if bool(github_token) != bool(self.github_repositories.strip()):
            raise ValueError("GITHUB_API_TOKEN and GITHUB_REPOSITORIES must be configured together")
        if github_token and (
            len(github_token) < 16
            or len(github_token) > 512
            or len(repositories) > 3
            or len(repositories) != len({repo.lower() for repo in repositories})
            or any(
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repo)
                or any(part in {".", ".."} for part in repo.split("/"))
                for repo in repositories
            )
        ):
            raise ValueError("GitHub config requires a token and up to 3 valid owner/repo entries")
        cloudflare_token = self.cloudflare_api_token.get_secret_value()
        cloudflare_write_token = self.cloudflare_dns_write_token.get_secret_value()
        zone_id = self.cloudflare_zone_id.strip()
        if bool(cloudflare_token) != bool(zone_id):
            raise ValueError(
                "CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID must be configured together"
            )
        if cloudflare_token and (
            len(cloudflare_token) < 16
            or len(cloudflare_token) > 512
            or not cloudflare_token.isascii()
            or not cloudflare_token.isprintable()
            or any(char.isspace() for char in cloudflare_token)
            or not re.fullmatch(r"[0-9a-fA-F]{32}", zone_id)
        ):
            raise ValueError("Cloudflare config requires a token and 32-character Zone ID")
        zone_name = self.cloudflare_zone_name.strip().rstrip(".")
        if cloudflare_write_token and not (cloudflare_token and zone_name):
            raise ValueError(
                "CLOUDFLARE_DNS_WRITE_TOKEN requires DNS read config and CLOUDFLARE_ZONE_NAME"
            )
        if cloudflare_write_token and cloudflare_write_token == cloudflare_token:
            raise ValueError("CLOUDFLARE_DNS_WRITE_TOKEN must differ from the DNS read token")
        if cloudflare_write_token and (
            len(cloudflare_write_token) < 16
            or len(cloudflare_write_token) > 512
            or not cloudflare_write_token.isascii()
            or not cloudflare_write_token.isprintable()
            or any(char.isspace() for char in cloudflare_write_token)
            or len(zone_name) > 253
            or not zone_name.isascii()
            or not re.fullmatch(
                r"(?=.{1,253}$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)*"
                r"[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?",
                zone_name,
            )
        ):
            raise ValueError("Cloudflare DNS write config requires a valid token and Zone name")
        if self.cf_access_aud.strip():
            audiences = [part.strip() for part in self.cf_access_aud.split(",")]
            if (
                any(not part for part in audiences)
                or len(audiences) > 4
                or any(not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", part) for part in audiences)
            ):
                raise ValueError(
                    "CF_ACCESS_AUD must list 1 to 4 Access application audience tags"
                )
        if self.app_mode == "live":
            if not self.cf_access_issuer or not self.cf_access_aud:
                raise ValueError("Live mode requires CF_ACCESS_ISSUER and CF_ACCESS_AUD")
            if not self.web_origin:
                raise ValueError("Live mode requires WEB_ORIGIN")
            issuer = urlsplit(self.cf_access_issuer)
            if (
                issuer.scheme != "https"
                or not issuer.netloc
                or issuer.path not in {"", "/"}
                or issuer.query
                or issuer.fragment
            ):
                raise ValueError("CF_ACCESS_ISSUER must be an HTTPS origin")
            if self.cf_access_jwks_url:
                jwks = urlsplit(self.cf_access_jwks_url)
                if (
                    jwks.scheme != "https"
                    or jwks.netloc != issuer.netloc
                    or jwks.path != "/cdn-cgi/access/certs"
                ):
                    raise ValueError("CF_ACCESS_JWKS_URL must use the configured Access issuer")
        return self

    @property
    def access_audiences(self) -> list[str]:
        return [item.strip() for item in self.cf_access_aud.split(",") if item.strip()]

    @property
    def jwks_url(self) -> str:
        return (
            self.cf_access_jwks_url or f"{self.cf_access_issuer.rstrip('/')}/cdn-cgi/access/certs"
        )

    @property
    def github_repo_list(self) -> list[str]:
        return [repo.strip() for repo in self.github_repositories.split(",") if repo.strip()]

    def emails(self, field: str) -> set[str]:
        return {item.strip().lower() for item in getattr(self, field).split(",") if item.strip()}
