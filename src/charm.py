#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module defining the Charmed operator for the FINOS Legend SDLC Server."""

import logging

import yaml
from charms.finos_legend_libs.v0 import legend_operator_base
from ops import charm, main, model

logger = logging.getLogger(__name__)

SDLC_SERVICE_NAME = "sdlc"
SDLC_CONTAINER_NAME = "sdlc"
LEGEND_DB_RELATION_NAME = "legend-db"
LEGEND_GITLAB_RELATION_NAME = "legend-sdlc-gitlab"
LEGEND_STUDIO_RELATION_NAME = "legend-sdlc"

SDLC_SERVICE_URL_FORMAT = "%(schema)s://%(host)s:%(port)s%(path)s"
SDLC_CONFIG_FILE_CONTAINER_LOCAL_PATH = "/sdlc-config.yaml"
SDLC_MAIN_GITLAB_REDIRECT_URL = "%(base_url)s/auth/callback"
SDLC_GITLAB_REDIRECT_URI_FORMATS = [
    SDLC_MAIN_GITLAB_REDIRECT_URL,
    "%(base_url)s/pac4j/login/callback",
]

TRUSTSTORE_PASSPHRASE = "Legend SDLC"
TRUSTSTORE_CONTAINER_LOCAL_PATH = "/truststore.jks"

APPLICATION_CONNECTOR_PORT_HTTP = 7070
APPLICATION_ADMIN_CONNECTOR_PORT_HTTP = 7076
APPLICATION_ROOT_PATH = "/api"

APPLICATION_LOGGING_FORMAT = "%d{yyyy-MM-dd HH:mm:ss.SSS} %-5p [%thread] %c - %m%n"

GITLAB_PROJECT_VISIBILITY_PUBLIC = "public"
GITLAB_PROJECT_VISIBILITY_PRIVATE = "private"
GITLAB_REQUIRED_SCOPES = ["openid", "profile", "api"]


class LegendSDLCServerCharm(legend_operator_base.BaseFinosLegendCoreServiceCharm):
    """Charmed operator for the FINOS Legend SDLC Server."""

    def __init__(self, *args):
        super().__init__(*args)

        # Studio relation events:
        self.framework.observe(
            self.on[LEGEND_STUDIO_RELATION_NAME].relation_joined, self._on_studio_relation_joined
        )
        self.framework.observe(
            self.on[LEGEND_STUDIO_RELATION_NAME].relation_changed, self._on_studio_relation_changed
        )

    @classmethod
    def _get_application_connector_port(cls):
        return APPLICATION_CONNECTOR_PORT_HTTP

    @classmethod
    def _get_workload_container_name(cls):
        return SDLC_CONTAINER_NAME

    @classmethod
    def _get_workload_service_names(cls):
        return [SDLC_SERVICE_NAME]

    @classmethod
    def _get_workload_pebble_layers(cls):
        return {
            "sdlc": {
                "summary": "SDLC layer.",
                "description": "Pebble config layer for FINOS Legend SDLC.",
                "services": {
                    "sdlc": {
                        "override": "replace",
                        "summary": "sdlc",
                        "command": (
                            # NOTE(aznashwan): starting through bash is needed
                            # for the classpath glob (-cp ...) to be expanded:
                            "/bin/sh -c 'java -XX:+ExitOnOutOfMemoryError "
                            "-XX:MaxRAMPercentage=60 -Xss4M -cp /app/bin/*.jar"
                            " -Dfile.encoding=UTF8 "
                            '-Djavax.net.ssl.trustStore="%s" '
                            '-Djavax.net.ssl.trustStorePassword="%s" '
                            "org.finos.legend.sdlc.server.LegendSDLCServer "
                            'server "%s"\''
                            % (
                                TRUSTSTORE_CONTAINER_LOCAL_PATH,
                                TRUSTSTORE_PASSPHRASE,
                                SDLC_CONFIG_FILE_CONTAINER_LOCAL_PATH,
                            )
                        ),
                        # NOTE(aznashwan): considering the SDLC service expects
                        # a singular config file which already contains all
                        # relevant options in it (some of which will require
                        # the relation with DB/Gitlab to have already been
                        # established), we do not auto-start:
                        "startup": "disabled",
                        # TODO(aznashwan): determine any env vars we could pass
                        # (most notably, things like the RAM percentage etc...)
                        "environment": {},
                    }
                },
            }
        }

    def _get_jks_truststore_preferences(self):
        jks_prefs = {
            "truststore_path": TRUSTSTORE_CONTAINER_LOCAL_PATH,
            "truststore_passphrase": TRUSTSTORE_PASSPHRASE,
            "trusted_certificates": {},
        }
        cert = self._get_legend_gitlab_certificate()
        if cert:
            # NOTE(aznashwan): cert label 'gitlab-sdlc' is arbitrary:
            jks_prefs["trusted_certificates"]["gitlab-sdlc"] = cert
        return jks_prefs

    @classmethod
    def _get_legend_gitlab_relation_name(cls):
        return LEGEND_GITLAB_RELATION_NAME

    @classmethod
    def _get_legend_db_relation_name(cls):
        return LEGEND_DB_RELATION_NAME

    def _get_sdlc_service_url(self):
        ip_address = legend_operator_base.get_ip_address()
        return SDLC_SERVICE_URL_FORMAT % (
            {
                # NOTE(aznashwan): we always return the plain HTTP endpoint:
                "schema": "http",
                "host": ip_address,
                "port": APPLICATION_CONNECTOR_PORT_HTTP,
                "path": APPLICATION_ROOT_PATH,
            }
        )

    def _get_legend_gitlab_redirect_uris(self):
        base_url = self._get_sdlc_service_url()
        redirect_uris = [fmt % {"base_url": base_url} for fmt in SDLC_GITLAB_REDIRECT_URI_FORMATS]
        return redirect_uris

    def _get_core_legend_service_configs(self, legend_db_credentials, legend_gitlab_credentials):
        # Check DB-related options:
        if not legend_db_credentials:
            return model.WaitingStatus("no legend db info present in relation yet")
        legend_db_uri = legend_db_credentials["uri"]
        legend_db = legend_db_credentials["database"]

        # Check gitlab-related options:
        gitlab_project_visibility = GITLAB_PROJECT_VISIBILITY_PRIVATE
        if self.model.config["gitlab-create-new-projects-as-public"]:
            gitlab_project_visibility = GITLAB_PROJECT_VISIBILITY_PUBLIC

        if not legend_gitlab_credentials:
            return model.WaitingStatus("no legend gitlab info present in relation yet")
        gitlab_client_id = legend_gitlab_credentials["client_id"]
        gitlab_client_secret = legend_gitlab_credentials["client_secret"]
        gitlab_openid_discovery_url = legend_gitlab_credentials["openid_discovery_url"]
        gitlab_project_tag = self.model.config["gitlab-project-tag"]
        gitlab_project_creation_group_pattern = self.model.config[
            "gitlab-project-creation-group-pattern"
        ]

        # Check Java logging options:
        request_logging_level = self._get_logging_level_from_config(
            "server-requests-logging-level"
        )
        server_logging_level = self._get_logging_level_from_config("server-logging-level")
        if not all([server_logging_level, request_logging_level]):
            return model.BlockedStatus(
                "one or more logging config options are improperly formatted "
                "or missing, please review the debug-log for more details"
            )

        # Compile base config:
        sdlc_config = {
            "applicationName": "Legend SDLC",
            "server": {
                "rootPath": APPLICATION_ROOT_PATH,
                "applicationConnectors": [
                    {
                        "type": legend_operator_base.APPLICATION_CONNECTOR_TYPE_HTTP,
                        "port": APPLICATION_CONNECTOR_PORT_HTTP,
                        "maxRequestHeaderSize": "128KiB",
                    }
                ],
                "adminConnectors": [
                    {
                        "type": legend_operator_base.APPLICATION_CONNECTOR_TYPE_HTTP,
                        "port": APPLICATION_ADMIN_CONNECTOR_PORT_HTTP,
                    }
                ],
                "gzip": {"includedMethods": ["GET", "POST"]},
                "requestLog": {
                    "type": "classic",
                    "level": request_logging_level,
                    "appenders": [{"type": "console", "logFormat": "OFF"}],
                },
            },
            "filterPriorities": {
                "GitLab": 1,
                "org.pac4j.j2e.filter.CallbackFilter": 2,
                "org.pac4j.j2e.filter.SecurityFilter": 3,
                "CORS": 4,
            },
            "pac4j": {
                "callbackPrefix": "/api/pac4j/login",
                "mongoUri": legend_db_uri,
                "mongoDb": legend_db,
                "clients": [
                    {
                        "org.finos.legend.server.pac4j.gitlab.GitlabClient": {
                            "name": "gitlab",
                            "clientId": gitlab_client_id,
                            "secret": gitlab_client_secret,
                            "discoveryUri": gitlab_openid_discovery_url,
                            # NOTE(aznashwan): needs to be a space-separated str:
                            "scope": " ".join(GITLAB_REQUIRED_SCOPES),
                        }
                    }
                ],
                "mongoSession": {"enabled": True, "collection": "userSessions"},
                "bypassPaths": ["/api/info"],
            },
            "gitLab": {
                "newProjectVisibility": gitlab_project_visibility,
                "projectTag": gitlab_project_tag,
                "uat": {
                    "server": {
                        "scheme": legend_gitlab_credentials["gitlab_scheme"],
                        "host": "%s:%s"
                        % (
                            legend_gitlab_credentials["gitlab_host"],
                            legend_gitlab_credentials["gitlab_port"],
                        ),
                    },
                    "app": {
                        "id": gitlab_client_id,
                        "secret": gitlab_client_secret,
                        "redirectURI": (
                            SDLC_MAIN_GITLAB_REDIRECT_URL
                            % {"base_url": self._get_sdlc_service_url()}
                        ),
                    },
                },
            },
            "projectStructure": {
                "projectCreation": {"groupIdPattern": gitlab_project_creation_group_pattern},
                "extensionProvider": {
                    "org.finos.legend.sdlc.server.gitlab.finos."
                    "FinosGitlabProjectStructureExtensionProvider": {}
                },
            },
            "logging": {
                "level": server_logging_level,
                "appenders": [
                    {
                        "type": "console",
                        "logFormat": APPLICATION_LOGGING_FORMAT,
                    }
                ],
            },
            "swagger": {
                "title": "Legend SDLC",
                "resourcePackage": "org.finos.legend.sdlc.server.resources",
                "version": "local-snapshot",
                "schemes": [],
            },
        }

        return {SDLC_CONFIG_FILE_CONTAINER_LOCAL_PATH: yaml.dump(sdlc_config)}

    def _on_studio_relation_joined(self, event: charm.RelationJoinedEvent) -> None:
        rel = event.relation
        sdlc_url = self._get_sdlc_service_url()
        logger.info("Providing following SDLC URL to Studio: %s", sdlc_url)
        rel.data[self.app]["legend-sdlc-url"] = sdlc_url

    def _on_studio_relation_changed(self, event: charm.RelationChangedEvent) -> None:
        pass


if __name__ == "__main__":
    main.main(LegendSDLCServerCharm)
