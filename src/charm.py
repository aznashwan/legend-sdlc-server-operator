#!/usr/bin/env python3
# Copyright 2021 Canonical
# See LICENSE file for licensing details.

""" Module defining the Charmed operator for the FINOS Legend SDLC Server. """

import json
import logging
import subprocess

from ops import charm
from ops import framework
from ops import main
from ops import model
import yaml

from charms.nginx_ingress_integrator.v0 import ingress


logger = logging.getLogger(__name__)

SDLC_CONFIG_FILE_CONTAINER_LOCAL_PATH = "/sdlc-config.yaml"
SDLC_SERVICE_URL_FORMAT = "%(schema)s://%(host)s:%(port)s%(path)s"

APPLICATION_CONNECTOR_TYPE_HTTP = "http"
APPLICATION_CONNECTOR_TYPE_HTTPS = "https"
APPLICATION_CONNECTOR_PORT_HTTP = 7070
APPLICATION_ADMIN_CONNECTOR_PORT_HTTP = 7076
APPLICATION_ROOT_PATH = "/api"

APPLICATION_LOGGING_FORMAT = (
    "%d{yyyy-MM-dd HH:mm:ss.SSS} %-5p [%thread] %c - %m%n")
VALID_APPLICATION_LOG_LEVEL_SETTINGS = [
    "INFO", "WARN", "DEBUG", "TRACE", "OFF"]

GITLAB_PROJECT_VISIBILITY_PUBLIC = "public"
GITLAB_PROJECT_VISIBILITY_PRIVATE = "private"
GITLAB_REQUIRED_SCOPES = ["openid", "profile", "api"]
GITLAB_OPENID_DISCOVERY_URL = (
    "https://gitlab.com/.well-known/openid-configuration")


class LegendSDLCServerOperatorCharm(charm.CharmBase):
    """ Charmed operator for the FINOS Legend SDLC Server. """

    _stored = framework.StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self._set_stored_defaults()

        self.ingress = ingress.IngressRequires(
            self,
            {
                "service-hostname": self.app.name,
                "service-name": self.app.name,
                "service-port": APPLICATION_CONNECTOR_PORT_HTTP,
            },
        )

        # Standard charm lifecycle events:
        self.framework.observe(
            self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on.sdlc_pebble_ready, self._on_sdlc_pebble_ready)

        # DB relation lifecycle events:
        self.framework.observe(
            self.on["legend-db"].relation_joined,
            self._on_db_relation_joined)
        self.framework.observe(
            self.on["legend-db"].relation_changed,
            self._on_db_relation_changed)

        # Studio relation events:
        self.framework.observe(
            self.on["legend-sdlc"].relation_joined,
            self._on_studio_relation_joined)
        self.framework.observe(
            self.on["legend-sdlc"].relation_changed,
            self._on_studio_relation_changed)

    def _set_stored_defaults(self) -> None:
        self._stored.set_default(log_level="DEBUG")
        self._stored.set_default(mongodb_credentials={})

    def _on_sdlc_pebble_ready(self, event: framework.EventBase) -> None:
        """Define the SDLC workload using the Pebble API.
        Note that this will *not* start the service, but instead leave it in a
        blocked state until the relevant relations required for it are added.
        """
        # Get a reference the container attribute on the PebbleReadyEvent
        container = event.workload

        # Define an initial Pebble layer configuration
        pebble_layer = {
            "summary": "SDLC layer.",
            "description": "Pebble config layer for FINOS Legend SDLC Server.",
            "services": {
                "sdlc": {
                    "override": "replace",
                    "summary": "sdlc",
                    "command": (
                        # NOTE(aznashwan): starting through bash is required
                        # for the classpath glob (-cp ...) to be expanded:
                        "/bin/sh -c 'java -XX:+ExitOnOutOfMemoryError "
                        "-XX:MaxRAMPercentage=60 -Xss4M -cp /app/bin/*.jar "
                        "-Dfile.encoding=UTF8 "
                        "org.finos.legend.sdlc.server.LegendSDLCServer "
                        "server %s'" % (
                            SDLC_CONFIG_FILE_CONTAINER_LOCAL_PATH)
                    ),
                    # NOTE(aznashwan): considering the SDLC service expects
                    # a singular config file which already contains all
                    # relevant options in it (some of which will require the
                    # relation with DB/Gitlab to have already been
                    # established), we do not auto-start:
                    "startup": "disabled",
                    # TODO(aznashwan): determine any env vars we could pass
                    # (most notably, things like the RAM percentage etc...)
                    "environment": {},
                }
            },
        }

        # Add intial Pebble config layer using the Pebble API
        container.add_layer("sdlc", pebble_layer, combine=True)

        # NOTE(aznashwan): as mentioned above, we will *not* be auto-starting
        # the service until the relations with DBMan and Gitlab are added:
        # container.autostart()

        self.unit.status = model.BlockedStatus(
            "Awaiting Legend Database and Gitlab relations.")

    def _get_logging_level_from_config(self, option_name) -> str:
        """Fetches the config option with the given name and checks to
        ensure that it is a valid `java.utils.logging` log level.

        Returns None if an option is invalid.
        """
        value = self.model.config[option_name]
        if value not in VALID_APPLICATION_LOG_LEVEL_SETTINGS:
            logger.warning(
                "Invalid Java logging level value provided for option "
                "'%s': '%s'. Valid Java logging levels are: %s. The charm "
                "shall block until a proper value is set.",
                option_name, value, VALID_APPLICATION_LOG_LEVEL_SETTINGS)
            return None
        return value

    def _add_base_service_config_from_charm_config(
            self, sdlc_config: dict = {}) -> model.BlockedStatus:
        """This method adds all relevant SDLC config options into the provided
        dict to be directly rendered to YAML and passed to the SDLC container.

        Returns:
            None if all of the config options derived from the config/relations
            are present and have passed Charm-side valiation steps.
            A `model.BlockedStatus` instance with a relevant message otherwise.
        """
        # Check gitlab-related options:
        gitlab_project_visibility = GITLAB_PROJECT_VISIBILITY_PRIVATE
        if self.model.config['gitlab-create-new-projects-as-public']:
            gitlab_project_visibility = GITLAB_PROJECT_VISIBILITY_PUBLIC
        # TODO(aznashwan): remove this check on eventual Gitlab relation:
        gitlab_client_id = self.model.config.get('gitlab-client-id')
        gitlab_client_secret = self.model.config.get('gitlab-client-secret')
        gitlab_project_tag = self.model.config['gitlab-project-tag']
        gitlab_project_creation_group_pattern = (
            self.model.config['gitlab-project-creation-group-pattern'])
        if not all([
                gitlab_project_visibility, gitlab_client_id,
                gitlab_client_secret, gitlab_project_tag,
                gitlab_project_creation_group_pattern]):
            return model.BlockedStatus(
                "One or more Gitlab-related charm configuration options "
                "are missing.")

        # Check Java logging options:
        request_logging_level = self._get_logging_level_from_config(
            "server-requests-logging-level")
        server_logging_level = self._get_logging_level_from_config(
            "server-logging-level")
        if not all([server_logging_level, request_logging_level]):
            return model.BlockedStatus(
                "One or more logging config options are improperly formatted "
                "or missing. Please review the debug-log for more details.")

        # Check Mongo-related options:
        mongo_creds = self._stored.mongodb_credentials
        if not mongo_creds or 'replica_set_uri' not in mongo_creds:
            return model.BlockedStatus(
                "No stored MongoDB credentials were found yet. Please "
                "ensure the Charm is properly related to MongoDB.")
        mongo_replica_set_uri = self._stored.mongodb_credentials[
            'replica_set_uri']
        databases = mongo_creds.get('databases')
        database_name = None
        if databases:
            database_name = databases[0]
            # NOTE(aznashwan): the Java MongoDB can't handle DB names in the
            # URL, so we need to trim that part and pass the database name
            # as a separate parameter within the config as the
            # sdlc_config['pac4j']['mongoDb'] option below.
            split_uri = [
                elem
                for elem in mongo_replica_set_uri.split('/')[:-1]
                # NOTE: filter any empty strings resulting from double-slashes:
                if elem]
            # NOTE: schema prefix needs two slashes added back:
            mongo_replica_set_uri = "%s//%s" % (
                split_uri[0], "/".join(split_uri[1:]))

        # Compile base config:
        sdlc_config.update({
            "applicationName": "Legend SDLC",
            "server": {
                "rootPath": APPLICATION_ROOT_PATH,
                "applicationConnectors": [{
                    "type": APPLICATION_CONNECTOR_TYPE_HTTP,
                    "port": APPLICATION_CONNECTOR_PORT_HTTP,
                    "maxRequestHeaderSize": "128KiB"
                }],
                "adminConnectors": [{
                    "type": APPLICATION_CONNECTOR_TYPE_HTTP,
                    "port": self.model.config[
                        'server-admin-connector-port-http']
                }],
                "gzip": {
                    "includedMethods": ["GET", "POST"]
                },
                "requestLog": {
                    "type": "classic",
                    "level": request_logging_level,
                    "appenders": [{
                        "type": "console",
                        # TODO(aznashwan): check whether this will lead to
                        # senseless "OFF" lines in the logs:
                        "logFormat": "OFF"
                    }]
                }
            },
            "filterPriorities": {
                "GitLab": 1,
                "org.pac4j.j2e.filter.CallbackFilter": 2,
                "org.pac4j.j2e.filter.SecurityFilter": 3,
                "CORS": 4
            },
            "pac4j": {
                "callbackPrefix": "/api/pac4j/login",
                "mongoUri": mongo_replica_set_uri,
                # TODO(aznashwan): must be set to the correct one:
                "mongoDb": database_name,
                "clients": [{
                    "org.finos.legend.server.pac4j.gitlab.GitlabClient": {
                        "name": "gitlab",
                        # TODO(aznashwan): set these on Gitlab relation:
                        "clientId": gitlab_client_id,
                        "secret": gitlab_client_secret,
                        "discoveryUri": GITLAB_OPENID_DISCOVERY_URL,
                        # NOTE(aznashwan): needs to be a space-separated str:
                        "scope": " ".join(GITLAB_REQUIRED_SCOPES)
                    }
                }],
                "mongoSession": {
                    "enabled": True,
                    "collection": "userSessions"},
                "bypassPaths": ["/api/info"]
            },
            "gitLab": {
                "newProjectVisibility": gitlab_project_visibility,
                "projectTag": gitlab_project_tag,
                "uat": {
                    "server": {
                        # NOTE(aznashwan): these will need configuring when we
                        # add support for relating to a Juju-managed Gitlab:
                        "scheme": "https",
                        "host": "gitlab.com",
                    },
                    "app": {
                        # TODO(aznashwan): set these on Gitlab relation:
                        "id": gitlab_client_id,
                        "secret": gitlab_client_secret,
                        "redirectURI": (
                            "http://localhost:7070/api/auth/callback")
                    }
                },
            },
            "projectStructure": {
                "extensionProvider": {
                    "org.finos.legend.sdlc.server.gitlab.finos."
                    "FinosGitlabProjectStructureExtensionProvider": {}
                }
            },
            "logging": {
                "level": server_logging_level,
                "appenders": [{
                    "type": "console",
                    "logFormat": APPLICATION_LOGGING_FORMAT,
                }]
            },
            "swagger": {
                "title": "Legend SDLC",
                "resourcePackage": "org.finos.legend.sdlc.server.resources",
                "version": "local-snapshot",
                "schemes": []
            }
        })

        return None

    def _update_sdlc_service_config(
            self, container: model.Container, config: dict) -> None:
        """Generates YAML config for the SDLC server and adds it into the
        container via Pebble files API.
        """
        logger.debug(
            "Adding following config under '%s' in container: %s",
            SDLC_CONFIG_FILE_CONTAINER_LOCAL_PATH, config)
        container.push(
            SDLC_CONFIG_FILE_CONTAINER_LOCAL_PATH,
            yaml.dump(config),
            make_dirs=True)
        logger.info(
            "Successfully wrote config file in container under '%s'",
            SDLC_CONFIG_FILE_CONTAINER_LOCAL_PATH)

    def _restart_sdlc_service(self, container: model.Container) -> None:
        """Restarts the SDLC service using the Pebble container API.
        """
        logger.debug("Restarting SDLC service")
        container.restart("sdlc")
        logger.debug("Successfully issues SDLC service restart")

    def _reconfigure_sdlc_service(self) -> None:
        """Generates the YAML config for the SDLC server and adds it into the
        container via Pebble files API.
        - regenerating the YAML config for the SDLC server
        - adding it via Pebble
        - instructing Pebble to restart the SDLC server
        The Service is power-cycled for the new configuration to take effect.
        """
        config = {}
        possible_blocked_status = (
            self._add_base_service_config_from_charm_config(config))
        if possible_blocked_status:
            logger.warning("Missing/erroneous configuration options")
            self.unit.status = possible_blocked_status
            return

        container = self.unit.get_container("sdlc")
        if container.can_connect():
            logger.debug("Updating SDLC service configuration")
            self._update_sdlc_service_config(container, config)
            self._restart_sdlc_service(container)
            self.unit.status = model.ActiveStatus(
                "SDLC service has been started.")
            return

        logger.info("SDLC container is not active yet. No config to update.")
        self.unit.status = model.BlockedStatus(
            "Awaiting Legend DB and Gitlab relations.")

    def _on_config_changed(self, _) -> None:
        """Reacts to configuration changes to the service by:
        - regenerating the YAML config for the SDLC server
        - adding it via Pebble
        - instructing Pebble to restart the SDLC server
        """
        self._reconfigure_sdlc_service()

    def _on_db_relation_joined(self, event: charm.RelationJoinedEvent):
        logger.debug("No actions are to be performed during DB relation join")

    def _on_db_relation_changed(
            self, event: charm.RelationChangedEvent) -> None:
        rel_id = event.relation.id
        rel = self.framework.model.get_relation("legend-db", rel_id)
        mongo_creds_json = rel.data[event.app].get("legend-db-connection")
        if not mongo_creds_json:
            self.unit.status = model.WaitingStatus(
                "Awaiting DB relation data.")
            event.defer()
            return
        logger.debug(
            "Mongo JSON credentials returned by DB relation: %s",
            mongo_creds_json)

        mongo_creds = None
        try:
            mongo_creds = json.loads(mongo_creds_json)
        except (ValueError, TypeError) as ex:
            logger.warn(
                "Exception occured while deserializing DB relation "
                "connection data: %s", str(ex))
            self.unit.status = model.BlockedStatus(
                "Could not deserialize Legend DB connection data.")
            return
        logger.debug(
            "Deserialized Mongo credentials returned by DB relation: %s",
            mongo_creds)

        self._stored.mongodb_credentials = mongo_creds

        # Attempt to reconfigure and restart the service with the new data:
        self._reconfigure_sdlc_service()

    def _get_sdlc_service_url(self):
        ip_address = subprocess.check_output(
            ["unit-get", "private-address"]).decode().strip()
        return SDLC_SERVICE_URL_FORMAT % ({
            # NOTE(aznashwan): we always return the plain HTTP endpoint:
            "schema": "http",
            "host": ip_address,
            "port": APPLICATION_CONNECTOR_PORT_HTTP,
            "path": APPLICATION_ROOT_PATH})

    def _on_studio_relation_joined(
            self, event: charm.RelationJoinedEvent) -> None:
        rel = event.relation
        sdlc_url = self._get_sdlc_service_url()
        logger.info("### Providing following SDLC URL to Studio: %s", sdlc_url)
        rel.data[self.app]["legend-sdlc-url"] = sdlc_url

    def _on_studio_relation_changed(
            self, event: charm.RelationChangedEvent) -> None:
        pass


if __name__ == "__main__":
    main.main(LegendSDLCServerOperatorCharm)
