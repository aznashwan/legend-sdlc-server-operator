#!/usr/bin/env python3
# Copyright 2021 Canonical
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

""" Module defining the Charmed operator for the FINOS Legend SDLC Server. """

import logging

from ops import charm
from ops import framework
from ops import main
from ops import model
import yaml

LOG = logging.getLogger(__name__)


SDLC_CONFIG_FILE_LOCAL_CONTAINER_PATH = "/sdlc-config.yaml"

APPLICATION_CONNECTOR_TYPE_HTTP = "http"
APPLICATION_CONNECTOR_TYPE_HTTPS = "https"

VALID_APPLICATION_LOG_LEVEL_SETTINGS = [
    "INFO", "WARN", "DEBUG", "TRACE", "OFF"]

GITLAB_PROJECT_VISIBILITY_PUBLIC = "public"
GITLAB_PROJECT_VISIBILITY_PRIVATE = "private"
GITLAB_OPENID_DISCOVERY_URL = (
    "https://gitlab.com/.well-known/openid-configuration")
GITLAB_REQUIRED_SCOPES = [
    "openid", "profile", "api"]


class LegendSDLCServerOperatorCharm(charm.CharmBase):
    """ Charmed operator for the FINOS Legend SDLC Server. """

    _stored = framework.StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on.sdlc_pebble_ready, self._on_sdlc_pebble_ready)

        self._set_stored_defaults()

    def _set_stored_defaults(self) -> None:
        self._stored.set_default(log_level="DEBUG")

    def _on_sdlc_pebble_ready(self, event: framework.EventBase) -> None:
        """Define and start a workload using the Pebble API.

        TEMPLATE-TODO: change this example to suit your needs.
        You'll need to specify the right entrypoint and environment
        configuration for your specific workload. Tip: you can see the
        standard entrypoint of an existing container using docker inspect

        Learn more about Pebble layers at https://github.com/canonical/pebble
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
                        "/bin/sh -c 'java -XX:+ExitOnOutOfMemoryError "
                        "-XX:MaxRAMPercentage=60 -Xss4M -cp /app/bin/*.jar "
                        "-Dfile.encoding=UTF8 "
                        "org.finos.legend.sdlc.server.LegendSDLCServer "
                        "server %s" % (
                            SDLC_CONFIG_FILE_LOCAL_CONTAINER_PATH)
                    ),
                    # NOTE(aznashwan): considering the SDLC service expects
                    # a singular config file which already contains all
                    # relevant options in it (some of which will require the
                    # relation with Mongo/Gitlab to have already been
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
        # the service until the relations with Mongo and Gitlab are added:
        # container.autostart()

        self.unit.status = model.WaitingStatus(
            "Awaiting Legend Engine, Mongo, and Gitlab relations.")

    def _get_logging_level_from_config(self, option_name) -> str:
        """Fetches the config option with the given name and checks to
        ensure that it is a valid `java.utils.logging` log level.

        Returns None if an option is invalid.
        """
        value = self.model.config[option_name]
        if value not in VALID_APPLICATION_LOG_LEVEL_SETTINGS:
            LOG.warning(
                "Invalid Java logging level value provided for option "
                "'%s': '%s'. Valid Java logging levels are: %s. The charm "
                "shall block until a proper value is set." % (
                    option_name, value, VALID_APPLICATION_LOG_LEVEL_SETTINGS))
            return None
        return value

    def _derive_base_service_config_from_charm_config(self) -> dict:
        """This method returns a `dict` containing all of the relevant options
        required by the SDLC service in the exact format it expects them.
        """
        gitlab_project_visibility = GITLAB_PROJECT_VISIBILITY_PRIVATE
        if self.model.config['gitlab-create-new-projects-as-public']:
            gitlab_project_visibility = GITLAB_PROJECT_VISIBILITY_PUBLIC

        request_logging_level = self._get_logging_level_from_config(
            "server-requests-logging-level")
        server_logging_level = self._get_logging_level_from_config(
            "server-logging-level")

        special_options = [
            gitlab_project_visibility, request_logging_level,
            server_logging_level]
        if None in special_options:
            LOG.warning(
                "One or more config options are improperly formatted or "
                "missing. Please review the debug logs for more details.")
            return {}

        sdlc_config = {
            "applicationName": "Legend SDLC",
            "server": {
                "rootPath": self.model.config["server-root-path"],
                "applicationConnectors": [{
                    "type": APPLICATION_CONNECTOR_TYPE_HTTP,
                    "port": self.model.config[
                        'server-application-connector-port-http'],
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
                # TODO(aznashwan): configure this during MongoDB relation:
                "mongoUri": "mongodb://admin:3ZmzSj1NObM=@mongod:27017",
                # TODO(aznashwan): parametrize DB name too?
                "mongoDb": "legend",
                "clients": [{
                    "org.finos.legend.server.pac4j.gitlab.GitlabClient": {
                        "name": "gitlab",
                        # TODO(aznashwan): set these on Gitlab relation:
                        "clientId": self.model.config['gitlab-client-id'],
                        "secret": self.model.config['gitlab-client-secret'],
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
                "projectTag": self.model.config['gitlab-project-tag'],
                "uat": {
                    "server": {
                        # NOTE(aznashwan): these will need configuring when we
                        # add support for relating to a Juju-managed Gitlab:
                        "scheme": "https",
                        "host": "gitlab.com",
                    },
                    "app": {
                        # TODO(aznashwan): set these on Gitlab relation:
                        "id": self.model.config['gitlab-client-id'],
                        "secret": self.model.config['gitlab-client-secret'],
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
                    "logFormat": self.model.config['server-logging-format'],
                }]
            },
            # TODO(aznashwan): determine how relevant these options would be
            # in the main charm config if they were added:
            "swagger": {
                "title": "Legend SDLC",
                "resourcePackage": "org.finos.legend.sdlc.server.resources",
                "version": "local-snapshot",
                "schemes": []
            }
        }

        return sdlc_config

    def _update_sdlc_service_config(
            self, container: model.Container, config: dict) -> None:
        """Generates YAML config for the SDLC server and adds it into the
        container via Pebble files API.
        """
        LOG.debug(
            "Adding following config under '%s' in container: %s",
            SDLC_CONFIG_FILE_LOCAL_CONTAINER_PATH, config)
        container.push(
            SDLC_CONFIG_FILE_LOCAL_CONTAINER_PATH,
            yaml.dump(config),
            make_dirs=True)
        LOG.debug(
            "Successfully wrote config file '%s'",
            SDLC_CONFIG_FILE_LOCAL_CONTAINER_PATH)

    def _restart_sdlc_service(self, container: model.Container) -> None:
        """Restarts the SDLC service using the Pebble container API.
        """
        LOG.debug("Restarting SDLC service")
        container.restart("sdlc")
        LOG.debug("Successfully issues SDLC service restart")

    def _reconfigure_sdlc_service(
            self, container: model.Container, config: dict) -> None:
        """Generates the YAML config for the SDLC server and adds it into the
        container via Pebble files API.
        The Service is power-cycled for the new configuration to take effect.
        """
        self._update_sdlc_service_config(container, config)
        self._restart_sdlc_service(container)

    def _on_config_changed(self, _) -> None:
        """Reacts to configuration changes to the service by:
        - regenerating the YAML config for the SDLC server
        - adding it via Pebble
        - instructing Pebble to restart the SDLC server
        """
        config = self._derive_base_service_config_from_charm_config()
        if not config:
            self.unit.status = model.BlockedStatus(
                "Missing/erroneous configuration options.")
            return

        with self.unit.get_container("sdlc").is_ready() as container:
            LOG.debug("Updating SDLC service configuration")
            self._reconfigure_sdlc_service(container, config)
            return

        LOG.warning("SDLC container is not active yet")
        self.unit.status = model.WaitingStatus(
            "Awaiting Pebble initialization.")


if __name__ == "__main__":
    main.main(LegendSDLCServerOperatorCharm)
