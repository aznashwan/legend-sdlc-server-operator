#!/usr/bin/env python3
# Copyright 2021 Canonical
# See LICENSE file for licensing details.

""" Module defining the Charmed operator for the FINOS Legend SDLC Server. """

import functools
import logging

from ops import charm
from ops import framework
from ops import main
from ops import model
import yaml

from charms.mongodb_k8s.v0 import mongodb

LOG = logging.getLogger(__name__)


SDLC_CONFIG_FILE_CONTAINER_LOCAL_PATH = "/sdlc-config.yaml"

APPLICATION_CONNECTOR_TYPE_HTTP = "http"
APPLICATION_CONNECTOR_TYPE_HTTPS = "https"

VALID_APPLICATION_LOG_LEVEL_SETTINGS = [
    "INFO", "WARN", "DEBUG", "TRACE", "OFF"]

GITLAB_PROJECT_VISIBILITY_PUBLIC = "public"
GITLAB_PROJECT_VISIBILITY_PRIVATE = "private"
GITLAB_REQUIRED_SCOPES = ["openid", "profile", "api"]
GITLAB_OPENID_DISCOVERY_URL = (
    "https://gitlab.com/.well-known/openid-configuration")


def _logged_charm_entry_point(fun):
    """ Add logging for method call/exits. """
    @functools.wraps(fun)
    def _inner(*args, **kwargs):
        LOG.info(
            "### Initiating Legend SDLC charm call to '%s'", fun.__name__)
        res = fun(*args, **kwargs)
        LOG.info(
            "### Completed Legend SDLC charm call to '%s'", fun.__name__)
        return res
    return _inner


class LegendSDLCServerOperatorCharm(charm.CharmBase):
    """ Charmed operator for the FINOS Legend SDLC Server. """

    _stored = framework.StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self._set_stored_defaults()

        # MongoDB consumer setup:
        self._mongodb_consumer = mongodb.MongoConsumer(
            self, "db", {"mongodb": ">=4.0"}, multi=False)

        # Standard charm lifecycle events:
        self.framework.observe(
            self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on.sdlc_pebble_ready, self._on_sdlc_pebble_ready)

        # DB relation lifecycle events:
        self.framework.observe(
            self.on["db"].relation_joined,
            self._on_db_relation_joined)
        self.framework.observe(
            self.on["db"].relation_changed,
            self._on_db_relation_changed)

    def _set_stored_defaults(self) -> None:
        self._stored.set_default(log_level="DEBUG")
        self._stored.set_default(mongodb_credentials={})

    @_logged_charm_entry_point
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

        self.unit.status = model.BlockedStatus(
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
        server_logging_format = self.model.config['server-logging-format']
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
                    "logFormat": server_logging_format,
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
        LOG.debug(
            "Adding following config under '%s' in container: %s",
            SDLC_CONFIG_FILE_CONTAINER_LOCAL_PATH, config)
        container.push(
            SDLC_CONFIG_FILE_CONTAINER_LOCAL_PATH,
            yaml.dump(config),
            make_dirs=True)
        LOG.info(
            "Successfully wrote config file in container under '%s'",
            SDLC_CONFIG_FILE_CONTAINER_LOCAL_PATH)

    def _restart_sdlc_service(self, container: model.Container) -> None:
        """Restarts the SDLC service using the Pebble container API.
        """
        LOG.debug("Restarting SDLC service")
        container.restart("sdlc")
        LOG.debug("Successfully issues SDLC service restart")

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
            LOG.warning("Missing/erroneous configuration options")
            self.unit.status = possible_blocked_status
            return

        container = self.unit.get_container("sdlc")
        with container.can_connect():
            LOG.debug("Updating SDLC service configuration")
            self._update_sdlc_service_config(container, config)
            self._restart_sdlc_service(container)
            self.unit.status = model.ActiveStatus(
                "SDLC service has been started.")
            return

        LOG.info("SDLC container is not active yet. No config to update.")
        self.unit.status = model.BlockedStatus(
            "Awaiting Legend Engine, Mongo, and Gitlab relations.")

    @_logged_charm_entry_point
    def _on_config_changed(self, _) -> None:
        """Reacts to configuration changes to the service by:
        - regenerating the YAML config for the SDLC server
        - adding it via Pebble
        - instructing Pebble to restart the SDLC server
        """
        self._reconfigure_sdlc_service()

    @_logged_charm_entry_point
    def _on_db_relation_joined(self, event: charm.RelationJoinedEvent):
        LOG.debug("No actions are to be performed during Mongo relation join")

    @_logged_charm_entry_point
    def _on_db_relation_changed(
            self, event: charm.RelationChangedEvent) -> None:
        # _ = self.model.get_relation(event.relation.name, event.relation.id)
        rel_id = event.relation.id

        # Check whether credentials for a database are available:
        mongo_creds = self._mongodb_consumer.credentials(rel_id)
        if not mongo_creds:
            LOG.info(
                "No MongoDB database credentials present in relation. "
                "Returning now to await their availability.")
            self.unit.status = model.WaitingStatus(
                "Waiting for MongoDB database credentials.")
            return
        LOG.info(
            "Current MongoDB database creds provided by relation are: %s",
            mongo_creds)

        # Check whether the databases were created:
        databases = self._mongodb_consumer.databases(rel_id)
        if not databases:
            LOG.info(
                "No MongoDB database currently present in relation. "
                "Requesting creation now.")
            self._mongodb_consumer.new_database()
            self.unit.status = model.WaitingStatus(
                "Waiting for MongoDB database creation.")
            return
        LOG.info(
            "Current MongoDB databases provided by the relation are: %s",
            databases)
        # NOTE(aznashwan): we hackily add the databases in here too:
        mongo_creds['databases'] = databases
        self._stored.mongodb_credentials = mongo_creds

        # Attempt to reconfigure and restart the service with the new data:
        self._reconfigure_sdlc_service()


if __name__ == "__main__":
    main.main(LegendSDLCServerOperatorCharm)
