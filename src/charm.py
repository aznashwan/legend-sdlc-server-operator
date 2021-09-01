#!/usr/bin/env python3
# Copyright 2021 Canonical
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

""" Module defining the Charmed operator for the FINOS Legend SDLC Server. """

import logging

from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus

logger = logging.getLogger(__name__)


class LegendSDLCServerOperatorCharm(CharmBase):
    """ Charmed operator for the FINOS Legend SDLC Server. """

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(
            self.on.httpbin_pebble_ready, self._on_httpbin_pebble_ready)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.fortune_action, self._on_fortune_action)

        self._set_stored_defaults()

    def _set_stored_defaults(self):
        self._stored.set_default(log_level="DEBUG")

    def _on_httpbin_pebble_ready(self, event):
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
                        # TODO(aznashwan): ensure config volume/file exists:
                        "server /config/config.json'"
                        ),
                    "startup": "enabled",
                    # TODO(aznashwan): determine any env vars we could pass
                    # (most notably, things like the RAM percentage etc...)
                    "environment": {},
                }
            },
        }

        # Add intial Pebble config layer using the Pebble API
        container.add_layer("sdlc", pebble_layer, combine=True)

        # Autostart any services that were defined with startup: enabled
        container.autostart()

        # Learn more about statuses in the SDK docs:
        # https://juju.is/docs/sdk/constructs#heading--statuses
        self.unit.status = ActiveStatus()

    def _on_config_changed(self, _):
        """Just an example to show how to deal with changed configuration.

        TEMPLATE-TODO: change this example to suit your needs.
        If you don't need to handle config, you can remove this method,
        the hook created in __init__.py for it, the corresponding test,
        and the config.py file.

        Learn more about config at https://juju.is/docs/sdk/config
        """

        # TODO(aznashwan): handle possible config changes:
        # - various run params (e.g. RAM%)
        # - PAC4J config changes?

        current = self.config["thing"]
        if current not in self._stored.things:
            logger.debug("found a new thing: %r", current)
            self._stored.things.append(current)

    def _on_fortune_action(self, event):
        """Just an example to show how to receive actions.

        TEMPLATE-TODO: change this example to suit your needs.
        If you don't need to handle actions, you can remove this method,
        the hook created in __init__.py for it, the corresponding test,
        and the actions.py file.

        Learn more about actions at https://juju.is/docs/sdk/actions
        """
        fail = event.params["fail"]
        if fail:
            event.fail(fail)
        else:
            event.set_results(
                {"fortune":
                    "A bug in the code is worth two in the documentation."})


if __name__ == "__main__":
    main(LegendSDLCServerOperatorCharm)
