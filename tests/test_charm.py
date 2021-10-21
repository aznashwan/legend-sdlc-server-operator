# Copyright 2021 Canonical
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

from unittest import mock

from charms.finos_legend_libs.v0 import legend_operator_testing
from ops import testing as ops_testing

import charm


class LegendSdlcTestWrapper(
    charm.LegendSDLCServerCharm, legend_operator_testing.BaseFinosLegendCoreServiceTestCharm
):

    WORKLOAD_CONTAINER_NAME = "sdlc"
    WORKLOAD_SERVICE_NAMES = ["sdlc"]
    DB_RELATION_NAME = "legend-db"
    GITLAB_RELATION_NAME = "legend-sdlc-gitlab"
    RELATIONS = [DB_RELATION_NAME, GITLAB_RELATION_NAME]
    RELATIONS_DATA = {
        DB_RELATION_NAME: {"database": "DB relation test data"},
        GITLAB_RELATION_NAME: {"gitlab": "GitLab relation test data"},
    }

    def _get_jks_truststore_preferences(self):
        return self.TRUSTSTORE_PREFERENCES


class LegendSdlcTestCase(legend_operator_testing.TestBaseFinosCoreServiceLegendCharm):
    @classmethod
    def _set_up_harness(cls):
        harness = ops_testing.Harness(LegendSdlcTestWrapper)
        return harness

    @mock.patch("ops.testing._TestingPebbleClient.restart_services")
    @mock.patch("ops.testing._TestingPebbleClient.start_services")
    @mock.patch("ops.testing._TestingPebbleClient.stop_services")
    def _test_relations_waiting(
        self, _container_stop_mock, _container_start_mock, _container_restart_mock
    ):
        self._test_relations_waiting(_container_stop_mock, _container_restart_mock)
