""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from integrations.crudhub import make_request
from django.conf import settings
from .operations import operations, _check_health, MACRO_LIST, CONNECTOR_NAME

logger = get_logger('apivoid')


class apivoid(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            params.update({"operation": operation})
            operation = operations.get(operation)
            return operation(config, params)
        except Exception as err:
            logger.error('apivoid:{}'.format(err))
            raise ConnectorError('apivoid:{}'.format(err))

    def check_health(self, config):
        return _check_health(config)

    def del_micro(self, config):
        if not settings.LW_AGENT:
            for macro in MACRO_LIST:
                try:
                    resp = make_request(f'/api/wf/api/dynamic-variable/?name={macro}', 'GET')
                    if resp['hydra:member']:
                        logger.info("resetting global variable '%s'" % macro)
                        macro_id = resp['hydra:member'][0]['id']
                        resp = make_request(f'/api/wf/api/dynamic-variable/{macro_id}/?format=json', 'DELETE')
                except Exception as e:
                    logger.error(e)

    def on_deactivate(self, config):
        self.del_micro(config)

    def on_activate(self, config):
        self.del_micro(config)

    def on_add_config(self, config, active):
        self.del_micro(config)

    def on_delete_config(self, config):
        self.del_micro(config)
