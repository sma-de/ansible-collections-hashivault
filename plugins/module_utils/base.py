#!/usr/bin/env python

# TODO: copyright, owner license
#

"""
TODO module / file doc string
"""

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import abc
import collections
import os
from urllib.parse import urlparse

from ansible.module_utils.basic import \
  AnsibleModule,\
  boolean,\
  env_fallback,\
  missing_required_lib

##from ansible.module_utils.common.parameters import env_fallback
##from ansible.errors import AnsibleAuthenticationFailure
from ansible.module_utils._text import to_native, to_text
##from ansible.utils.display import Display

##from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import ArgsPlugin


##display = Display()


class HashiAuthError(Exception):
    pass


class MandatoryParamMissingError(Exception):

    def __init__(self, param_name, msg_tmpl=None):
        msg_tmpl = msg_tmpl or "Mandatory param '{}' unset"
        self.param_name = param_name
        super().__init__(msg_tmpl.format(param_name))



def _mandatory_param(val, pname, errmsg=None):
    if val is None:
        raise MandatoryParamMissingError(pname, msg_tmpl=errmsg)

    return val



def fb_verify(evar):
    if evar in os.environ:
        return not boolean(os.environ[evar])

    return True



class HashiVaultBase(abc.ABC):

    def __init__(self):
        self._token = None
 
    @property
    def hvac_client(self):
        return self.init_hvac_client()
 
    @property
    def expect_authing(self):
        return True


##    @property
##    def hvault_instance_id(self):
##        ##return self.hvault_host + ':' + str(self.hvault_port)
##        return self.server_url


    @property
    def auth_token(self):
        tmp = getattr(self, '_hvac_client', None)
        if tmp and tmp.token:
            return tmp.token

        return _mandatory_param(self._pretoken, 'token', 
            errmsg="Must provide a valid vault auth token either as"\
            " param or as environment variable"
        )

    @property
    def server_url(self):
        return '{scheme}://{host}:{port}'.format(**self.connection)


    def prepare_connection(self, raw_param_con, pretoken, ssl_verify):
        if not isinstance(raw_param_con, collections.abc.Mapping):
            ## assume complete url string, split it into components
            tmp = urlparse(raw_param_con)

            raw_param_con = {
              'scheme': tmp.scheme,
              'host': tmp.hostname,
              'port': tmp.port,
              'ssl_verify': ssl_verify,
            }

        raw_param_con.setdefault('scheme', 'https')
        raw_param_con.setdefault('host', '127.0.0.1')
        raw_param_con.setdefault('port', 8200)
        raw_param_con.setdefault('ssl_verify', True)

        self.connection = raw_param_con
        self._pretoken = pretoken


    def init_hvac_client(self, forced_token=None):
        c = getattr(self, '_hvac_client', None)
        if c:
            return c

        # standard pretext, connect and auth
        import hvac
        c = hvac.Client(url=self.server_url,
          verify=self.connection['ssl_verify']
        )

        if self.expect_authing or forced_token:
            c.token = forced_token or self.auth_token

            if not c.is_authenticated():
                raise HashiAuthError(
                    "Authing with given token failed"
                )

        self._hvac_client = c
        return c



class HashiVaultBaseModule(AnsibleModule, HashiVaultBase):

    @staticmethod
    def get_standard_args():
        return {
          'url': {
             'fallback': (env_fallback, ['VAULT_ADDR'])
          },

          'token': {
             'fallback': (env_fallback, ['VAULT_TOKEN'])
          },

          'verify': {
             'type': 'bool',
             'fallback': (fb_verify, ['VAULT_SKIP_VERIFY'])
          },
        }

    @abc.abstractmethod
    def _run_specific(self, result):
        pass

    def run(self, result):
        self.prepare_connection(self.params['url'],
          self.params['token'], self.params['verify']
        )

        try:
            return self._run_specific(result)
        except HashiAuthError as e:
            self.fail_json(msg=str(e), **result)
        except MandatoryParamMissingError as e:
            self.fail_json(msg=str(e), **result)
        except ImportError as e:
            self.fail_json(msg=missing_required_lib(e.name), **result)

