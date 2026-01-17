

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}


import copy
import collections
import os
import re

from ansible.errors import AnsibleFilterError, AnsibleOptionsError
from ansible.module_utils.six import iteritems, string_types
from ansible.module_utils.common._collections_compat import MutableMapping
from ansible.module_utils._text import to_native

from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import MAGIC_ARGSPECKEY_META
from ansible_collections.smabot.base.plugins.module_utils.plugins.filter_base import FilterBase
from ansible.utils.display import Display

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import merge_dicts
from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert


display = Display()


class SecretCycleCfgFilter(FilterBase):

    FILTER_ID = 'filter_secretcycle_cfg'

    @property
    def argspec(self):
        tmp = super(SecretCycleCfgFilter, self).argspec

        subspec_type = {
          'include': ([list(string_types)], []),
          'exclude': ([list(string_types)], []),
        }

        tmp.update({
          'type': ([collections.abc.Mapping], {}, subspec_type),
        })

        return tmp


    def filter_by_type(self, cfg):
        def filter_primitive(cfgkeys, filters, inclusive):
            if not filters:
                return cfgkeys

            res = []

            for k in cfgkeys:
                matched = False

                for f in filters:
                    if re.match(f, k):
                        matched = True
                        break


                if inclusive:
                    if matched:
                        # keep inclusive matching keys
                        res.append(k)
                else:
                    if not matched:
                        # keep exclusive non matching keys
                        res.append(k)

            return res

        type_filter = self.get_taskparam('type')

        if not type_filter:
            return cfg

        display.vv("[{}]:: filter by type: {}".format(
          type(self).FILTER_ID, type_filter)
        )

        cyclers = cfg.get('cyclers', None)

        if not cyclers:
            return cfg

        res = {}
        tmp = list(cyclers.keys())

        # excludes have higher prio than includes
        tmp = filter_primitive(tmp, type_filter['exclude'], False)
        tmp = filter_primitive(tmp, type_filter['include'], True)

        for k in tmp:
            res[k] = cyclers[k]

        cfg.update({ 'cyclers': res })
        return cfg


    def run_specific(self, indict):
        if not isinstance(indict, MutableMapping):
            raise AnsibleOptionsError(
               "filter input must be a dictionary, but given value"\
               " '{}' has type '{}'".format(indict, type(indict))
            )

        display.vvv("[{}]:: input: {}".format(type(self).FILTER_ID, indict))

        if not indict:
            return indict

        res = {}
        res.update(indict)

        res = self.filter_by_type(res)

        return res



class ConvertUpdateCredsParamsFilter(FilterBase):

    FILTER_ID = 'convert_update_creds_params'

    @property
    def argspec(self):
        tmp = super(ConvertUpdateCredsParamsFilter, self).argspec

        tmp.update({
          'upload_creds': ([collections.abc.Mapping]),
          'config': ([collections.abc.Mapping]),
          'global_settings': ([collections.abc.Mapping], {}),
          'mode': (list(string_types), 'write', ['read', 'write']),
        })

        return tmp


    def _conv_method_azure_keyvault(self, value, upload_creds, cfg, name_pfx):
        readmode = self.get_taskparam('mode') == 'read'
        subkey = 'set_secrets'

        if readmode:
            subkey = 'get_secrets'

        secret_cfgs = {}

        for k,v in upload_creds['creds'].items():
            if readmode and k != 'secret':
                # we only need to read the actual secret, nothing else
                continue

            n = (name_pfx + '_' + k).replace('_', '-')

            tmp = {}

            if readmode:
                # totally possible an old secret does not exist yet when
                # this is the initial run for this credential updater config
                tmp['optional'] = True
            else:
                tmp['value'] = v

            secret_cfgs[n] = tmp

        tmp = {
          'secrets': secret_cfgs
        }

        if readmode:
            tmp['return_list'] = True

        value[subkey] = tmp
        return value


    def _conv_method_hashivault(self, value, upload_creds, cfg, name_pfx):
        readmode = self.get_taskparam('mode') == 'read'
        glob_sets = self.get_taskparam('global_settings')

        subkey = 'set_secrets'

        tmp = copy.deepcopy(value['secret_def'])

        if readmode:
            subkey = 'get_secrets'
            tmp['data_keys'] = ['secret']
            tmp['optional'] = True
        else:
            tmp['data'] = upload_creds['creds']

        secret_cfg = {
          'secrets': {
             'auto_upload_hvault_cred_' + name_pfx: tmp
          }
        }

        if readmode:
            secret_cfg['return_list'] = True

        res = {
          subkey: secret_cfg
        }

        tmp = value.get('login', None)

        if tmp and not glob_sets.get('use_vault_global_login', False):
            res['login'] = tmp

        return res


    def run_specific(self, value):
        if not isinstance(value, collections.abc.Mapping):
            raise AnsibleOptionsError(
               "input value must be a dict type but is of type"\
               " '{}': {}".format(type(value), value)
            )

        ##display.vvv("[{}]:: input: {}".format(type(self).FILTER_ID, value))

        # first we need to merge the dicts together without changing
        # the source dicts
        value = copy.deepcopy(value)

        cfg = self.get_taskparam('config')
        conv_fn = getattr(self, '_conv_method_' + str(cfg['method']), None)

        ansible_assert(conv_fn,
          "Unsupported method '{}'".format(cfg['method'])
        )

        upload_creds = self.get_taskparam('upload_creds')

        name_template = cfg['name_template']
        name_pfx = name_template.format(
          upload_creds['type'], upload_creds['name']
        )

        value = conv_fn(
          value, upload_creds, cfg, name_pfx
        )

        return value



class ChangeLoginMethodFilter(FilterBase):

    FILTER_ID = 'change_login_method'

    @property
    def argspec(self):
        tmp = super(ChangeLoginMethodFilter, self).argspec

        tmp.update({
          'method': (list(string_types)),
          'params': ([collections.abc.Mapping]),
        })

        return tmp

    def run_specific(self, value):
        if not isinstance(value, collections.abc.Mapping):
            raise AnsibleOptionsError(
               "input value must be a dict type but is of type"\
               " '{}': {}".format(type(value), value)
            )

        ##display.vvv("[{}]:: input: {}".format(type(self).FILTER_ID, value))

        # first we need to merge the dicts together without changing
        # the source dicts
        value = copy.deepcopy(value)

        value['creds'].update({
          'method': self.get_taskparam('method'),
          'params': self.get_taskparam('params'),
        })

        return value



# ---- Ansible filters ----
class FilterModule(object):
    ''' filter related to this collection config types '''

    def filters(self):
        res = {}

        for f in [ChangeLoginMethodFilter, ConvertUpdateCredsParamsFilter,
          SecretCycleCfgFilter
        ]:
            res[f.FILTER_ID] = f()

        return res

