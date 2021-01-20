

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}


import collections
import re

from ansible.errors import AnsibleFilterError, AnsibleOptionsError
from ansible.module_utils.six import iteritems, string_types
from ansible.module_utils.common._collections_compat import MutableMapping
from ansible.module_utils._text import to_native

from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import MAGIC_ARGSPECKEY_META
from ansible_collections.smabot.base.plugins.module_utils.plugins.filter_base import FilterBase
from ansible.utils.display import Display


display = Display()


class SecretCycleCfgFilter(FilterBase):

    FILTER_ID = 'filter_secretcycle_cfg'

    @property
    def argspec(self):
        tmp = super(SecretCycleCfgFilter, self).argspec

        subspec_inout = {
          'include': ([list(string_types)], []),
          'exclude': ([list(string_types)], []),
        }

        tmp.update({
          'type': ([collections.abc.Mapping], {}, subspec_inout),
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



# ---- Ansible filters ----
class FilterModule(object):
    ''' filter related to this collection config types '''

    def filters(self):
        res = {}

        for f in [SecretCycleCfgFilter]:
            res[f.FILTER_ID] = f()

        return res

