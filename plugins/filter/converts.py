

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


class ReadSecretsToListFilter(FilterBase):

    FILTER_ID = 'read_secrets_to_list'

##    @property
##    def argspec(self):
##        tmp = super(ReadSecretsToListFilter, self).argspec
##
##        tmp.update({
##          'method': (list(string_types)),
##          'params': ([collections.abc.Mapping]),
##        })
##
##        return tmp


    # simply take any leave node values of given multilevel dict,
    # as this operation heavily looses structure makes only sense
    # for very specific situations (if just one secret is requested,
    # or if all secrets requested are somewhat interchangeable
    # (like putting ssh keys in authorized keys or similar)
    def _flatten_resmap(self, map_in, reslst=None):
        if reslst is None:
            reslst = []

        if not isinstance(map_in, collections.abc.Mapping):
            reslst.append(map_in)
            return reslst

        for k,v in map_in.items():
            self._flatten_resmap(v, reslst=reslst)

        return reslst


    def run_specific(self, value):
        if not isinstance(value, collections.abc.Mapping):
            raise AnsibleOptionsError(
               "input value must be a dict type but is of type"\
               " '{}': {}".format(type(value), value)
            )

        ##display.vvv("[{}]:: input: {}".format(type(self).FILTER_ID, value))
        return self._flatten_resmap(value)



# ---- Ansible filters ----
class FilterModule(object):
    ''' filter related to this collection config types '''

    def filters(self):
        res = {}

        for f in [
          ReadSecretsToListFilter,
        ]:
            res[f.FILTER_ID] = f()

        return res

