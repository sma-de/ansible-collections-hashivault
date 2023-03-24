

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

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import merge_dicts, setdefault_none
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



class AppendHVSecrets(FilterBase):

    FILTER_ID = 'append_hv_secrets'

    @property
    def argspec(self):
        tmp = super(AppendHVSecrets, self).argspec

        tmp.update({
          'new_secret': ([collections.abc.Mapping]),
          'secret_cfg': ([collections.abc.Mapping]),
          'common_cfg': ([collections.abc.Mapping]),
        })

        return tmp


    def _secret_key_filter_one_of(self, keys, one_of_lst=None, **kwargs):
        res = []

        for k in keys:
            if k in one_of_lst:
                res.append(k)

        return res


    ##
    ## this layout builds return value based on vault
    ## internal buildup like this:
    ##
    ##   engine_name:
    ##     path_in_vault:
    ##       key1: secret1
    ##       key2: secret2
    ##
    def _save_layout_vault_paths_nested(self, value, ns, secret_cfg,
        **kwargs
    ):
        ## get secret parent dict
        sp = setdefault_none(value,
          secret_cfg['config']['engine_mount_point'], {}
        )

        sp = setdefault_none(sp, secret_cfg['config']['path'], {})

        merge_dicts(sp, ns)

        return value


    ##
    ## this layout builds mirrors given input cfg for this role like this:
    ##
    ##   get_secrets:
    ##     secrets:
    ##
    ##        foo:
    ##          [...]
    ##
    ##        bar:
    ##          [...]
    ##
    ## ==>
    ##
    ##   read_results:
    ##     foo:
    ##       key1: secret1
    ##       key2: secret2
    ##     bar:
    ##       key1: secret1
    ##       key2: secret2
    ##
    def _save_layout_mirror_inputcfg(self, value, ns, secret_cfg,
        orig_cfgkey=None, **kwargs
    ):
        ## get secret parent dict
        sp = setdefault_none(value,
          orig_cfgkey, {}
        )

        merge_dicts(sp, ns)
        return value


    def run_specific(self, value):
        if not isinstance(value, MutableMapping):
            raise AnsibleOptionsError(
               "input value must be a mapping, but is of"\
               " type '{}'".format(type(value))
            )

        new_secret = self.get_taskparam('new_secret')
        secret_cfg = self.get_taskparam('secret_cfg')
        common_cfg = self.get_taskparam('common_cfg')

        cfgkey = secret_cfg['key']
        secret_cfg = secret_cfg['value']

        only_vals = secret_cfg['only_values']
        ret_secrets = secret_cfg['return_secrets']

        key_filters = []
        for kf in secret_cfg.get('key_filters', {}).values():
            ##display.vvv("handle keyfilter: {}".format(kf))

            kfa = kf.get('args', {})
            kft = kf['type']

            tmp = getattr(self, '_secret_key_filter_' + kft, None)
            ansible_assert(tmp,
               "Unsupported key filter type '{}'".format(kft)
            )

            key_filters.append((tmp, kfa))

        ns = new_secret
        nss = ns['secret']

        keys_keep = list(nss.keys())

        for kf, kfa in key_filters:
            ## optionally filter out secrets based on key
            keys_keep = kf(keys_keep, **kfa)

        ## optionally return just a list of secret keys without values
        for k in list(nss.keys()):
            if k not in keys_keep:
                nss.pop(k)
                continue

            v = nss[k]

            if not ret_secrets:
                v = None

            nss[k] = v

        ## either return full upstream answer with all extra meta sub maps, or just the secrets
        if only_vals:
            ns = ns['secret']

        ## layout final result mapping
        rl = common_cfg['return_layout']
        tmp = getattr(self, '_save_layout_' + rl, None)

        ansible_assert(tmp,
           "Unsupported result layout fn '{}'".format(rl)
        )

        return tmp(value, ns, secret_cfg, orig_cfgkey=cfgkey)


# ---- Ansible filters ----
class FilterModule(object):
    ''' filter related to this collection config types '''

    def filters(self):
        res = {}

        for f in [
          ReadSecretsToListFilter, AppendHVSecrets,
        ]:
            res[f.FILTER_ID] = f()

        return res

