
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from ansible.module_utils.six import string_types
##from ansible.utils.display import Display

from ansible_collections.smabot.base.plugins.module_utils.plugins.action_base import BaseAction


##display = Display()


class ActionModule(BaseAction):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_check_mode = False
        self._supports_async = False


    @property
    def argspec(self):
        tmp = super(ActionModule, self).argspec

        tmp.update({
          'url': (list(string_types) + [type(None)], None),
          'token': (list(string_types) + [type(None)], None),
          'verify': ([bool, type(None)], None),
          'key_shares': ([int, type(None)], None),
          'key_threshold': ([int, type(None)], None),
          'save_mkeys_internally': ([bool], False),
        })

        return tmp


    def run_specific(self, result):
        modargs = {}

        for x in ['url', 'token', 'verify', 'key_shares', 'key_threshold']:
            tmp = self.get_taskparam(x)
            if tmp is None:
                continue

            modargs[x] = tmp

        mres = self.exec_module('smabot.hashivault.config_initialize',
          modargs=modargs
        )

        for x in ['changed', 'key_setup', 'vault_info']:
            if x not in mres:
                continue

            result[x] = mres[x]

        save_mkeys = self.get_taskparam('save_mkeys_internally')
        if not result['changed'] or not save_mkeys:
            # vault instance is not new or no key autosave, nothing more todo
            return result

        # optionally temp save master keys to our new vault, it is up 
        # to the user how he want to handle these delicate secrets from here on
        modargs.pop('key_shares', None)
        modargs.pop('key_threshold', None)

        # TODO: allow more customisation of options here???
        modargs.update({
          'token': result['key_setup']['root_token'],
          'name': '_internal_bkp_kv/',
          'backend': 'kv-v2', 'state': 'present',
        })

        # create master key backup secret engine
        self.exec_module('terryhowe.hashivault.hashivault_secret_engine',
          modargs=modargs
        )

        modargs.pop('backend')
        modargs['mount_point'] = modargs.pop('name')
        modargs['secret'] = 'self_master_keys'

        tmp = {}

        i = 1
        for k in result['key_setup']['keys']:
            tmp["key{:d}".format(i)] = k
            i += 1

        modargs['data'] = tmp

        # write master keys to new secret engine
        self.exec_module('terryhowe.hashivault.hashivault_secret',
          modargs=modargs
        )

        # TODO: remove master keys from result when vault internal tmp saving is used to mininimze exposure???
        ##result['key_setup'].pop('keys')
        ##result['key_setup'].pop('keys_base64')
        result['key_setup']['master_keys'] = {
          'mount_point': modargs['mount_point'],
          'secret': modargs['secret'],
        }

