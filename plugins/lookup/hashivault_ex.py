
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

## DOCUMENTATION = r'''
## TODO
## '''
## 
## EXAMPLES = r"""
## TODO
## """
## 
## RETURN = r"""
## TODO
## """

import copy

HAS_HVAC = False
try:
    import hvac
    HAS_HVAC = True
except ImportError:
    HAS_HVAC = False


from ansible.errors import AnsibleOptionsError

from ansible.module_utils.six import string_types
from ansible.module_utils._text import to_native, to_text
from ansible.utils.display import Display
from ansible.module_utils.six import iteritems

from ansible_collections.community.hashi_vault.plugins.lookup import hashi_vault
from ansible_collections.smabot.hashivault.plugins.lookup import hashivault_dbg
from ansible_collections.smabot.base.plugins.module_utils.plugins.lookup_base import BaseLookup


display = Display()


##
## this is wrapper around the community standard hashivault lookup 
## module, atm there is not much added value vs the vanilla module, the 
## only reasons this exists atm actually is because upstream changed its 
## authing env vars to be prefixed with "ANSIBLE_*" which is unfortunately 
## forbidden to be set by user credentials in awx, so we use this module 
## just for inducing standard vars to upstream module
##

class LookupModule(BaseLookup, hashi_vault.LookupModule):
##class LookupModule(BaseLookup, hashivault_dbg.LookupModule):

    def __init__(self, *args, **kwargs):
        BaseLookup.__init__(self, *args, **kwargs)
        hashi_vault.LookupModule.__init__(self, *args, **kwargs)
        ##hashivault_dbg.LookupModule.__init__(self, *args, **kwargs)


    @property
    def argspec(self):
        tmp = super(LookupModule, self).argspec

        tmp.update({
          'auth_role_id': {
            'type': list(string_types),
            'defaulting': {
              'ansvar': ['approle_login_id', 'awxcred_hashivault_approle_id'],
              'env': ['ANSIBLE_HASHI_VAULT_ROLE_ID', 'VAULT_ROLE_ID'],
              'fallback': None,
            },
          },

          'auth_secret_id': {
            'type': list(string_types),
            'defaulting': {
              'ansvar': ['approle_login_secret', 'awxcred_hashivault_approle_secret'],
              'env': ['ANSIBLE_HASHI_VAULT_SECRET_ID', 'VAULT_SECRET_ID'],
              'fallback': None,
            },
          },

          'url': {
            'type': list(string_types),
            'defaulting': {
              'ansvar': ['approle_login_server', 'awxcred_hashivault_server'],
              'env': ['VAULT_ADDR', 'ANSIBLE_HASHI_VAULT_ADDR'],
            },
          },

          'auth_mp': {
            'type': list(string_types),
            'defaulting': {
              'ansvar': ['approle_login_mount', 'awxcred_hashivault_approle_mount'],
##              'env': ['ANSIBLE_HASHI_VAULT_AUTH_METHOD', 'VAULT_AUTH_METHOD'],
              'fallback': 'approle/'
            },
          },

          'auth_method': {
            'type': list(string_types),
            'defaulting': {
##              'ansvar': ['approle_login_mount', 'awxcred_hashivault_approle_mount'],
              'env': ['ANSIBLE_HASHI_VAULT_AUTH_METHOD', 'VAULT_AUTH_METHOD'],
              'fallback': 'approle'
            },
          },

          'ca_cert': {
            'type': list(string_types),
            'defaulting': {
##              'ansvar': ['approle_login_mount', 'awxcred_hashivault_approle_mount'],
##              'env': ['ANSIBLE_HASHI_VAULT_AUTH_METHOD', 'VAULT_AUTH_METHOD'],
              'fallback': ''
            },
          },

          'validate_certs': {
            'type': [bool],
            'defaulting': {
##              'ansvar': ['approle_login_mount', 'awxcred_hashivault_approle_mount'],
##              'env': ['ANSIBLE_HASHI_VAULT_AUTH_METHOD', 'VAULT_AUTH_METHOD'],
              'fallback': True
            },
          },

          'return_format': {
            'type': list(string_types),
            'defaulting': {
##              'ansvar': ['approle_login_mount', 'awxcred_hashivault_approle_mount'],
##              'env': ['ANSIBLE_HASHI_VAULT_AUTH_METHOD', 'VAULT_AUTH_METHOD'],
              'fallback': 'dict'
            },
          },

        })

        return tmp


## note: calling other lookup plugin does not properly work atm, because plugin parameters are not properly parsed, the reason for that I think is that whatever magic parses the docu strings and converts it into an argspec is not run when I simply create an object of the plugin, so according to this theory it should work, if one used the called plugin beforehand "normally"
##    def run_specific(self, terms):
##        print("lname: " + str(self._load_name))
##        print("lname: " + str(hashi_vault.LookupModule.__module__))
##        kwargs = {
##          'token': 'foo',
##          'url': self.get_taskparam('url'),
##          'role_id': self.get_taskparam('auth_role_id'),
##          'secret_id': self.get_taskparam('auth_secret_id'),
##          'auth_method': self.get_taskparam('auth_method'),
##          'mount_point': self.get_taskparam('auth_mp'),
##        }
##
##        return self.run_other_lookup_plugin(
##          ##hashi_vault.LookupModule, *terms, **kwargs
##          hashivault_dbg.LookupModule, *terms, **kwargs
##        )

    def run_specific(self, terms):
        # note: this is atm unfortunately copy and pasted from hashi_vault.LookupModule because calling lookup modules does not work yet
        if not HAS_HVAC:
          raise AnsibleError("Please pip install hvac to use the hashi_vault lookup module.")

        ret = []

        # convert our opts to upstream opts
        conv_table = {
          'auth_role_id': 'role_id',
          'auth_secret_id': 'secret_id',
          'auth_mp': 'mount_point',
        }

        opts = copy.deepcopy(self._taskparams)

        # note: anything not explicitly mentioned in conv_table 
        #   will be passed through 1:1
        for (k,v) in iteritems(conv_table):
            opts[v] = opts.pop(k)

        for term in terms:
            # convert our params to upstream params
            tmp = copy.deepcopy(opts)
            tmp.update(self.parse_term(term))
            self._options = tmp

            self.process_options()
            client = hashi_vault.HashiVault(**self._options)
            client.authenticate()
            ret.extend(client.get())

        return ret


    # note: overwrites hashivault.LookupModule, this is broken in my setup but also not needed
    def low_preference_env_vars(self):
        pass

