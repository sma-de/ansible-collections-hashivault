
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import copy
from urllib.parse import urlparse

from ansible.errors import AnsibleOptionsError
##from ansible.module_utils.six import iteritems, string_types

from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import default_param_value
from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.base import ConfigNormalizerBaseMerger, NormalizerBase, NormalizerNamed, DefaultSetterConstant, DefaultSetterOtherKey

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import SUBDICT_METAKEY_ANY, setdefault_none

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert



class ConfigRootNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          AuthMethodInstNormer(pluginref),
          PoliciesNormer(pluginref),
          AppRolersNormer(pluginref),
          SecretEnginesNormer(pluginref),
          LoginCredsNormer(pluginref),
        ]

        super(ConfigRootNormalizer, self).__init__(pluginref, *args, **kwargs)
        self.default_setters['initial_config'] = DefaultSetterConstant({})

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        url = urlparse(my_subcfg['server_url'])

        my_subcfg['connection'] = {
          'scheme': url.scheme,
          'host': url.hostname,
          'port': url.port,
        }

        return my_subcfg


class LoginCredsNormer(NormalizerBase):

    @property
    def config_path(self):
        return ['login', 'creds']


    def _default_login_from_updcreds_azure_keyvault(self,
       vaultman, credtype, cfg, my_subcfg, cfgpath_abs
    ):
        res = copy.deepcopy(vaultman['update_creds'])
        res.pop('enabled')

        tmp = {}

        ntmpl = vaultman['update_creds']['name_template']

        for k in ['id', 'secret', 'login_mount']:
            n = ntmpl.format(credtype, vaultman['config']['name']) + '_' + k
            n = n.replace('_', '-')

            tmp[k] = {
              'name': n,
            }

        t2 = setdefault_none(res, 'params', {})
        t2['get_secrets'] = {
          'secrets': tmp
        }
        
        my_subcfg.update(res)


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)

        if not my_subcfg:
            # if no login creds are explicitly set
            # default to vaultman update creds config
            vman = pcfg.get('approlers', {}).get('_vaultman', None)

            ansible_assert(vman,
              "No vaultmanager approle defined, so defaulting login"\
              " credentials is not possible, please specify some explicitly"
            )

            tmp = vman['update_creds']

            ansible_assert(tmp['method'],
              "Defined vaultmanager approle has no update method"\
              " defined, defaulting login credentials not"\
              " possible, please specify some explicitly"
            )

            deffn = getattr(self,
              '_default_login_from_updcreds_' + str(tmp['method']),
              None
            )

            ansible_assert(deffn,
              "Defined vaultmanager approle defined update credential"\
              " method '{}' is not supported for defaulting login"\
              " credentials, please specify some explicitly".format(
                 tmp['method']
              )
            )

            deffn(vman, 'approle', cfg, my_subcfg, cfgpath_abs)

        return my_subcfg


class SecretEnginesNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          AllEnginesNormer(pluginref),
        ]

        super(SecretEnginesNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['secret_engines']


class AllEnginesNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          EngineInstNormer(pluginref),
        ]

        super(AllEnginesNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['engines']


class EngineInstNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          EngineInstDefPolsNormer(pluginref),
        ]

        super(EngineInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['default_policies'] = DefaultSetterConstant(True)

    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        c = setdefault_none(my_subcfg, 'config', {})

        setdefault_none(c, 'state', 'present')
        c['name'] = my_subcfg['mount_point']
        c['backend'] = my_subcfg['type']

        return my_subcfg


class EngineInstDefPolsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          PolSrcDirInstNormer(pluginref),
          EngineInstDefPolInstNormer(pluginref),
        ]

        super(EngineInstDefPolsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['dirs'] = DefaultSetterConstant({
          'templates/vault_policies/engine_defaults': None,
        })

        self.default_setters['policies'] = DefaultSetterConstant({
          'templates/vault_policies/manage_secret_engine.hcl.j2': {
             'config': { 'name': 'manage' },
          },
        })


    @property
    def simpleform_key(self):
        return "enabled"

    @property
    def config_path(self):
        return ['default_policies']


class EngineInstDefPolInstNormer(NormalizerNamed):

##    def __init__(self, pluginref, *args, **kwargs):
##        super(EngineInstDefPolInstNormer, self).__init__(
##           pluginref, *args, **kwargs
##        )

    @property
    def config_path(self):
        return ['policies', SUBDICT_METAKEY_ANY]

    @property
    def name_key(self):
        return 'src'


##
## TODO: support other types of vault managers besides approle???
##
class AppRolersNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          AppRolersInstNormer(pluginref),
        ]

        super(AppRolersNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['approlers']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        vman = []

        for k,v in my_subcfg.get('approlers', {}).items():
            if v['vault_manager']:
                tmp = not vman
                vman.append(v)
                ansible_assert(tmp, 
                   "There can only be one approle responsible as"\
                   " vault manager, but found at least 2: {}".format(vman)
                )

        if vman:
            vman = vman[0]
        else:
            vman = None

        my_subcfg['_vaultman'] = vman
        return my_subcfg


class AppRolersInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          (UpdateCredsNormer, True),
        ]

        super(AppRolersInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['update_creds'] = DefaultSetterConstant(False)
        self.default_setters['init_policies'] = DefaultSetterConstant(False)
        self.default_setters['vault_manager'] = DefaultSetterConstant(False)
        self.default_setters['policies'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return ['approlers', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        if my_subcfg['vault_manager']:
            my_subcfg['init_policies'] = True

        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)

        c = {
          'name': my_subcfg['name'],
          'mount_point': pcfg['auth_methods'][my_subcfg['auther']]['mount_point'],
          'policies': my_subcfg['policies'],
          'state': 'present',
        }

        c.update(my_subcfg.get('options', {}))
        my_subcfg['config'] = c

        return my_subcfg


class UpdateCredsNormer(NormalizerBase):

    NORMER_CONFIG_PATH = ['update_creds']

    def __init__(self, pluginref, *args, **kwargs):
        super(UpdateCredsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['method'] = DefaultSetterConstant(None)
        self.default_setters['params'] = DefaultSetterConstant({})
        self.default_setters['enabled'] = DefaultSetterConstant(True)
        self.default_setters['name_template'] = DefaultSetterConstant('hashivault_{}_{}')

    @property
    def simpleform_key(self):
        return "enabled"

    @property
    def config_path(self):
        return self.NORMER_CONFIG_PATH


class AuthMethodInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          AuthMethodPolicyNormer(pluginref),
        ]

        super(AuthMethodInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['extra_opts'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return ['auth_methods', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        setdefault_none(my_subcfg, 'type', my_subcfg['name'])

        ## on default a specific (management) policy for each auth method
        ## is created, can be optionally disabled by setting 'policy'
        ## subkey to something falsy != None (empty) or a custom policy
        ## can be used by explicitly setting it to a path to a custom
        ## policy file
        setdefault_none(my_subcfg, 'policy',
           'templates/vault_policies/manage_authmethod.hcl.j2'
        )

        ##setdefault_none(my_subcfg, 'mount_point', my_subcfg['type'] + '/')
        tmp = setdefault_none(my_subcfg, 'mount_point', my_subcfg['type'])

        if tmp[-1] == '/':
            my_subcfg['mount_point'] = tmp[:-1]

        c = setdefault_none(my_subcfg, 'config', {})
        setdefault_none(c, 'state', 'enabled')

        c['method_type'] = my_subcfg['type']

        tmp = my_subcfg['mount_point']

##        if tmp[-1] == '/':
##            tmp = tmp[:-1]

        c['mount_point'] = tmp

        c['config'] = my_subcfg['extra_opts']

        if not c['config']:
            c.pop('config')

        return my_subcfg


class AuthMethodPolicyNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(AuthMethodPolicyNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['state'] = DefaultSetterConstant('present')

    @property
    def config_path(self):
        return ['policy']

    @property
    def simpleform_key(self):
        return "rules"

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        setdefault_none(my_subcfg, 'name', "manage_authx_{}".format(pcfg['name']))

        if pcfg['config']['state'] != 'enabled':
            my_subcfg['state'] = 'absent'

        return my_subcfg


class PoliciesNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          PolicySourceDirsNormer(pluginref),
          PolicyOverwritesNormer(pluginref),
        ]

        super(PoliciesNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['policies']


class PolicySourceDirsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          PolSrcDirInstNormer(pluginref),
        ]

        super(PolicySourceDirsNormer, self).__init__(pluginref, *args, **kwargs)

        self.default_setters['no_defaults'] = DefaultSetterConstant(False)
        self.default_setters['dirs'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return ['source_dirs']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        if not my_subcfg['no_defaults']:
            for x in ['basic', 'admin']:
                my_subcfg['dirs']['templates/vault_policies/{}'.format(x)] = {
                  'tags': {
                     'init_pol': None
                  },
                }

        return my_subcfg


class PolSrcDirInstNormer(NormalizerNamed):

##    def __init__(self, *args, **kwargs):
##        super(PolSrcDirInstNormer, self).__init__(*args, **kwargs)

    @property
    def config_path(self):
        return ['dirs', SUBDICT_METAKEY_ANY]

    @property
    def name_key(self):
        return 'path'


class PolicyOverwritesNormer(NormalizerNamed):

    def __init__(self, *args, **kwargs):
        super(PolicyOverwritesNormer, self).__init__(*args, **kwargs)
        self.default_setters['state'] = DefaultSetterConstant('present')

    @property
    def config_path(self):
        return ['policy_overwrites', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg['config'] = {
          'name': my_subcfg['name'],
          'state': my_subcfg['state'],
        }

        return my_subcfg


class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(ConfigRootNormalizer(self), 
            *args, default_merge_vars=[
               'smabot_hashivault_config_instance_args_extra'
            ],
            ##extra_merge_vars_ans=['smabot_hashivault_config_instance_args_extra'],
            **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_hashivault_config_instance_args'

