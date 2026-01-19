
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import json


from ansible.errors import AnsibleOptionsError
##from ansible.module_utils.six import iteritems, string_types
from ansible.utils.display import Display

from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import default_param_value
from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.base import ConfigNormalizerBaseMerger, NormalizerBase, NormalizerNamed, DefaultSetterConstant, DefaultSetterOtherKey

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import SUBDICT_METAKEY_ANY, setdefault_none, get_subdict

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert


display = Display()


class ConfigRootNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          LoginNormer(pluginref),
          UseVenvNormer(pluginref),
          SystemSetupNormer(pluginref),
          GetSecretsNormer(pluginref),
          SetSecretInstNormer(pluginref),
          RemoveSecretsInstNormer(pluginref),
        ]

        super(ConfigRootNormalizer, self).__init__(pluginref, *args, **kwargs)

        self.default_setters['hide_secrets'] = DefaultSetterConstant(True)



class SystemSetupNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(SystemSetupNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['enabled'] = DefaultSetterConstant(True)

    @property
    def simpleform_key(self):
        return 'enabled'

    @property
    def config_path(self):
        return ['system_setup']


class UseVenvNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(UseVenvNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['enabled'] = DefaultSetterConstant(True)

    @property
    def simpleform_key(self):
        return 'enabled'

    @property
    def config_path(self):
        return ['use_venv']


class LoginNormer(NormalizerBase):

    @property
    def simpleform_key(self):
        return 'enabled'

    @property
    def config_path(self):
        return ['login']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ena = my_subcfg.pop('enabled', None)

        if ena is None:
            ##
            ## if caller explicitly set anything here besides
            ## enabled flag we assume they want login to
            ## happening on default, otherwise login will be
            ## disabled on default as experience has shown
            ## that in most practical contextes it is more
            ## practical to have some kind of pre-auth instead
            ## of using builtin login feature here, so having this on
            ## false as default is the actually the more senseable
            ## choice here
            ##
            ena = bool(my_subcfg)

        my_subcfg['enabled'] = ena
        return my_subcfg



class SecretInstNormerBase(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        super(SecretInstNormerBase, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['config'] = DefaultSetterConstant({})

    @property
    def name_key(self):
        return 'path'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## TODO: change from terryhow modules to community modules
        c = my_subcfg['config']

        c['secret'] = my_subcfg['path']

        se = my_subcfg.get('secret_engine', None)

        if se:
            c['mount_point'] = se

        return my_subcfg


##
## instead of terry-how based standard module interface
## use community modules one
##
class SecretInstNormerBaseCommunity(SecretInstNormerBase):

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        super(SecretInstNormerBaseCommunity, self)._handle_specifics_presub(
          cfg, my_subcfg, cfgpath_abs
        )

        c = my_subcfg['config']
        c['path'] = c.pop('secret')
        c['engine_mount_point'] = c.pop('mount_point')

        return my_subcfg


# TODO: support reading all and matching per regex
class GetSecretsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          GetSecretInstNormer(pluginref),
        ]

        super(GetSecretsNormer, self).__init__(pluginref, *args, **kwargs)

        self.default_setters['return_list'] = DefaultSetterConstant(False)
        self.default_setters['return_layout'] = DefaultSetterConstant('vault_paths_nested')

    @property
    def config_path(self):
        return ['get_secrets']


class GetSecretInstNormer(SecretInstNormerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(GetSecretInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['optional'] = DefaultSetterConstant(False)
        self.default_setters['only_values'] = DefaultSetterConstant(True)
        self.default_setters['return_secrets'] = DefaultSetterConstant(True)
        self.default_setters['key_filters'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return ['secrets', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        super(GetSecretInstNormer, self)._handle_specifics_presub(
          cfg, my_subcfg, cfgpath_abs
        )

        # map classic data keys feature to new more general key_filters method
        dk = my_subcfg.get('data_keys', None)

        if dk:
            my_subcfg['key_filters']['data_keys'] = {
              'type': 'one_of',
              'args': {
                'one_of_lst': dk,
              },
            }

        c = my_subcfg['config']

        # note: currently used version of upstream library is
        #   somewhat dated and still has kv engine 1 as default,
        #   but it should obviously be version 2
        setdefault_none(c, 'version', 2)

        ## note: atm we use terryhowe modules for writing and already did the switch to community modules for reading which means we need to convert between modules api's for now here
        c['path'] = c.pop('secret')
        c['engine_mount_point'] = c.pop('mount_point')

        my_subcfg['kv_version'] = c.pop('version')
        return my_subcfg


class SetSecretInstNormer(SecretInstNormerBase):

    @property
    def config_path(self):
        return ['set_secrets', 'secrets', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        display.vvv("handle secret setter '{}':\n{}".format(
            '.'.join(cfgpath_abs), json.dumps(my_subcfg, indent=2))
        )

        super(SetSecretInstNormer, self)._handle_specifics_presub(
          cfg, my_subcfg, cfgpath_abs
        )

        c = my_subcfg['config']
        c['data'] = my_subcfg['data']

        setdefault_none(c, 'state', 'present')
        return my_subcfg


class RemoveSecretsInstNormer(SecretInstNormerBaseCommunity):

    @property
    def config_path(self):
        return ['remove_secrets', 'secrets', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        super(RemoveSecretsInstNormer, self)._handle_specifics_presub(
          cfg, my_subcfg, cfgpath_abs
        )

        c = my_subcfg['config']

        vers = my_subcfg.get('versions', None)

        if vers:
            c['versions'] = vers

        return my_subcfg



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(ConfigRootNormalizer(self),
            *args, default_merge_vars=[
               'smabot_hashivault_readwrite_secrets_args_defaults',
            ],
            ##extra_merge_vars_ans=['smabot_hashivault_config_instance_args_extra'],
            **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_hashivault_readwrite_secrets_args'

