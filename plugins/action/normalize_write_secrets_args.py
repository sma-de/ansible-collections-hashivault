
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from ansible.errors import AnsibleOptionsError
##from ansible.module_utils.six import iteritems, string_types

from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import default_param_value
from ansible_collections.smabot.base.plugins.module_utils.plugins.config_normalizing.base import ConfigNormalizerBaseMerger, NormalizerBase, NormalizerNamed, DefaultSetterConstant, DefaultSetterOtherKey

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import SUBDICT_METAKEY_ANY, setdefault_none, get_subdict

from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert



class ConfigRootNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          LoginNormer(pluginref),
          SecretInstNormer(pluginref),
        ]

        super(ConfigRootNormalizer, self).__init__(pluginref, *args, **kwargs)


class LoginNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(LoginNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['enabled'] = DefaultSetterConstant(True)

    @property
    def simpleform_key(self):
        return 'enabled'

    @property
    def config_path(self):
        return ['login']


class SecretInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        super(SecretInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['config'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return ['secrets', SUBDICT_METAKEY_ANY]

    @property
    def name_key(self):
        return 'path'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']

        c['secret'] = my_subcfg['path']
        c['data'] = my_subcfg['data']

        se = my_subcfg.get('secret_engine', None)

        if se:
            c['mount_point'] = se

        setdefault_none(c, 'state', 'present')
        return my_subcfg


class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(ConfigRootNormalizer(self),
            *args,
            ##default_merge_vars=[
            ##   'smabot_hashivault_config_instance_args_extra'
            ##],
            ##extra_merge_vars_ans=['smabot_hashivault_config_instance_args_extra'],
            **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'smabot_hashivault_write_secrets_args'

