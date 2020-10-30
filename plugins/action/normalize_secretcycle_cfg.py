
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


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
          CyclersNormalizer(pluginref),
        ]

        super(ConfigRootNormalizer, self).__init__(pluginref, *args, **kwargs)


class CyclersNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          WinAdUserNormalizer(pluginref),
        ]

        super(CyclersNormalizer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['cyclers']


class WinAdUserNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          WinAdUserServersNormalizer(pluginref),
        ]

        super(WinAdUserNormalizer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['winad_user']


class WinAdUserServersNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          WinAdUserSrvInstNormalizer(pluginref),
        ]

        super(WinAdUserServersNormalizer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['servers']


class WinAdUserSrvInstNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          SecretCyclesNormer(pluginref),
        ]

        super(WinAdUserSrvInstNormalizer, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]


    def _create_val_defaulter_fn(self, valname, defcfg):
        def val_defaulter_fn(defval):
            return default_param_value(
               valname, defcfg, self.pluginref._ansible_varspace, 
               self.pluginref._templar
            )
    
        return val_defaulter_fn


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        if my_subcfg.get('default', False):
            ## this instance is the default instance, do special stuff

            ## default mandatory server description params from ansvars
            setdefault_none(my_subcfg, 'url', 
               ##
               ## note: it is totally possible that value defaulting 
               ##   will fail if referenced variables are not set, but 
               ##   this is not an issue if an explicit value is given, 
               ##   so make sure that defaulting is done lazy (only 
               ##   when really needed)
               ##
               defval_fn=self._create_val_defaulter_fn(
                 'url', {'ansvar': ['awxcred_ldap_server']}
               )
            )

            setdefault_none(my_subcfg, 'domain', 
               defval_fn=self._create_val_defaulter_fn(
                 'domain', {'ansvar': ['awxcred_ldap_domain']}
               )
            )

            setdefault_none(my_subcfg, 'base_dn', 
               defval_fn=self._create_val_defaulter_fn(
                 'base_dn', {'ansvar': ['awxcred_ldap_base_dn']}
               )
            )

        return my_subcfg


class SecretCyclesNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          SecretCyclesInstNormer(pluginref),
        ]

        super(SecretCyclesNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['cycles']


class SecretCyclesInstNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          SecretCyclesSubjectsNormer(pluginref),
        ]

        super(SecretCyclesInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['pwlen'] = DefaultSetterConstant(40)

    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        sp = setdefault_none(my_subcfg, 'secret_path', {})
        setdefault_none(sp, 'prefix', '')
        setdefault_none(sp, 'suffix', '')
        return my_subcfg


class SecretCyclesSubjectsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          SecretCyclesSubjectInstNormer(pluginref),
        ]

        super(SecretCyclesSubjectsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['subjects']


class SecretCyclesSubjectInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        super(SecretCyclesSubjectInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['vault_path'] = DefaultSetterOtherKey('name')


    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]



class ActionModule(ConfigNormalizerBaseMerger):

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(ConfigRootNormalizer(self), 
            *args, default_merge_vars=['hvault_cycle_secrets_defaults'], 
            extra_merge_vars_ans=['extra_hvault_cycle_secrets_config_maps'], 
            **kwargs
        )

        self._supports_check_mode = False
        self._supports_async = False


    @property
    def my_ansvar(self):
        return 'hvault_cycle_secrets_cfg'

