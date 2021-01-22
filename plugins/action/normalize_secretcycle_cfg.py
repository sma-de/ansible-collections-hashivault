
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import re

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
          GitLabSshKeyUserNormalizer(pluginref),
          GitLabSshKeyDeployNormalizer(pluginref),
          GitLabUsrTokenNormalizer(pluginref),
        ]

        super(CyclersNormalizer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['cyclers']


class GitLabNormalizerBase(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          ServersNormalizer(pluginref, authrole='smabot.gitlab.auth_gitlab'),
        ]

        super(GitLabNormalizerBase, self).__init__(
           pluginref, *args, **kwargs
        )


class GitLabSshKeyUserNormalizer(GitLabNormalizerBase):

    def __init__(self, *args, **kwargs):
        super(GitLabSshKeyUserNormalizer, self).__init__(*args, **kwargs)

    @property
    def config_path(self):
        return ['gitlab_ssh_user']


class GitLabSshKeyDeployNormalizer(GitLabNormalizerBase):

    def __init__(self, *args, **kwargs):
        super(GitLabSshKeyDeployNormalizer, self).__init__(*args, **kwargs)

    @property
    def config_path(self):
        return ['gitlab_ssh_deploy']


class GitLabUsrTokenNormalizer(GitLabNormalizerBase):

    def __init__(self, *args, **kwargs):
        super(GitLabUsrTokenNormalizer, self).__init__(*args, **kwargs)

    @property
    def config_path(self):
        return ['gitlab_user_token']


class WinAdUserNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          ServersWinAdNormalizer(pluginref),
        ]

        super(WinAdUserNormalizer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['winad_user']


class ServersNormalizer(NormalizerBase):

    def __init__(self, pluginref, *args, authrole=None, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          self.cycles_normtype(pluginref),
        ]

        super(ServersNormalizer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.authrole = authrole


    @property
    def config_path(self):
        return ['servers', SUBDICT_METAKEY_ANY]

    @property
    def cycles_normtype(self):
        return SecretCyclesNormer


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        if self.authrole:
            setdefault_none(setdefault_none(my_subcfg, 'auth', {}), 
              'role', self.authrole
            )

        return my_subcfg


class ServersWinAdNormalizer(ServersNormalizer):

    @property
    def server_inst_type(self):
        return SecretCyclesWinAdNormer


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

        return super(ServersWinAdNormalizer, self)._handle_specifics_presub(
          cfg, my_subcfg, cfgpath_abs
        )


class SecretCyclesNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          SecretCyclesSubjectsNormer(pluginref),
        ]

        super(SecretCyclesNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['unset_ok'] = DefaultSetterConstant(False)


    @property
    def allow_unsetting(self):
        return True

    @property
    def config_path(self):
        return ['cycles', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        sp = setdefault_none(my_subcfg, 'secret_path', {})
        setdefault_none(sp, 'prefix', '')
        setdefault_none(sp, 'suffix', '')
        return my_subcfg


class SecretCyclesWinAdNormer(SecretCyclesNormer):

    def __init__(self, pluginref, *args, **kwargs):
        super(SecretCyclesWinAdNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['pwlen'] = DefaultSetterConstant(40)


class SecretCyclesSubjectsNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        super(SecretCyclesSubjectsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['subjects', SUBDICT_METAKEY_ANY]


    def _subst_vault_path(self, vp, cfg, cfgpath_abs):
        # we support some special var replacements inside vault paths

        ## handle magic var 'server_id' which is based on the url 
        ## with some modifications (replacing '.' by '_')
        server = self.get_parentcfg(cfg, cfgpath_abs, level=4)
        tmp = server['connection']['host'].replace('.', '_')

        vp = re.sub(r'\{\$\s*server_id\s*\$\}', tmp, vp)
        return vp


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        tmp = self.get_parentcfg(cfg, cfgpath_abs, level=2)

        vp = tmp['secret_path']['prefix'] \
          + (my_subcfg.get('vault_path') or my_subcfg['name']) \
          + tmp['secret_path']['suffix']

        my_subcfg['vault_path'] = self._subst_vault_path(vp, cfg, cfgpath_abs)

        setdefault_none(my_subcfg, 'unset_ok', tmp['unset_ok'])

        return my_subcfg



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

