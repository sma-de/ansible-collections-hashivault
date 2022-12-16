
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import abc
import copy
from urllib.parse import urlparse
import os

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
          AgentNormer(pluginref),
          CertsInstNormer(pluginref),
          SelfAuthNormer(pluginref),
        ]

        super(ConfigRootNormalizer, self).__init__(pluginref, *args, **kwargs)


class SelfAuthNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        super(SelfAuthNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['enabled'] = DefaultSetterConstant(True)
        self.default_setters['mount_point'] = DefaultSetterConstant('auth/cert')

    @property
    def config_path(self):
        return ['self_auth']

    @property
    def simpleform_key(self):
        return 'enabled'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        if not my_subcfg['enabled']:
            return my_subcfg

        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        auth_cert = my_subcfg.get('cert', None)

        tmp = pcfg['certs']['certs']
        ansible_assert(tmp,
          "No cert templating setup, configure at least one cert to template"
        )

        if not auth_cert:
            ansible_assert(len(tmp) == 1,
               "Found more than one cert config to template which means"\
               " auto defaulting which one to use for self authing is"\
               " not possible, please explicitly set one of these for"\
               " self authing purposes: {}".format(list(tmp.keys()))
            )

            auth_cert = next(iter(tmp.keys()))
            my_subcfg['cert'] = auth_cert

        my_subcfg['cert'] = pcfg['certs']['certs'][auth_cert]
        ccert = my_subcfg['cert']['target_paths']['only_cert']

        tvars = {
          'MOUNT_POINT': my_subcfg['mount_point'],
          'CLIENT_CERT': ccert,
          'CLIENT_KEY': my_subcfg['cert']['target_paths']['private_key'],
        }

        tmp = my_subcfg.get('role', None)
        if tmp:
            tvars['ROLE_NAME'] = tmp

        my_rolepath = self.pluginref.get_ansible_var('role_path')
        tmp = "{}/templates/self_cert_auth.hcl.j2".format(my_rolepath)

        cfgfiles = setdefault_none(pcfg['agent']['agent_cfg'], 'files', {})
        cfgfiles['self_auth'] = {
          'src': tmp,
          'target_name': "40_self_auth.hcl",
          'template_vars': tvars,
          'init_auth': False,
        }

        tmp = setdefault_none(pcfg['agent']['agent_cfg']['cfgfile'],
          'initial_opts', {}
        )

        # it should not matter which of the created cert files we
        # use as reference here, just choose one
        tmp['creates'] = ccert

        return my_subcfg


class CertsInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          CertsInstOptsNormer(pluginref),
          CertsInstTargetPathsNormer(pluginref),
        ]

        super(CertsInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['mount_point'] = DefaultSetterConstant('pki')

    @property
    def config_path(self):
        return ['certs', 'certs', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)
        token = None

        ## default role name
        if not my_subcfg.get('role_name', None):
            if not token:
                tk = self.pluginref.get_ansible_var(
                  'smabot_hashivault_login_creds'
                )

                token = tk['token']

            tmp = self.pluginref.exec_module(
               'terryhowe.hashivault.hashivault_pki_role_list',
               modargs={
                 'token': token,
                 'url': pcfg['server_url'],
                 'mount_point': my_subcfg['mount_point'],
               }
            )

            tmp = tmp['data']

            ansible_assert(tmp,
               "Cannot default role for given pki mountpoint '{}',"\
               " no roles found for this mountpoint".format(
                  my_subcfg['mount_point']
               )
            )

            my_subcfg['role_name'] = tmp[0]

        ## default domain
        if not my_subcfg.get('domain', None):
            if not token:
                tk = self.pluginref.get_ansible_var(
                  'smabot_hashivault_login_creds'
                )

                token = tk['token']

            tmp = self.pluginref.exec_module(
               'terryhowe.hashivault.hashivault_pki_role_get',
               modargs={
                 'token': token,
                 'url': pcfg['server_url'],
                 'mount_point': my_subcfg['mount_point'],
                 'name': my_subcfg['role_name'],
               }
            )

            allowed_domains = tmp['data']['allowed_domains']

            ansible_assert(allowed_domains,
               "Cannot default domain for given role '{}' ('{}'), it"\
               " seems that no domains are allowed for this"\
               " endpoint".format(my_subcfg['role_name'],
                   my_subcfg['mount_point']
               )
            )

            tmp = allowed_domains[0]
            t2 = tmp.split('.')

            if '*' in t2[0]:
                t2 = t2[1:]

                ansible_assert(t2,
                   "Cannot default domain for given role '{}' ('{}')"\
                   " and determined avaible domains {} as first entry '{}'"\
                   " is empty when the glob part is removed".format(
                       my_subcfg['role_name'],
                       my_subcfg['mount_point'], allowed_domains, tmp
                   )
                )

                tmp = '.'.join(t2)

            ansible_assert("*" not in tmp,
               "Cannot default domain for given role '{}' ('{}') and"\
               " determined avaible domains {} as defaulting for domains"\
               " with globs is only supported when there is just one glob"\
               " in the first part of the domain, but given first domain"\
               " entry '{}' has more globs".format(my_subcfg['role_name'],
                  my_subcfg['mount_point'], allowed_domains, tmp
               )
            )

            my_subcfg['domain'] = tmp

        return my_subcfg


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)

        ## create upstream cfg settings
        my_rolepath = self.pluginref.get_ansible_var('role_path')
        tmp = "{}/templates/ssl_template_source.ctmpl.j2".format(my_rolepath)

        ## stringify request options
        opts = []

        for k,v in my_subcfg['options'].items():
            opts.append('"{}={}"'.format(k, v))

        opts = ' '.join(opts)

        files_id = 'ssl_cert_' + my_subcfg['name']

        ctmpls = setdefault_none(pcfg['agent']['agent_cfg'], 'ctmpls', {})
        ctmpls[files_id] = {
          'src': tmp,
          'target_name': "ssl_cert_{}.ctmpl".format(my_subcfg['name']),
          'template_vars': {
             'MOUNT_POINT': my_subcfg['mount_point'],
             'ROLE_NAME': my_subcfg['role_name'],
             'REQUEST_PARAMS': opts,
          }
        }

        ## note: technically neither a hcl nor a direct agent cfgfile
        ##   but can be templated convienently with the same mechanism
        tmp = "{}/templates/exec_scripts/split_cert_super_pem.sh.j2".format(my_rolepath)

        target_relpath = 'exec_scripts/split_cert_super_pem.sh'

        ctmpls[files_id + '_exec_script'] = {
          'src': tmp,
          'target_dir': os.path.dirname(target_relpath),
          'target_name': os.path.basename(target_relpath),
          'template_vars': {
             'FILEPATH_PRIVATE_KEY': my_subcfg['target_paths']['private_key'],
             'FILEPATH_CERT_ONLY': my_subcfg['target_paths']['only_cert'],
             'FILEPATH_CERT_CHAINED': my_subcfg['target_paths']['cert_chained'],
             'FILEPATH_CA_CHAIN': my_subcfg['target_paths']['ca_chain'],
          }
        }

        tmp = "{}/templates/ssl_template_stanza.hcl.j2".format(my_rolepath)

        cfgfiles = setdefault_none(pcfg['agent']['agent_cfg'], 'files', {})
        cfgfiles[files_id] = {
          'src': tmp,
          'target_name': "70_template_cfg_{}.hcl".format(my_subcfg['name']),
          'ctmpl_file': files_id,
          'template_vars': {
             'DESTFILE': my_subcfg['target_paths']['super_pem'],
             'EXEC_SCRIPT': target_relpath,
          }
        }

        return my_subcfg


class CertsInstTargetPathsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(CertsInstTargetPathsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['autovol_path'] = DefaultSetterConstant(None)

    @property
    def config_path(self):
        return ['target_paths']

    @property
    def simpleform_key(self):
        return 'super_pem'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        sp = my_subcfg['super_pem']

        tmp = os.path.dirname(sp)

        my_subcfg['private_key'] = tmp + '/' + setdefault_none(
          my_subcfg, 'private_key', 'cert_private_key.pem'
        )

        my_subcfg['only_cert'] = tmp + '/' + setdefault_none(
          my_subcfg, 'only_cert', 'cert_only.pem'
        )

        my_subcfg['cert_chained'] = tmp + '/' + setdefault_none(
          my_subcfg, 'cert_chained', 'cert_chained.pem'
        )

        my_subcfg['ca_chain'] = tmp + '/' + setdefault_none(
          my_subcfg, 'ca_chain', 'cert_ca_chain.pem'
        )

        avp = my_subcfg['autovol_path']

        if avp:
            pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=5)

            tmp = os.path.dirname(my_subcfg[avp])

            vols = setdefault_none(pcfg['agent']['compose'], 'volumes', {})
            vols[tmp] = {
              'vault_export_dir': True,
            }

        return my_subcfg


class CertsInstOptsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(CertsInstOptsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['ttl'] = DefaultSetterConstant('72h')

    @property
    def config_path(self):
        return ['options']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        ## default common name
        hostname = self.pluginref.get_ansible_fact('hostname')
        setdefault_none(my_subcfg, 'common_name',
          "{}.{}".format(hostname, pcfg['domain'])
        )

        return my_subcfg


class AgentNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          ComposeNormer(pluginref),
          AgentConfigNormer(pluginref),
          InitAuthNormer(pluginref),
        ]

        super(AgentNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['agent']


class InitAuthNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(InitAuthNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['method'] = DefaultSetterConstant('from_login_approle')

    @property
    def config_path(self):
        return ['init_auth']


class AgentConfigNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          AgentConfigDirNormer(pluginref),
          AgentConfigFilesAllNormer(pluginref),
        ]

        super(AgentConfigNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['cfgfile'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return ['agent_cfg']


class AgentConfigFilesAllNormer(NormalizerBase):

    @property
    def config_path(self):
        return ['files']


class AgentConfigDirNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          AgentConfigDirSourcesNormer(pluginref),
        ]

        super(AgentConfigDirNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['dir']


class AgentConfigDirSourcesNormer(NormalizerBase):

    @property
    def config_path(self):
        return ['sources']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        my_rolepath = self.pluginref.get_ansible_var('role_path')

        # add default config templates to agent config (TODO: makes this optionally disablable??)
        my_subcfg["{}/templates/agent_static_config".format(my_rolepath)] = None
        return my_subcfg


class ComposeNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(ComposeNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['service_id'] = DefaultSetterConstant(
          'hashivault_agent_sslcerts'
        )

    @property
    def config_path(self):
        return ['compose']


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
        return 'smabot_hashivault_ssl_cert_agent_args'

