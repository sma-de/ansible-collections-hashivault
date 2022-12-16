
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
          ComposeNormer(pluginref),

          ## depends on compose normer run
          AgentConfigNormer(pluginref),
          InitAuthNormer(pluginref),
          AgentConfigFilesInstNormer(pluginref),

          ## depends on compose agentcfg normer run
          ComposeAllVolumesNormer(pluginref),
          ComposeEnvNormer(pluginref),
        ]

        super(ConfigRootNormalizer, self).__init__(pluginref, *args, **kwargs)

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg['_vol_export_dirs'] = {}
        return my_subcfg

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        init_pot = {}
        noninit_pot = {}
        
        acfg_files = my_subcfg['agent_cfg']['files']

        for k,v in acfg_files.items():
            if v['init_auth']:
                init_pot[k] = v
            else:
                noninit_pot[k] = v

        agent_cfgdirs = [my_subcfg['agent_cfg']['dir']]
        agent_cfgfiles = [my_subcfg['agent_cfg']['cfgfile']]

        if init_pot and noninit_pot:
            ## in this case we have two configs, an initial one to
            ## get the show running and another one for day-to-day
            ## production mode, so we need to create two config
            ## sets and switch between them
            tmp = copy.deepcopy(my_subcfg['agent_cfg']['dir'])
            new_cfgdir = os.path.dirname(
              tmp['host_path']['path']
            ) + '/init_conf.d'

            tmp['host_path']['path'] = new_cfgdir
            my_subcfg['_target_dirs'][new_cfgdir] = {
              'path': new_cfgdir,
            }

            my_rolepath = self.pluginref.get_ansible_var('role_path')
            t2 = "{}/templates/agent_config/initcfg_special".format(my_rolepath)

            tmp['sources'][t2] = {
              'path': t2,
            }

            agent_cfgdirs.append(tmp)

            old_cfgdir = my_subcfg['agent_cfg']['dir']['host_path']['path']
            for k,v in init_pot.items():
                if v['init_auth_only']:
                    acfg_files.pop(k)

                v = copy.deepcopy(v)

                v['target_dir'] = new_cfgdir + '/'\
                   + os.path.relpath(v['target_dir'], start=old_cfgdir)

                acfg_files["init_cfg_" + k] = v

                my_subcfg['_target_dirs'][v['target_dir']] = {
                  'path': v['target_dir'],
                }

            init_cfgfile = copy.deepcopy(my_subcfg['agent_cfg']['cfgfile'])
            init_cfgfile.update(init_cfgfile.pop('initial_opts'))

            init_cfgfile['host_path'] = os.path.dirname(
              init_cfgfile['host_path']
            ) + '/init_cfg.hcl'

            init_cfgfile['config']['src'] = new_cfgdir
            init_cfgfile['config']['dest'] = init_cfgfile['host_path']
            init_cfgfile['initial'] = True

            agent_cfgfiles.append(init_cfgfile)
            my_subcfg['_agent_initialcfg'] = init_cfgfile

        my_subcfg['_agent_confdirs'] = agent_cfgdirs
        my_subcfg['_agent_cfgfiles'] = agent_cfgfiles
        return my_subcfg


class InitAuthNormer(NormalizerBase):

    @property
    def config_path(self):
        return ['init_auth']

    def _handle_method_specific_from_login_approle(self, cfg, my_subcfg, cfgpath_abs):
        login_creds = self.pluginref.get_ansible_var(
          'smabot_hashivault_login_creds', None
        )

        ansible_assert(login_creds,
          "No login creds found, make sure to call the vault login"\
          " role before coming here or alternatively fill"\
          " 'smabot_hashivault_login_creds' manually with the correct values"
        )

        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        fp_cfg = os.path.dirname(pcfg['agent_cfg']['cfgfile']['host_path'])
        mp = my_subcfg['params']

        fp_role = setdefault_none(mp, 'filepath_role_id',
           '{}/.auth_secrets/role_id'.format(fp_cfg)
        )

        tmp = os.path.dirname(fp_role)
        setdefault_none(pcfg, '_target_dirs', {}).update({
          tmp: {'path': tmp},
        })

        fp_secret = setdefault_none(mp, 'filepath_secret',
           '{}/.auth_secrets/secret_id'.format(fp_cfg)
        )

        tmp = os.path.dirname(fp_secret)
        setdefault_none(pcfg, '_target_dirs', {}).update({
          tmp: {'path': tmp},
        })

        my_rolepath = self.pluginref.get_ansible_var('role_path')
        tmp = "{}/templates/agent_auth_methods/auth_approle.hcl.j2".format(my_rolepath)

        cfgfiles = setdefault_none(pcfg['agent_cfg'], 'files', {})
        cfgfiles['init_auth'] = {
          'init_auth_only': True,
          'src': tmp,
          'target_name': "20_init_auth.hcl",
          'template_vars': {
             'ROLE_ID_FILE': os.path.relpath(fp_role, start=fp_cfg),
             'SECRET_ID_FILE': os.path.relpath(fp_secret, start=fp_cfg),
             'MOUNT_POINT': 'auth/' + login_creds['login_mount'],
          }
        }


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        if not my_subcfg:
            ## init auth feature is totally optional and can be empty/unused
            return my_subcfg

        setdefault_none(my_subcfg, 'params', {})

        method = my_subcfg.get('method', None)
        ansible_assert(method, "Must supply a method to to use for init_auth")

        tmp = getattr(self,
          '_handle_method_specific_' + method, None
        )

        ansible_assert(tmp,
          "unsupported init_auth method '{}'".format(method)
        )

        tmp(cfg, my_subcfg, cfgpath_abs)
        return my_subcfg


class AgentConfigNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          AgentConfigCfgFileNormer(pluginref),
          AgentConfigDirNormer(pluginref),
          AgentConfigCtmplInstNormer(pluginref),

          ## depends on ConfigDirNormer
          AgentConfigCfgFilePostNormer(pluginref),
        ]

        super(AgentConfigNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['agent_cfg']


class AgentConfigCfgFileNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(AgentConfigCfgFileNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['initial_opts'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return ['cfgfile']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg['initial'] = False

        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)

        setdefault_none(my_subcfg, 'host_path',
          pcfg['compose']['dir'] + '/config/config.hcl'
        )

        tmp = os.path.dirname(my_subcfg['host_path'])

        setdefault_none(pcfg, '_target_dirs', {}).update({
          tmp: {'path': tmp},
        })

        tmp = setdefault_none(my_subcfg, 'config', {})
        tmp['dest'] = my_subcfg['host_path']

        return my_subcfg


class AgentConfigCfgFilePostNormer(NormalizerBase):

    @property
    def config_path(self):
        return ['cfgfile']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        my_subcfg['config']['src'] = pcfg['dir']['host_path']['path']
        return my_subcfg


class AgentConfigCtmplInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        super(AgentConfigCtmplInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['template_vars'] = DefaultSetterConstant({})
        self.default_setters['config'] = DefaultSetterConstant({})

    @property
    def name_key(self):
        return 'src'

    @property
    def config_path(self):
        return ['ctmpls', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']

        ## note that we have a symbol conflict here on default as
        ## both ansible/jinja and the vault agent template engine
        ## use "{{" and "}}" as their default variable meta symbols
        setdefault_none(c, 'variable_start_string', '[[')
        setdefault_none(c, 'variable_end_string', ']]')

        ## default target dir
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)

        td = setdefault_none(my_subcfg, 'target_dir', 'templates')

        if not os.path.isabs(td):
            td = os.path.dirname(pcfg['cfgfile']['host_path']) + '/' + td
            my_subcfg['target_dir'] = os.path.normpath(td)

        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)
        setdefault_none(pcfg, '_target_dirs', {}).update({
          my_subcfg['target_dir']: {'path': my_subcfg['target_dir']},
        })

        ## default target name
        tmp = my_subcfg.get('target_name', None)
        if not tmp:
            tmp = os.path.basename(my_subcfg['src'])
            tmp = os.path.splitext(tmp)
            my_subcfg['target_name'] = tmp[0]

        return my_subcfg


class AgentConfigFilesInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        super(AgentConfigFilesInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['template_vars'] = DefaultSetterConstant({})
        self.default_setters['init_auth'] = DefaultSetterConstant(True)
        self.default_setters['init_auth_only'] = DefaultSetterConstant(False)

    @property
    def name_key(self):
        return 'src'

    @property
    def config_path(self):
        return ['agent_cfg', 'files', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## default target dir
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)

        td = setdefault_none(my_subcfg, 'target_dir', './')
        td = pcfg['dir']['host_path']['path'] + '/' + td
        my_subcfg['target_dir'] = os.path.normpath(td)

        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)
        setdefault_none(pcfg, '_target_dirs', {}).update({
          my_subcfg['target_dir']: {'path': my_subcfg['target_dir']},
        })

        ## if this cfg file references ctmplates files,
        ## we set the correct path template var here
        tmp = my_subcfg.get('ctmpl_file', None)
        if tmp:
            pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
            tmp = pcfg['ctmpls'][tmp]
            tmp = tmp['target_dir'] + '/' + tmp['target_name']
            tmp = os.path.relpath(tmp,
              start=os.path.dirname(pcfg['cfgfile']['host_path'])
            )

            my_subcfg['template_vars']['SRCFILE'] = tmp

        return my_subcfg


class AgentConfigDirNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          AgentConfigDirHostPathNormer(pluginref),
          AgentConfigDirAllSourcesNormer(pluginref),
        ]

        super(AgentConfigDirNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['dir']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        setdefault_none(my_subcfg, 'host_path',
          os.path.dirname(pcfg['cfgfile']['host_path']) + '/conf.d'
        )

        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)

        setdefault_none(pcfg, '_target_dirs', {}).update({
          my_subcfg['host_path']: {'path': my_subcfg['host_path']},
        })

        return my_subcfg


class AgentConfigDirHostPathNormer(NormalizerBase):

    @property
    def simpleform_key(self):
        return 'path'

    @property
    def config_path(self):
        return ['host_path']


class AgentConfigDirAllSourcesNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          AgentConfigDirSourceNormer(pluginref),
        ]

        super(AgentConfigDirAllSourcesNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['sources']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        # add default config templates
        # TODO: make default cfgtemlates disablableable??
        my_rolepath = self.pluginref.get_ansible_var('role_path')
        tmp = "{}/templates/agent_config/always".format(my_rolepath)

        my_subcfg[tmp] = None

        return my_subcfg


class AgentConfigDirSourceNormer(NormalizerNamed):

    @property
    def name_key(self):
        return 'path'

    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]



class ComposeNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          ComposeImageNormer(pluginref),
        ]

        super(ComposeNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['service_id'] = DefaultSetterConstant('hashivault_agent')

    @property
    def config_path(self):
        return ['compose']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        setdefault_none(my_subcfg, 'contname', my_subcfg['service_id'])

        setdefault_none(my_subcfg, 'dir',
          '/srv/docker/compose/{}'.format(my_subcfg['service_id'])
        )

        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        tmp = setdefault_none(pcfg, '_target_dirs', {})
        tmp[my_subcfg['dir']] = {'path': my_subcfg['dir']}

        return my_subcfg


class ComposeAllVolumesNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          ComposeVolInstNormer(pluginref),
        ]

        super(ComposeAllVolumesNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['compose', 'volumes']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        ## add agent config dir as standard volume
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
        hp = os.path.dirname(pcfg['agent_cfg']['cfgfile']['host_path'])

        my_subcfg[hp] = {
          'target': '/vault/config/agent',
          ##'options': 'ro',
        }

        return my_subcfg


class ComposeEnvNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(ComposeEnvNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['settings'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return ['compose', 'environment']


class ComposeVolInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        super(ComposeVolInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['options'] = DefaultSetterConstant(None)
        self.default_setters['vault_export_dir'] = DefaultSetterConstant(False)

    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]

    @property
    def name_key(self):
        return 'src'

    @property
    def simpleform_key(self):
        return 'target'

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        setdefault_none(my_subcfg, 'target', my_subcfg['src'])

        # create final mapping string
        tmp = []

        tmp.append(my_subcfg['src'])
        tmp.append(my_subcfg['target'])

        if my_subcfg['options']:
            tmp.append(my_subcfg['options'])

        my_subcfg['_mapping'] = ':'.join(tmp)

        if my_subcfg['vault_export_dir']:
            pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)
            pcfg['_vol_export_dirs'][my_subcfg['src']] = {
              'path': my_subcfg['src'],
            }

        return my_subcfg


class ComposeImageNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(ComposeImageNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['name'] = DefaultSetterConstant('vault')
        self.default_setters['version'] = DefaultSetterConstant('latest')

    @property
    def config_path(self):
        return ['image']


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
        return 'smabot_hashivault_agent_dockcomp_args'

