
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
          ConnectionNormer(pluginref),
          DockerNormer(pluginref),

          DirsNormer(pluginref),
          SrvCfgNormer(pluginref),

          ## depends on connection normed
          SslNormer(pluginref),
        ]

        super(ConfigRootNormalizer, self).__init__(pluginref, *args, **kwargs)



class SslNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          SslWhenMissingNormer(pluginref),
          SslFilesNormer(pluginref),
        ]

        super(SslNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['ssl']


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        my_subcfg['enabled'] = pcfg['connection']['scheme'] == 'https'
        return my_subcfg


class SslWhenMissingNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        # TODO: when missing behaviours get senseable subkeys in the future, add !!lazy!! normers here for them
        ##subnorms = kwargs.setdefault('sub_normalizers', [])
        ##subnorms += [
        ##  SslFilesNormer(pluginref),
        ##]

        super(SslWhenMissingNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['when_missing']


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        if not pcfg['enabled']:
            return my_subcfg  ## noop

        # on default at standard error behaviour
        if not my_subcfg:
            my_subcfg['error'] = None

        return my_subcfg


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        tmp = len(my_subcfg)
        ansible_assert(tmp == 1,
           "There must always be exactly on 'when_missing' behvaviour"\
           " defined for ssl certs, but found '{}':\n{}".format(
              tmp, my_subcfg
           )
        )

        return my_subcfg


class SslFileNormerBase(NormalizerBase):

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)

        if not pcfg['enabled']:
            return my_subcfg  ## noop
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


class SslFileNormerCert(NormalizerBase):

    @property
    def config_path(self):
        return ['files', 'cert']

class SslFileNormerKey(NormalizerBase):

    @property
    def config_path(self):
        return ['files', 'key']


class DockerNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          DockerImageNormer(pluginref),
        ]

        super(DockerNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['docker']


class DockerImageNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(DockerImageNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['image'] = DefaultSetterConstant('vault')
        self.default_setters['tag'] = DefaultSetterConstant('latest')

    @property
    def config_path(self):
        return ['image']


class DirsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          # mandatory, must be first
          LocalDirComposeRootNormer(pluginref),
          LocalDirConfigNormer(pluginref),
          LocalDirDataNormer(pluginref),
        ]

        super(DirsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['directories']

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        # make list of all local dirs
        locallst = []

        for k,v in my_subcfg['local'].items():
            locallst.append(v)

        my_subcfg['_local_dirs'] = locallst
        return my_subcfg


class LocalDirBaseNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(LocalDirBaseNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['config'] = DefaultSetterConstant({})

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        c = my_subcfg['config']

        c['path'] = my_subcfg['path']
        c['state'] = my_subcfg['directory']

        return my_subcfg


class LocalDirComposeRootNormer(LocalDirBaseNormer):

    @property
    def config_path(self):
        return ['local', 'compose_root']


class LocalDirDataNormer(LocalDirBaseNormer):

    @property
    def config_path(self):
        return ['local', 'data']


class LocalDirConfigNormer(LocalDirBaseNormer):

    @property
    def config_path(self):
        return ['local', 'config']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        setdefault_none(my_subcfg, 'path',
          pcfg['compose_root']['path']
        )

        return super(LocalDirConfigNormer, self)._handle_specifics_presub(
          cfg, my_subcfg, cfgpath_abs
        )


class ConnectionNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(ConnectionNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['connection']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        url = urlparse(my_subcfg['url'])

        ## default url scheme
        scheme = setdefault_none(my_subcfg, 'scheme', url.scheme or 'https')

        ## default url port and if ssl should be verified
        defport = 80

        if scheme == 'https':
            defport = 443
            setdefault_none(my_subcfg, 'validate_ssl', True)
        else:
            setdefault_none(my_subcfg, 'validate_ssl', False)

        my_subcfg['port'] = int(setdefault_none(my_subcfg,
          'port', url.port or defport)
        )

        return my_subcfg


class SrvCfgNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          SrvCfgDefParentRolesDefBehaveNormer(pluginref),
          SrvCfgDefParentRolesAllRolesNormer(pluginref),
        ]

        super(SrvCfgNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['default_config_files'] = \
            DefaultSetterConstant(True)

    @property
    def config_path(self):
        return ['server_config']


class SrvCfgFilesInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        super(SrvCfgFilesInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['template'] = \
            DefaultSetterConstant(True)

    @property
    def name_key(self):
        return 'srcpath'

    @property
    def config_path(self):
        return ['files', 'files', SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        bn = os.path.basename(my_subcfg['srcpath'])

        tmp = os.path.splitext(bn)

        if tmp[1] == '.j2':
            bn = tmp[0]

        return my_subcfg


class SrvCfgDefParentRolesDefBehaveNormer(NormalizerBase):

# TODO: add subnormers here for supported methods 'direct_parent_only', 'all_parents', 'no_defaults' here when this becomes necessary some day
##    def __init__(self, pluginref, *args, **kwargs):
##        super(SrvCfgDefParentRolesDefBehaveNormer, self).__init__(
##           pluginref, *args, **kwargs
##        )

    @property
    def config_path(self):
        return ['default_parent_roles', 'default_behaviour']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        if not my_subcfg:
            # default "direct_parent_only" only method when nothing else
            # is explicitly selected
            my_subcfg['direct_parent_only'] = None

        return my_subcfg

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        tmp = len(my_subcfg)
        ansible_assert(tmp == 1,
           "config must contain exakt a single behaviour to handle"\
           " 'default_parent_roles', but '{}' were set:\n{}'".format(
              tmp, my_subcfg
           )
        )

        return my_subcfg


class SrvCfgDefParentRolesAllRolesNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          SrvCfgDefParentRoleInstNormer(pluginref),
        ]

        super(SrvCfgDefParentRolesDefBehaveNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['default_parent_roles', 'roles']


    def _defbehave_direct_parent_only(self, cfg, my_subcfg, cfgpath_abs):
        # assure direct parent is part or default roles
        pp = self.pluginref.get_ansible_var('ansible_parent_role_paths')
        pp = pp[0]

        my_subcfg.setdefault(pp, None)

    def _defbehave_no_defaults(self, cfg, my_subcfg, cfgpath_abs):
        pass  # noop

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        defbh = next(iter(pcfg['default_behaviour']))

        tmp = getattr(self, '_defbehave_' + tmp, None)

        ansible_assert(tmp,
          "Unsupported 'default_behaviour' method '{}'".format(defbh)
        )

        tmp(cfg, my_subcfg, cfgpath_abs)

        return my_subcfg


class SrvCfgDefParentRoleInstNormer(NormalizerNamed):

    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]

    @property
    def name_key(self):
        return 'rolepath'


    def _create_srcdir_entries_from_parent(self, srcdir_root, cfg, my_subcfg, cfgpath_abs):
        p = my_subcfg['role_path']

        srcdir_root.setdefault(p + '/files', {
          'file_attributes': {
             '__norming_auto_created__': {
               'attributes': {
                  'templates': False
               },
             }
          },
        })

        srcdir_root.setdefault(p + '/templates', {
          ## atm not needed as we only overwrite template setting, which is default anyway
          ##'file_attributes': {
          ##   '__norming_auto_created__': {
          ##     'attributes': {
          ##        'templates': False
          ##     },
          ##   }
          ##},
        })

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, lvl=3)
        srcdirs = setdefault_none(
          setdefault_none(pcfg, 'files', {}), 'srcdirs', {}
        )

        self._create_srcdir_entries_from_parent(
          srcdirs, cfg, my_subcfg, cfgpath_abs
        )

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
        return 'smabot_hashivault_vault_server_dockcomp_args'

