
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
          AuthMethodInstNormer(pluginref),
          PoliciesNormer(pluginref),
          AppRolersNormer(pluginref),
          PkiInstNormer(pluginref),
          SecretEnginesNormer(pluginref),
          LoginNormer(pluginref),
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


class InstDefPolInstNormer(NormalizerNamed):

    @property
    def config_path(self):
        return ['policies', SUBDICT_METAKEY_ANY]

    @property
    def name_key(self):
        return 'src'


class PkiInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          PkiInstDefPolsNormer(pluginref),
          PkiInstRootCaNormer(pluginref),
          PkiInstIntermedAllTreesNormer(pluginref),
          PkiInstIssuerRolesAllNormer(pluginref),
        ]

        super(PkiInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['pkis', 'pkis', SUBDICT_METAKEY_ANY]


class PkiInstIssuerRolesAllNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          PkiInstIssuerRoleInstNormer(pluginref),
        ]

        super(PkiInstIssuerRolesAllNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['issuer_roles', 'roles']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        if not my_subcfg:
            ## when no roles are explicitly defined for this pki
            ## auto-create single default role
            my_subcfg['default'] = None
        return my_subcfg


class PkiInstIssuerRoleInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          PkiInstIssuerRoleInstOptsNormer(pluginref),
          PkiInstIssuerRoleInstPolInstNormer(pluginref),
        ]

        super(PkiInstIssuerRoleInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['inherit_from_parent'] = DefaultSetterConstant(True)
        self.default_setters['default_policies'] = DefaultSetterConstant(True)
        self.default_setters['policies'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pki_cfg = self.get_parentcfg(cfg, cfgpath_abs, level=3)

        ca = my_subcfg.get('ca', None)
        if not ca:
            ca = pki_cfg['_role_default_ca']
            ansible_assert(ca,
               "CA for role could not bet auto-defaulted, either set"\
               " it explicitly or make sure to mark one CA"\
               " (root/intermediate) as role-default"
            )

        # replace ca ref-id with ca cfg
        if ca == 'root_ca':
            ca = pki_cfg['root_ca']
        else:
            ca = get_subdict(pki_cfg, ['intermeds', 'trees'] + ca.split('.'))

        my_subcfg['ca'] = ca

        if my_subcfg['default_policies']:
            my_rolepath = self.pluginref.get_ansible_var('role_path')
            tmp = "{}/templates/vault_policies/pkis/request_certs.hcl.j2".format(my_rolepath)

            setdefault_none(my_subcfg['policies'], tmp, None)

        return my_subcfg


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        opts = my_subcfg['options']

        ## on default limit client cert time to live to just 3 days
        setdefault_none(opts, 'ttl', '72h')

        c = setdefault_none(my_subcfg, 'config', {})

        c['name'] = my_subcfg['name']
        c['mount_point'] = my_subcfg['ca']['mount_point']

        c['config'] = opts

        if not c['config']:
            c.pop('config')

        setdefault_none(c, 'state', 'present')
        return my_subcfg


class PkiInstIssuerRoleInstPolInstNormer(InstDefPolInstNormer):

    def __init__(self, pluginref, *args, **kwargs):
        super(PkiInstIssuerRoleInstPolInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)
        srcpath = my_subcfg['src']

        if not my_subcfg.get('name', None):
            n1 = os.path.basename(srcpath).split('.')
            n1 = n1[0]

            my_subcfg['name'] = "{}_{}_{}".format(n1,
              pcfg['ca']['mount_point'].replace('/', '_'), pcfg['name']
            )

        c = setdefault_none(my_subcfg, 'config', {})
        c['rules'] = srcpath
        c['name'] = my_subcfg['name']

        tvars = setdefault_none(my_subcfg, 'template_vars', {})
        tvars['mp'] = pcfg['ca']['mount_point']
        tvars['pki_rolename'] = pcfg['name']

        return my_subcfg


class PkiInstIssuerRoleInstOptsNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(PkiInstIssuerRoleInstOptsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        # be rather restrictive on default
        self.default_setters['allow_localhost'] = DefaultSetterConstant(False)
        self.default_setters['allow_wildcard_certificates'] = DefaultSetterConstant(False)
        self.default_setters['allow_glob_domains'] = DefaultSetterConstant(True)

    @property
    def config_path(self):
        return ['options']

    def _inherit_from_parent(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        if not pcfg['inherit_from_parent']:
            return my_subcfg

        ca = pcfg['ca']

        tmp = copy.deepcopy(ca['options'])

        ## some key's differ somewhat between ca's metadata
        ## and role metadata, translate them here
        t2 = tmp.pop('permitted_dns_domains', None)
        if t2:
            t3 = []

            for x in t2:
                if x[0] == '.':
                    x = x[1:]

                ## note: it seems for the standard case of allowing
                ##   to create certs like "<hostname>.<domain>" it
                ##   is necessary to allow glob domains and start
                ##   the domain pattern with a glob
                x = '*.' + x

                t3.append(x)

            tmp['allowed_domains'] = t3

        tmp.update(my_subcfg)
        return tmp


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        my_subcfg = self._inherit_from_parent(cfg, my_subcfg, cfgpath_abs)
        return my_subcfg


class PkiInstCaBaseNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          PkiInstEngineNormer(pluginref,
             cfg_toplvl=self.cfg_toplvl,
             default_opts=self.engine_defopts
          ),
        ]

        super(PkiInstCaBaseNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['type'] = DefaultSetterConstant('internal')
        self.default_setters['options'] = DefaultSetterConstant({})
        self.default_setters['role_default'] = DefaultSetterConstant(False)

    @property
    def engine_defopts(self):
        return {
          # on default allow maximal 5 years for a cert to live
          'max_lease_ttl': '43800h',
        }

    @property
    @abc.abstractmethod
    def ca_kind(self):
        pass

    @property
    @abc.abstractmethod
    def cur_pki_baselvl(self):
        pass

    @property
    def cfg_toplvl(self):
        return self.cur_pki_baselvl + 4

    @property
    def is_root(self):
        return self.ca_kind == 'root'

    def _norm_ca_cfgvalues(self, ca_opts, cfg, my_subcfg, cfgpath_abs):
        pass

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs,
          level=self.cur_pki_baselvl
        )

        setdefault_none(my_subcfg, 'common_name',
          pcfg['name'].replace('_', '.')
        )

        def_mp = 'pkis/{}/{}'.format(pcfg['name'], self.ca_kind)

        if not self.is_root:
            def_mp += '/' + my_subcfg['name']

        setdefault_none(my_subcfg, 'mount_point', def_mp)

        modcfgs = setdefault_none(my_subcfg, '_modcfgs', {})

        ## config for creating ca
        c = setdefault_none(modcfgs, 'pki_ca', {})

        c['kind'] = self.ca_kind
        c['type'] = my_subcfg['type']
        c['mount_point'] = my_subcfg['mount_point']

        c['common_name'] = my_subcfg['common_name']

        opts = setdefault_none(my_subcfg, 'options', {})
        self._norm_ca_cfgvalues(opts, cfg, my_subcfg, cfgpath_abs)

        c['config'] = my_subcfg['options']

        if not c['config']:
            c.pop('config')

        setdefault_none(c, 'state', 'present')

        cfg_top = self.get_parentcfg(cfg, cfgpath_abs,
          level=self.cfg_toplvl
        )

        ## config for setting/updating ca urls
        c = setdefault_none(modcfgs, 'pki_ca_urls', {})

        def_base_url = '{}/v1/{}'.format(
          cfg_top['server_url'], my_subcfg['mount_point']
        )

        c['mount_point'] = my_subcfg['mount_point']
        setdefault_none(c, 'issuing_certificates', def_base_url + '/ca')
        setdefault_none(c, 'crl_distribution_points', def_base_url + '/crl')

        return my_subcfg


class PkiInstRootCaNormer(PkiInstCaBaseNormer):

    @property
    def cur_pki_baselvl(self):
        return 1

    @property
    def ca_kind(self):
        return 'root'

    @property
    def config_path(self):
        return ['root_ca']


    def _norm_ca_cfgvalues(self, ca_opts, cfg, my_subcfg, cfgpath_abs):
        ## on default convert ca name to a domain and restrict
        ## allowed dns domains to exactly that one
        tmp = my_subcfg['common_name'].replace('_', '.')
        setdefault_none(ca_opts, 'permitted_dns_domains', ['.' + tmp])


    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        opts = my_subcfg['options']

        # on default set root cert to one year
        setdefault_none(opts, 'ttl', '8760h')

        return super(PkiInstRootCaNormer, self)._handle_specifics_presub(
          cfg, my_subcfg, cfgpath_abs
        )


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        # opportunisticly set root-ca as role default, might
        # be overriden later when intermeds are normalized
        pcfg = self.get_parentcfg(cfg, cfgpath_abs,
          level=self.cur_pki_baselvl
        )

        pcfg['_role_default_ca'] = cfgpath_abs[-1]

        return super(PkiInstRootCaNormer, self)._handle_specifics_postsub(
          cfg, my_subcfg, cfgpath_abs
        )


class PkiInstIntermedAllTreesNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          PkiInstIntermedTreeNormer(pluginref),
        ]

        super(PkiInstIntermedAllTreesNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['intermeds', 'trees']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        if not my_subcfg:
            # on default if not custom intermeds cfg is given create
            # exactly one standard intermed below root_ca
            pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)

            setdefault_none(my_subcfg, 'default', {
              pcfg['root_ca']['common_name'].replace('.', '_'): None,
            })

        return my_subcfg


class PkiInstIntermedTreeNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          PkiInstIntermedCaNormer(pluginref),
        ]

        super(PkiInstIntermedTreeNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]


    def _get_final_ordering(self, ordermap,
      curkey=None, parents=None, result=None
    ):
        if curkey is None:
            # init condition
            result = []
            parents = []
            curkey = 'root_ca'

        for x in ordermap.get(curkey, []):
            ansible_assert(x not in parents,
               "detected circular dependency, intermediate ca '{}' has"\
               " '{}' as direct parent but is also part of the grand"\
               " parents of its parent: {}".format(x, curkey, parents)
            )

            ## any key directly dependend on curkey should be safe
            ## now to handle
            result.append(x)

            ## recurse down to next deps level
            self._get_final_ordering(ordermap, curkey=x,
              parents=parents + [curkey], result=result
            )

        return result


    def _norm_ca_cfgvalues(self, cfg, my_subcfg, cfgpath_abs):
        if not my_subcfg['inherit_from_parent']:
            return

        pcfg = my_subcfg['parent']
        tmp = copy.deepcopy(pcfg['options'])
        tmp.update(my_subcfg['options'])

        my_subcfg['options'] = tmp

        if not tmp:
            return

        c = my_subcfg['_modcfgs']['pki_ca']
        c['config'] = tmp


    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        def_order = {}
        def_sorted = []
        
        for k in sorted(my_subcfg.keys()):
            if def_sorted:
                def_order[k] = def_sorted[-1]
            else:
                def_order[k] = 'root_ca'

            def_sorted.append(k)

        pcfg_base = self.get_parentcfg(cfg, cfgpath_abs, level=3)

        role_default = pcfg_base['_role_default_ca']

        if role_default == 'root_ca' and \
        not pcfg_base['root_ca']['role_default']:
            # root_ca was only set opporunisticly speculating
            # no intermeds were defined, but there are some,
            # so undo root-ca default setting
            role_default = None

        real_order = {}
        for k, v in my_subcfg.items():
            p = setdefault_none(v, 'parent', def_order[k])
            real_order.setdefault(p, []).append(k)

            # replace parent id with reference to parent cfg
            if p == 'root_ca':
                p = pcfg_base[p]
            else:
                p = my_subcfg[p]

            v['parent'] = p

            v['_modcfgs']['sign_intermed']['mount_point'] = p['mount_point']

            self._norm_ca_cfgvalues(cfg, v, cfgpath_abs + [k])

            if v['role_default']:
                tmp = cfgpath_abs[-1:] + [k]
                tmp = '.'.join(tmp)

                ansible_assert(not role_default,
                   "Only one cert ca (root/intermediate) can be set as"\
                   " role-default but found at least two: {}".format(
                      [role_default, tmp]
                   )
                )

                role_default = tmp

        ## create a final indermeds ordering guaranteeing that any
        ## parent or grandparent for an intermed was handled before itself
        real_order = self._get_final_ordering(real_order)

        trees = self.get_parentcfg(cfg, cfgpath_abs)

        if not role_default and len(trees) == 1 and my_subcfg:
            # there is exactly one intermed tree defined and no role
            # default explicitly set, fallback to "lowest"
            # intermed in this tree (last in ordering)
            tmp = real_order[-1]
            my_subcfg[tmp]['role_default'] = True

            role_default = cfgpath_abs[-1:] + [tmp]
            role_default = '.'.join(role_default)

        pcfg_base['_role_default_ca'] = role_default

        my_subcfg['_ordering'] = real_order
        return my_subcfg


class PkiInstIntermedCaNormer(PkiInstCaBaseNormer):

    def __init__(self, pluginref, *args, **kwargs):
        super(PkiInstIntermedCaNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['inherit_from_parent'] = DefaultSetterConstant(True)

    @property
    def cur_pki_baselvl(self):
        return 4

    @property
    def ca_kind(self):
        return 'intermediate'

    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        opts = my_subcfg['options']

        # on default set root cert to half a year
        setdefault_none(opts, 'ttl', '4380h')

        my_subcfg = super(PkiInstIntermedCaNormer, self)._handle_specifics_presub(
          cfg, my_subcfg, cfgpath_abs
        )

        mcfgs = my_subcfg['_modcfgs']

        c = setdefault_none(mcfgs, 'sign_intermed', {})

        c['type'] = self.ca_kind
        c['common_name'] = my_subcfg['common_name']

        c = setdefault_none(mcfgs, 'set_signed', {})
        c['mount_point'] = my_subcfg['mount_point']

        return my_subcfg


class PkiInstEngineNormer(NormalizerBase):

    def __init__(self, pluginref, *args,
        cfg_toplvl=None, default_opts=None, **kwargs
    ):
        self.cfg_toplvl = cfg_toplvl
        self.default_opts = default_opts or {}

        super(PkiInstEngineNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['options'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return ['engine']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)

        eng_id = pcfg['mount_point']
        my_subcfg['type'] = 'pki'

        setdefault_none(my_subcfg, 'mount_point', eng_id)

        engopts = copy.deepcopy(self.default_opts)
        engopts.update(my_subcfg['options'])
        my_subcfg['options'] = engopts

        pcfg = self.get_parentcfg(cfg, cfgpath_abs,
          level=self.cfg_toplvl
        )

        tmp = setdefault_none(pcfg, 'secret_engines', {})
        tmp = setdefault_none(tmp, 'engines', {})

        unset = object()
        t2 = tmp.get(eng_id, unset)

        ansible_assert(t2 == unset,
           "creating a secret engine config for pki {} with id '{}' is"\
           " not possible as another secret engine config with the same"\
           " id exists:\n{}".format(cfgpath_abs[:-1], eng_id, t2)
        )

        ## add pki engine config to managed engines submap
        tmp[eng_id] = my_subcfg

        return my_subcfg


class LoginNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          LoginCredsNormer(pluginref),
        ]

        super(LoginNormer, self).__init__(pluginref, *args, **kwargs)

    @property
    def config_path(self):
        return ['login']

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs)
        my_subcfg['server_url'] = pcfg['server_url']
        return my_subcfg


class LoginCredsNormer(NormalizerBase):

    @property
    def config_path(self):
        return ['creds']


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


class EngineInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          EngineInstDefPolsNormer(pluginref),
        ]

        super(EngineInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['options'] = DefaultSetterConstant({})

    @property
    def config_path(self):
        return [SUBDICT_METAKEY_ANY]

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        setdefault_none(my_subcfg, 'mount_point',
          'secrets/{}', my_subcfg['name']
        )

        c = setdefault_none(my_subcfg, 'config', {})

        setdefault_none(c, 'state', 'present')
        c['name'] = my_subcfg['mount_point']
        c['backend'] = my_subcfg['type']

        c['config'] = my_subcfg['options']

        return my_subcfg


class InstDefaultPolsNormerBase(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          PolSrcDirInstNormer(pluginref),
          InstDefPolInstNormer(pluginref),
        ]

        super(InstDefaultPolsNormerBase, self).__init__(
           pluginref, *args, **kwargs
        )


    @property
    def simpleform_key(self):
        return "enabled"

    @property
    def config_path(self):
        return ['default_policies']


class EngineInstDefPolsNormer(InstDefaultPolsNormerBase):

    def __init__(self, pluginref, *args, **kwargs):
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


class PkiInstDefPolsNormer(InstDefaultPolsNormerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(PkiInstDefPolsNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['dirs'] = DefaultSetterConstant({
          'templates/vault_policies/pki_defaults': None,
        })

        self.default_setters['policies'] = DefaultSetterConstant({
          'templates/vault_policies/manage_pki.hcl.j2': {
             'config': { 'name': 'manage' },
          },
        })


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
          'mount_point': pcfg['auth_methods']['authers'][my_subcfg['auther']]['mount_point'],
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
        return ['auth_methods', 'authers', SUBDICT_METAKEY_ANY]

    def _type_specific_norming_cert(self, cfg, my_subcfg, cfgpath_abs):
        ## cert based auth has some special subtree keys to handle
        self.sub_normalizers.append(
          AuthMethodInstCertInstNormer(self.pluginref),
        )

        return my_subcfg

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        mytype = setdefault_none(my_subcfg, 'type', my_subcfg['name'])

        ## on default a specific (management) policy for each auth method
        ## is created, can be optionally disabled by setting 'policy'
        ## subkey to something falsy != None (empty) or a custom policy
        ## can be used by explicitly setting it to a path to a custom
        ## policy file
        setdefault_none(my_subcfg, 'policy',
           'templates/vault_policies/manage_authmethod.hcl.j2'
        )

        ##setdefault_none(my_subcfg, 'mount_point', my_subcfg['type'] + '/')
        tmp = setdefault_none(my_subcfg, 'mount_point', mytype)

        if tmp[-1] == '/':
            my_subcfg['mount_point'] = tmp[:-1]

        c = setdefault_none(my_subcfg, 'config', {})
        setdefault_none(c, 'state', 'enabled')

        c['method_type'] = mytype

        tmp = my_subcfg['mount_point']

##        if tmp[-1] == '/':
##            tmp = tmp[:-1]

        c['mount_point'] = tmp

        c['config'] = my_subcfg['extra_opts']

        if not c['config']:
            c.pop('config')

        tmp = getattr(self, '_type_specific_norming_' + mytype, None)
        if tmp:
            my_subcfg = tmp(cfg, my_subcfg, cfgpath_abs)

        return my_subcfg


class AuthMethodInstCertInstNormer(NormalizerNamed):

    def __init__(self, pluginref, *args, **kwargs):
        subnorms = kwargs.setdefault('sub_normalizers', [])
        subnorms += [
          AuthMethodInstCertInstCertCfgNormer(pluginref),
          AuthMethodInstCertInstPolInstNormer(pluginref),
        ]

        super(AuthMethodInstCertInstNormer, self).__init__(
           pluginref, *args, **kwargs
        )

    @property
    def config_path(self):
        return ['certs', SUBDICT_METAKEY_ANY]

    def _handle_specifics_postsub(self, cfg, my_subcfg, cfgpath_abs):
        pcfg = self.get_parentcfg(cfg, cfgpath_abs, level=2)

        c = setdefault_none(my_subcfg, 'config', {})
        c['name'] = my_subcfg['name']
        c['mount_point'] = pcfg['mount_point']

        tmp = []

        for k,v in my_subcfg['policies'].items():
            tmp.append(v['name'])

        c['policies'] = tmp

        setdefault_none(c, 'state', 'present')
        return my_subcfg


class AuthMethodInstCertInstPolInstNormer(NormalizerNamed):

    @property
    def config_path(self):
        return ['policies', SUBDICT_METAKEY_ANY]


class AuthMethodInstCertInstCertCfgNormer(NormalizerBase):

    def __init__(self, pluginref, *args, **kwargs):
        super(AuthMethodInstCertInstCertCfgNormer, self).__init__(
           pluginref, *args, **kwargs
        )

        self.default_setters['type'] = DefaultSetterConstant('vault_pki')

    @property
    def config_path(self):
        return ['certcfg']

    def _type_specific_norming_vault_pki(self, cfg, my_subcfg, cfgpath_abs):
        p = setdefault_none(my_subcfg, 'params', {})

        setdefault_none(p, 'mount_point', 'pki')
        p['serial'] = 'ca'
        return my_subcfg

    def _handle_specifics_presub(self, cfg, my_subcfg, cfgpath_abs):
        tmp = getattr(self,
          '_type_specific_norming_' + my_subcfg['type'], None
        )

        if tmp:
            my_subcfg = tmp(cfg, my_subcfg, cfgpath_abs)

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

