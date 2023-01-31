

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}


import copy
import collections
import os
import re

from ansible.errors import AnsibleFilterError, AnsibleOptionsError
from ansible.module_utils.six import iteritems, string_types
from ansible.module_utils.common._collections_compat import MutableMapping
from ansible.module_utils._text import to_native

from ansible_collections.smabot.base.plugins.module_utils.plugins.plugin_base import MAGIC_ARGSPECKEY_META
from ansible_collections.smabot.base.plugins.module_utils.plugins.filter_base import FilterBase
from ansible.utils.display import Display

from ansible_collections.smabot.base.plugins.module_utils.utils.dicting import merge_dicts
from ansible_collections.smabot.base.plugins.module_utils.utils.utils import ansible_assert


display = Display()



class PoliciesFromFilesFilter(FilterBase):

    FILTER_ID = 'policies_from_files'

    @property
    def argspec(self):
        tmp = super(PoliciesFromFilesFilter, self).argspec

        tmp.update({
          'policy_cfg': ([collections.abc.Mapping]),
          'dircfg': ([collections.abc.Mapping]),
        })

        return tmp


    def run_specific(self, value):
        if not isinstance(value, list):
            raise AnsibleOptionsError(
               "expected a list as filter input, but given value"\
               " '{}' has type '{}'".format(value, type(value))
            )

        ##display.vvv("[{}]:: input: {}".format(type(self).FILTER_ID, value))

        polcfg = self.get_taskparam('policy_cfg')
        dircfg = self.get_taskparam('dircfg')
        ending = '.hcl.j2'

        res = []

        for x in value:
            display.vvv(
               "[{}]:: current input list item: {}".format(
                  type(self).FILTER_ID, x
            ))

            if not isinstance(x, collections.abc.Mapping):
                ## assume simple string file path
                x = {
                  'state': 'file',
                  'src': x,
                }

            if x.get('state', 'file') != 'file':
                continue  # we only care about files here

            fp = x['src']

            if not fp.endswith(ending):
                continue

            rule_id = os.path.basename(fp)
            rule_id = rule_id[:-len(ending)]

            c = {
              'name': rule_id,
              'rules': fp,
              'state': 'present',
            }

            display.vvv("[{}]:: item x config: {}".format(type(self).FILTER_ID, str(x.get('config', None))))

            c.update(x.get('config', {}))

            display.vvv("[{}]:: item x post cfg merge: {}".format(type(self).FILTER_ID, str(c)))

            tmp = {
              'config': c,
              'tags': merge_dicts(copy.deepcopy(dircfg.get('tags', {})), x.get('tags', {})),
            }

            # optionally overwrite rule settings
            merge_dicts(tmp, polcfg.get(
                'policy_overwrites', {}
              ).get(rule_id, {}).get('config', {})
            )

            res.append(tmp)

        return res


##class FinalizeRolePoliciesFilter(FilterBase):
##
##    FILTER_ID = 'finalize_role_policies'
##
##    @property
##    def argspec(self):
##        tmp = super(FinalizeRolePoliciesFilter, self).argspec
##
##        tmp.update({
##          'to_merge': ([[collections.abc.Mapping]]),
##        })
##
##        return tmp
##
##
##    def run_specific(self, value):
##        if not isinstance(value, collections.abc.Mapping):
##            raise AnsibleOptionsError(
##               "input value must be a dict type but is of type"\
##               " '{}': {}".format(type(value), value)
##            )
##
##        ##display.vvv("[{}]:: input: {}".format(type(self).FILTER_ID, value))
##
##        # first we need to merge the dicts together without changing
##        # the source dicts
##        value = copy.deepcopy(value)
##
##        for d in self.get_taskparam('to_merge'):
##            merge_dicts(value, copy.deepcopy(d))
##
##        # finally we need to convert input dict into
##        # a flat list of string policy names
##        res = []
##
##        for k in value:
##            res.append(k)
##
##        return res



class SelectPoliciesFilter(FilterBase):

    FILTER_ID = 'select_policies'

    @property
    def argspec(self):
        tmp = super(SelectPoliciesFilter, self).argspec

        tmp.update({
          'existing_pols': ([collections.abc.Mapping]),
        })

        return tmp


    def _match_pols_postval_multimatch(self, pol, expols, matched, matcher, matchtype):
        cmin = pol['match_opts']['cnt_min']
        cmax = pol['match_opts']['cnt_max']

        if cmin:
            ansible_assert(len(matched) >= cmin,
               "Matching policies by {} '{}' did fail its constrain:"\
               " Expected to find at least '{}' policies to match but"\
               " found only '{}':\n  Matched: {}\n  All Avaible: {}".format(
                   matchtype, matcher, cmin, len(matched), matched, list(expols.keys())
               )
            )

        if cmax:
            ansible_assert(len(matched) <= cmax,
               "Matching policies by {} '{}' did fail its constrain:"\
               " Expected to find at most '{}' policies to match but"\
               " found '{}':\n  Matched: {}\n  All Avaible: {}".format(
                   matchtype, matcher, cmax, len(matched), matched, list(expols.keys())
               )
            )

    def _match_pols_by_tag(self, pol, expols):
        res = []
        tag = pol['name']

        for p,v in expols.items():
            if tag in v.get('tags', {}):
                res.append(p)

        self._match_pols_postval_multimatch(pol, expols, res, tag, 'tag')
        return res

    def _match_pols_by_name(self, pol, expols):
        pn = pol['name']

        ansible_assert(not pol['mandatory'] or pn in expols,
           "Mandatory policy with name '{}' was not found inside"\
           " server policies: {}".format(pn, expols)
        )

        return [ pn ]

    def _match_pols_by_regex(self, pol, expols):
        res = []
        rgx = pol['name']

        for p in expols:
            if re.match(rgx, p):
                res.append(p)

        self._match_pols_postval_multimatch(pol, expols, res, rgx, 'regex')
        return res

    def run_specific(self, value):
        if not isinstance(value, collections.abc.Mapping):
            raise AnsibleOptionsError(
               "input value must be a dict type but is of type"\
               " '{}': {}".format(type(value), value)
            )

        ##display.vvv("[{}]:: input: {}".format(type(self).FILTER_ID, value))

        expols = self.get_taskparam('existing_pols')

        res = {}
        excludes = []

        for k,v in value.items():
            tmp = getattr(self, '_match_pols_by_' + v['type'], None)

            ansible_assert(tmp,
              "Unsupported policy match type '{}'".format(v['type'])
            )

            if v['exclude']:
                excludes += tmp(v, expols)
            else:
                for x in tmp(v, expols):
                    res[x] = True

        for ex in excludes:
            res.pop(ex, None)

        return list(res.keys())



class AttachPolicyMetaFilter(FilterBase):

    FILTER_ID = 'attach_policy_meta'

    @property
    def argspec(self):
        tmp = super(AttachPolicyMetaFilter, self).argspec

        tmp.update({
          'pols_meta': ([collections.abc.Mapping]),
        })

        return tmp


    def _match_pols_default(self, matcher, policies):
        # for now we simply always match per regex
        res = []

        for x in policies:
            if re.match(matcher, x):
                res.append(x)

        return res

    def run_specific(self, value):
        if not isinstance(value, list):
            raise AnsibleOptionsError(
               "input value must be a list but is of type"\
               " '{}': {}".format(type(value), value)
            )

        ##display.vvv("[{}]:: input: {}".format(type(self).FILTER_ID, value))

        pmeta = self.get_taskparam('pols_meta')
        res = {}

        # convert flat list of policy names (strings) to dict
        # where each policy is a key and its value will be
        # filled by its meta data
        for p in value:
            res[p] = {}

        for k,v in pmeta.items():
            for mp in self._match_pols_default(v['matcher'], value):

                # attach any matching pol meta to any matching
                # policy, when more than one meta matches, merge
                # them together
                merge_dicts(res[mp], v['meta'])

        return res



class PolicyMetaUpdateFilter(FilterBase):

    FILTER_ID = 'update_policy_meta'

    @property
    def argspec(self):
        tmp = super(PolicyMetaUpdateFilter, self).argspec

        tmp.update({
          'newpol': ([collections.abc.Mapping]),
          'newpol_meta_src': ([collections.abc.Mapping]),
        })

        return tmp


    def run_specific(self, value):
        if not isinstance(value, collections.abc.Mapping):
            raise AnsibleOptionsError(
               "input value must be a dict type but is of type"\
               " '{}': {}".format(type(value), value)
            )

        ##display.vvv("[{}]:: input: {}".format(type(self).FILTER_ID, value))

        np = self.get_taskparam('newpol')
        np_meta_src = self.get_taskparam('newpol_meta_src')

        npn = np['name']

        # note: for the moment with the possibility to preset policy
        #   meta pre-existing and overwriting is okay/possible
        # TODO: do we need to merge here
        ##ansible_assert(npn not in value,
        ##   "Expected to add metadata for new policy named '{}', but"\
        ##   " there already exists metadata for a policy with such"\
        ##   " a name:\n{}".format(npn, value)
        ##)

        # create one meta attacher rule per policy which only
        # matches exactly this policy
        value[npn] = {
          'matcher': npn,
          'meta': {
            # note: currently the only supported policy metadata are tags
            'tags': np_meta_src.get('tags'),
          }
        }

        return value



# ---- Ansible filters ----
class FilterModule(object):
    ''' filter related to this collection configuration process for policies '''

    def filters(self):
        res = {}

        for f in [PoliciesFromFilesFilter, PolicyMetaUpdateFilter,
##          FinalizeRolePoliciesFilter,
          SelectPoliciesFilter, AttachPolicyMetaFilter
        ]:
            res[f.FILTER_ID] = f()

        return res

