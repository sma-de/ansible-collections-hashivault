#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, SMA Solar Technology
# BSD 3-Clause Licence (see LICENSE or https://spdx.org/licenses/BSD-3-Clause.html)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = r'''
---
module: config_initialize

short_description: initial basic configuration for a new out-of-the-box vault server instance

version_added: "1.0.0"

description: >-
  This module handles the initial configuration of a fresh hashicorp vault server,
  creating master keys, obtaining a root token, initial unsealing and some more.
  To auth against vault in this initial phase this module must run on the same
  system as the server itself. TODO: add standard param docu

options:
    key_shares:
      description:
        - How many key shares should be created for master key.
      type: number
      default: 5
    key_threshold:
      description:
        - How many key shares are needed to recreate the master key or root token.
      type: number
      default: 3

author:
    - Mirko Wilhelmi (@yourGitHubHandle)
'''

# TODO: github handle
EXAMPLES = r'''
- name: initialize hashicorp vault server
  smabot.hashivault.config_initialize:
  register: hashivault_init_state

- name: initialize hashicorp vault server non default url and key_shares
  smabot.hashivault.config_initialize:
    key_shares: 2
    url: https://my-example-vault.org:7776
  register: hashivault_init_state
'''


RETURN = r'''
key_setup:
  description: Initial master secret keys. Be very careful with what you do with them.
  returned: the first time a new vault instance is initialised
  type: dict
  contains:

    keys:
      description: One or more master keyshares depending on setting for "key_shares" parameter
      type: list
      elements: string
      sample: 
        - "8a711245938cebdb3d98bf2cbd419e8e36e01a7dd382d24640711e9171516939b7"
        - "5272de9b4498e434167610b4670277084f1a17f078a3fa4ab309a9979a1b4088d3"

    keys_base64:
      description: Same keys as in "keys" only base64 encoded
      type: list
      elements: string
      sample: 
        - "inESRZOM69s9mL8svUGejjbgGn3TgtJGQHEekXFRaTm3"
        - "UnLem0SY5DQWdhC0ZwJ3CE8aF/B4o/pKswmpl5obQIjT"

vault_info:
  description: Infos/Facts about new vault server post initialisation process
  type: dict
  returned: the first time a new vault instance is initialised
  sample: 
    build_date: "2022-09-23T06:01:14Z"
    cluster_id: "f3b4bf54-372c-ee7d-7d6f-ff6b9ece53b7"
    cluster_name: "vault-cluster-d229d1ba"
    initialized: true
    migration: false
    n: 5
    nonce: ""
    progress: 0
    recovery_seal: false
    sealed: false
    storage_type: "file"
    t: 3
    type: "shamir"
    version: "1.11.4"
'''

from ansible.module_utils.basic import AnsibleModule

##from ansible.module_utils.common.parameters import env_fallback

##from ansible.module_utils.errors import ArgumentValueError
##from ansible.module_utils.urls import fetch_file

from ansible_collections.smabot.hashivault.plugins.module_utils.base import HashiVaultBaseModule



class HashiVaultInit(HashiVaultBaseModule):

    @property
    def expect_authing(self):
       return False

    def _basic_vault_init(self, result):
        hc = self.hvac_client

        if hc.sys.is_initialized():
            # vault already initiliazed, noop
            # TODO: support case where initialized is true, but vault is still sealed ??
            return True

        result['changed'] = True
        result['key_setup'] = hc.sys.initialize(self.params['key_shares'],
          self.params['key_threshold']
        )

        if not hc.sys.is_initialized():
            self.fail_json(
               msg="vault is flagged uninitialized after initialize step was completed, this is really strange.",
               **result
            )

        if not hc.sys.is_sealed():
            self.fail_json(
               msg="vault seems not to be sealed before we unsealed it this should never happen.",
               **result
            )

        result['vault_info'] = hc.sys.submit_unseal_keys(
          result['key_setup']['keys']
        )

        if hc.sys.is_sealed():
            self.fail_json(
               msg="vault is flagged sealed after unseal step, this is really strange.",
               **result
            )

        return False


    def _run_specific(self, result):
        if self._basic_vault_init(result):
            return result

        return result


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
      key_shares=dict(
        type='int',
        default=5,
      ),
      key_threshold=dict(
        type='int',
        default=3,
      ),
    )

    module_args.update(HashiVaultBaseModule.get_standard_args())

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
      changed=False,
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = HashiVaultInit(
      argument_spec=module_args,
      supports_check_mode=False # TODO: make this True
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    module.run(result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()

