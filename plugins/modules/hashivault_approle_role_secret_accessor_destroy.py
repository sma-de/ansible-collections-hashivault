#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashivault_argspec
from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashivault_auth_client
from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashivault_init
from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashiwrapper

ANSIBLE_METADATA = {'status': ['stableinterface'], 'supported_by': 'community', 'version': '1.0'}
DOCUMENTATION = '''
---
module: hashivault_approle_role_secret_accessor_destroy
short_description: Destroy a Hashicorp Vault approle secret by its accessor

description: >-
  Destroy a Hashicorp Vault approle secret by its accessor

options:
    name:
        description:
            - role name.
    mount_point:
        description:
            - mount point for role.
        default: approle
    accessor:
        description:
            - accessor id.
    optional:
        description:
            - if given accessor must still map to a valid accessor before delete or bad invalid accessors are simply silently ignored.
        default: False

extends_documentation_fragment: hashivault
'''
EXAMPLES = '''
---
  - name: "destroy approle secret by its accessor"
    smabot.hashivault.hashivault_approle_role_secret_accessor_destroy:
      name: role_name
      mount_point: role-mount
      accessor: accessor-string
    register: auth_info
'''


def main():
    argspec = hashivault_argspec()

    argspec['name'] = dict(required=True, type='str')
    argspec['accessor'] = dict(required=True, type='str')
    argspec['mount_point'] = dict(required=False, type='str', default='approle')
    argspec['optional'] = dict(required=False, type='bool', default=False)

    module = hashivault_init(argspec)
    result = hashivault_approle_role_secret_accessor_destroy(module.params)

    if result.get('failed'):
        module.fail_json(**result)
    else:
        module.exit_json(**result)


@hashiwrapper
def hashivault_approle_role_secret_accessor_destroy(params):
    name = params.get('name')
    mount_point = params.get('mount_point')
    accessor = params.get('accessor')
    optional = params.get('optional')

    client = hashivault_auth_client(params)
    do_destroy = True
    result = {}

    if optional:
        ## check if there currently is a secret matching given accessor
        import hvac

        try:
            cur_secret = client.auth.approle.read_secret_id_accessor(
              name, accessor, mount_point=mount_point
            )

        except hvac.exceptions.InvalidPath:
            ## this should only mean that given accessor does
            ## not map to a valid secret (anymore)
            do_destroy = False

            result['msg'] = "Destroy not possible for invalid accessor,"\
                          + " as optional flag was set this is not seen"\
                          + " as error and simply ignored"

    if do_destroy:
        ## secret, there is => destroy it
        client.auth.approle.destroy_secret_id_accessor(
          name, accessor, mount_point=mount_point
        )

        result['changed'] = True

    return result


if __name__ == '__main__':
    main()

