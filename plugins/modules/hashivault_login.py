#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashivault_argspec
##from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashivault_auth_client
from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashivault_client, AppRoleClient
from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashivault_init
from ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault import hashiwrapper

ANSIBLE_METADATA = {'status': ['stableinterface'], 'supported_by': 'community', 'version': '1.0'}
DOCUMENTATION = '''
---
module: hashivault_login
short_description: Login to Hashicorp Vault by any supported method

description: >-
  Simply authenticates against a vault server by any supported
  means and outputs the returned token which from then on can
  be used for auth purposes instead of full login credentials.

extends_documentation_fragment: hashivault
'''
EXAMPLES = '''
---
  - name: "login to vault with username/password"
    smabot.hashivault.hashivault_login:
      authtype: userpass
      username: user
      password: foobar
      url: https://vaultinst:8200
    register: auth_info
'''


class AppRoleClientSub(AppRoleClient):

    def auth(self):
        auth_resp = self.client.auth_approle(
          self.role_id, secret_id=self.secret_id, mount_point=self.login_mount_point
        )

        self.client.token = str(auth_resp['auth']['client_token'])
        return auth_resp


    def __getattr__(self, name):
        client = object.__getattribute__(self, 'client')
        return client.__getattribute__(name)

    def __getattribute__(self, name):
        return object.__getattribute__(self, name)


##
## this method is directly copy&pasted from
## "ansible_collections.terryhowe.hashivault.plugins.module_utils.hashivault",
## unfortunately it seems the login return info we need cannot be accessed using upstream code directly
##
def hashivault_auth(client, params):
    token = params.get('token')
    authtype = params.get('authtype')

    login_mount_point = params.get('login_mount_point', authtype)

    if not login_mount_point:
        login_mount_point = authtype

    username = params.get('username')
    password = params.get('password')
    secret_id = params.get('secret_id')
    role_id = params.get('role_id')

    if authtype == 'github':
        # TODO
        return (client, client.auth.github.login(token, mount_point=login_mount_point))

    if authtype == 'userpass':
        # TODO
        return (client, client.auth_userpass(username, password, mount_point=login_mount_point))

    if authtype == 'ldap':
        # TODO
        return (client, client.auth.ldap.login(username, password, mount_point=login_mount_point))

    if authtype == 'approle':
        client = AppRoleClientSub(client, role_id,
          secret_id, mount_point=login_mount_point
        )

        resp = client.auth()

        return (client, {
          'token': resp['auth']['client_token'],
          'rolename': resp['auth']['metadata']['role_name'],
          'details': resp,
        })

    if authtype == 'tls':
        # TODO
        return (client, client.auth_tls())

    if authtype == 'aws':
        # TODO
        credentials = get_ec2_iam_credentials(params.get['aws_header'], role_id)
        return (client, client.auth_aws_iam(**credentials))

    client.token = token
    return (client, {'token': token})


def main():
    argspec = hashivault_argspec()
    module = hashivault_init(argspec)
    result = hashivault_login(module.params)

    if result.get('failed'):
        module.fail_json(**result)
    else:
        module.exit_json(**result)


@hashiwrapper
def hashivault_login(params):
    client, login_res = hashivault_auth(hashivault_client(params), params)

    result = {'changed': False}
    result['login'] = login_res
    return result


if __name__ == '__main__':
    main()

