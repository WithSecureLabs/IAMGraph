import json
import re
import logging


logger = logging.getLogger(__name__)


def parse_gaad(authorization_details, prod_accounts=[]):
    roles, account_details = parse_roles(authorization_details['RoleDetailList'], prod_accounts)
    users = parse_users(authorization_details['UserDetailList'])
    return {
        'AccountDetails': account_details,
        'Roles': roles,
        'Users': users
    }


def parse_users(users):
    for user in users:
        user['AccountId'] = user['Arn'].split(':')[4]
        user['UserPolicyList'] = json.dumps(user.get('UserPolicyList', ''), indent=4)
        user['AttachedManagedPolicies'] = json.dumps(user.get('AttachedManagedPolicies', ''), indent=4)
        user['GroupList'] = json.dumps(user.get('GroupList', ''), indent=4)
        user['Tags'] = json.dumps(user.get('Tags', []), indent=4)
    return users


def parse_roles(roles, prod_accounts):
    for role in roles:
        trust_policy = role['AssumeRolePolicyDocument']
        account_id = role['Arn'].split(':')[4]
        role['AccountId'] = account_id
        role['ParsedTrustStatements'] = parse_trust_policy_document(trust_policy)
        role['RawTrustPolicy'] = json.dumps(trust_policy, indent=4)
        role['ManagedPolicies'] = json.dumps(role['AttachedManagedPolicies'], indent=4)
        role['InlinePolicies'] = json.dumps(role['RolePolicyList'], indent=4)
        role['Tags'] = json.dumps(role.get('Tags', []), indent=4)
        role['LastUsed'] = json.dumps(role['RoleLastUsed'], indent=4)
        role['IsInstanceProfile'] = bool(role['InstanceProfileList'])

    account_details = {
        'AccountId': account_id,
        'AccountArn': f'arn:aws:iam::{account_id}:root',
        'Prod': account_id in prod_accounts
    }
    return roles, account_details


def parse_trust_policy_document(policy_document):
    # IAM Policy reference:
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
    parsed_statements = []
    for statement in policy_document.get('Statement'):
        trusts_service = False
        trusted_services = None
        trusts_iam_principal = False
        trusted_principals = []

        principal_block = statement.get('Principal')
        if principal_block == {'AWS': '*'} or principal_block == '*':
            trusted_principals.append({
                'Type': 'any',
                'Id': '*'
            })
            trusts_iam_principal = True
            logger.warn('!!!Role trust policy allows public access (*)!!!')

        else:
            if trusted_services := principal_block.get('Service', None):
                trusts_service = True
                if isinstance(trusted_services, str):
                    trusted_services = [trusted_services]

            if trusts := principal_block.get('AWS', None):
                trusts_iam_principal = True
                if isinstance(trusts, str):
                    trusts = [trusts]

                for t in trusts:
                    # t is principal_id_string can be either account_id or ARN:
                    #   123456789012
                    #   arn:aws:iam::123456789012:root
                    #   arn:aws:iam::123456789012:role/somerole
                    #   arn:aws:iam::123456789012:user/someuser
                    # OR Unique ID like:
                    #   "AIDACKCEVSQ6C2EXAMPLE",
                    #   "AROADBQP57FF2AEXAMPLE"
                    try:
                        re.findall('\d{12}', t)[0]
                    except IndexError:
                        # unique ID
                        trusted_principals.append({
                            'Type': 'uid',
                            'Id': t
                        })
                        continue

                    splitted_arn = t.split(':')
                    if len(splitted_arn) > 1:
                        if 'root' == splitted_arn[-1]:
                            resource_type = 'account'
                        else:
                            resource_type = splitted_arn[-1].split('/')[0]

                        trusted_principals.append({
                            'Type': resource_type,
                            'Id': t
                        })

                    else:
                        # trusted principal was in a form of just account id
                        # convert it to arn
                        trusted_principals.append({
                            'Type': 'account',
                            'Id': f'arn:aws:iam::{t}:root'
                        })

            if identity_provider_arn := principal_block.get('Federated', None):
                trusts_iam_principal = True
                trusted_principals.append({
                    'Type': 'identity_provider',
                    'Id': str(identity_provider_arn)
                })

        parsed_statements.append(
            {
                'TrustsService': trusts_service,
                'TrustedServices': trusted_services,
                'TrustsIamPrincipal': trusts_iam_principal,
                'TrustedPrincipals': trusted_principals
            }
        )

    return parsed_statements
