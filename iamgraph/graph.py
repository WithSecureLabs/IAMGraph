import logging
import json

from iamgraph.parsing import parse_gaad


logger = logging.getLogger(__name__)


def model_gaads_to_graph(db, input_gaads):
    logger.info(f'Input files: {input_gaads}')
    parsed_gaads = []
    # Parse and collect GAADs to the db
    for input_file in input_gaads:
        with open(input_file, 'r') as f:
            iam_details = json.load(f)

        logger.info(f'Parsing input file: {input_file}')
        parsed_iam_details = parse_gaad(iam_details)

        # Collect data from gaad to the database
        model_account(db, parsed_iam_details['AccountDetails'])
        model_users(db, parsed_iam_details['Users'])
        model_roles(db, parsed_iam_details['Roles'])

        parsed_gaads.append(parsed_iam_details)

    # Trust relationships are created after all in scope IAM principals are collected to the db
    model_trust_relationships(db, parsed_gaads)


def model_roles(db, parsed_roles):
    CYPHER = '''
    UNWIND $roles AS r
    MATCH (account:Account {AccountId: r.AccountId})
    WITH account, r

    MERGE (role:IAMRole {ARN: r.Arn})
        SET role:IAMPrincipal
        SET role.Path = r.Path
        SET role.Name = r.RoleName
        SET role.UniqueID = r.RoleId
        SET role.TrustPolicy = r.RawTrustPolicy
        SET role.ManagedPolicies = r.ManagedPolicies
        SET role.InlinePolicies = r.InlinePolicies
        SET role.Tags = r.Tags
        SET role.LastUsed = r.LastUsed
        SET role.IsInstanceProfile = r.IsInstanceProfile
        SET role.InDataset = true
        SET role.AccountId = r.AccountId
    MERGE (role)-[:IN]->(account)
    '''
    db.run(CYPHER, roles=parsed_roles)
    logger.info('IAM roles collected to the database')


def model_trust_relationships(db, parsed_gaads):
    CYPHER = '''
    UNWIND $gaads AS gaad
    WITH gaad.Roles as roles

    UNWIND roles AS r
    MATCH (role:IAMRole {ARN: r.Arn})
    WITH r, role
    UNWIND r.ParsedTrustStatements AS ts
    WITH ts, role
    WHERE ts.TrustsIamPrincipal = true
    UNWIND ts.TrustedPrincipals AS trusted
    WITH role, trusted

    // FOREACH hack to do conditional operations in cypher without needing APOC
    FOREACH (_ IN CASE WHEN trusted.Type='role' THEN [1] ELSE [] END |
        MERGE (tn:IAMRole {ARN: trusted.Id})
        ON CREATE
            SET tn.InDataset = false
            SET tn:IAMPrincipal
        MERGE (role)-[t:TRUSTS]->(tn)
    )
    FOREACH (_ IN CASE WHEN trusted.Type='user' THEN [1] ELSE [] END |
        MERGE (tn:IAMUser {ARN: trusted.Id})
        ON CREATE
            SET tn.InDataset = false
            SET tn:IAMPrincipal
        MERGE (role)-[t:TRUSTS]->(tn)
    )
    FOREACH (_ IN CASE WHEN trusted.Type='account' THEN [1] ELSE [] END |
        MERGE (tn:Account {ARN: trusted.Id})
        ON CREATE
            SET tn.InDataset = false
            SET tn:IAMPrincipal
        MERGE (role)-[t:TRUSTS]->(tn)
    )
    FOREACH (_ IN CASE WHEN trusted.Type='uid' THEN [1] ELSE [] END |
        MERGE (tn:IAMPrincipal {UniqueID: trusted.Id})
        ON CREATE
            SET tn.InDataset = false
        MERGE (role)-[t:TRUSTS]->(tn)
    )
    FOREACH (_ IN CASE WHEN trusted.Type='any' THEN [1] ELSE [] END |
        MERGE (tn:IAMPrincipal {ARN: trusted.Id})
        ON CREATE
            SET tn.InDataset = false
        MERGE (role)-[t:TRUSTS]->(tn)
    )
    FOREACH (_ IN CASE WHEN trusted.Type='identity_provider' THEN [1] ELSE [] END |
        MERGE (tn:IdentityProvider {ARN: trusted.Id})
        ON CREATE
            SET tn.InDataset = false
            SET tn:IAMPrincipal
        MERGE (role)-[t:TRUSTS]->(tn)
    )
    // Default case
    FOREACH (_ IN CASE WHEN NOT trusted.Type IN ['account', 'role', 'user', 'uid', 'any', 'identity_provider'] THEN [1] ELSE [] END |
        MERGE (tn:UNKNOWN {Identifier: trusted.Id})
        MERGE (role)-[t:TRUSTS]->(tn)
    )
    '''
    logger.info('Creating trust relationships from IAM roles')
    db.run(CYPHER, gaads=parsed_gaads)
    logger.info('Trust Relationships Created')


def model_users(db, users):
    CYPHER = '''
    UNWIND $users AS u

    MATCH (account:Account {AccountId: u.AccountId})
    WITH account, u

    MERGE (user:IAMUser {ARN: u.Arn})
        SET user:IAMPrincipal
        SET user.Path = u.Path
        SET user.Name = u.UserName
        SET user.UniqueID = u.UserId
        SET user.InlinePolicies = u.UserPolicyList
        SET user.ManagedPolicies = u.AttachedManagedPolicies
        SET user.Groups = u.GroupList
        SET user.Tags = u.Tags
        SET user.InDataset = true
        SET user.AccountId = u.AccountId
    MERGE (user)-[:IN]->(account)
    '''
    db.run(CYPHER, users=users)
    logger.info('IAM users collected to the database')


def model_account(db, account_details):
    CYPHER = '''
    MERGE (account:Account {ARN: $a.AccountArn})
        SET account:IAMPrincipal
        SET account.InDataset = true
        SET account.AccountId = $a.AccountId
    WITH account, $a.Prod AS prodAccount WHERE prodAccount = true
        SET account.Prod = true
    '''
    db.run(CYPHER, a=account_details)
    logger.info(f'Account {account_details["AccountId"]} collected to the db')
