import logging

from iamspy.model import Model
from multiprocessing import Pool
from itertools import repeat, chain


logger = logging.getLogger(__name__)


PROCESSES = 10


FIND_ROLE_TRUST_RELATIONSHIPS_CYPHER = '''
MATCH (a:Account)<-[i:IN]-(r:IAMRole)-[t:TRUSTS]->(tn:IAMPrincipal)
    WHERE tn.InDataset=true
WITH collect(r.ARN) AS roles, tn, a.AccountId AS role_account, tn.AccountId AS trusted_account, labels(tn) AS l
WITH {roles: roles, trusted_arn: tn.ARN, trusted_node_labels: l} AS roles_trusted_pair, role_account, trusted_account
RETURN role_account, collect(roles_trusted_pair), trusted_account
'''

CREATE_ASSUME_PATHS_CYPHER = '''
UNWIND $role_principal_pairs AS rp
MATCH (trusting_role:IAMRole {ARN: rp.trusting_role})
UNWIND rp.principals AS p_arn
MATCH (principal:IAMPrincipal {ARN: p_arn})
MERGE (principal)-[a:CAN_ASSUME]->(trusting_role)
'''


def analyse_assume_role_permissions(row, aid_gaad_map):
    ret = []
    role_account_id, roles_trusted_dicts, trusted_account_id = row
    logger.info(f'Analysing assume-role paths between accounts {role_account_id} and {trusted_account_id}')

    model = Model()

    try:
        model.load_gaad(aid_gaad_map[int(role_account_id)])
        if role_account_id != trusted_account_id:
            model.load_gaad(aid_gaad_map[int(trusted_account_id)])
    except:
        logger.error(
            f'IAMSpy failed to load GAADs of {role_account_id} and/or {trusted_account_id}. '
             'This is likely an issue with the input data. Skipping these accounts!'
        )
        return []

    for roles_trusted in roles_trusted_dicts:
        trusted_node_labels = roles_trusted.get('trusted_node_labels')
        trusting_roles = roles_trusted.get('roles')
        trusted_arn = roles_trusted.get('trusted_arn')

        if 'Account' in trusted_node_labels:
            for role in trusting_roles:
                logger.debug(f'IAMSpying potential path between {role} and account {trusted_arn}')
                if principals := model.who_can('sts:AssumeRole', role):
                    ret.append({
                        'trusting_role': role,
                        'principals': principals
                    })

        elif ('IAMRole' in trusted_node_labels) or ('IAMUser' in trusted_node_labels):
            for role in trusting_roles:
                logger.debug(f'IAMSpying potential path between {role} and principal {trusted_arn}')
                if model.can_i(trusted_arn, 'sts:AssumeRole', role):
                    ret.append({
                        'trusting_role': role,
                        'principals': [trusted_arn]
                    })
    return ret


def find_assume_role_paths(db, aid_gaad_map, processes=PROCESSES):
    # find potential roles
    logger.info('Querying role trust relationships from the graph')
    ret = db.run(FIND_ROLE_TRUST_RELATIONSHIPS_CYPHER)
    role_principal_pairs = []

    # do the analysis with IAMSpy
    logger.info('Analysing the found relationships for assume role paths')
    with Pool(processes) as p:
        role_principal_pairs = list(chain.from_iterable(
            p.starmap(analyse_assume_role_permissions, zip(ret, repeat(aid_gaad_map)))
        ))

    # create assume role paths based on the analysis
    logger.info('Writing the found paths to the database')
    db.run(CREATE_ASSUME_PATHS_CYPHER,
           role_principal_pairs=role_principal_pairs)
