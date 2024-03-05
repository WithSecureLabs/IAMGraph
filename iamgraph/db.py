import logging

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError


logger = logging.getLogger(__name__)


def clear_neo4j(db):
    logger.info('Clearing the db')

    QUERY = '''
    match (a) -[r] -> () delete a, r
    '''
    db.run(QUERY)

    QUERY = '''
    match (a) delete a
    '''
    db.run(QUERY)


class Neo4jDB(object):
    def __init__(self, db_user=None, uri='bolt://localhost:7687', db_pwd=None):
        self._driver = GraphDatabase.driver(uri, auth=(db_user, db_pwd))

    def close(self):
        self._driver.close()

    def run(self, cypher: str, **kwargs):
        try:
            with self._driver.session() as session:
                res = session.run(cypher, **kwargs)
                ret = res.values()
            return ret
        except AuthError as e:
            logger.error('Failed to authenticate to the Neo4j database. Ensure you\'ve configured the '
                         'needed credentials correctly')
            raise e
        except ServiceUnavailable as e:
            logger.error('Failed to connect to the Neo4j database. Ensure it is running and reachable '
                         'and you\'ve provided the correct URI')
            raise e