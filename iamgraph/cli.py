import click
import os

from iamgraph.analysis import find_assume_role_paths
from iamgraph.db import Neo4jDB, clear_neo4j
from iamgraph.graph import model_gaads_to_graph
from iamgraph.utils import list_files_on_dir, generate_aid_gaad_map, configure_logging


@click.group()
@click.option('--db-uri', '-du',
              default='bolt://localhost:7687', show_default=True,
              help='''
              URI of Neo4j database instance.
              ''')
@click.option('--db-user', '-u',
              required=False,
              help='''
              User used to authenticate to Neo4j database instance.
              ''')
@click.option('-v', '--verbose',
              count=True, default=0,
              help='''
              Verbosity level. Repeat for more log output.
              ''')
@click.pass_context
def cli(ctx, db_uri, db_user, verbose):
    configure_logging(verbose)
    db_password = None
    if db_user:
        db_password = click.prompt(
                        f'Give password for database user {db_user} to authenticate to the db',
                        hide_input=True, default='', show_default=False
                      )
    db = Neo4jDB(uri=db_uri, db_user=db_user, db_pwd=db_password)
    ctx.ensure_object(dict)
    ctx.obj['db'] = db


@cli.command(help='Model the IAM configurations of the target accounts to a graph')
@click.option('--input-dir', '-i',
              required=True,
              help='''
              A name of the directory containing files with output from\n
              aws iam get-account-authorization-details\n
              from each target account
              ''')
@click.option('--clear-db', '-c',
              default=False, is_flag=True,
              help='''
              Clear the contents of the db before ingesting the data
              ''')
@click.pass_context
def model(ctx, input_dir, clear_db):
    db = ctx.obj['db']
    if clear_db:
        print('Clearing the contents of the database')
        clear_neo4j(db)
    if os.path.isfile(input_dir):
        input_files = [input_dir]
    elif os.path.isdir(input_dir) and not (input_files := list_files_on_dir(input_dir)):
        print(f'Provided input directory {input_dir} is empty')
        return

    print(f'Modelling input files from {input_dir} to the graph...')
    model_gaads_to_graph(db, input_files)
    print('Modelling ready')


@cli.command(help='Analyse the graph modelled to the database with IAMSpy. Note that '
             'this command needs to be run AFTER the "model" command')
@click.option('--input-dir', '-i',
              required=True,
              help='''
              A name of the directory containing files with output from\n
              aws iam get-account-authorization-details\n
              from each target account
              ''')
@click.option('--processes', '-p',
              required=False, default=10, show_default=True,
              help='''
              Number of processes used for multiprocessing
              ''')
@click.pass_context
def analyse(ctx, input_dir, processes):
    db = ctx.obj['db']
    if not (aid_gaad_map := generate_aid_gaad_map(input_dir)):
        print(f'Provided input directory {input_dir} is empty')
        return
    print('Analysing the graph with IAMSpy to find assume role paths...')
    find_assume_role_paths(db, aid_gaad_map, processes)
    print('IAMSpy analysis ready')


@cli.command(help='Run both model and analyse')
@click.option('--input-dir', '-i',
              required=True,
              help='''
              A name of the directory containing files with output from\n
              aws iam get-account-authorization-details\n
              from each target account
              ''')
@click.option('--clear-db', '-c',
              default=False, is_flag=True,
              help='''
              Clear the contents of the db before ingesting the data
              ''')
@click.option('--processes', '-p',
              required=False, default=10, show_default=True,
              help='''
              Number of processes used for multiprocessing
              ''')
def run(input_dir, clear_db, processes):
    model.callback(input_dir=input_dir, clear_db=clear_db)
    analyse.callback(input_dir=input_dir, processes=processes)
    print('Done! Query the resulting graph with Neo4j browser UI')


if __name__ == '__main__':
    cli()
