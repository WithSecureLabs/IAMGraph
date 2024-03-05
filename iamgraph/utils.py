import json
import logging
import os


logger = logging.getLogger(__name__)


def generate_aid_gaad_map(input_dir):
    if os.path.isfile(input_dir):
        input_gaads = [input_dir]
    elif not (input_gaads := list_files_on_dir(input_dir)):
        logger.error(f'Provided input directory {input_dir} is empty')

    account_id_gaad_location_map = {}
    for input_file in input_gaads:
        with open(input_file, 'r') as f:
            iam_details = json.load(f)
        account_id = iam_details.get('RoleDetailList')[0].get('Arn').split(':')[4]
        account_id_gaad_location_map[int(account_id)] = input_file
    return account_id_gaad_location_map


def list_files_on_dir(input_dir):
    if not (os.path.exists(input_dir)):
        logger.error(f'Provided input directory {input_dir} does not exist!')
        return None

    input_files = [os.path.join(input_dir, f) for f in os.listdir(input_dir)
                   if os.path.isfile(os.path.join(input_dir, f))]

    return input_files


def configure_logging(verbosity):
    level = {
        0: logging.ERROR,
        1: logging.WARNING,
        2: logging.INFO,
        3: logging.DEBUG,
    }.get(verbosity, 0)
    logging.basicConfig(level=level)

    # IAMSpy generates a LOT of logs and since we run it in parallel
    # those are impossible to follow
    logging.getLogger('iamspy').setLevel(logging.ERROR)
