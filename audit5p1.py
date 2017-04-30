import argparse
import logging
import json

from SSHInterrogator import SSHInterrogator
from LocalInterrogator import LocalInterrogator
from SerialInterrogator import SerialInterrogator
from GenericLinuxPlan import GenericLinuxPlan

from Utils import *


def main():
    return_code = EXIT_SUCCESS

    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)

    parser = argparse.ArgumentParser(description="Audit a target with regards to 5+1 security concept")
    parser.add_argument('--ssh', dest="using_ssh", action="store_const", help="Connect to target with SSH",
                        const=True)
    parser.add_argument('--serial', dest="using_serial", action="store_const", help="Connect to target with Serial",
                        const=True)
    parser.add_argument('target', help="Target for interrogation, ssh: target:port, serial: /dev/ttySX")
    parser.add_argument('username', help="Username for target")
    parser.add_argument('password', help="Password for user on target")
    parser.add_argument('config', help="Config file to use for target")


    args = parser.parse_args()

    logging.info("5+1 Auditor is starting")

    target, username, password, config_file = args.target, args.username, args.password, args.config

    if args.using_ssh is not None:
        logging.info("SSH Interrogator was chosen")
        interrogator = SSHInterrogator()
    elif args.using_serial is not None:
        logging.info("Serial Interrogator was chosen")
        interrogator = SerialInterrogator()
    else:
        interrogator = LocalInterrogator()

    try:
        interrogator.connect(target, None)
    except ConnectionError:
        logging.error("Failed to connect to target!")
        return_code = EXIT_FAILURE_EXCEPTION
        return return_code
    try:
        interrogator.login(username, password)
    except UserWarning:
        logging.error("Failed to login to target!")
        return_code = EXIT_FAILURE_EXCEPTION
        return return_code

    os = get_operating_system(interrogator)

    plan = None
    config = None
    if os == OS_LINUX:
        logging.info("Linux platform detected!")
        plan = GenericLinuxPlan(interrogator, logging)
        try:
            with open(config_file, "r") as f:
                config = f.read()
        except IOError:
            logging.error("Could not open config file")
            return_code = EXIT_FAILURE_EXCEPTION
            return return_code

    if not plan:
        logging.error("Platform not detected!")
        return_code = EXIT_FAILURE_PLATFORM
        return return_code

    plan.load(config=config)
    plan.run()
    interrogator.disconnect()

    plan.report()
    logging.info("Audit finished")
    return return_code

if __name__ == "__main__":
    rtnCode = main()
    exit(rtnCode)