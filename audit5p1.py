import argparse
import logging

from commonlib.Utils import *
from iolib.LocalInterrogator import LocalInterrogator
from iolib.SSHInterrogator import SSHInterrogator
from iolib.SerialInterrogator import SerialInterrogator


def main():
    return_code = EXIT_SUCCESS

    logging.basicConfig(format='%(levelname)s %(filename)s:%(funcName)s %(asctime)s %(message)s', level=logging.INFO)

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
    try:
        with open(config_file, "r") as f:
            config = f.read()
    except IOError:
        logging.error("Could not open config file")
        return_code = EXIT_FAILURE_EXCEPTION
        return return_code

    if args.using_ssh is not None:
        logging.info("SSH Interrogator was chosen")
        interrogator = SSHInterrogator()
    elif args.using_serial is not None:
        logging.info("Serial Interrogator was chosen")
        # TODO: Implement serial interrogator
        interrogator = SerialInterrogator(config, logging)
    else:
        # TODO: Implement local interrogator
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
    platform = get_platform_module(config)(logging)

    # Verify target matches the platform's expected OS
    if not platform.check(os):
        logging.error("Platform does not match config!")
        return_code = EXIT_FAILURE_PLATFORM
        return return_code

    # Load the test plan for the platform
    plan = get_plan_module(config)(interrogator, logging)

    if not plan:
        logging.error("Failed to load plan module")
        return_code = EXIT_FAILURE_PLATFORM
        return return_code

    # Execute the test plan for the platform
    plan.load(config=config)
    plan.run()
    interrogator.disconnect()

    results = plan.report()

    # Validate the test plan for the platform
    platform.validate(results)

    platform.report()

    logging.info("Audit finished")
    return return_code


if __name__ == "__main__":
    rtnCode = main()
    exit(rtnCode)
