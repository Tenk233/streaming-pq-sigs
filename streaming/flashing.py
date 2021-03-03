import logging
import subprocess


log = logging.getLogger(__name__)


def reset_device():
    log.info("Reseting target device.")
    try:
        output = subprocess.check_output(
            "openocd -f nucleo-f2.cfg -c 'init' -c 'reset init' -c 'reset run' -c 'exit'",
            stderr=subprocess.STDOUT,
            shell=True
        )
        log.debug("OpenOCD output: %s", output.decode())
        return True
    except subprocess.CalledProcessError as ex:
        log.error("Could not reset device: %s", str(ex))
        return False