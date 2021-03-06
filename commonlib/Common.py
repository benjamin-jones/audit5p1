# Return codes
EXIT_SUCCESS = 0
EXIT_FAILURE_EXCEPTION = 1
EXIT_FAILURE_PLATFORM = 2

# OS Enums
OS_LINUX = 0
OS_QNX = 1
OS_ANDROID = 2

# SHELLS
SHELL_BASH = 0
SHELL_BUSYBOX = 1
SHELL_KSH = 2
SUPPORTED_SHELL = {"bash": SHELL_BASH, "busybox": SHELL_BUSYBOX, "ksh": SHELL_KSH}