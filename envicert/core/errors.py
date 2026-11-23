class EnvicertError(Exception):
    exit_code = 3


class InvalidInputError(EnvicertError):
    exit_code = 2


class ConfigError(InvalidInputError):
    pass
