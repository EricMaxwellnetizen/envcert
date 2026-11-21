class EnvCertError(Exception):
    exit_code = 3


class InvalidInputError(EnvCertError):
    exit_code = 2


class ConfigError(InvalidInputError):
    pass
