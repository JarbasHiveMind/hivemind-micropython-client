"""Single source of truth for the package version.

``package.json`` (the ``mip``/``mpremote`` install manifest) mirrors this
value; keep the two in sync on every release.
"""

VERSION: tuple = (0, 1, 0)
VERSION_STR: str = "%d.%d.%d" % VERSION
