"""
Main CLI module
"""

import click

from fedcloudclient.checkin import token
from fedcloudclient.conf import config
from fedcloudclient.ec3 import ec3
from fedcloudclient.endpoint import endpoint
from fedcloudclient.openstack import openstack, openstack_int
from fedcloudclient.secret import secret
from fedcloudclient.select import select
from fedcloudclient.sites import site


@click.group()
@click.version_option()
def cli():
    """
    CLI main function. Intentionally empty
    """
    """
    https://fedcloudclient.readthedocs.io/en/2.0-alpha1/usage.html#fedcloud-token-commands
    """


cli.add_command(token)
cli.add_command(endpoint)
cli.add_command(ec3)
cli.add_command(site)
cli.add_command(secret)
cli.add_command(select)
cli.add_command(openstack)
cli.add_command(openstack_int)
cli.add_command(config)

if __name__ == "__main__":
    cli()
