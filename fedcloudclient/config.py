"""
Read/write configuration files
"""
import json
import os
import sys
from pathlib import Path

import click
import yaml
from tabulate import tabulate

DEFAULT_CONFIG_LOCATION = Path.home() / ".config/fedcloud/config.yaml"
DEFAULT_SETTINGS = {
    "site": "IISAS-FedCloud",
    "vo": "vo.access.egi.eu",
    "site_list_url": "https://raw.githubusercontent.com/tdviet/fedcloudclient/master/config/sites.yaml",
    "site_dir": str(Path.home() / ".config/fedcloud/site-config/"),
    "oidc_url": "https://aai.egi.eu/auth/realms/egi",
    "openstack_auth_protocol": "openid",
    "openstack_auth_provider": "egi.eu",
    "openstack_auth_type": "v3oidcaccesstoken",
    "gocdb_public_url": "https://goc.egi.eu/gocdbpi/public/",
    "gocdb_service_group": "org.openstack.nova",
    "vault_endpoint": "https://vault.services.fedcloud.eu:8200",
    "vault_role": "demo",
    "vault_mount_point": "/secrets",
    "vault_salt": "fedcloud_salt"
}


def save_config(filename, config_data):
    """
    Save configuration to file
    :param filename: name of config file
    :param config_data: dict containing configuration
    :return: None
    """
    config_file = Path(filename).resolve()
    try:
        with config_file.open(mode="w+", encoding="utf-8") as file:
            yaml.dump(config_data, file)
    except Exception as exception:
        print(f"Error during saving configuration to {filename}")
        raise SystemExit(f"Exception: {exception}")


def load_config(filename):
    """
    Load configuration file
    :param filename:
    :return: configuration data
    """

    config_file = Path(filename).resolve()
    try:
        with config_file.open(mode="r", encoding="utf-8") as file:
            return yaml.safe_load(file)
    except Exception as exception:
        print(f"Error during reading site config from {filename}")
        raise SystemExit(f"Exception: {exception}")


def load_env():
    """
    Load configs from environment variables
    :return: config
    """
    env_config = dict()
    for env in os.environ:
        if env.startswith("FEDCLOUD_"):
            config_key = env[9:].lower()
            env_config[config_key] = os.environ[env]
    return env_config


@click.group()
def config():
    """
    Managing fedcloud configurations
    """


@config.command()
@click.option(
    "--config-file",
    type=click.Path(dir_okay=False),
    default=DEFAULT_CONFIG_LOCATION,
    help="configuration file",
    envvar="FEDCLOUD_CONFIG_FILE",
    show_default=True,
)
def create(config_file):
    """Create default configuration file"""
    save_config(config_file, DEFAULT_SETTINGS)
    print(f"Default configuration is saved in {config_file}")


@config.command()
@click.option(
    "--config-file",
    type=click.Path(dir_okay=False),
    default=DEFAULT_CONFIG_LOCATION,
    help="configuration file",
    envvar="FEDCLOUD_CONFIG_FILE",
    show_default=True,
)
@click.option(
    "--output-format",
    "-f",
    required=False,
    help="Output format",
    type=click.Choice(["text", "YAML", "JSON"], case_sensitive=False),
)
def show(config_file, output_format):
    """Show actual client configuration """
    saved_config = load_config(config_file)
    env_config = load_env()
    act_config = {**DEFAULT_SETTINGS, **saved_config, **env_config}
    if output_format == "YAML":
        yaml.dump(act_config, sys.stdout, sort_keys=False)
    elif output_format == "JSON":
        json.dump(act_config, sys.stdout, indent=4)
    else:
        print(tabulate(act_config.items(), headers=["parameter", "value"]))
