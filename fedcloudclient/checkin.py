

from datetime import datetime

import click
import liboidcagent as agent
import requests

from fedcloudclient.decorators import (oidc_params)



@click.group()
def token():
    """
    Get details of access token
    """


@token.command()
@oidc_params
def check(access_token):
    """
    Check validity of access token
    """
    check_token(access_token, verbose=True)


@token.command()
@oidc_params
def list_vos(access_token):
    """
    List VO membership(s) of access token
    """
    vos = token_list_vos(access_token)
    print("\n".join(vos))


@token.command()
@oidc_params
def issue(access_token):
    """
    print access token (from mytoken or oidc-agent)
    """
    print(access_token)