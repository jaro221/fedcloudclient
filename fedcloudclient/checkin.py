

from datetime import datetime

import click

from fedcloudclient.auth import OIDCToken as Token
from fedcloudclient.decorators import oidc_params




@click.group()
def token():
    """
    Get details of access token
    """



@token.command()
@oidc_params
def check_access(*args, **kwargs):
    """
    Check availability of variables for access token
    """   
    token=Token(None, kwargs["verbose"], False)
    token.check_access()

@token.command()
@oidc_params
def check(*args, **kwargs):
    """
    Check validity of access token
    """
    print("Token check")
    token=Token(None, kwargs["verbose"], False)
    token.check_token()
    

@token.command()
@oidc_params
def list_vos(*args, **kwargs):
    """
    List VO membership(s) of access token
    """
    
    token=Token(None, kwargs["verbose"], False)
    token.access_token=kwargs["access_token"]
    vos = token.token_list_vos()
    print("\n".join(vos))
    

@token.command()
@oidc_params
def issue(access_token):
    """
    print access token (from mytoken or oidc-agent)
    """
    #print(access_token)