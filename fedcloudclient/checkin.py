

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
def check(access_token):
    """
    Check validity of access token
    """

    #Token().check_access()
    
    


@token.command()
@oidc_params
def list_vos(access_token):
    """
    List VO membership(s) of access token
    """
    
    token=Token()
    token.access_token=access_token
    user_id=token.get_user_id()
    request_json=token.oidc_discover()
    vos = token.token_list_vos()
    print("\n".join(vos))
    

@token.command()
@oidc_params
def issue(access_token):
    """
    print access token (from mytoken or oidc-agent)
    """
    #print(access_token)