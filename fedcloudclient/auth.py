"""
Class for managing tokens
"""

import jwt
import liboidcagent as agent
import requests
import os
import re
import click
import time
from datetime import datetime
import sys

from fedcloudclient.conf import CONF as CONF
from fedcloudclient.conf import save_config, load_config
from fedcloudclient.exception import TokenError
from fedcloudclient.logger import log_and_raise



class Token:
    """
    Abstract object for managing tokens
    """

    def get_token(self):
        ...

    def get_token_type(self):
        ...



class OIDCToken(Token):
    """
    OIDC tokens. Managing access tokens, oidc-agent account and mytoken
    """

    def __init__(self, access_token=None, verbose=False, init=False):
        super().__init__()
        self.access_token = access_token
        self.payload = None
        self.oidc_agent_account = None
        self.mytoken = None
        self.user_id = None
        self._VO_PATTERN = "urn:mace:egi.eu:group:(.+?):(.+:)*role=member#aai.egi.eu"
        self._MIN_ACCESS_TOKEN_TIME = 30
        self._LOG_DATA={}
        self.verbose=verbose
        if init==True:
            self.init_access()
            print(f"Done init_access()")
        else:
            CONF=load_config("FEDCLOUD_CONFIG")
            self._LOG_DATA=CONF["_LOG_DATA"]
 
    def get_token(self):
        """
        Return access token or raise error
        :return:
        """
        if self.access_token:
            return self.access_token
        else:
            error_msg = "Token is not initialized"
            log_and_raise(error_msg, TokenError)

    def decode_token(self) -> dict:
        """
        Decoding access token to payload
        :return:
        """
        #if not self.payload:
        try:
            self.payload = jwt.decode(self.access_token, options={"verify_signature": False})
            self.user_id = self.payload["sub"]
            return self.payload
        except jwt.exceptions.InvalidTokenError:
            error_msg = "Invalid access token"
            """Move to init, up, where is not possible to obtain access_token"""
            self.print_msg(error_msg, self.verbose)
            return None

        

    def get_user_id(self) -> str:
        """
        Return use ID
        :return:
        """

        if not self.payload:
            self.decode_token()
        return self.user_id

    def get_token_from_oidc_agent(self, oidc_agent_account: str) -> str:
        """
        Get access token from oidc-agent
        :param oidc_agent_account: account name in oidc-agent
        :return: access token, and set internal token, raise TokenError on None
        """

        if oidc_agent_account:
            try:
                access_token = agent.get_access_token(
                    oidc_agent_account,
                    min_valid_period=CONF.get("min_access_token_time"),
                    application_hint="fedcloudclient",
                )
                self.access_token = access_token
                self.oidc_agent_account = oidc_agent_account


                return access_token
            except agent.OidcAgentError as exception:
                error_msg = f"Error getting access token from oidc-agent: {exception}"
                log_and_raise(error_msg, TokenError)

        else:
            error_msg = f"Error getting access token from oidc-agent: account name is {oidc_agent_account}"
            log_and_raise(error_msg, TokenError)

    def get_token_from_mytoken(self, mytoken: str, mytoken_server: str = None) -> str:
        """
        Get access token from mytoken server
        :param mytoken:
        :param mytoken_server:
        :return: access token, or None on error
        """
        if not mytoken_server:
            mytoken_server = CONF.get("mytoken_server")

        if mytoken:
            try:
                data = {
                    "grant_type": "mytoken",
                    "mytoken": mytoken,
                }
                req = requests.post(
                    mytoken_server + "/api/v0/token/access",
                    json=data,
                )
                req.raise_for_status()
                access_token = req.json().get("access_token")
                self.access_token = access_token
                self.mytoken = mytoken
                return access_token

            except requests.exceptions.HTTPError as exception:
                error_msg = f"Error getting access token from mytoken server: {exception}"
                log_and_raise(error_msg, TokenError)

        else:
            error_msg = f"Error getting access token from mytoken server: mytoken is {mytoken}"
            log_and_raise(error_msg, TokenError)

    def multiple_token(self, access_token: str, oidc_agent_account: str, mytoken: str,mytoken_server: str = None, verbose:bool=False):
        """
        Select valid token from multiple options
        :param access_token:
        :param oidc_agent_account:
        :param mytoken:
        :return:
        - if there will be new update and the working new variable, it is necessary store to the system variable 
        """
        if mytoken:
            try:
                """need to implement from mytoken and check"""
                self.get_token_from_mytoken(mytoken)
                self._LOG_DATA["MYTOKEN"]={"exp": self.check_token()}
            except TokenError:
                self._LOG_DATA["MYTOKEN"]={"exp": "ACCESS DENIED"}
                
        if oidc_agent_account:
            try:
                self.get_token_from_oidc_agent(oidc_agent_account)
                self._LOG_DATA["OIDC_AGENT"]={"exp": self.check_token()}
            except TokenError:
                self._LOG_DATA["OIDC_AGENT"]={"exp": "ACCESS DENIED"}
        if access_token:
            try:
                self.access_token = access_token
                self._LOG_DATA["ACCESS_TOKEN"]={"exp": self.check_token()}
            except:
                self._LOG_DATA["ACCESS_TOKEN"]={"exp": "ACCESS DENIED"}

        else:
            self._LOG_DATA["ACCESS_TOKEN"]={"exp": "ACCESS DENIED"}
        
        
    def check_access_tokens(self):        
        if self.verbose==True:
            for idx, item in enumerate(self._LOG_DATA.keys()):
                self.print_msg(item+" is valid: "+str(self._LOG_DATA[item]["exp"]),False) 

        
    def oidc_discover(self) -> dict:
        """
        :param oidc_url: CheckIn URL get from payload
        :return: JSON object of OIDC configuration
        """
        oidc_url=self.payload["iss"]
        request = requests.get(oidc_url + "/.well-known/openid-configuration")
        request.raise_for_status()
        self.request_json=request.json()
        return self.request_json

    def token_list_vos(self):
        """
        List VO memberships in EGI Check-in
        :return: list of VO names
        """
        self.oidc_discover()
        oidc_ep  = self.request_json
        z_user_info=oidc_ep["userinfo_endpoint"]
        z_head={"Authorization": f"Bearer {self.access_token}"}
        
        request = requests.get(
            oidc_ep["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {self.access_token}"},
        )

        request.raise_for_status()
        vos = set()
        pattern = re.compile(self._VO_PATTERN)
        for claim in request.json().get("eduperson_entitlement", []):
            vo = pattern.match(claim)
            if vo:
                vos.add(vo.groups()[0])
            request.raise_for_status()

        return sorted(vos)
    
    def get_checkin_id(self,oidc_token):
        """
        Get EGI Check-in ID from access token

        :param oidc_token: the token

        :return: Check-in ID
        """
        payload = self.decode_token() #payload = self.decode_token(oidc_token)
        if payload is None:
            return None
        return payload["sub"]
    
    def check_access(self) -> None:

        access_token= os.environ.get("ACCESS_TOKEN","")
        if len(access_token)>0 and self.verbose==True:
            print(f"ACCESS_TOKEN \t\t-> Identified from environment")
        mytoken=os.environ.get("FEDCLOUD_MYTOKEN","")
        if len(mytoken)>0 and self.verbose==True:
            print(f"MYTOKEN \t\t-> Identified from environment")
        oidc_agent_name=os.environ.get("OIDC_AGENT_ACCOUNT","")
        if len(oidc_agent_name)>0 and self.verbose==True:
            print(f"OIDC_AGENT_ACCOUNT \t-> Identified from environment")
    
    ####################################################################################################    
    def gen_access_token(self, *args,**kwargs) -> str:
        """return "ACCESS_TOKEN" """
        list_times=list()
        
        exp_time=self.verify_access_token(args[0]) - int(time.time())
        list_times.apdate([exp_time])
        
        access_token=self.get_token_from_oidc_agent(args[1])
        xp_time=self.check_token() - int(time.time())
        list_times.apdate([exp_time])
        
        self.get_token_from_mytoken(args[2])
        
        
        
        for item in self._LOG_DATA:
            print(self._LOG_DATA[item]["exp"])
            if self._LOG_DATA[item]["exp"]!="ACCESS DENIED":
                exp_time=int(self._LOG_DATA[item]["exp"]) - int(time.time())
                if exp_time < self._MIN_ACCESS_TOKEN_TIME:
                    
                    pass
    ####################################################################################################                
    
    def verify_access_token(self,access_token) ->str:
        self.access_token=access_token
        exp_timestamp=self.check_token()
        try:
            exp_time_in_sec = exp_timestamp - int(time.time())
            return exp_time_in_sec
        except:
            return 0
           
                    
    
    def init_access(self) -> bool:
        
        """Check access from os environment in every initialization of OIDCToken"""
        access_token= os.environ.get("ACCESS_TOKEN","")
        mytoken=os.environ.get("FEDCLOUD_MYTOKEN","")
        oidc_agent_name=os.environ.get("OIDC_AGENT_ACCOUNT","")
        self.verbose=True
        self.multiple_token(access_token,oidc_agent_name,mytoken,None, True)
        CONF["_LOG_DATA"]=self._LOG_DATA
        save_config("FEDCLOUD_CONFIG",CONF)
        
        return 
        
        

    def check_token(self):
        """
        Check validity of access token
        :param verbose:
        :param oidc_token: the token to check
        :return: access token, or None on error
        """
        
        payload = self.decode_token()
        if payload is None:
            return None

        exp_timestamp = int(payload["exp"])
        current_timestamp = int(time.time())
        exp_time_in_sec = exp_timestamp - current_timestamp

        if exp_time_in_sec < self._MIN_ACCESS_TOKEN_TIME:
            self.print_msg("Error: Expired access token.", False)
            return None

        exp_time_str = datetime.fromtimestamp(exp_timestamp).strftime("%Y-%m-%d %H:%M:%S")
        if self.verbose:
            exp_time_str = datetime.fromtimestamp(exp_timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            print(f"Token is valid until {exp_time_str} UTC")
            if exp_time_in_sec < 24 * 3600:
                print(f"Token expires in {exp_time_in_sec} seconds")
            else:
                exp_time_in_days = exp_time_in_sec // (24 * 3600)
                print(f"Token expires in {exp_time_in_days} days")
        return exp_timestamp
        

        
    
    def print_msg(self,message, quiet):
        """
        Print error message to stderr if not quiet
        """
        if quiet:
            print(message, file=sys.stderr)