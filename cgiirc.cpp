/*
 * Copyright (C) 2015 Ashley "you10" Lavery ashley@you10.co.uk
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <znc/Client.h>
#include <znc/IRCNetwork.h>
#include <znc/Modules.h>
#include <znc/User.h>

using std::vector;

#ifndef HOSTNAME_IS_ALPHA
#define HOSTNAME_IS_ALPHA(c) (((*c >= 'A') && (*c <= 'Z')) || ((*c >= 'a') && (*c <= 'z')))
#endif

#ifndef HOSTNAME_IS_NUM
#define HOSTNAME_IS_NUM(c) ((*c >= '0') && (*c <= '9'))
#endif

#define CGIIRC_HOSTNAME_SUFFIX ".sa-irc.bnc"

class CCgiIrcMod : public CModule {
public:
	MODCONSTRUCTOR(CCgiIrcMod) {}

	virtual ~CCgiIrcMod() {}
	
	virtual bool OnLoad(const CString& sArgs, CString& sMessage) {

		MCString::iterator it1;

		// Load saved settings
		for (it1 = BeginNV(); it1 != EndNV(); ++it1) {
			SetNV(it1->first, it1->second);
		}
	
		if (!sArgs.empty()) {
			SetNV("Password", sArgs);
		}
	
		return true;
	}
	
	virtual void OnClientLogin() {
		SetNV("IP_" +  m_pUser->GetUserName(), m_pClient->GetRemoteIP());
	}
	
	virtual EModRet OnDeleteNetwork(CIRCNetwork& Network) {
		DelNV("Enabled_" + Network.GetUser()->GetUserName() + "/" + Network.GetName());
	
		return CONTINUE;
	}
	
	virtual EModRet OnDeleteUser(CUser& User) {
		DelNV("IP_" + User.GetUserName());
		
		const vector<CIRCNetwork*>& networks = User.GetNetworks();
		for (vector<CIRCNetwork*>::const_iterator network = networks.begin(); network != networks.end(); ++network) {
			DelNV("Enabled_" + User.GetUserName() + "/" + (*network)->GetName());
		}
	
		return CONTINUE;
	}
	
	virtual EModRet OnIRCRegistration(CString& sPass, CString& sNick, CString& sIdent, CString& sRealName) {
		CString sUserIP = GetNV("IP_" + m_pUser->GetUserName());
		CString sCGIPass = GetNV("Password");
		
		if(IsEnabled(m_pUser->GetUserName(), m_pNetwork->GetName()) && !sUserIP.empty() && !sCGIPass.empty()) {
			PutIRC("WEBIRC " + sCGIPass + " ZNC " + CleanHostname(m_pUser->GetCleanUserName()) + CGIIRC_HOSTNAME_SUFFIX + " 0.0.0.0");
		}
		
		return CONTINUE;
	}
	
	bool OnEmbeddedWebRequest(CWebSock& WebSock, const CString& sPageName, CTemplate& Tmpl) {
		if (sPageName == "webadmin/network" && WebSock.GetSession()->IsAdmin()) {
			CString sAction = Tmpl["WebadminAction"];
			CIRCNetwork* pNetwork = SafeGetNetworkFromParam(WebSock);
			
			if(pNetwork) {
				if (sAction == "display") {
					Tmpl["CGIEnabled"] = CString(IsEnabled(Tmpl["Username"], pNetwork->GetName()));
					return true;
				}
				if (sAction == "change" && WebSock.GetParam("embed_cgiirc_presented").ToBool()) {
					if (WebSock.GetParam("embed_cgiirc_enable").ToBool()) {
						if (!WebSock.GetParam("embed_cgiirc_old").ToBool()) {
							if (Enable(Tmpl["Username"], pNetwork)) {
								WebSock.GetSession()->AddSuccess("CGI:IRC Enabled [" + Tmpl["Username"] + "/" + pNetwork->GetName() + "]");
							} else {
								WebSock.GetSession()->AddError("Couldn't enable CGI:IRC [" + Tmpl["Username"] + "/" + pNetwork->GetName() + "]");
							}
						}
					} else  if (WebSock.GetParam("embed_cgiirc_old").ToBool()){
						if (DelNV("Enabled_" + Tmpl["Username"] + "/" + pNetwork->GetName())) {
							WebSock.GetSession()->AddSuccess("CGI:IRC Disabled [" + Tmpl["Username"] + "/" + pNetwork->GetName() + "]");
						} else {
						WebSock.GetSession()->AddError("User [" + Tmpl["Username"] + "/" + pNetwork->GetName() + "] does not have CGI:IRC enabled");
						}
					}
					return true;
				}
			}
		}
		
		return false;
	}
	
private:
	/*********************************************/
	/*        Borrowed from webadmin.cpp         */
	/*********************************************/
	
	CString SafeGetUserNameParam(CWebSock& WebSock) {
		CString sUserName = WebSock.GetParam("user"); // check for POST param
		if(sUserName.empty() && !WebSock.IsPost()) {
			// if no POST param named user has been given and we are not
			// saving this form, fall back to using the GET parameter.
			sUserName = WebSock.GetParam("user", false);
		}
		return sUserName;
	}

	CString SafeGetNetworkParam(CWebSock& WebSock) {
		CString sNetwork = WebSock.GetParam("network"); // check for POST param
		if(sNetwork.empty() && !WebSock.IsPost()) {
			// if no POST param named user has been given and we are not
			// saving this form, fall back to using the GET parameter.
			sNetwork = WebSock.GetParam("network", false);
		}
		return sNetwork;
	}
	
	CIRCNetwork* SafeGetNetworkFromParam(CWebSock& WebSock) {
		CUser* pUser = CZNC::Get().FindUser(SafeGetUserNameParam(WebSock));
		CIRCNetwork* pNetwork = NULL;

		if (pUser) {
			pNetwork = pUser->FindNetwork(SafeGetNetworkParam(WebSock));
		}

		return pNetwork;
	}
	
	/*********************************************/

	/*********************************************/
	/*      Borrowed from CGI::IRC Spoofing      */
	/*              Module for ZNC               */
	/*     (c) 2009 N Lum <nol888@gmail.com      */
	/*********************************************/
	
	CString CleanHostname(const CString unclean) {
		CString clean;
        const char* chararray = unclean.c_str();
                
        while(*chararray) {
			if(HOSTNAME_IS_ALPHA(chararray) || HOSTNAME_IS_NUM(chararray) || (*chararray == '-')) {
				clean += CString(*chararray);
            } else {
                clean += "-";
            }
                        
            chararray++;
        }
                
        return clean;
	}
	
	/*********************************************/
	
	bool IsEnabled(const CString& sUser, const CString& sNetwork) {
		MCString::iterator it;
		for (it = BeginNV(); it != EndNV(); ++it) {
			if ("Enabled_" + sUser + "/" + sNetwork == it->first) {
				return true;
			}
		}
		return false;
	}
	
	bool Enable(const CString& sUser, CIRCNetwork* pNetwork) {
		CUser *pUser = CZNC::Get().FindUser(sUser);

		if (!pUser || !pNetwork)
			return false;
		
		SetNV("Enabled_" + pUser->GetUserName() + "/" + pNetwork->GetName(), "");
		return true;
	}
};

template<> void TModInfo<CCgiIrcMod>(CModInfo& Info) {
	Info.SetHasArgs(true);
	Info.SetArgsHelpText("Password for CGI:IRC.");
}

GLOBALMODULEDEFS(CCgiIrcMod, "Provide dynamic IP spoofing to assist with user accountability.")
