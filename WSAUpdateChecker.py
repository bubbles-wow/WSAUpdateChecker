#!/usr/bin/python3
#
# This file is part of MagiskOnWSALocal.
#
# MagiskOnWSALocal is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# MagiskOnWSALocal is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with MagiskOnWSALocal.  If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (C) 2023 LSPosed Contributors
#

import os
import time
import html
import json
import urllib
import logging
import requests
import urllib.request

from typing import Any, OrderedDict
from xml.dom import minidom

from requests import Session

from smtplib import SMTP_SSL
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header

from plyer import notification

class Prop(OrderedDict):
    def __init__(self, props: str = ...) -> None:
        super().__init__()
        for i, line in enumerate(props.splitlines(False)):
            if '=' in line:
                k, v = line.split('=', 1)
                self[k] = v
            else:
                self[f".{i}"] = line

    def __setattr__(self, __name: str, __value: Any) -> None:
        self[__name] = __value

    def __repr__(self):
        return '\n'.join(f'{item}={self[item]}' for item in self)

timer = 60
logging.captureWarnings(True)
dir = os.path.dirname(__file__)

release_type = "WIF"
ms_account_conf = dir + "\\.ms_account"

#Catagory ID
cat_id = '858014f3-3934-4abe-8078-4aa193e74ca8'

session = Session()
session.verify = False

user_token = ""

#flag == 0 -> release version
#flag == 1 -> beta version
flag = 0

#newverflag == 0 -> no new version
#newverflag == 1 -> new version found
newverflag = 0

tokenflag = "00"

#check if release UpdateID is the same as the beta one
release_id = ""

list = []
if os.path.exists(dir + "\\versionlist.json"):
    with open(dir + "\\versionlist.json", "r") as f:
        mainjson = json.loads(f.read())
        f.close()
    for i in mainjson:
        list.append(i)

def getURL(user, UpdateID, RevisionNumber, ReleaseType):
    with open(dir + "\\xml\\FE3FileUrl.xml", "r") as f:
        FE3_file_content = f.read()
        f.close()
    try:
        out = session.post(
            'https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured',
            data=FE3_file_content.format(user, UpdateID, RevisionNumber, ReleaseType),
            headers={'Content-Type': 'application/soap+xml; charset=utf-8'}
        )
    except:
        for i in range(timer,-1,-1):
            print(f"\rNetwork Error! The program will retry in {i} seconds.",end="")
            time.sleep(1)
        print("\n")
        return "null"
    if len(out.text) < 1500:
        print("Failed to get URL!")
        return "null"
    doc = minidom.parseString(out.text)
    for l in doc.getElementsByTagName("FileLocation"):
        url = l.getElementsByTagName("Url")[0].firstChild.nodeValue
        if url.split("/")[2] == "tlu.dl.delivery.mp.microsoft.com":
            return url

def sendEmail(Version, Filename, URL, betaflag):
    host_server = 'smtp.163.com'
    sender_address = 'Ghost12345@163.com'
    pwd = 'MJHEWYMVTCYSPEBE'
    receiver = ['917749218@qq.com']
    if betaflag == 0:
        message = "New released update for WSA!"
        mail_title = "New released update for WSA! Version " + Version + " is now available!"
    else:
        message = "New beta update for WSA!"
        mail_title = "New beta update for WSA! Version " + Version + " is now available!"
    mail_content = "File Name: " + Filename + "\nURL: " + URL
    msg = MIMEMultipart()
    msg["Subject"] = Header(mail_title,'utf-8')
    msg["From"] = sender_address
    msg['To'] = ";".join(receiver)
    msg.attach(MIMEText(mail_content,'plain','utf-8'))
    smtp = SMTP_SSL(host_server)
    smtp.login(sender_address,pwd)
    smtp.sendmail(sender_address,receiver,msg.as_string())
    smtp.quit()
    title = "WSA version " + Version + " is now available!"
    notification.notify(
            title = title,
            message = message,
            app_icon = dir + "\\wsa.ico",
            timeout = 5,
        )

while 1:
    print("Loading config...\n")
    config = {}
    if os.path.exists(dir + "\\config.json"):
        with open(dir + "\\config.json", "r") as f:
            config = json.loads(f.read())
            f.close()
    else:
        print("Config file not found! Please check your installation!")
        exit()
    users = {""}
    if config["CheckBetaVersion"] == True:
        if os.path.exists(ms_account_conf):
            with open(ms_account_conf, "r") as f:
                conf = Prop(f.read())
                user_token = conf.get('user_code')
        if config["UseLocalToken"] == False:
            try:
                if config["GetTokenURL"].startswith("https://raw.githubusercontent.com"):
                    response = urllib.request.urlopen(config["GetTokenURL"])
                    text = response.read().decode("utf-8")
                else:
                    response = requests.get(config["GetTokenURL"])
                    text = response.text
                user_code = Prop(text).get("user_code")
                updatetime = Prop(text).get("update_time")
                print("Successfully get user token from server!")
                print(f"Last update time: {updatetime}\n")
            except:
                user_code = ""
            if user_code == "":
                print("Fail to get user token from server! Please check \"GetTokenURL\" in config.json, and make sure your Internet is working!")
            elif user_token != user_code:
                with open(ms_account_conf, "w") as f:
                    f.write(f"user_code={user_code}")
                    f.close()
                print("Updated user token!")
                user_token = user_code
        users = {"", user_token}
    print("Generating WSA download link...\n")
    flag = 0
    for user in users:
        if user == "":
            print("Checking release version...\n")
        else:
            print("Checking beta version...\n")
        with open(dir + ("\\xml\\GetCookie.xml"), "r") as f:
            cookie_content = f.read().format(user)
            f.close()
        try:
            out = session.post(
                'https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx',
                data=cookie_content,
                headers={'Content-Type': 'application/soap+xml; charset=utf-8'}
            )
        except:
            for i in range(timer,-1,-1):
                print(f"\rNetwork Error! The program will retry in {i} seconds.",end="")
                time.sleep(1)
            print("\n")
            break
        doc = minidom.parseString(out.text)
        cookie = doc.getElementsByTagName('EncryptedData')[0].firstChild.nodeValue
        with open(dir + "\\xml\\WUIDRequest.xml", "r") as f:
            cat_id_content = f.read().format(user, cookie, cat_id, release_type)
            f.close()
        try:
            out = session.post(
                'https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx',
                data=cat_id_content,
                headers={'Content-Type': 'application/soap+xml; charset=utf-8'}
            )
        except:
            for i in range(timer,-1,-1):
                print(f"\rNetwork Error! The program will retry in {i} seconds.",end="")
                time.sleep(1)
            print("\n")
            break
        doc = minidom.parseString(html.unescape(out.text))
        filenames = {}
        for node in doc.getElementsByTagName('ExtendedUpdateInfo')[0].getElementsByTagName('Updates')[0].getElementsByTagName('Update'):
            node_xml = node.getElementsByTagName('Xml')[0]
            node_files = node_xml.getElementsByTagName('Files')
            if not node_files:
                continue
            else:
                for node_file in node_files[0].getElementsByTagName('File'):
                    if node_file.hasAttribute('InstallerSpecificIdentifier') and node_file.hasAttribute('FileName'):
                        filenames[node.getElementsByTagName('ID')[0].firstChild.nodeValue] = (f"{node_file.attributes['InstallerSpecificIdentifier'].value}_{node_file.attributes['FileName'].value}",
                                                                                          node_xml.getElementsByTagName('ExtendedProperties')[0].attributes['PackageIdentityName'].value)
        identities = {}
        for node in doc.getElementsByTagName('NewUpdates')[0].getElementsByTagName('UpdateInfo'):
            node_xml = node.getElementsByTagName('Xml')[0]
            if not node_xml.getElementsByTagName('SecuredFragment'):
                continue
            else:
                id = node.getElementsByTagName('ID')[0].firstChild.nodeValue
                update_identity = node_xml.getElementsByTagName('UpdateIdentity')[0]
                if id in filenames:
                    fileinfo = filenames[id]
                    if fileinfo[0] not in identities:
                        identities[fileinfo[0]] = ([update_identity.attributes['UpdateID'].value,
                                                update_identity.attributes['RevisionNumber'].value], fileinfo[1])
        info_list = []
        for value in filenames.values():
            if value[0].find("_neutral_") != -1:
                info_list.append(value[0])
        info_list = sorted(
            info_list,
            key=lambda x: (
                x.split("_")[1].split(".")[0],
                x.split("_")[1].split(".")[1],
                x.split("_")[1].split(".")[2],
                x.split("_")[1].split(".")[3]
            ),
            reverse=False
        )
        if flag == 1 and release_id == identities[max(info_list)][0][0]:
            print("Your user token is invalid, please check it.")
            notification.notify(
                title = "Please update your user token!",
                message = "Your user token is invalid, please check it.",
                app_icon = dir + "\\wsa.ico",
                timeout = 5,
            )
            flag = 0
            for i in range(timer,-1,-1):
                print(f"\rThe program will reboot in {i} seconds.",end="")
                time.sleep(1)
            break
        #record if the version is already in the list
        #if not, add it to the list
        markflag = 0
        for key in info_list:
            if key.split("_")[0] == "MicrosoftCorporationII.WindowsSubsystemForAndroid":
                #empty list, add item
                if len(list) == 0:
                    markflag = 1
                #not empty list, check version
                for num in range(len(list)):
                    if list[num]["Version"] == key.split("_")[1]:
                        #found, check UpdateID
                        if identities[key][0][0] not in list[num]["UpdateID"]:
                            list[num]["UpdateID"].append(identities[key][0][0])
                            with open(dir + "\\versionlist.json", "w") as f:   
                                f.write(json.dumps(list, indent=4))
                                f.close()
                        markflag = 0
                        break
                    else:
                        #not found, mark
                        markflag = 1
                        continue
                #not found, add item
                if markflag == 1:
                    newverflag = 1
                    additem = {
                        "Version": key.split("_")[1],
                        "File name": "MicrosoftCorporationII.WindowsSubsystemForAndroid_" + key.split("_")[1] + "_neutral_~_8wekyb3d8bbwe.Msixbundle",
                        "MD5": "null",
                        "SHA256": "null",
                        "UpdateID": [identities[key][0][0]]
                    }
                    list.append(additem)
                    with open(dir + "\\versionlist.json", "w") as f:   
                        f.write(json.dumps(list, indent=4))
                        f.close()
                    url = getURL(user, identities[key][0][0], identities[key][0][1], release_type)
                    while url == "null":
                        url = getURL(user, identities[key][0][0], identities[key][0][1], release_type)
                    sendEmail(
                        key.split("_")[1],
                        "MicrosoftCorporationII.WindowsSubsystemForAndroid_" + key.split("_")[1] + "_neutral_~_8wekyb3d8bbwe.Msixbundle",
                        url,
                        flag
                    )
                    print("New version found: " + key.split("_")[1])
                    print("File name: " + "MicrosoftCorporationII.WindowsSubsystemForAndroid_" + key.split("_")[1] + "_neutral_~_8wekyb3d8bbwe.Msixbundle")
                    print("URL: " + url)
                    print("")
        #sort the list
        list = sorted(
            list, 
            key = lambda x: (
                int(x["Version"].split(".")[0]), 
                int(x["Version"].split(".")[1]), 
                int(x["Version"].split(".")[2]), 
                int(x["Version"].split(".")[3])
            ),
            reverse=False
        )
        url = getURL(user, identities[max(info_list)][0][0], identities[max(info_list)][0][1], release_type)
        if url == "null":
            break
        if newverflag == 0:
            print("Latest version: " + max(info_list).split("_")[1])
            print("File name: MicrosoftCorporationII.WindowsSubsystemForAndroid_" + max(info_list).split("_")[1] + "_neutral_~_8wekyb3d8bbwe.Msixbundle")
            print("URL: " + url)
            print("")
        elif newverflag == 1:
            newverflag = 0
        if flag == 1:
            for i in range(timer,-1,-1):
                print(f"\rThe program will reboot in {i} seconds.",end="")
                time.sleep(1)
            print("Done!\n")
        elif flag == 0 and config["CheckBetaVersion"] == True:
            flag = 1
            release_id = identities[max(info_list)][0][0]
        else:
            for i in range(timer,-1,-1):
                print(f"\rThe program will reboot in {i} seconds.",end="")
                time.sleep(1)
            print("Done!\n")
        