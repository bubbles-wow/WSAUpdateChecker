import os
import sys
import html
import json
import base64
import logging
import hashlib
import requests
import subprocess

from xml.dom import minidom
from requests import Session
from smtplib import SMTP_SSL
from email.header import Header
from typing import Any, OrderedDict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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

# Catagory ID
cat_id = '858014f3-3934-4abe-8078-4aa193e74ca8'

file_name_format = "MicrosoftCorporationII.WindowsSubsystemForAndroid_{0}_neutral_~_8wekyb3d8bbwe.Msixbundle"

session = Session()
session.verify = False

user_token = ""

# check if release UpdateID is the same as the beta one
release_id = ""

# get environment information
host_server = os.getenv("HOST_SERVER")
sender_email = os.getenv("SENDER_EMAIL")
sender_password = os.getenv("SENDER_PASSWORD")
receiver = os.getenv("RECEIVER_EMAIL")
archive_repos = os.getenv("ARCHIVE_REPOS")

if len(sys.argv) > 1:
    if sys.argv[1] == "--no-archive":
        archive_repos = None

list = []
if os.path.exists("List.json"):
    with open("List.json", "r") as f:
        mainjson = json.loads(f.read())
        f.close()
    for i in mainjson:
        list.append(i)

def getURL(user, UpdateID, RevisionNumber, ReleaseType):
    with open("./xml/FE3FileUrl.xml", "r") as f:
        FE3_file_content = f.read()
        f.close()
    try:
        out = session.post(
            'https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured',
            data=FE3_file_content.format(user, UpdateID, RevisionNumber, ReleaseType),
            headers={'Content-Type': 'application/soap+xml; charset=utf-8'}
        )
    except:
        return "null"
    if len(out.text) < 1500:
        return "null"
    doc = minidom.parseString(out.text)
    for l in doc.getElementsByTagName("FileLocation"):
        url = l.getElementsByTagName("Url")[0].firstChild.nodeValue
        if url.split("/")[2] == "tlu.dl.delivery.mp.microsoft.com":
            return url

def send_email(Version, Filename, URL, check_type, host_server = host_server, sender_email = sender_email, sender_password = sender_password, receiver = receiver):
    if check_type == "Retail":
        mail_title = f"[WSA] Stable version {Version} Updated!"
    if check_type == "Windows Insider":
        mail_title = f"[WSA] Windows Insider version {Version} Updated!"
    if check_type == "WSA Insider":
        mail_title = f"[WSA] WSA Insider version {Version} Updated!"
    mail_content = "File Name: " + Filename + "\nURL: " + URL
    msg = MIMEMultipart()
    msg["Subject"] = Header(mail_title,'utf-8')
    msg["From"] = sender_email
    msg['To'] = ";".join(receiver)
    msg.attach(MIMEText(mail_content,'plain','utf-8'))
    smtp = SMTP_SSL(host_server)
    smtp.login(sender_email, sender_password)
    smtp.sendmail(sender_email, receiver, msg.as_string())
    smtp.quit()

def calculate_hashes(data):
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    for chunk in data.iter_content(8192):
        md5_hash.update(chunk)
        sha256_hash.update(chunk)
    return md5_hash.hexdigest(), sha256_hash.hexdigest()

def checker(user, release_type, list = list):
    # set check type
    check_type = "Retail"
    if release_type == "WIF":
        check_type = "Windows Insider"
    if user != "":
        check_type = "WSA Insider"
    # set flag
    new_version = False
    show_latest = True
    global release_id
    global cur_time
    with open("./xml/GetCookie.xml", "r") as f:
        cookie_content = f.read().format(user)
        f.close()
    try:
        out = session.post(
            'https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx',
            data=cookie_content,
            headers={'Content-Type': 'application/soap+xml; charset=utf-8'}
        )
    except:
        print("Network Error!")
        return 1
    doc = minidom.parseString(out.text)
    cookie = doc.getElementsByTagName('EncryptedData')[0].firstChild.nodeValue
    with open("./xml/WUIDRequest.xml", "r") as f:
        cat_id_content = f.read().format(user, cookie, cat_id, release_type)
        f.close()
    try:
        out = session.post(
            'https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx',
            data=cat_id_content,
            headers={'Content-Type': 'application/soap+xml; charset=utf-8'}
        )
    except:
        print("Network Error!")
        return 1
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
            int(x.split("_")[1].split(".")[0]),
            int(x.split("_")[1].split(".")[1]),
            int(x.split("_")[1].split(".")[2]),
            int(x.split("_")[1].split(".")[3])
        ),
        reverse=False
    )
    if check_type == "Windows Insider":
        release_id = identities[info_list[-1]][0][0]
    if check_type == "WSA Insider":
        if identities[info_list[-1]][0][0] == release_id:
            print("Invaild token!")
            return 1

    url = "null"
    for key in info_list:
        if key.split("_")[0] == "MicrosoftCorporationII.WindowsSubsystemForAndroid":
            # empty list, add item
            if len(list) == 0:
                new_version = True
            # not empty list, check version
            for num in range(len(list)):
                if list[num]["Version"] == key.split("_")[1]:
                    # check if MD5 and SHA256 are missing
                    if list[num]["MD5"] == None or list[num]["SHA256"] == None:
                        url = getURL(user, identities[key][0][0], identities[key][0][1], release_type)
                        response = requests.get(url)
                        Filename = file_name_format.format(key.split("_")[1])
                        if response.status_code == 200:
                            print(f"Missing MD5 or SHA256 value in version {key.split("_")[1]}, Calculating...")
                            md5_hash, sha256_hash = calculate_hashes(response)
                            print(f"MD5: {md5_hash}")
                            print(f"SHA256: {sha256_hash}")
                            list[num]["MD5"] = md5_hash
                            list[num]["SHA256"] = sha256_hash
                            with open("List.json", "w") as f:   
                                f.write(json.dumps(list, indent=4))
                                f.close()
                        else:
                            print(f"An error occured when downloading: {response.status_code}")
                        print("")
                    # check UpdateID
                    if identities[key][0][0] not in list[num]["UpdateID"]:
                        list[num]["UpdateID"].append(identities[key][0][0])
                        with open("List.json", "w") as f:   
                            f.write(json.dumps(list, indent=4))
                            f.close()
                    new_version = False
                    break
                else:
                    # not found, mark
                    new_version = True
                    continue

            # add item
            if new_version == True:
                if key.split("_")[1] == info_list[-1].split("_")[1]:
                    show_latest = False
                command_update_list = "git add List.json && git commit -m \"Add UpdateID\" && git push && exit"
                if os.path.getmtime("List.json") != cur_time:
                    subprocess.Popen(command_update_list, shell=True, stdout=None, stderr=None).wait()
                    cur_time = os.path.getmtime("List.json")
                Filename = file_name_format.format(key.split("_")[1])

                url = getURL(user, identities[key][0][0], identities[key][0][1], release_type)
                while url == "null":
                    url = getURL(user, identities[key][0][0], identities[key][0][1], release_type)
                
                print("New version found: " + key.split("_")[1])
                print("File name: " + file_name_format.format(key.split("_")[1]))
                print("URL: " + url)

                add_item = {
                    "Version": key.split("_")[1],
                    "FileName": Filename,
                    "MD5": None,
                    "SHA256": None,
                    "UpdateID": [identities[key][0][0]]
                }
                response = requests.get(url)
                if response.status_code == 200:
                    print("Calculating MD5 and SHA256...")
                    md5_hash, sha256_hash = calculate_hashes(response)
                    print(f"MD5: {md5_hash}")
                    print(f"SHA256: {sha256_hash}")
                    add_item["MD5"] = md5_hash
                    add_item["SHA256"] = sha256_hash
                else:
                    print(f"An error occured when downloading: {response.status_code}")
                list.append(add_item)
                print("")

                # sort the list
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
                with open("List.json", "w") as f:   
                    f.write(json.dumps(list, indent=4))
                    f.close()
                if sender_email != None and receiver != None:
                    send_email(key.split("_")[1], file_name_format.format(key.split("_")[1]), url, check_type)
                with open(f"./{archive_repos}/UpdateInfo.cfg", "w") as f:
                    f.write(f"Version={key.split('_')[1]}\nUpdateID={identities[key][0][0]}\nURL={url}")
                    f.close()
                
                command_update_list = f"git add List.json && git commit -m \"Update version {key.split('_')[1]}\" && git push && exit"
                command_update_archive = f"cd ./{archive_repos} && git add UpdateInfo.cfg && git commit -m \"Update version {key.split("_")[1]}\" && git push && exit"
                subprocess.Popen(command_update_list, shell=True, stdout=None, stderr=None).wait()
                if archive_repos != None:
                    subprocess.Popen(command_update_archive, shell=True, stdout=None, stderr=None).wait()
                cur_time = os.path.getmtime("List.json")
                new_version = False
    if show_latest == True:
        url = getURL(user, identities[info_list[-1]][0][0], identities[info_list[-1]][0][1], release_type)
        if url == "null":
            print("Failed to get URL!")
            return 1
        print("Latest version: " + info_list[-1].split("_")[1])
        print("File name: MicrosoftCorporationII.WindowsSubsystemForAndroid_" + info_list[-1].split("_")[1] + "_neutral_~_8wekyb3d8bbwe.Msixbundle")
        print("URL: " + url)
        print("")

print("Processing...\n")
user_code = ""
with open("token.conf", "r") as f:
    text = f.read()
    user_code = Prop(text).get("user_code")
    f.close()
users = {"", user_code}
# Check if needs push to GitHub
cur_time = os.path.getmtime("List.json")

for user in users:
    if user == "":
        print("Checking Stable version...\n")
        if checker(user, "retail") == 1:
            break
        print("Checking Windows Insider version...\n")
        if checker(user, "WIF") == 1:
            break
    else:
        print("Checking WSA Insider version...\n")
        if checker(user, "WIF") == 1:
            break
git = "git add List.json && git commit -m \"Add UpdateID\" && git push && exit"
if os.path.getmtime("List.json") != cur_time:
    subprocess.Popen(git, shell=True, stdout=None, stderr=None).wait()

print("All done!")