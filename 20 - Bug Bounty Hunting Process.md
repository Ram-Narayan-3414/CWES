# Bug Bounty 101
- Consider BBP as a crowdsourcing initiative through which one can receive recognition and compensation for discovering and reporting software bugs.
- BBP is continuous and proactive security testing that supplements internal code audits and pentests and completes an organization's vuln management strategy.
## Bug Bounty Programs
Two types:
- Private bug bounty programs:
	1. Hunters can only participate in a private bug bounty program upon receiving specific invitations.
- Public bug bounty programs are accessible by the entire hacking community.
- Parent/Child Programs:
	- A bounty pool and a single cyber security team are shared between a parent company and its subsidiaries.
	- If a subsidiary launches a bug bounty program(child program), this program will be linked to the parent one.

| BBP                                                              | VDP                                                                                                                 |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Incentivizes third parties to discover and report software bugs. | Provides guidance on how an organization prefers receiving information on identified vulnerabilities by third party |
| Bug  Bounty hunters receive monetary rewards in return           | Hunters receive recognition.                                                                                        |
### Bug Bounty Program Code of Conduct
Spend considerable time reading the code of conduct as it does not just establish expectations for behavior but also makes bug bounty hunters more effective and successful during their bug report submissions.

Strike a balance between professionalism and technical capabilities.

### Bug Bounty Program Structure
A bug bounty program usually consists of the following elements:

| `Vendor Response SLAs`          | Defines when and how the vendor will reply                                                                        |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `Access`                        | Defines how to create or obtain accounts for research purposes                                                    |
| `Eligibility Criteria`          | For example, be the first reporter of a vulnerability to be eligible, etc.                                        |
| `Responsible Disclosure Policy` | Defines disclosure timelines, coordination actions to safely disclose a vulnerability, increase user safety, etc. |
| `Rules of Engagement`           |                                                                                                                   |
| `Scope`                         | In-scope IP Ranges, domains, vulnerabilities, etc.                                                                |
| `Out of Scope`                  | Out-of-scope IP Ranges, domains, vulnerabilities, etc.                                                            |
| `Reporting Format`              |                                                                                                                   |
| `Rewards`                       |                                                                                                                   |
| `Safe Harbor`                   |                                                                                                                   |
| `Legal Terms and Conditions`    |                                                                                                                   |
| `Contact Information`           |                                                                                                                   |

## Writing Good Report
- Bug reports should include information on how exploitation of each vulnerability can be reproduced step-by-step.
- When reporting to less mature companies, we may have to translate technical security issues into more understandable/ business terms for them to understand the actual impact of each vulnerability
The essential elements of a good bug report are (the element order can vary):

| `Vulnerability Title`       | Including vulnerability type, affected domain/parameter/endpoint, impact etc.                                                                                        |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CWE & CVSS score`          | For communicating the characteristics and severity of the vulnerability.                                                                                             |
| `Vulnerability Description` | Better understanding of the vulnerability cause.                                                                                                                     |
| `Proof of Concept (POC)`    | Steps to reproduce exploiting the identified vulnerability clearly and concisely.                                                                                    |
| `Impact`                    | Elaborate more on what an attacker can achieve by fully exploiting the vulnerability. Business impact and maximum damage should be included in the impact statement. |
| `Remediation`               | Optional in bug bounty programs, but good to have.                                                                                                                   |

Readable and well-formatted bug reports can drastically minimize both vulnerability reproduction time and time to triage.

### Why CWE & CVSS
- CWE: Common Weaknesses Enumeration
- A community-developed list of software and hardware weakness types.
- It server as a common language, a measuring stick for security tools, and as a baseline for weakness identification, mitigation, and prevention efforts.
- In the case of a vulnerability chain, choose a CWE related to the initial vulnerability.
In case of communication of the severity of an identified vulnerability, the Common Vulnerability Scoring System (CVSS) should be used, as it is a published standard used by organizations worldwide.

### Using CVSS Calculator
[CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)

Focus on Base Score area only.
#### Attack Vector

Shows how the vulnerability can be exploited.

- `Network (N):` Attackers can only exploit this vulnerability through the network layer (remotely exploitable).
    
- `Adjacent (A):` Attackers can exploit this vulnerability only if they reside in the same physical or logical network (secure VPN included).
    
- `Local (L):` Attackers can exploit this vulnerability only by accessing the target system locally (e.g., keyboard, terminal, etc.) or remotely (e.g., SSH) or through user interaction.
    
- `Physical (P):` Attackers can exploit this vulnerability through physical interaction/manipulation.
#### Attack Complexity

Depicts the conditions beyond the attackers' control and must be present to exploit the vulnerability successfully.

- `Low (L):` No special preparations should take place to exploit the vulnerability successfully. The attackers can exploit the vulnerability repeatedly without any issue.
    
- `High (H):` Special preparations and information gathering should take place to exploit the vulnerability successfully.
#### Privileges Required

Show the level of privileges the attacker must have to exploit the vulnerability successfully.

- `None (N):` No special access related to settings or files is required to exploit the vulnerability successfully. The vulnerability can be exploited from an unauthorized perspective.
    
- `Low (L):` Attackers should possess standard user privileges to exploit the vulnerability successfully. The exploitation in this case usually affects files and settings owned by a user or non-sensitive assets.
    
- `High (H):` Attackers should possess admin-level privileges to exploit the vulnerability successfully. The exploitation in this case usually affects the entire vulnerable system.
#### User Interaction

Shows if attackers can successfully exploit the vulnerability on their own or user interaction is required.

- `None (N):` Attackers can successfully exploit the vulnerability independently.
    
- `Required (R):` A user should take some action before the attackers can successfully exploit the vulnerability.
#### Scope

Shows if successful exploitation of the vulnerability can affect components other than the affected one.

- `Unchanged (U):` Successful exploitation of the vulnerability affects the vulnerable component or affects resources managed by the same security authority.
    
- `Changed (C):` Successful exploitation of the vulnerability can affect components other than the affected one or resources beyond the scope of the affected component's security authority.

#### Confidentiality

Shows how much the vulnerable component's confidentiality is affected upon successfully exploiting the vulnerability. Confidentiality limits information access and disclosure to authorized users only and prevents unauthorized users from accessing information.

- `None (N):` The confidentiality of the vulnerable component does not get impacted.
    
- `Low (L):` The vulnerable component will experience some loss of confidentiality upon successful exploitation of the vulnerability. In this case, the attackers do not have control over what information is obtained.
    
- `High (H):` The vulnerable component will experience total (or serious) loss of confidentiality upon successfully exploiting the vulnerability. In this case, the attackers have total (or some) control over what information is obtained.

#### Integrity

Shows how much the vulnerable component's integrity is affected upon successfully exploiting the vulnerability. Integrity refers to the trustworthiness and veracity of information.

- `None (N):` The integrity of the vulnerable component does not get impacted.
    
- `Low (L):` Attackers can modify data in a limited manner on the vulnerable component upon successfully exploiting the vulnerability. Attackers do not have control over the consequence of a modification, and the vulnerable component does not get seriously affected in this case.
    
- `High (H):` Attackers can modify all or critical data on the vulnerable component upon successfully exploiting the vulnerability. Attackers have control over the consequence of a modification, and the vulnerable component will experience a total loss of integrity.
#### Availability

Shows how much the vulnerable component's availability is affected upon successfully exploiting the vulnerability. Availability refers to the accessibility of information resources in terms of network bandwidth, disk space, processor cycles, etc.

- `None (N):` The availability of the vulnerable component does not get impacted.
    
- `Low (L):` The vulnerable component will experience some loss of availability upon successfully exploiting the vulnerability. The attacker does not have complete control over the vulnerable component's availability and cannot deny the service to users, and performance is just reduced.
    
- `High (H):` The vulnerable component will experience total (or severe) availability loss upon successfully exploiting the vulnerability. The attacker has complete (or significant) control over the vulnerable component's availability and can deny the service to users. Performance is significantly reduced.
---
## Examples
Find below some examples of using CVSS 3.1 to communicate the severity of vulnerabilities.

| `Title:`               | Cisco ASA Software IKEv1 and IKEv2 Buffer Overflow Vulnerability (CVE-2016-1287)                                                                                                          |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CVSS 3.1 Score:`      | 9.8 (Critical)                                                                                                                                                                            |
| `Attack Vector:`       | Network - The Cisco ASA device was exposed to the internet since it was used to facilitate connections to the internal network through VPN.                                               |
| `Attack Complexity:`   | Low - All the attacker has to do is execute the available exploit against the device                                                                                                      |
| `Privileges Required:` | None - The attack could be executed from an unauthenticated/unauthorized perspective                                                                                                      |
| `User Interaction:`    | None - No user interaction is required                                                                                                                                                    |
| `Scope:`               | Unchanged - Although you can use the exploited device as a pivot, you cannot affect other components by exploiting the buffer overflow vulnerability.                                     |
| `Confidentiality:`     | High - Successful exploitation of the vulnerability results in unrestricted access in the form of a reverse shell. Attackers have total control over what information is obtained.        |
| `Integrity:`           | High - Successful exploitation of the vulnerability results in unrestricted access in the form of a reverse shell. Attackers can modify all or critical data on the vulnerable component. |
| `Availability:`        | High - Successful exploitation of the vulnerability results in unrestricted access in the form of a reverse shell. Attackers can deny the service to users by powering the device off     |

---

|                        |                                                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `Title:`               | Stored XSS in an admin panel (Malicious Admin -> Admin)                                                                  |
| `CVSS 3.1 Score:`      | 5.5 (Medium)                                                                                                             |
| `Attack Vector:`       | Network - The attack can be mounted over the internet.                                                                   |
| `Attack Complexity:`   | Low - All the attacker (malicious admin) has to do is specify the XSS payload that is eventually stored in the database. |
| `Privileges Required:` | High - Only someone with admin-level privileges can access the admin panel.                                              |
| `User Interaction:`    | None - Other admins will be affected simply by browsing a specific (but regularly visited) page within the admin panel.  |
| `Scope:`               | Changed - Since the vulnerable component is the webserver and the impacted component is the browser                      |
| `Confidentiality:`     | Low - Access to DOM was possible                                                                                         |
| `Integrity:`           | Low - Through XSS, we can slightly affect the integrity of an application                                                |
| `Availability:`        | None - We cannot deny the service through XSS                                                                            |

---
## Good Report Examples

Find below some good report examples selected by HackerOne:

- [SSRF in Exchange leads to ROOT access in all instances](https://hackerone.com/reports/341876)
- [Remote Code Execution in Slack desktop apps + bonus](https://hackerone.com/reports/783877)
- [Full name of other accounts exposed through NR API Explorer (another workaround of #476958)](https://hackerone.com/reports/520518)
- [A staff member with no permissions can edit Store Customer Email](https://hackerone.com/reports/980511)
- [XSS while logging in using Google](https://hackerone.com/reports/691611)
- [Cross-site Scripting (XSS) on HackerOne careers page](https://hackerone.com/reports/474656)
## Interacting with Organizations/BBP Hosts
Suppose that a report has been submitted, how should you interact with the security/triage team after that:
- Don't interact with them, allow the triage team some time to process your report, validate your finding and maybe ask questions.
- Understand how long it can take for them to get back to a submission.
- Don't spam the triage team within a short period of time.
- Contact mediation if the team doesn't get back to you in a reasonable amount of time if the report was made through BB platform.
- Note the team member's username as they will probably the one who will be fixing the issue.
- Don't interact with them from any other social media.
- Have a Professional communication, remain calm and interact with the security/triage team as a security professional would.
- In case of disagreement, proceed as follows:
	- Explain why you chose the CVSS for the issue and delegate professionally
	- Make sure to comply with both the policy and scope of the program.
	- None of the above was fruitful contact mediation or a similar platform service.
# Professionally Reporting Bugs

## Example 1: Reporting Stored XSS

`Title`: Stored Cross-Site Scripting (XSS) in X Admin Panel

`CWE`: [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

`CVSS 3.1 Score`: 5.5 (Medium)

`Description`: During our testing activities, we identified that the "X for administrators" web application is vulnerable to stored cross-site scripting (XSS) attacks due to inadequate sanitization of user-supplied data. Specifically, the file uploading mechanism at "Admin Info" -> "Secure Data Transfer" -> "Load of Data" utilizes a value obtained from user input, specifically the uploaded file's filename, which is not only directly reflected back to the user’s browser but is also stored into the web application’s database. However, this value does not appear to be adequately sanitized. It, therefore, results in the application being vulnerable to reflected and stored cross-site scripting (XSS) attacks since JavaScript code can be entered in the filename field.

`Impact`: Cross-Site Scripting issues occur when an application uses untrusted data supplied by offensive users in a web browser without sufficient prior validation or escaping. A potential attacker can embed untrusted code within a client-side script to be executed by the browser while interpreting the page. Attackers utilize XSS vulnerabilities to execute scripts in a legitimate user's browser leading to user credentials theft, session hijacking, website defacement, or redirection to malicious sites. Anyone that can send data to the system, including administrators, are possible candidates for performing XSS attacks against the vulnerable application. This issue introduces a significant risk since the vulnerability resides in the "X for administrators” web application, and the uploaded files are visible and accessible by every administrator. Consequently, any administrator can be a possible target of a Cross-Site Scripting attack.

`POC`:

Step 1: A malicious administrator could leverage the fact that the filename value is reflected back to the browser and stored in the web application’s database to perform cross-site scripting attacks against other administrators by uploading a file containing malicious JavaScript code into its filename. The attack is feasible because administrators can view all uploaded files regardless of the uploader. Specifically, we named the file, as follows, using a Linux machine.

Code: javascript

```javascript
"><svg onload = alert(document.cookie)>.docx
```

![File upload interface showing a potentially malicious file.](https://academy.hackthebox.com/storage/modules/161/2.png)

Step 2: When another administrator clicks the view button to open the abovementioned file, the malicious JavaScript code in the file’s filename will be executed on the browser.

![Admin interface showing uploaded files, including a highlighted file named 'malicious_filename' uploaded by Pentest Admin01.](https://academy.hackthebox.com/storage/modules/161/3.png) ![Admin interface with a session alert popup displaying session details for Pentest Admin02.](https://academy.hackthebox.com/storage/modules/161/4.png)

---

## CVSS Score Breakdown

| `Attack Vector:`       | Network - The attack can be mounted over the internet.                                                                  |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `Attack Complexity:`   | Low - All the attacker (malicious admin) has to do is specify the XSS payload eventually stored in the database.        |
| `Privileges Required:` | High - Only someone with admin-level privileges can access the admin panel.                                             |
| `User Interaction:`    | None - Other admins will be affected simply by browsing a specific (but regularly visited) page within the admin panel. |
| `Scope:`               | Changed - Since the vulnerable component is the webserver and the impacted component is the browser                     |
| `Confidentiality:`     | Low - Access to DOM was possible                                                                                        |
| `Integrity:`           | Low - Through XSS, we can slightly affect the integrity of an application                                               |
| `Availability:`        | None - We cannot deny the service through XSS                                                                           |

## Example 2: Reporting CSRF
`Title`: Cross-Site Request Forgery (CSRF) in Consumer Registration

`CWE`: [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

`CVSS 3.1 Score`: 5.4 (Medium)

`Description`: During our testing activities, we identified that the web page responsible for consumer registration is vulnerable to Cross-Site Request Forgery (CSRF) attacks. Cross-Site Request Forgery (CSRF) is an attack where an attacker tricks the victim into loading a page that contains a malicious request. It is malicious in the sense that it inherits the identity and privileges of the victim to perform an undesired function on the victim's behalf, like change the victim's e-mail address, home address, or password, or purchase something. CSRF attacks generally target functions that cause a state change on the server but can also be used to access sensitive data.

`Impact`: The impact of a CSRF flaw varies depending on the nature of the vulnerable functionality. An attacker could effectively perform any operations as the victim. Because the attacker has the victim's identity, the scope of CSRF is limited only by the victim's privileges. Specifically, an attacker can register a fintech application and create an API key as the victim in this case.

`POC`:

Step 1: Using an intercepting proxy, we looked into the request to create a new fintech application. We noticed no anti-CSRF protections being in place.

![Application registration form with fields for application type, name, description, and developer email.](https://academy.hackthebox.com/storage/modules/161/5.png) ![HTTP POST request to /consumer-registration with parameters for app type, name, developer email, and description.](https://academy.hackthebox.com/storage/modules/161/6.png)

Step 2: We used the abovementioned request to craft a malicious HTML page that, if visited by a victim with an active session, a cross-site request will be performed, resulting in the advertent creation of an attacker-specific fintech application.

![HTTP request with CSRF HTML form showing POST to /consumer-registration with parameters for app type, name, developer email, and description.](https://academy.hackthebox.com/storage/modules/161/7.png)

Step 3: To complete the attack, we would have to send our malicious web page to a victim having an open session. The following image displays the actual cross-site request that would be issued if the victim visited our malicious web page.

![HTTP POST request to /consumer-registration with parameters for app type, name, developer email, and description.](https://academy.hackthebox.com/storage/modules/161/8.png)

Step 4: The result would be the inadvertent creation of a new fintech application by the victim. It should be noted that this attack could have taken place in the background if combined with finding 6.1.1. <-- 6.1.1 was an XSS vulnerability.

![API registration confirmation showing application type 'Web', name 'Unwanted_FinTech App', developer email 'j_irons@gmail.com', and consumer keys.](https://academy.hackthebox.com/storage/modules/161/9.png)

---

## CVSS Score Breakdown

| `Attack Vector:`       | Network - The attack can be mounted over the internet.                                                                                         |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `Attack Complexity:`   | Low - All the attacker has to do is trick a user that has an open session into visiting a malicious website.                                   |
| `Privileges Required:` | None - The attacker needs no privileges to mount the attack.                                                                                   |
| `User Interaction:`    | Required - The victim must click a crafted link provided by the attacker.                                                                      |
| `Scope:`               | Unchanged - Since the vulnerable component is the webserver and the impacted component is again the webserver.                                 |
| `Confidentiality:`     | Low - The attacker can create a fintech application and obtain limited information.                                                            |
| `Integrity:`           | Low - The attacker can modify data (create an application) but limitedly and without seriously affecting the vulnerable component's integrity. |
| `Availability:`        | None - The attacker cannot perform a denial-of-service through this CSRF attack.                                                               |
## Example 3: Reporting RCE
`Title`: IBM WebSphere Java Object Deserialization RCE

`CWE`: [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

`CVSS 3.1 Score`: 9.8 (Critical)

`Description`: During our testing activities, we identified that the remote WebSphere application server is affected by a vulnerability related to insecure Java object deserialization allowing remote attackers to execute arbitrary commands. By issuing a request to the remote WebSphere application server over HTTPS on port 8880, we identified the existence of raw, serialized Java objects that were base64-encoded. It is possible to identify base64 encoded serialized Java objects by the "rO0" header. We were able to craft a SOAP request containing a serialized Java object that can exploit the aforementioned vulnerability in the Apache Commons Collections (ACC) library used by the WebSphere application server. The crafted Java object contained a `ping` command to be executed by the affected system.

`Impact`: Command injection vulnerabilities typically occur when data enters the application from an untrusted source, such as a terminal or a network socket, without authenticating the source, or the data is part of a string that is executed as a command by the application, again without validating the input against a predefined list of allowed commands, such as a whitelist. The application executes the provided command under the current user's security context. If the application is executed as a privileged user, administrative or driver interface, such as the SYSTEM account, it can potentially allow the complete takeover of the affected system.

`POC`:

Step 1: We identified that the application uses serialized data objects by capturing and decoding a request to port 8880 of the server. The following images display the original request and the remote server's response, along with its decoded content.

![HTTP GET request to 192.168.44.63:8880 with XML error response showing SOAP fault details.](https://academy.hackthebox.com/storage/modules/161/10.png)

Step 2: We crafted a SOAP request containing a command to be executed by the remote server. The command would send `ping` messages from the affected server to our host. The image below displays the crafted request and its decoded payload.

![Burp Suite Decoder showing a base64 encoded string and its decoded Java object content.](https://academy.hackthebox.com/storage/modules/161/11.png)

Step 3: The following image displays the crafted SOAP request allowing to remotely execute a `ping` command from the affected system. Capturing traffic via Wireshark, we observed the `ping` request from the Websphere application server to our machine.

![Burp Suite and Wireshark interface showing a SOAP request with XML content and ICMP traffic indicating a ping command to 10.95.220.105.](https://academy.hackthebox.com/storage/modules/161/12.png)

## CVSS Score Breakdown

| `Attack Vector:`       | Network - The attack can be mounted over the internet.                                                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Attack Complexity:`   | Low - All the attacker has to do is send a crafted request against the vulnerable application.                                                               |
| `Privileges Required:` | None - The attack can be mounted from an unauthenticated perspective.                                                                                        |
| `User Interaction:`    | None - No user interaction is required to exploit this vulnerability successfully.                                                                           |
| `Scope:`               | Unchanged - Since the vulnerable component is the webserver and the impacted component is again the webserver.                                               |
| `Confidentiality:`     | High - Successful exploitation of the vulnerability results in remote code execution, and attackers have total control over what information is obtained.    |
| `Integrity:`           | High - Successful exploitation of the vulnerability results in remote code execution. Attackers can modify all or critical data on the vulnerable component. |
| `Availability:`        | High - Successful exploitation of the vulnerability results in remote code execution. Attackers can deny the service to users by powering the webserver off. |
