# Getting Started

## Intro to Web Proxies
- Most applications heavily rely on back-end servers to process data, testing the back-end servers is more important.
- Testing web-requests to back-end servers make up the bulk of Web Application Penetration Testing, Which includes concepts that apply to both web and mobile applications.
### What are Web Proxies?
- It is a man-in-the-middle tool which help us analyze web requests being sent between both back-end server and client application.
- Web proxies mainly work with web ports but not limited to HTTP/80 and HTTPS/443.
- We can intercept a specific request to modify its data and see how the back-end server handles them.
### Uses of Web Proxies
While the primary use of web proxies is to capture and replay HTTP requests, they have many other features that enable different uses for web proxies. The following list shows some of the other tasks we may use web proxies for:

- Web application vulnerability scanning
- Web fuzzing
- Web crawling
- Web application mapping
- Web request analysis
- Web configuration testing
- Code reviews
### Burp Suite
Mostly Glazing Pro and how Free version is enough for these modules

### OWASP Zed Attack Proxy (ZAP)
- Completely Open Source.
- No throttling or limitations.
- Many of the Burp's paid feature available in ZAP.
- Burp Pro could be more mature.
## Setting Up
Installation Procedure.

### Burp Suite
Basic installation and running software.

### ZAP
We can create multiple Project files.

``` bash
Tip: If you prefer to use to a dark theme, you may do so in Burp by going to (`User Options>Display`) and selecting "dark" under (`theme`), and in ZAP by going to (`Tools>Options>Display`) and selecting "Flat Dark" in (`Look and Feel`).
```
# Web Proxy
## Proxy Setup
We can set up these tools as a proxy for any application, such that all web requests would be routed through them so that we can manually examine what web requests an application is sending and receiving. This will enable us to understand better what the application is doing in the background and allows us to intercept and change these requests or reuse them with various changes to see how the application responds.

### Pre-Configure Browser
Both come with a pre-configured browser.

### Proxy Setup
**Note:** In case we wanted to serve the web proxy on a different port, we can do that in Burp under (`Proxy>Options`), or in ZAP under (`Tools>Options>Local Proxies`). In both cases, we must ensure that the proxy configured in Firefox uses the same port.

Download FoxyProxy> click on options> click on add on the left pane> set Proxy IP address or DNS name as localhost > set Port as 8080 and name it to Burp or ZAP.

After adding click on the option in the browser extension to connect to burp/zap.

### Installing CA Certificate
While running Burp and with proxy up, search the url `http://burp` and download the CA Certificate.
To get ZAP's certificate, we can go to `tools> Options > Dynamic SSL Certification` then click on save.

Add the certificate under about:preferences#privacy and click on view certificates on the bottom of the web site.

under authorities tab click on import and select the downloaded CA certificate.

click on both trust options.
## Intercepting Web Requests


## Intercepting Responses

## Automatic Modification

## Repeating Requests

## Encoding/Decoding

## Proxying Tools

# Web Fuzzer

## Burp Intruder

## ZAP Fuzzer

# Web Scanner

## Burp Scanner

## Zap Scanner

## Extensions

# Skills Assessment