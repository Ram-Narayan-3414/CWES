# HTTP Fundamentals
## 1.HyperText Transfer Protocol (HTTP)
Nothing much here, just basics of how HTTP works and how data is transferred.
There is just mentioning of FQDN [Fully Qualified Domain Name]. 

### Url
``http://admin:password@inlanefreight.com:80/dashboard.php?login=true#status
here the following are the components of the above URL

|**Component**|**Example**|**Description**|
|---|---|---|
|`Scheme`|`http://` `https://`|This is used to identify the protocol being accessed by the client, and ends with a colon and a double slash (`://`)|
|`User Info`|`admin:password@`|This is an optional component that contains the credentials (separated by a colon `:`) used to authenticate to the host, and is separated from the host with an at sign (`@`)|
|`Host`|`inlanefreight.com`|The host signifies the resource location. This can be a hostname or an IP address|
|`Port`|`:80`|The `Port` is separated from the `Host` by a colon (`:`). If no port is specified, `http` schemes default to port `80` and `https` default to port `443`|
|`Path`|`/dashboard.php`|This points to the resource being accessed, which can be a file or a folder. If there is no path specified, the server returns the default index (e.g. `index.html`).|
|`Query String`|`?login=true`|The query string starts with a question mark (`?`), and consists of a parameter (e.g. `login`) and a value (e.g. `true`). Multiple parameters can be separated by an ampersand (`&`).|
|`Fragments`|`#status`|Fragments are processed by the browsers on the client-side to locate sections within the primary resource (e.g. a header or section on the page).|
Not all components are required to access a resource. The main mandatory fields are the scheme and the host, without which the request would have no resource to request.
### HTTP flow
The below steps is how a request in the web is made for a resource:
1. The user enters the URL into the browser, it sends a request to a DNS server to resolve the domain and gets its IP.
2. The DNS server looks up the IP address for the URL and returns it.
3. Our Browsers usually look up records in local '/etc/hosts' file, if the requested domain does not exist within it, then they would contact other DNS servers.
4. Once the browser gets the IP address linked to the requested domain, it sends a GET request to the defualt HTTP port asking for the root / path.
5. Then the web server receives the request and processes it.
6. When the requested file is retrieved as response from server with status code 200 OK, the browser then renders the base file on the root path and presents to the user.
### cURL
Under this section curl was used to make requests, which is a command line tool.
This command line tool is also a library which primarily supports HTTP along with many other protocols.
Pretty good tool for automation and scripting.

E.g:
	`curl inlanefrieght.com`
Basic curl command wont print out Request and Response Header, we can also download files using the following command:
	`curl -O inlanefrieght.com/index.html`

## 2.HyperText Transfer Protocol Secure (HTTPS)
The last section was mostly based on the insecure HTTP protocol, this module is about the secured one, HTTP when captured by a man-in-the-middle attack then the transferred data can be views in clear-text format.

In HTTPs all communications are transferred in an encrypted format.

### HTTPs Overview
Nothing much here as the section goes through the request under HTTP and HTTPs using wireshark and teaches how to identify if a website is running HTTPS or not.

### HTTPs Flow
The below are the steps that follow when communicated using HTTPs:
1. Giving http:// instead of https:// to a website which enforces HTTPs, the browser initially makes request to the default port 80 of the webserver first, this is detected by the server and is redirected to port 443 which is secured compared to port 80 with the status code of `301 Moved Permanently`.
2. The client and server makes initial handshake which is then followed by a key exchange to exchange SSL Certificates. The client too sends the key/certificate.
3. After this an encrypted handshake is initiated to confirm whether the encryption and transfer are working.
4. Once the encrypted handshake is established, normal HTTP communication takes place in encrypted form.
### curl for HTTPs
curl automatically handles all HTTPs communication by performing a secure handshake and then encrypt and decrypt data automatically. If we ever come across a website without SSL then curl will not proceed with the request to protect against MITM attacks.

To skip certificate checks:
	`curl -k https://inlanefreight.com`

## 3.HTTP Requests and Responses
HTTP communications is mainly of two part:
	1. HTTP request:
		1. The client sends a HTTP request which is processed by the server.
		2. The requests contain, the url, request data, headers or options, etc.
	2. HTTP response:
		1. Once the server receives the HTTP request, it processes it and responds by sending the HTTP response which contain the response code and resource data if the requester has access to it.

### HTTP Request
A request contains **HTTP method, Path to Url, HTTP Version, HTTP headers.**
If the server was requested a resource which requires some data, this data too is provided in the request.
The HTTP Headers contains various header values like HOST, User-Agent, Cookies, etc.

### HTTP Response
A response contains **HTTP version, Response Code, Response Headers, Response Body**
Response codes are used to determine the request's status, and the response body in the HTTP response could contain HTML code, JSON data, images, style sheets or scripts, PDFs.

### curl
With the help of curl we can also preview the full HTTP request and the full HTTP response.

To view the full HTTP request and response:
	`curl inlanefreight.com -v`

### Browser DevTools
Browsers come with built in developer tools, which are mainly intended for developers to test their web apps but is as vital as a browser to pentesters.

Using the Network tab we can see how the requests are made.

## 4.HTTP Headers
There are 5 different header categories:
	1. General Headers
	2. Entity Headers
	3. Request Headers
	4. Response Headers
	5. Security Headers

### General Headers
It is used in both request and response, it is used to describe the message rather than its contents.

|**Header**|**Example**|**Description**|
|---|---|---|
|`Date`|`Date: Wed, 16 Feb 2022 10:38:44 GMT`|Holds the date and time at which the message originated. It's preferred to convert the time to the standard [UTC](https://en.wikipedia.org/wiki/Coordinated_Universal_Time) time zone.|
|`Connection`|`Connection: close`|Dictates if the current network connection should stay alive after the request finishes. Two commonly used values for this header are `close` and `keep-alive`. The `close` value from either the client or server means that they would like to terminate the connection, while the `keep-alive` header indicates that the connection should remain open to receive more data and input.|

---
### Entity Headers
Similar to General Headers, these are used to describe the content transferred by a message. They are usually found in responses and POST or PUT requests.

| **Header**         | **Example**                   | **Description**                                                                                                                                                                                                                                                            |
| ------------------ | ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Content-Type`     | `Content-Type: text/html`     | Used to describe the type of resource being transferred. The value is automatically added by the browsers on the client-side and returned in the server response. The `charset` field denotes the encoding standard, such as [UTF-8](https://en.wikipedia.org/wiki/UTF-8). |
| `Media-Type`       | `Media-Type: application/pdf` | The `media-type` is similar to `Content-Type`, and describes the data being transferred. This header can play a crucial role in making the server interpret our input. The `charset` field may also be used with this header.                                              |
| `Boundary`         | `boundary="b4e4fbd93540"`     | Acts as a marker to separate content when there is more than one in the same message. For example, within a form data, this boundary gets used as `--b4e4fbd93540` to separate different parts of the form.                                                                |
| `Content-Length`   | `Content-Length: 385`         | Holds the size of the entity being passed. This header is necessary as the server uses it to read data from the message body, and is automatically generated by the browser and tools like cURL.                                                                           |
| `Content-Encoding` | `Content-Encoding: gzip`      | Data can undergo multiple transformations before being passed. For example, large amounts of data can be compressed to reduce the message size. The type of encoding being used should be specified using the `Content-Encoding` header.                                   |
### Request Headers
These headers are used in an HTTP request and do not relate to the content of the message.

|**Header**|**Example**|**Description**|
|---|---|---|
|`Host`|`Host: www.inlanefreight.com`|Used to specify the host being queried for the resource. This can be a domain name or an IP address. HTTP servers can be configured to host different websites, which are revealed based on the hostname. This makes the host header an important enumeration target, as it can indicate the existence of other hosts on the target server.|
|`User-Agent`|`User-Agent: curl/7.77.0`|The `User-Agent` header is used to describe the client requesting resources. This header can reveal a lot about the client, such as the browser, its version, and the operating system.|
|`Referer`|`Referer: http://www.inlanefreight.com/`|Denotes where the current request is coming from. For example, clicking a link from Google search results would make `https://google.com` the referer. Trusting this header can be dangerous as it can be easily manipulated, leading to unintended consequences.|
|`Accept`|`Accept: */*`|The `Accept` header describes which media types the client can understand. It can contain multiple media types separated by commas. The `*/*` value signifies that all media types are accepted.|
|`Cookie`|`Cookie: PHPSESSID=b4e4fbd93540`|Contains cookie-value pairs in the format `name=value`. A [cookie](https://en.wikipedia.org/wiki/HTTP_cookie) is a piece of data stored on the client-side and on the server, which acts as an identifier. These are passed to the server per request, thus maintaining the client's access. Cookies can also serve other purposes, such as saving user preferences or session tracking. There can be multiple cookies in a single header separated by a semi-colon.|
|`Authorization`|`Authorization: BASIC cGFzc3dvcmQK`|Another method for the server to identify clients. After successful authentication, the server returns a token unique to the client. Unlike cookies, tokens are stored only on the client-side and retrieved by the server per request. There are multiple types of authentication types based on the webserver and application type used.|

A complete list of request headers and their usage can be found [here](https://tools.ietf.org/html/rfc7231#section-5).

### Response Headers
Used in an HTTP response and do not relate to the content of the response.
It is used to provide more context about the response.

|**Header**|**Example**|**Description**|
|---|---|---|
|`Server`|`Server: Apache/2.2.14 (Win32)`|Contains information about the HTTP server, which processed the request. It can be used to gain information about the server, such as its version, and enumerate it further.|
|`Set-Cookie`|`Set-Cookie: PHPSESSID=b4e4fbd93540`|Contains the cookies needed for client identification. Browsers parse the cookies and store them for future requests. This header follows the same format as the `Cookie` request header.|
|`WWW-Authenticate`|`WWW-Authenticate: BASIC realm="localhost"`|Notifies the client about the type of authentication required to access the requested resource.|

### Security Headers
In order to enhance the security against web-based attacks security headers were introduced, these are a class of response headers used to specify certain rules and policies to be followed by the browser while accessing the website.

|**Header**|**Example**|**Description**|
|---|---|---|
|`Content-Security-Policy`|`Content-Security-Policy: script-src 'self'`|Dictates the website's policy towards externally injected resources. This could be JavaScript code as well as script resources. This header instructs the browser to accept resources only from certain trusted domains, hence preventing attacks such as [Cross-site scripting (XSS)](https://en.wikipedia.org/wiki/Cross-site_scripting).|
|`Strict-Transport-Security`|`Strict-Transport-Security: max-age=31536000`|Prevents the browser from accessing the website over the plaintext HTTP protocol, and forces all communication to be carried over the secure HTTPS protocol. This prevents attackers from sniffing web traffic and accessing protected information such as passwords or other sensitive data.|
|`Referrer-Policy`|`Referrer-Policy: origin`|Dictates whether the browser should include the value specified via the `Referer` header or not. It can help in avoiding disclosing sensitive URLs and information while browsing the website.|
### curl
Various commands to fetch response headers and set response headers:
	`curl -I https://www.inlanefreight.com` displays on the response headers
	`curl -i https://www.inlanefreight.com` displays both headers and the response body
	`curl -A 'Mozilla/5.0' https://www.inlanefreight.com` sets the user-agent header as specified agent, also in order to set other header flags we can use `-H`.

### Browser DevTools
under the Network tab, if we click on a request we can see its headers, cookies, etc.



# HTTP Methods

## 5.HTTP Methods and Codes
Request methods are used by browser to send information, forms or files to the server. These are used to tell the server how to process the request we send and how to reply.
### Request Methods
The following are some of the commonly used methods:

|**Method**|**Description**|
|---|---|
|`GET`|Requests a specific resource. Additional data can be passed to the server via query strings in the URL (e.g. `?param=value`).|
|`POST`|Sends data to the server. It can handle multiple types of input, such as text, PDFs, and other forms of binary data. This data is appended in the request body present after the headers. The POST method is commonly used when sending information (e.g. forms/logins) or uploading data to a website, such as images or documents.|
|`HEAD`|Requests the headers that would be returned if a GET request was made to the server. It doesn't return the request body and is usually made to check the response length before downloading resources.|
|`PUT`|Creates new resources on the server. Allowing this method without proper controls can lead to uploading malicious resources.|
|`DELETE`|Deletes an existing resource on the webserver. If not properly secured, can lead to Denial of Service (DoS) by deleting critical files on the web server.|
|`OPTIONS`|Returns information about the server, such as the methods accepted by it.|
|`PATCH`|Applies partial modifications to the resource at the specified location.|

The list only highlights a few of the most commonly used HTTP methods. The availability of a particular method depends on the server as well as the application configuration. For a full list of HTTP methods, you can visit this [link](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods).
### Status Codes
HTTP status codes are used to tell the client the status of their request. An HTTP server can return five classes of status codes:

|**Class**|**Description**|
|---|---|
|`1xx`|Provides information and does not affect the processing of the request.|
|`2xx`|Returned when a request succeeds.|
|`3xx`|Returned when the server redirects the client.|
|`4xx`|Signifies improper requests `from the client`. For example, requesting a resource that doesn't exist or requesting a bad format.|
|`5xx`|Returned when there is some problem `with the HTTP server` itself.|

The following are some of the commonly seen examples from each of the above HTTP status code classes:

|**Code**|**Description**|
|---|---|
|`200 OK`|Returned on a successful request, and the response body usually contains the requested resource.|
|`302 Found`|Redirects the client to another URL. For example, redirecting the user to their dashboard after a successful login.|
|`400 Bad Request`|Returned on encountering malformed requests such as requests with missing line terminators.|
|`403 Forbidden`|Signifies that the client doesn't have appropriate access to the resource. It can also be returned when the server detects malicious input from the user.|
|`404 Not Found`|Returned when the client requests a resource that doesn't exist on the server.|
|`500 Internal Server Error`|Returned when the server cannot process the request.|

For a full list of standard HTTP status codes, you can visit this [link](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status). Apart from the standard HTTP codes, various servers and providers such as [Cloudflare](https://support.cloudflare.com/hc/en-us/articles/115003014432-HTTP-Status-Codes) or [AWS](https://docs.aws.amazon.com/AmazonSimpleDB/latest/DeveloperGuide/APIError.html) implement their own codes.
## 6.Get
Whenever a user requests using a url, the browser defaults to a GET request to obtain a landing page.
### HTTP Basic Auth
Under this para, they taught about the exercise and how to solve using dev tools and curl, interesting takeaway is `curl -u username:password http://<server_ip>:<port>/` and `curl http://username:password@<server_ip>:<port>/` which can also be used in the browser to login
### HTTP Authorization Header
Under this para, they taught how to use authorization header using curl:
	`curl -H 'Authorization: Basic YWRtaW46YWRtaW4= URL` gives the same access, incase of JWT the header will be `Bearer`
### Get Parameters
Here the lab exercise was further explained. 
## 7.POST
whenever web applications need to transfer files or move the user parameters from the URL, they utilize POST requests.

There are three main benefit for placing user parameters within the HTTP request body:
	1. Lack of logging: the server will not log the POST requests as it may transfer large files and it is inefficient for the server to log all uploaded files as part of the requested URL.
	2. Less Encoding Requirements: Unlike URLs(https://something.com) which needs to be encoded completely, POST request places data in the body which can accept binary data, only the characters which are used to separate parameters are required to be encoded.
	3. More data can be sent: There is a maximum limit to URL length between different browsers. Generally the length is kept below 2000 characters, so they cannot handle a lot of data.

### Login Forms
Nothing much useful here, as they talk about the exercise in this section, but they teach how to craft a POST curl request:
	`curl -X POST -d 'username=username&password=password' URL`
since after logging in the websites redirect to other pages we can also add `-L` to follow redirects
### Authenticated Cookies
under this section we were taught how to use the cookie which is created once we are authenticated to a web app.
using the following commands one can authenticate to web apps:
	`curl -b 'COOKIENAME=COOKIEVALUE' URL`
	`curl -H 'COOKIENAME=COOKIEVALUE' URL`
### JSON Data
Under this section two interesting methods to access web app was discussed one is using CURL and the other a devtool based interaction:
	1. CURL: `curl -X POST -d '{"json":"data"}' -b 'COOKIENAME=COOKIEVALUE' -H 'Content-Type: application/json' URL`
	2. DevTool: in the network tab copy the request as "Copy as Fetch" and in the console tab we can execute the copied code.
## 8.CRUD API
intro of this section, login which uses APIs.
### APIs
APIs are used to interact with a database using API queries and HTTP method to perform operations needed.
eg:
	`curl -X PUT URL/api.php/city/london ..SNIP..`
here in the SNIP portion we add COOKIE or Authentication creds
### CRUD
The 4 main operations in APIs:

|Operation|HTTP Method|Description|
|---|---|---|
|`Create`|`POST`|Adds the specified data to the database table|
|`Read`|`GET`|Reads the specified entity from the database table|
|`Update`|`PUT`|Updates the data of the specified database table|
|`Delete`|`DELETE`|Removes the specified row from the database table|
### Read
To read:
	`curl -s URL/api.php/city/london | jq`
### Create
Just like discussed previously where we used POST method to update, we used content-type to add json data here:
	`curl -X POST URL/api.php/city/ -d '{"Json":"value"}' -H 'Content-Type: application/json'`
### Update
Put is used to update API entries and modify their details, PATCH is used to partially update an entry (only some of the data like only one entry), using OPTIONS we can check which of the two methods is accepted by the server.

To edit using PUT:
	`curl -X PUT URL/api.php/city/london -d '{"City_name":"New_City", "Country_name":"HTB"}' -H 'Content-Type: application/json'`
### Delete
To delete using DELETE:
	`curl -X DELETE URL/api.php/city/CITYNAME`
To delete using POST method:
	First find the api endpoint and the methods that are being used
		`curl -X POST URL/api.php/city/delete -d {"json":"value"} -H 'Content-Type: application/json'`