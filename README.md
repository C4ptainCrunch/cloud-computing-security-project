# Cloud Computing security project

## Bob is naive

Bob made a nice website at https://bob-cloud-computing.tk/ but it has some weaknesses.
Let's hope nobody will exploit them !

To run Bob's website on you server (it's open-source, why not try it ?) run those commands:
```bash
cd bob/
npm install
node index.js
```
It will then listen on port 8211 on `localhost`. You should then proxy that and add SSL
on top of it of course.

## Eve is an evil attacker: Eve likes XSS !

Eve made a phishing website called https://eve-cloud-computing.tk/ the domain name looks so
much like the original (https://bob-cloud-computing.tk/) than nobody notices the
difference.

Eve's website has a [nice page](https://eve-cloud-computing.tk/hidden.html),
where you can distract yourself with a nice video of cats.

(Eve likes simplicity, Eve's website is static so serving `eve/*.html` with any
webserver will work)

But while you are distracted and watching, Eve can use your browser and make it
send an carefully crafted payload to https://bob-cloud-computing.tk/unsecure
to extract data on your behalf.

Eve is a bad person, but not too bad so she shows you how she does that trick.
You can go to https://eve-cloud-computing.tk/ and see the a form containing
the payload that was sent behind the scene.

The first part of the page shows a benign payload that proves the XSS but the
second part of the page ("Try a real extraction on unsecure") shows a smarter
payload that sends all your secrets to a remote server.

Data is exfiltrated to a [requestbin](https://requestbin.etnarek.com/rw8pd2s0?inspect).
You can look at the data that has been sent over there.
(Beware that the requestbin has a fairly short life time, it might have been
deleted if you read this too far in the future.)

### Mitigation techniques

Bob's website is vulnerable to Eve's attack but not every page is created equal :
`/secure` is vulnerable but the other ones are not. Nevertheless Eve also added the
payload forms so you can see that the XSS no longer works.

Here is a list of the pages and the protections :
 * `chrome_protect` : Activate the [XSS Auditor](https://www.chromium.org/developers/design-documents/xss-auditor) in Chrome
 * `referer_check` : check the HTTP Referer on every non GET request and block the rendering if the origin is not the same
 * `source_self` : CSP with "script-src self" that prevents in-line JS
 * `no_extract` : CSP to prevent data exfiltration by restricting outbound requests
 * `escape` : Escaping the user input server-side
 * `crsf` : Use a CSRF token

Both CSP rules have a report-url to send violations to a [sentry](https://sentry.io) instance)

## Eve is an evil attacker: Eve breaks into the admin

Let's say Eve stole a cookie from the admin user with an XSS somewhere.
```
auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXAiOiI5MS4xODIuMjM3LjI0NyIsImlhdCI6MTUyODk4MzI3NX0.TocbMpx0DrAW6r-gpOg_7ycMU3l0ar3f4smD2VQh9PA
```

Eve inserts the cookie into its own browser and tries to access to https://bob-cloud-computing.tk/admin but receives some bad news: the server greets Eve with `Bad ip`. Humm.

Eve realizes that it's a JWT (Json Web Token) so she decodes it with https://jwt.io/

The header is :
```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```

And the body :
```json
{
  "username": "admin",
  "ip": "91.182.237.247",
  "iat": 1528983275
}
```

Oh, that's where the IP comes from !

The bad news is that Eve can't forge a new version of this token with its own
ip because Eve doesn't know the secret used by the server for the HMAC (`"alg": "HS256"`) :/

But what is Eve changes the algorithm from `HS256` to `none` ? Would the server
accepts the algorithm from the header instead of a fixed value on its side ?
It's worth a try !

Eve then writes a short js PoC (`./poc.js`) that decodes the JWT, changes the ip
and signs it with the `none` algorithm. Eve then makes an http request to the
vulnerable server and ...

`./poc.js` takes the original token as first argument and the attacker's ip as the
second.

(Eve might want to `cd eve/; npm install` before running this command)

``` bash
./poc.js eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXAiOiI5MS4xODIuMjM3LjI0NyIsImlhdCI6MTUyODk4MzI3NX0.TocbMpx0DrAW6r-gpOg_7ycMU3l0ar3f4smD2VQh9PA 1.1.1.1
```

Voila !

### Mitigation techniques

First, the server should verify that the hashmac algoritm was not changed (see this [blog post](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) for more details)

The cookie should be set to [HTTP only](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies) so that the JS can not read it and of course you should fix the XSS that was used to steal the cookie.

Other mitigation techniques could include storing the ip (and other user-agent information) on the server side, setting an expiration on the token meaning that the attack should happen quickly, using 2 factor auth before showing sensitive information, ...
