# Be Cool Couriers Users API Check

Date: 2026-07-08

Endpoints checked:

```text
https://api.becoolcouriers.com.au/users/
https://api.becoolcouriers.com.au/users
```

Scope context:

```text
api.becoolcouriers.com.au is listed as an in-scope HelloFresh program asset.
Checks were unauthenticated, non-mutating, and low volume.
```

## Results

`GET /users/`:

```text
status=404
content_type=text/html; charset=UTF-8
body_size=0
server=nginx
x-cache=Error from cloudfront
```

`HEAD /users/`:

```text
status=404
content_type=text/html; charset=UTF-8
body_size=0
server=nginx
x-cache=Error from cloudfront
```

`OPTIONS /users/`:

```text
status=404
content_type=text/html; charset=UTF-8
body_size=0
server=nginx
x-cache=Error from cloudfront
```

`GET /users/` with arbitrary Origin:

```text
Origin: https://example.invalid
status=404
content_type=text/html; charset=UTF-8
body_size=0
access-control-allow-origin: https://example.invalid
access-control-allow-credentials: true
vary: Origin
server=nginx
x-cache=Error from cloudfront
```

`GET /users` without trailing slash:

```text
status=404
content_type=text/html; charset=UTF-8
body_size=0
server=nginx
x-cache=Error from cloudfront
```

`GET /users` without trailing slash and with arbitrary Origin:

```text
Origin: https://example.invalid
status=404
content_type=text/html; charset=UTF-8
body_size=0
access-control-allow-origin: https://example.invalid
access-control-allow-credentials: true
vary: Origin
server=nginx
x-cache=Error from cloudfront
```

## Interpretation

The base `/users` collection route does not appear publicly exposed. Both
trailing-slash and no-slash variants returned empty 404 responses through
CloudFront/nginx.

Security-relevant observation:

```text
The API reflects arbitrary Origin and sets Access-Control-Allow-Credentials:
true even on 404 responses.
```

Current impact:

```text
No user data, account state, or endpoint behavior beyond empty 404 responses
was exposed. The permissive CORS behavior is only an observation here; it would
need to be demonstrated on a sensitive authenticated endpoint to be reportable.
```

## Path Enumeration Under `/users/<value>`

GET-only candidate paths:

```text
me              404 text/html; charset=UTF-8 size=0
profile         404 text/html; charset=UTF-8 size=0
current         404 text/html; charset=UTF-8 size=0
googlelogin     200 application/json size=305
login           404 text/html; charset=UTF-8 size=0
register        404 text/html; charset=UTF-8 size=0
signup          404 text/html; charset=UTF-8 size=0
signin          404 text/html; charset=UTF-8 size=0
logout          404 text/html; charset=UTF-8 size=0
password        404 text/html; charset=UTF-8 size=0
forgot          404 text/html; charset=UTF-8 size=0
forgotpassword  404 text/html; charset=UTF-8 size=0
reset           404 text/html; charset=UTF-8 size=0
resetpassword   404 text/html; charset=UTF-8 size=0
passwordreset   404 text/html; charset=UTF-8 size=0
verify          404 text/html; charset=UTF-8 size=0
verify-email    404 text/html; charset=UTF-8 size=0
email           404 text/html; charset=UTF-8 size=0
token           404 text/html; charset=UTF-8 size=0
refresh         404 text/html; charset=UTF-8 size=0
auth            404 text/html; charset=UTF-8 size=0
session         404 text/html; charset=UTF-8 size=0
sessions        404 text/html; charset=UTF-8 size=0
address         404 text/html; charset=UTF-8 size=0
addresses       404 text/html; charset=UTF-8 size=0
orders          404 text/html; charset=UTF-8 size=0
drivers         404 text/html; charset=UTF-8 size=0
admin           404 text/html; charset=UTF-8 size=0
```

Empty JSON POST checks on likely auth-style paths:

```text
login           400 text/html; charset=UTF-8 size=0
register        400 application/json size=33
signup          404 text/html; charset=UTF-8 size=0
signin          404 text/html; charset=UTF-8 size=0
forgotpassword  404 text/html; charset=UTF-8 size=0
resetpassword   404 text/html; charset=UTF-8 size=0
passwordreset   404 text/html; charset=UTF-8 size=0
verify          404 text/html; charset=UTF-8 size=0
token           404 text/html; charset=UTF-8 size=0
refresh         404 text/html; charset=UTF-8 size=0
```

`POST /users/register` empty-body response:

```json
{"error":"Invalid body","code":0}
```

CORS behavior on live POST routes:

```text
Origin: https://example.invalid
POST /users/login    -> Access-Control-Allow-Origin reflected; credentials true
POST /users/register -> Access-Control-Allow-Origin reflected; credentials true
```

Path-scan interpretation:

```text
Confirmed live routes from this pass:
- GET/POST /users/googlelogin
- POST /users/login
- POST /users/register

No user records, PII, session tokens, or account data were exposed. The most
notable pattern remains permissive reflected CORS across the API, but impact
still requires a sensitive authenticated response that can be read cross-origin.
```
