# Be Cool Couriers Google Login API Check

Date: 2026-07-08

Endpoint:

```text
https://api.becoolcouriers.com.au/users/googlelogin
```

Scope context:

```text
api.becoolcouriers.com.au is listed as an in-scope HelloFresh program asset.
Checks were unauthenticated and low volume.
```

## Results

GET:

```text
status=200
content_type=application/json
server=nginx
x-cache=Miss from cloudfront
```

Response:

```json
{
  "url": "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&access_type=online&client_id=804152813603-ootpbk75j95ce2tmdm3ev8a0kca94aln.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fapi.becoolcouriers.com.au%2Fusers%2Fgooglelogin&state&scope=email%20profile&approval_prompt=auto"
}
```

POST with empty JSON body:

```text
status=200
content_type=application/json
body=same Google OAuth authorization URL as GET
```

OPTIONS:

```text
status=404
content_type=text/html; charset=UTF-8
body_size=0
x-cache=Error from cloudfront
```

GET with `state=codex_state_probe`:

```text
status=200
content_type=application/json
body still contains empty OAuth state parameter: &state&scope=...
```

GET with arbitrary Origin:

```text
Origin: https://example.invalid
status=200
access-control-allow-origin: https://example.invalid
access-control-allow-credentials: true
vary: Origin
```

GET callback shape with invalid code:

```text
https://api.becoolcouriers.com.au/users/googlelogin?code=codex_invalid_code_probe&state=codex_state_probe
status=401
content_type=text/html; charset=UTF-8
body_size=0
x-cache=Error from cloudfront
```

## Interpretation

The endpoint appears to initiate Google OAuth by returning a JSON object that
contains the Google authorization URL.

Security-relevant observations:

```text
1. The generated OAuth authorization URL contains an empty state parameter.
2. Supplying a state query parameter to the endpoint does not populate the
   generated OAuth URL.
3. GET and POST with an empty JSON body return the same OAuth URL.
4. The endpoint reflects arbitrary Origin and allows credentials, but this
   specific response is public and did not set cookies.
5. A bogus OAuth callback code fails cleanly with 401 and no response body.
```

Potential report angle:

```text
Missing or empty OAuth state may enable login CSRF or account confusion if the
callback accepts a valid Google authorization code without binding it to a
server-side user-initiated login transaction. This requires browser proof with
test accounts to establish impact.
```

Current limitations:

```text
No valid Google OAuth callback was completed.
No authenticated account state or PII was accessed.
The permissive CORS behavior was only observed on a public login-initiation
response, so it is not enough by itself for an impact claim.
```
