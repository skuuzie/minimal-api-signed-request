More or less, a "signed request" is when an incoming http request is an authenticated one, but this time the client is also capable of generating the signature. Utilizing the principle of cryptographic hash.

[Conceptually this.](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html)

---

This is an implementation demo using [ASP.NET Core Minimal API](https://dotnet.microsoft.com/en-us/apps/aspnet/apis) (.NET 8.0) via a custom middleware.

Run command: `dotnet run` (zero dependencies)

General flow:
1. Get current unix timestamp in seconds (fetch to `X-Timestamp` header)
2. Sign the timestamp with a shared-key and the defined algorithm, in this case using `HMAC-SHA512`  (i.e. `HMAC_SHA512(key, timestamp)`)
3. Get the digest and hexstring it (fetch to `X-Signature` header)

The request is now signed and will pass through the middleware.

You have the freedom to cherry pick your verification variable other than timestamp.

---

This is useful if you want to protect/monitor certain endpoints from replay "attack", scraping efforts, and other security cases.

_no more "what happens if i change this parameter?" attack_ 😅

However, it all depends on the signature generation complexity and frontend implementation. The more you obfuscate it, the better.