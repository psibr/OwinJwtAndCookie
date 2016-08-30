# JwtAndCookie
An owin middleware for JOSE RSA JWE & JWT token parsing from Authorization header and cookies with an owin signin delegate with optional cookie writing capabilities.

## OWIN configuration

Add the following to your ASPNETCORE startup, feeding your values from your own configuration scheme.

```csharp
app.UseOwin(owin =>
{
    owin((next) =>
        new JwtAndCookieMiddleware(next, new Options
        {
            Certificate = new X509Certificate2("C:\\jwtmiddleware.pfx", "test"),
            CookieName = "jwt",
            CookiePath = "/",
            CookieHttpOnly = true,
            TokenLifeSpan = TimeSpan.FromMinutes(30),
            ClaimsPrincipalResourceName = "principal",
            CreatePrincipal = (payload) => new ClaimsPrincipal(new ClaimsIdentity(new GenericIdentity("meh"))) //Example func
        }).Invoke);
});
```

ClaimsPrincipalResourceName is the OWIN environment key where the claims principal will be stored for further pipeline processing.

CreatePrincipal is a function given a payload of IDictionary<string, object> that expects a ClaimsPrincipal returned. The logic of mapping your JWT claims to a ClaimsPrincipal is your responsibility an example of a JWT with the claims: jti, sub, apikey, and claims is shown below. 

*Do note that the "JWT claim" claims is just an array of strings indicating which roles or permissions the user has and is not required, but is part of the REstate platform's JWT scheme. The claims jti and exp are the only claims this library provides.*

```csharp
private static ClaimsPrincipal CreatePrincipal(IDictionary<string, object> payload)
{
    if (payload == null) return null;

    object jtiObj;
    if (!payload.TryGetValue("jti", out jtiObj)) return null;

    object apikeyObj;
    if (!payload.TryGetValue("apikey", out apikeyObj)) return null;

    object identityObj;
    if (!payload.TryGetValue("sub", out identityObj)) return null;

    var identity = identityObj as string;
    var apikey = apikeyObj as string;
    var jti = jtiObj as string;
    if (identity == null || apikey == null) return null;

    var claims = payload.ContainsKey("claims")
        ? (payload["claims"] as IEnumerable)?.Cast<string>().Select(claim => new Claim("claim", claim))
          ?? new Claim[0]
        : new Claim[0];

    claims = claims.Union(new[] { new Claim("apikey", apikey), new Claim("jti", jti) });

    var principal = new ClaimsPrincipal(
        new ClaimsIdentity(
            new GenericIdentity(identity),
            claims));

    return principal;
}
```

## Issuing a JWT
Using the SignIn delegate does NOT require a reference to this library as long as the OWIN component has been registered.

Add the following using statement.

```csharp
using SignInDelegate = System.Func<System.Func<System.Guid, System.Collections.Generic.IDictionary<string, object>>, bool, string>;
```

Simplified the signature is `Func<Func<Guid, IDictionary<string, object>>, bool, string>`

This can be confusing if you are not familiar with middleware or functional programming techniques, so let me try to explain!

The SignInDelegate is a function that takes two arguments: a ClaimBuilder function and a boolean that indicates whether or not a cookie should be issued; the SignInDelegate itself returns the JWT as a string.

The ClaimBuilder function has a single parameter: the jti claim as a GUID, which is useful for encryption purposes since a jti is unique to every JWT issued globally; the return is an `IDictionary<string, object>` of the JWT claims you want included in addition to the standard jti and exp claims.

Here is an example of it in use from a Nancy module where a sub, encrypted apikey, and claims claim are added to the JWT:

```csharp
var environment = Context.GetOwinEnvironment();
var signInDelegate = (SignInDelegate)environment["jwtandcookie.signin"];

var jwt = signInDelegate((jti) => new Dictionary<string, object>
{
    { "sub", principal.UserOrApplicationName},
    { "apikey", crypto.EncryptionProvider.Encrypt(jti + principal.ApiKey)},
    { "claims", principal.Claims }
}, false);
```
