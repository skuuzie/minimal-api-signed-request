// SignedRequestMiddlewared dependencies
using Kriptos;
using KriptosUtil;
using Middleware;

var someKey = "Some not-so-secret key".ToBytes();
var kriptos = new KriptosSign(someKey, AuthenticatedHashAlgorithm.HMAC_SHA512);
// End 

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Add the middleware
// https://learn.microsoft.com/en-us/aspnet/core/fundamentals/middleware/write?view=aspnetcore-8.0#middleware-dependencies
app.UseMiddleware<SignedRequestMiddleware>(kriptos);

app.MapGet("/", () => "Hello World!");
app.MapGet("/spam_intolerance_endpoint", () => "ok.");

app.Run();