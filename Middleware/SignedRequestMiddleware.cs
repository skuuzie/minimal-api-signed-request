using System.Net;
using Kriptos;
using KriptosUtil;

namespace Middleware;

public class SignedRequestMiddleware(RequestDelegate next, KriptosSign signer)
{
    private readonly RequestDelegate _next = next;
    private readonly List<string> ProtectedEndpoints = ["/xyz", "/spam_intolerance_endpoint"];

    public async Task InvokeAsync(HttpContext context)
    {
        // Filter endpoints if needed
        if (!ProtectedEndpoints.Contains(context.Request.Path))
        {
            await _next(context);
            return;
        }

        var _ts = context.Request.Headers.TryGetValue("X-Timestamp", out var _rcvTimestamp);
        var _vts = long.TryParse(_rcvTimestamp, out long rcvTimestamp);
        var _sign = context.Request.Headers.TryGetValue("X-Signature", out var rcvSignature);

        // No custom headers & invalid timestamp
        if (!_ts || !_sign || !_vts)
        {
            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            context.Response.ContentType = "text/plain";

            Console.WriteLine("Fail: no ts / no sign / invalid ts");

            await context.Response.WriteAsync("Bad Request.");
            return;
        }

        // Make sure timestamp is acceptable
        var currentTs = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var tsOffset = currentTs - rcvTimestamp;

        if ((tsOffset > 360) || (tsOffset < 0))
        {
            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            context.Response.ContentType = "text/plain";

            Console.WriteLine("Fail: abnormal timestamp");

            await context.Response.WriteAsync("Bad Request.");
            return;
        }

        // Verify signature
        try
        {
            var isValid = signer.VerifyData(_rcvTimestamp.ToString().ToBytes(), rcvSignature.ToString());

            if (!isValid)
            {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                context.Response.ContentType = "text/plain";

                Console.WriteLine("Fail: invalid signature");

                await context.Response.WriteAsync("Bad Request.");
                return;
            }

        }
        catch (FormatException)
        {
            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            context.Response.ContentType = "text/plain";

            Console.WriteLine("Fail: invalid hexstring");

            await context.Response.WriteAsync("Bad Request.");
            return;
        }

        await _next(context);
    }
}