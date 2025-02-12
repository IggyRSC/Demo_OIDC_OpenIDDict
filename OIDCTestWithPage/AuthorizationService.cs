using System.Collections.Immutable;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OIDCTestWithPage
{
    public class AuthorizationService 
    {
        public bool IsIp { get; set; }
        private List<bool>? res=new List<bool>();
        public IDictionary<string, StringValues> ParseOAuthParameters(HttpContext httpContext, List<string>? excluding = null)
        {
            excluding ??= new List<string>();

            var parameters = httpContext.Request.HasFormContentType
                ? httpContext.Request.Form
                    .Where(v => !excluding.Contains(v.Key))
                    .ToDictionary(v => v.Key, v => v.Value)
                : httpContext.Request.Query
                    .Where(v => !excluding.Contains(v.Key))
                    .ToDictionary(v => v.Key, v => v.Value);

            return parameters;
        }

        public string BuildRedirectUrl(HttpRequest request, IDictionary<string, StringValues> oAuthParameters)
        {
            var url = request.PathBase + request.Path + QueryString.Create(oAuthParameters);
            return url;
        }

        public void IsIpSet(bool input)
        {
            res.Add(input);
        }

        public bool IsIpGetter()
        {
            if (res.Count == 0)
                res.Add(true);
            return res.First();
        }

        public bool IsAuthenticated(AuthenticateResult authenticateResult, OpenIddictRequest request)
        {
            if (IsIpGetter())
            {
                return true;
            }

            if (!authenticateResult.Succeeded  )
            {
                return false;
            }

            if (request.MaxAge.HasValue && authenticateResult.Properties != null)
            {
                var maxAgeSeconds = TimeSpan.FromSeconds(request.MaxAge.Value);

                var expired = !authenticateResult.Properties.IssuedUtc.HasValue ||
                              DateTimeOffset.UtcNow - authenticateResult.Properties.IssuedUtc > maxAgeSeconds;
                if (expired)
                {
                    return false;
                }
            }

            return true;
        }

        public static List<string> GetDestinations(ClaimsIdentity identity, Claim claim)
        {
            var destinations = new List<string>();

            if (claim.Type is OpenIddictConstants.Claims.Name or OpenIddictConstants.Claims.Email)
            {
                destinations.Add(OpenIddictConstants.Destinations.AccessToken);

                if (identity.HasScope(OpenIddictConstants.Scopes.OpenId))
                {
                    destinations.Add(OpenIddictConstants.Destinations.IdentityToken);
                }
            }

            return destinations;
        }

        //public async Task  ConnectSilently(OpenIddictRequest request, AuthenticateResult result)
        //{
            
            
        //    var ipIdentity = new ClaimsIdentity(
        //        authenticationType: TokenValidationParameters.DefaultAuthenticationType,
        //        nameType: Claims.Name,
        //        roleType: Claims.Role);

        //    ipIdentity.AddClaim(new Claim(Claims.Subject, "IsIp"));


        //    ipIdentity
        //    //.SetClaim("profile", "IsIp")
        //    .SetClaim("IsIp", true)
        //    .SetClaim(Claims.Subject, "IsIp")
        //    .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

        //    ipIdentity.SetDestinations(c => AuthorizationService.GetDestinations(ipIdentity, c));
        //    result.Principal.SetClaim(Claims.Locality, "IsIP");

        //    return SignIn(new ClaimsPrincipal(ipIdentity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        //}


        public bool IsRequestWithIp(OpenIddictRequest request)
        {
            return request.GetParameter("is_ip")!=null;
        }

        public void Validate(OpenIddictRequest request)
        {
            if (IsRequestWithIp(request))
            { return; }
              

        }

    }
}
