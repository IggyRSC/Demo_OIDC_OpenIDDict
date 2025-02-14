using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using Polly;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Net;
using System.Security.Claims;
using OpenIddict.Server.AspNetCore;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Immutable;
using Microsoft.AspNetCore.Authorization;
using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http.HttpResults;
using System.Net.Sockets;
using OIDCTestWithPage.Pages;
using AspNet.Security.OpenIdConnect.Primitives;
using System.Security.Principal;

namespace OIDCTestWithPage.Controllers
{

    [ApiController]
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private static readonly HashSet<string> _allowedIps = new() { "127.0.0.1", "::1" }; // Whitelisted IPs
        private readonly AuthorizationService _authService;
        private readonly IOpenIddictScopeManager _scopeManager;




        public AuthorizationController(IOpenIddictApplicationManager applicationManager, AuthorizationService authService, IOpenIddictScopeManager scopeManager)
        {
            _applicationManager = applicationManager;
            _authService = authService;
            _scopeManager = scopeManager;
        }

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        public async Task<ActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                                    throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();

            _authService.IsIpSet(request.GetParameter("is_ip")!=null);

            if (clientIp == null)
            {
                return BadRequest(new { error = "Cannot determine client IP." });
            }


            var parameters = _authService.ParseOAuthParameters(HttpContext, new List<string> { Parameters.Prompt });
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            if (request.GetParameter("is_ip") != null)
            {
                //AuthenticateResult success = result.Succeeded == false ? result : null;
                _authService.IsAuthenticated(result, request);
                //var ipuserId = result.Principal.FindFirst(ClaimTypes.Email)!.Value;
                var ipIdentity = new ClaimsIdentity(
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                //ipIdentity
                //.SetClaim(Claims.Subject, "email")
                //.SetClaim(Claims.Email, "email")
                //.SetClaim(Claims.Name, "ChuckNorris")
                //.SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

                ipIdentity.SetClaim(Claims.Subject, "Texas@email")
                    .SetClaim(Claims.Email, "Texas@email")
                    .SetClaim(Claims.Name, "ChuckNorris")
                    .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());


                //add location to the id_token
                ipIdentity.SetScopes(request.GetScopes());
                ipIdentity.SetResources(await _scopeManager.ListResourcesAsync(ipIdentity.GetScopes()).ToListAsync());

                ipIdentity.SetDestinations(c => AuthorizationService.GetDestinations(ipIdentity, c));
                return SignIn(new ClaimsPrincipal(ipIdentity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            if (!_authService.IsAuthenticated(result, request) && !request.HasPromptValue(PromptValues.Login))
            {

                if (request.Prompt != "none")
                {
                    return Challenge(properties: new AuthenticationProperties
                    {
                        RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters)
                    }, new[] { CookieAuthenticationDefaults.AuthenticationScheme });
                }

                return Forbid(
                                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                                 properties: new AuthenticationProperties(new Dictionary<string, string?>
                              {
                                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.UnauthorizedClient,
                                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                    "Registration not found"
                                }));
            }

            if (!_allowedIps.Contains(clientIp))
            {
                return Unauthorized(new { error = "IP address not allowed." });
            }

            var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
                              throw new InvalidOperationException("Details concerning the calling client application cannot be found.");


            if (request.HasPromptValue(PromptValues.Login))
            {
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                return Challenge(properties: new AuthenticationProperties
                {
                    RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters)
                }, new[] { CookieAuthenticationDefaults.AuthenticationScheme });
            }


            var consentClaim = result.Principal.GetClaim(Consts.ConsentNaming);

            // it might be extended in a way that consent claim will contain list of allowed client ids.
            if (consentClaim != Consts.GrantAccessValue || request.HasPromptValue(PromptValues.Consent))
            {
                var returnUrl = HttpUtility.UrlEncode(_authService.BuildRedirectUrl(HttpContext.Request, parameters));
                var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";

                return Redirect(consentRedirectUrl);
            }



            var userId = result.Principal.FindFirst(ClaimTypes.Email)!.Value;

            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, userId)
                .SetClaim(Claims.Email, userId)
                .SetClaim(Claims.Name, userId)
                .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

            identity.SetScopes(request.GetScopes());
            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
            identity.SetDestinations(c => AuthorizationService.GetDestinations(identity, c));

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        }

        [HttpPost("~/connect/token"), Produces("application/json")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");


            if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
                throw new InvalidOperationException("The specified grant type is not supported.");

            var result =
                await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var userId = result.Principal.GetClaim(Claims.Subject);

            if (result.Principal.GetClaim(Claims.Name) != Consts.Email)
            {
                var testIdentity = new ClaimsIdentity(result.Principal.Claims,
                    authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);


                testIdentity.SetClaim(Claims.Subject, userId)
                    .SetClaim(Claims.Email, userId)
                    .SetClaim(Claims.Name, userId)
                    .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());


                testIdentity.SetDestinations(c => AuthorizationService.GetDestinations(testIdentity, c));
                var officeClaim = new Claim("Walker", "Texas Ranger", ClaimValueTypes.Integer);
                var locationClaim = new Claim("Location", HttpContext.Connection.RemoteIpAddress?.ToString(), ClaimValueTypes.Integer);
                officeClaim.SetDestinations(OpenIddictConstants.Destinations.IdentityToken);
                locationClaim.SetDestinations(OpenIddictConstants.Destinations.IdentityToken);
                testIdentity.AddClaim(officeClaim);
                testIdentity.AddClaim(locationClaim);

                //testIdentity.SetDestinations(c => AuthorizationService.GetDestinations(testIdentity, c));
                return SignIn(new ClaimsPrincipal(testIdentity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                //////////////////////Chat gpt //////////////////////////
                //var testIdentity = new ClaimsIdentity(result.Principal.Claims,
                //                                     authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                //                                      nameType: Claims.Name,
                //                                      roleType: Claims.Role);
                //testIdentity.SetClaim(Claims.Email, userId)
                //.SetClaim(Claims.Name, userId)
                //.SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());
                //testIdentity.SetClaim(Claims.Subject, userId)
                //            .SetClaim(Claims.Email, "Kicks")
                //            .SetClaim(Claims.Name, "ChuckNorris")
                //            .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

                //foreach (var claim in testIdentity.Claims)
                //{
                //    claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);
                //}



                ////testIdentity.SetScopes(result.GetScopes());
                //testIdentity.AddClaim("custom_claim", "custom_value");

                //// Set necessary scopes
                ////principal.SetScopes(new[]
                ////{
                ////    OpenIddictConstants.Scopes.OpenId,
                ////    OpenIddictConstants.Scopes.Profile
                ////});
                //// Set destinations (where the claims should be sent)
                //testIdentity.AddClaim(OpenIddictConstants.Claims.Subject, "user-id-1234");
                //foreach (var claim in testIdentity.Claims)
                //{
                //    claim.SetDestinations(OpenIddictConstants.Destinations.IdentityToken);
                //}
                ////////////////////// END Chat gpt //////////////////////////
                //var Ip_identity = (ClaimsIdentity)result.Principal.Identity;
                //  var officeClaim = new Claim("office", "Test User", ClaimValueTypes.Integer);

                //testIdentity.SetDestinations(OpenIdConnectConstants.Destinations.AccessToken, OpenIdConnectConstants.Destinations.IdentityToken);

                //testIdentity.SetDestinations(c => AuthorizationService.GetDestinations(testIdentity, c));
                //var officeClaim = new Claim("Walker", "Texas Ranger", ClaimValueTypes.Integer);
                //officeClaim.SetDestinations(OpenIddictConstants.Destinations.IdentityToken);
                //testIdentity.AddClaim(officeClaim);

            }


            
            if (string.IsNullOrEmpty(userId))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Cannot find user from the token."
                    }));
            }

            var identity = new ClaimsIdentity(result.Principal.Claims,
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);



            identity.SetClaim(Claims.Subject, userId)
                .SetClaim(Claims.Email, userId)
                .SetClaim(Claims.Name, userId)
                .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

            identity.SetDestinations(c => AuthorizationService.GetDestinations(identity, c));

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            
        }

        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo")]
        public async Task<IActionResult> Userinfo()
        {
            if (User.GetClaim(Claims.Subject) != Consts.Email && !_authService.IsIpGetter())
            {
                return Challenge(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The specified access token is bound to an account that no longer exists."
                    }));
            }

            var claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
                [Claims.Subject] = Consts.Email
            };

            if (User.HasScope(Scopes.Email))
            {
                claims[Claims.Email] = Consts.Email;
            }


            return Ok(claims);
        }

        [HttpGet("welcome")]
        public IActionResult Welcome(string name, int numTimes = 1)
        {
            ViewData["Message"] = "Hello " + name;
            ViewData["NumTimes"] = numTimes;
            return View();
        }

        [HttpGet("~/connect/logout")]
        [HttpPost("~/connect/logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                });
        }
    }
}
