﻿using OIDCTestWithPage.Models;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OIDCTestWithPage
{
    public class ClientsSeeder
    {
        private readonly IServiceProvider _serviceProvider;

        public ClientsSeeder(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public async Task AddScopes()
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

            var apiScope = await manager.FindByNameAsync("api1");

            if (apiScope != null)
            {
                await manager.DeleteAsync(apiScope);
            }

            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                DisplayName = "Api scope",
                Name = "api1",
                Resources =
                {
                    "resource_server_1"
                }
            });
        }

        public async Task AddReactClient()
        {
            await using var scope = _serviceProvider.CreateAsyncScope();

            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync();

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var reactClient = await manager.FindByClientIdAsync("react-client");
            if (reactClient != null)
            {
                await manager.DeleteAsync(reactClient);
            }

            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "react-client",
                //ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "React client application",

                RedirectUris =
                {
                    new Uri("http://localhost:5173")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("http://localhost:5173")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.EndSession,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    $"{Permissions.Prefixes.Scope}api1"
                },
                //Requirements =
                //{
                //    Requirements.Features.ProofKeyForCodeExchange
                //}
            });
        }

        public async Task AddOidcDebuggerClient()
        {
            await using var scope = _serviceProvider.CreateAsyncScope();

            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            //await context.Database.EnsureCreatedAsync();

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            //var client = await manager.FindByClientIdAsync("oidc-debugger");
            //if (client != null)
            //{
            //    await manager.DeleteAsync(client);
            //}

            if (await manager.FindByClientIdAsync("oidc-debugger") == null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "oidc-debugger",
                    ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                    ConsentType = ConsentTypes.Explicit,
                    DisplayName = "Postman client application",
                    RedirectUris =
                {
                        new Uri("https://localhost:5173")
                },
                    PostLogoutRedirectUris =
                {
                        new Uri("https://localhost:5173")
                },
                    Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.EndSession,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                   $"{Permissions.Prefixes.Scope}api1"
                },
                });
            }
        }

        public async Task AddWebClient()
        {
            await using var scope = _serviceProvider.CreateAsyncScope();

            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync();

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var client = await manager.FindByClientIdAsync("web-client");


            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "web-client",
                ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "Swagger client application",
                RedirectUris =
                {
                    //new Uri("https://localhost:7002/swagger/oauth2-redirect.html")
                              new Uri("https://localhost:7002/swagger/oauth2-redirect.html")
                },
                PostLogoutRedirectUris =
                {
                       new Uri("https://localhost:5173")
                    //new Uri("https://localhost:7002/resources")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.EndSession,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                   $"{Permissions.Prefixes.Scope}api1"
                },
   
            });
        }
      

    }
}
