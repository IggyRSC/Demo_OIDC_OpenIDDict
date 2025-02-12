using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OIDCTestWithPage;
using OIDCTestWithPage.Models;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseInMemoryDatabase("db");
    
    //options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});


builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
                .UseDbContext<ApplicationDbContext>();
    })
    .AddServer(options =>
    {
        
        options.SetAuthorizationEndpointUris("connect/authorize")
                .SetEndSessionEndpointUris("connect/logout")
                .SetTokenEndpointUris("connect/token")
                .SetUserInfoEndpointUris("connect/userinfo");

        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.Address);

        options.AllowAuthorizationCodeFlow();
        options.AcceptAnonymousClients();

        options.AddEncryptionKey(new SymmetricSecurityKey(
            Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

        options.AddDevelopmentEncryptionCertificate()
                .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
                .EnableAuthorizationEndpointPassthrough()
                .EnableEndSessionEndpointPassthrough()
                .EnableTokenEndpointPassthrough()
                .EnableUserInfoEndpointPassthrough();


    });

builder.Services.AddTransient<AuthorizationService>();

builder.Services.AddControllers();
builder.Services.AddRazorPages();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(c =>
    {
        c.LoginPath = "/Authenticate";
    });

builder.Services.AddTransient<ClientsSeeder>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("http://localhost:5173")
            .AllowAnyHeader();

        policy.WithOrigins("http://localhost:7129")
     .AllowAnyHeader();
    });
});


var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<ClientsSeeder>();

    seeder.AddOidcDebuggerClient().GetAwaiter().GetResult();
    seeder.AddWebClient().GetAwaiter().GetResult();
    seeder.AddReactClient().GetAwaiter().GetResult();

    seeder.AddScopes().GetAwaiter().GetResult();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
// Add services to the container.
app.UseRouting();
app.UseHttpsRedirection();

app.UseCors();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapRazorPages();

app.Run();