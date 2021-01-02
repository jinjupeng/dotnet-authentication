# dotnet-authentication/authorization
> .NET框架之认证和授权学习

[TOC]

## Goal

- Learn the basics about Authentication and Authorization
- Know the differences of Roles, Policies, Claims

## Authentication (know who you are)

### Definitions

- Claims: List of Access roles and information properties
- Cookie vs. Token: https://dzone.com/articles/cookies-vs-tokens-the-definitive-guide

```
+---------------+       +----------------+       +--------------+
|               | 1   n |                | 1   n |              |
|   Principal   +-------+    Identity    +-------+    Claims    |
|               |       |                |       |              |
+---------------+       +----------------+       +--------------+
```

http://asciiflow.com/

### Scheme Actions

There are three scheme actions.

- **Authenticate** is about how the claims principle gets reconstructed on every request. (Cookie/Token)
- **Challenge** determines what happens if the user tries to access a resource for which authentication is required.
- **Forbid** determines what happens if the user accesses a resource she can't access because she doesn't have the rights.

### OpenID Servers

- https://github.com/openiddict/openiddict-core

- https://github.com/IdentityServer/IdentityServer4

- SPA Workflow:

   

  https://auth0.com/docs/flows

  - From 2019: [Authorization Code Flow with Proof Key for Code Exchange (PKCE)](https://auth0.com/docs/flows/concepts/auth-code-pkce)
  - Before 2019: [Implicit Flow](https://auth0.com/docs/flows/concepts/implicit)

### Login Procedure

1. Check if user can be authenticated
2. Generate Claims List
3. Generate ClaimsIdentity (Google, FaceBook, ...), add Claims list
4. Generate ClaimsPrincipal, add ClaimsIdentity
5. SignInAsync

### Add Authorize Attribute to all WebApi Endpoints

It is recommended, to remove access from all controllers/endpoints. (Set Authorize Attribute to all controllers/endpoints) To give access to all, set the `[AllowAnonymous]` attribute

```
public void ConfigureServices(IServiceCollection services)
{
    // add Authorize Attribute to all WebApi Endpoints
    services.AddControllersWithViews(o => o.Filters.Add(new AuthorizeFilter()));
}
```

### Configure Authentication (Example: Google)

```
public void ConfigureServices(IServiceCollection services)
{
    // configure Authentication
    services.AddAuthentication(o => {
        o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        //o.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
    })
        .AddCookie() // redirects to /login
        .AddCookie(ExternalAuthenticationDefaults.AuthenticationScheme)
        .AddGoogle(o =>
        {
            o.SignInScheme = ExternalAuthenticationDefaults.AuthenticationScheme;
            o.ClientId = Configuration["Google:ClientId"];
            o.ClientSecret = Configuration["Google:ClientSecret"];
        });
}
```

### Activate Authentication and Authorization

```
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    ...
    app.UseAuthentication();
    app.UseAuthorization();

    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllerRoute(
            name: "default",
            pattern: "{controller=Conference}/{action=Index}/{id?}");
    });
}
```

## Authorization

- Role-based authorization: https://docs.microsoft.com/en-us/aspnet/core/security/authorization/roles?view=aspnetcore-3.1
- Claim-based authorization: https://docs.microsoft.com/en-us/aspnet/core/security/authorization/claims?view=aspnetcore-3.1
- Policy-based authorization: https://docs.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-3.1

### Roles

- Boolean
- Encapsulating
  - Users
  - Functions

A "boolean" functionality: if the user is in a role, he has access to the function which is protected by the role.

```
+----------------------------------+
|             ROLE                 |
|  +---------+    +-------------+  |
|  |  Users  |    |  Functions  |  |
|  +---------+    +-------------+  |
+----------------------------------+
```

### Claims

- Key Value Pair. Examples:
  - UserId = `<userId>`
  - Email = `<email>`
- User Property
- Describes the User
- A user can have many claims (Admin has Admin-Clain and User-Claim)

### Policy

Authorization Functions

You can use:

- Roles
- Claims

```
                 +--------------+
+-----------+    |              |-----> Database
|  Context  |--->+    Policy    |-----> Files
+-----------+    |              |-----> Cache
                 |              |-----> Service
  OK or NOK <----|              |-----> ...
                 +--------------+
```

Details: https://docs.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-3.1

#### IAuthorizationFilter (poor way)

```
[AttributeUsage(AttributeTarget.Class | AttributeTarget.Method)]
public class YearsWorkedAttribute : TypeFilterAttribute
{
    public YearsWorkedAttribute() : base(typeof(YearsWorkedAuthorizeFilter))
    {
        Arguments = new object[] { years };
    }
}

// todo: tbv
public class AuthorizeFilterBase : IAuthorizationFilter
{
    public readonly IWebHostEnvironment _env;

    public AuthorizeFilterBase(IWebHostEnvironment env)
    {
        _env = env;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
    }
}

//
public class YearsWorkedAuthorizeFilter : AuthorizeFilterBase
{
    public int Years {get; set;}

    public YearsWorkedAuthorizeFilter(int years) => Years = years;

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        // bool isDevelopment = _env.IsDevelopment();
        var user = context.HttpContext.User;

        if (!user.IsAuthenticated) {
            context.Result = new UnauthorizedResult();
            return;
        }

        var started = user.Claims.FirstOrDefault(x => x.Type == "DateStarted").Value;
        var dateStarted = DateTime.Parse(started);

        if (DateTime.Now.Subtract(dateStarted).TotalDays < 365 * Years) {
            context.Result = new UnauthorizedResult();
            return;
        }

    }
}
// todo: webapi, not mvc
public class ClaimsController : Controller
{
    public IActionResult Index() => View();

    [YearsWorked(2)]
    public IActionResult TwoYearRewards() => View();

    [YearsWorked(5)]
    public IActionResult FiveYearRewards() => View();

    [YearsWorked(10)]
    public IActionResult TenYearRewards() => View();
}
```

#### IAuthorizationFilter (better way)

Source: https://github.com/T0shik/rolesvsclaimsvspolicy Youtube: https://www.youtube.com/watch?v=cbtK3U2aOlg

```
services.AddAuthorization(options =>
{
    options.AddPolicy("WorkedTwoYears", policy =>
        policy.Requirements.Add(new MinimumYearsWorkedRequirement(2)));

    options.AddPolicy("WorkedFiveYears", policy =>
        policy.Requirements.Add(new MinimumYearsWorkedRequirement(5)));

    options.AddPolicy("WorkedTenYears", policy =>
        policy.Requirements.Add(new MinimumYearsWorkedRequirement(10)));
});

services.AddSingleton<IAuthorizationHandler, YearsWorkedHandler>();
namespace Claims.PolicyHandlers
{
    public class MinimumYearsWorkedRequirement : IAuthorizationRequirement
    {
        public int Years { get; }

        public MinimumYearsWorkedRequirement(int yearsWorked)
        {
            Years = yearsWorked;
        }
    }

    public class YearsWorkedHandler : AuthorizationHandler<MinimumYearsWorkedRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MinimumYearsWorkedRequirement requirement)
        {
            if (!context.User.Identity.IsAuthenticated)
                return Task.CompletedTask;

            var started = context.User.Claims.FirstOrDefault(x => x.Type == "DateStarted").Value;
            var dateStarted = DateTime.Parse(started);

            if (DateTime.Now.Subtract(dateStarted).TotalDays > 365 * requirement.Years)
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }
}
// todo: webapi, not mvc
public class PolicyController : Controller
{
    public IActionResult Index() => View();

    [Authorize(Policy = "WorkedTwoYears")]
    public IActionResult TwoYearRewards() => View();

    [Authorize(Policy = "WorkedFiveYears")]
    public IActionResult FiveYearRewards() => View();

    [Authorize(Policy = "WorkedTenYears")]
    public IActionResult TenYearRewards() => View();
}
```

## ASP.NET Core Identity

Create a new project in Visual Studio, change "Authentication", select "Individual User Accounts". (Store user accounts in-app). Alternatively use this:

```
dotnet new mvc -au Individual
```

Benefits:

- Framework around cookie authentication
- Contains Helper classes and UI
- Customizable
- Configurable

Features:

- Login and logout
- User registration
- Third-party logins
- Password management
- Account lockout
- Tow-Factor authentication

Links:

- Documentation: https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity?view=aspnetcore-3.1&tabs=visual-studio
- Custom Data Stores: https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity-custom-storage-providers?view=aspnetcore-3.1

## Microsoft Identity platform

https://docs.microsoft.com/en-us/azure/active-directory/develop/

- About Microsoft identity platform
- Build a single-page app (Angular): https://docs.microsoft.com/en-us/azure/active-directory/develop/scenario-spa-overview
- Build a web app that signs in users
- Build a web app that calls web APIs
- Build a protected web API
- Web API that calls web APIs
- Build a desktop app that calls web APIs
- Build a daemon app that calls web APIs
- Build a mobile app that calls web APIs
- Build a customer-facing app that signs in social & local identities
- Call Microsoft Graph API

## Links

- Microsoft Identity Platform: https://docs.microsoft.com/en-us/azure/active-directory/develop/
- ASP.NET Identity: https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity?view=aspnetcore-3.1&tabs=visual-studio
- Security: https://docs.microsoft.com/en-us/aspnet/core/security/?view=aspnetcore-3.1
- Authentication: https://docs.microsoft.com/en-us/aspnet/core/security/authentication/?view=aspnetcore-3.1
- Authorization: https://docs.microsoft.com/en-us/aspnet/core/security/authorization/introduction?view=aspnetcore-3.1
- Policy: https://docs.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-3.1