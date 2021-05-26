using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace OIDC.Server
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            services.AddAuthentication(options =>
            {
                // 使用Cookies认证
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
                // 使用oidc
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(o => // 配置Cookies认证
            {
                o.Events.OnRedirectToAccessDenied = context =>
                {
                    context.Response.Redirect(context.RedirectUri);
                    return Task.CompletedTask;
                };
            })
            .AddOpenIdConnect(o => // 配置oidc，混合模式，推荐
            {
                o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.ClientId = "oidc.hybrid";
                o.ClientSecret = "secret";
                // 若不设置Authority，就必须指定MetadataAddress
                o.Authority = "https://localhost:5001/";
                // 默认为Authority+".well-known/openid-configuration"
                o.MetadataAddress = "https://localhost:5001/.well-known/openid-configuration";
                //o.RequireHttpsMetadata = false;

                // 使用混合流，区别于oauth2授权请求的一点，必须包含有id_token这一项。
                o.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                // 是否将Tokens保存到AuthenticationProperties中
                o.SaveTokens = true;
                // 是否从UserInfoEndpoint获取Claims
                o.GetClaimsFromUserInfoEndpoint = true;
                // 在本示例中，使用的是IdentityServer，而它的ClaimType使用的是JwtClaimTypes。
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name"
                };
                // 以下参数均有对应的默认值，通常无需设置。
                //o.CallbackPath = new PathString("/signin-oidc");
                //o.SignedOutCallbackPath = new PathString("/signout-callback-oidc");
                //o.RemoteSignOutPath = new PathString("/signout-oidc");
                //o.Scope.Add("openid"); // 区别于oauth2授权请求的一点，必须包含有openid这一项
                //o.Scope.Add("profile");
                //o.ResponseMode = OpenIdConnectResponseMode.FormPost; 

                /***********************************相关事件***********************************/
                // 未授权时，重定向到OIDC服务器时触发
                //o.Events.OnRedirectToIdentityProvider = context => Task.CompletedTask;

                // 获取到授权码时触发
                //o.Events.OnAuthorizationCodeReceived = context => Task.CompletedTask;
                // 接收到OIDC服务器返回的认证信息（包含Code, ID Token等）时触发
                //o.Events.OnMessageReceived = context => Task.CompletedTask;
                // 接收到TokenEndpoint返回的信息时触发
                //o.Events.OnTokenResponseReceived = context => Task.CompletedTask;
                // 验证Token时触发
                //o.Events.OnTokenValidated = context => Task.CompletedTask;
                // 接收到UserInfoEndpoint返回的信息时触发
                //o.Events.OnUserInformationReceived = context => Task.CompletedTask;
                // 出现异常时触发
                //o.Events.OnAuthenticationFailed = context => Task.CompletedTask;

                // 退出时，重定向到OIDC服务器时触发
                //o.Events.OnRedirectToIdentityProviderForSignOut = context => Task.CompletedTask;
                // OIDC服务器退出后，服务端回调时触发
                //o.Events.OnRemoteSignOut = context => Task.CompletedTask;
                // OIDC服务器退出后，客户端重定向时触发
                //o.Events.OnSignedOutCallbackRedirect = context => Task.CompletedTask;
            });
            //.AddOpenIdConnect(o => // 配置oidc，隐式模式，不推荐
            //{
            //    o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    o.ClientId = "oidc.implicit";
            //    o.Authority = "https://localhost:5001/";
            //    o.MetadataAddress = "https://localhost:5001/.well-known/openid-configuration";
            //    //o.RequireHttpsMetadata = false;
            //    o.ResponseType = OpenIdConnectResponseType.IdToken;
            //    o.SaveTokens = true;
            //    o.GetClaimsFromUserInfoEndpoint = true;
            //    o.TokenValidationParameters = new TokenValidationParameters
            //    {
            //        NameClaimType = "name"
            //    };
            //});
        }

        /// <summary>
        /// [ASP.NET Core 认证与授权[3]:OAuth & OpenID Connect认证](https://www.cnblogs.com/RainingNight/p/oidc-authentication-in-asp-net-core.html)
        /// </summary>
        /// <param name="app"></param>
        /// <param name="env"></param>
        /// <param name="optionsMonitor"></param>
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IOptionsMonitor<OpenIdConnectOptions> optionsMonitor)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseAuthentication();

            // 本地退出,但oidc服务器不会退出
            app.Map("/signout", signoutApp =>
            {
                signoutApp.Run(async context =>
                {
                    var response = context.Response;
                    response.ContentType = "text/html; charset=utf-8";
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    await response.WriteAsync("<html><body>");
                    await response.WriteAsync($"<h1>Signed out {context.User.Identity.Name}</h1>");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/\">Home</a>");
                    await response.WriteAsync("</body></html>");
                });
            });

            // 远程退出，即oidc先退出，oidc退出后，回调到本地应用退出页面后，本地应用再退出
            app.Map("/signout_remote", builder =>
            {
                builder.Run(async context =>
                {
                    await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties()
                    {
                        RedirectUri = "/signout"
                    });
                });
            });

            // 未授权页面
            app.Map("/Account/AccessDenied", builder =>
            {
                builder.Run(async context =>
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    var response = context.Response;
                    response.ContentType = "text/html; charset=utf-8";
                    await response.WriteAsync("<html><body>");
                    await response.WriteAsync($"<h1>Access Denied for user {context.User.Identity.Name} to resource '{context.Request.Query["ReturnUrl"]}'</h1>");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/signout\">退出</a>");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/\">首页</a>");
                    await response.WriteAsync("</body></html>");
                });
            });


            // 错误
            app.Map("/error", errorApp =>
            {
                errorApp.Run(async context =>
                {
                    var response = context.Response;
                    response.ContentType = "text/html; charset=utf-8";
                    await response.WriteAsync("<html><body>");
                    await response.WriteAsync("An remote failure has occurred: " + context.Request.Query["FailureMessage"] + "<br>");
                    await response.WriteAsync("<a href=\"/\">Home</a>");
                    await response.WriteAsync("</body></html>");
                });
            });

            // 认证通过，但是授权失败
            app.Map("/restricted", builder =>
            {
                builder.Run(async context =>
                {
                    if (!context.User.Identities.Any(identity => identity.HasClaim("special", "true")))
                    {
                        await context.ForbidAsync();
                    }
                    else
                    {
                        await context.Response.WriteAsync($"<h1>Hello Authorized User {(context.User.Identity.Name ?? "anonymous")}</h1>");
                    }
                });
            });

            // 刷新令牌
            app.Map("/refresh_token", signinApp =>
            {
                signinApp.Run(async context =>
                {
                    var response = context.Response;
                    // Setting DefaultAuthenticateScheme causes User to be set
                    // var user = context.User;

                    // This is what [Authorize] calls
                    var userResult = await context.AuthenticateAsync();
                    var user = userResult.Principal;
                    var authProperties = userResult.Properties;

                    // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
                    // var user = await context.AuthenticateAsync(MicrosoftAccountDefaults.AuthenticationScheme);

                    // Deny anonymous request beyond this point.
                    if (!userResult.Succeeded || user == null || !user.Identities.Any(identity => identity.IsAuthenticated))
                    {
                        // This is what [Authorize] calls
                        // The cookie middleware will handle this and redirect to /login
                        await context.ChallengeAsync();

                        // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
                        // await context.ChallengeAsync(MicrosoftAccountDefaults.AuthenticationScheme);

                        return;
                }

                var props = userResult.Properties;
                var refreshToken = props.GetTokenValue("refresh_token");
                if (string.IsNullOrEmpty(refreshToken))
                {
                    response.ContentType = "text/html; charset=utf-8";
                    await response.WriteAsync("<html><body>");
                    await response.WriteAsync($"No refresh_token is available.<br>");
                    await response.WriteAsync("<a class=\"btn btn-link\" href=\"/signout\">退出</a>");
                    await response.WriteAsync("</body></html>");
                    return;
                }

                var options = optionsMonitor.Get(OpenIdConnectDefaults.AuthenticationScheme);
                var metadata = await options.ConfigurationManager.GetConfigurationAsync(context.RequestAborted);

                var pairs = new Dictionary<string, string>()
                {
                    { "client_id", options.ClientId },
                    { "client_secret", options.ClientSecret },
                    { "grant_type", "refresh_token" },
                    { "refresh_token", refreshToken }
                };
                var content = new FormUrlEncodedContent(pairs);
                var tokenResponse = await options.Backchannel.PostAsync(metadata.TokenEndpoint, content, context.RequestAborted);
                tokenResponse.EnsureSuccessStatusCode();

                var payload = JObject.Parse(await tokenResponse.Content.ReadAsStringAsync());

                // Persist the new acess token
                props.UpdateTokenValue("access_token", payload.Value<string>("access_token"));
                props.UpdateTokenValue("refresh_token", payload.Value<string>("refresh_token"));
                if (int.TryParse(payload.Value<string>("expires_in"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds))
                {
                    var expiresAt = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(seconds);
                    props.UpdateTokenValue("expires_at", expiresAt.ToString("o", CultureInfo.InvariantCulture));
                }
                await context.SignInAsync(userResult.Principal, props);

                response.ContentType = "text/html; charset=utf-8";
                await response.WriteAsync("<html><body>");
                await response.WriteAsync($"<h1>Refreshed.</h1>");
                await response.WriteAsync("<a class=\"btn btn-default\" href=\"/refresh\">Refresh tokens</a>");
                await response.WriteAsync("<a class=\"btn btn-default\" href=\"/\">Home</a>");

                await response.WriteAsync("<h2>Tokens:</h2>");
                foreach (var token in props.GetTokens())
                {
                    await response.WriteAsync(token.Name + ": " + token.Value + "<br>");
                }
                await response.WriteAsync("<h2>Payload:</h2>");
                await response.WriteAsync(HtmlEncoder.Default.Encode(payload.ToString()).Replace(",", ",<br>") + "<br>");
                await response.WriteAsync("</body></html>");

                });
            });

            // 我的信息
            app.Map("/profile", builder =>
            {
                builder.Run(async context =>
                {
                    // Setting DefaultAuthenticateScheme causes User to be set
                    var user = context.User;

                    // This is what [Authorize] calls
                    // var user = await context.AuthenticateAsync();

                    // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
                    // var user = await context.AuthenticateAsync(MicrosoftAccountDefaults.AuthenticationScheme);

                    // Deny anonymous request beyond this point.
                    if (user == null || !user.Identities.Any(identity => identity.IsAuthenticated))
                    {
                        // This is what [Authorize] calls
                        // The cookie middleware will handle this and redirect to /login
                        await context.ChallengeAsync();

                        // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
                        // await context.ChallengeAsync(MicrosoftAccountDefaults.AuthenticationScheme);

                        return;
                    }
                    var response = context.Response;
                    response.ContentType = "text/html; charset=utf-8";
                    await response.WriteAsync("<html><body>");
                    await response.WriteAsync($"<h1>你好，当前登录用户： {(context.User.Identity.Name ?? "anonymous")}</h1>");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/refresh_token\">刷新令牌</a> ");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/restricted\">无权访问</a> ");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/signout\">本地退出 </a>");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/signout_remote\">远程退出</a> ");
                    await response.WriteAsync($"<h2>AuthenticationType：{context.User.Identity.AuthenticationType}</h2>");
                    await response.WriteAsync("<h2>Claims:</h2>");
                    foreach (var claim in context.User.Claims)
                    {
                        await response.WriteAsync(claim.Type + ": " + claim.Value + "<br>");
                    }

                    // 在第一章中介绍过HandleAuthenticateOnceAsync方法，在此调用并不会有多余的性能损耗。
                    var result = await context.AuthenticateAsync();
                    await response.WriteAsync("<h2>Tokens:</h2>");
                    foreach (var token in result.Properties.GetTokens())
                    {
                        await response.WriteAsync(token.Name + ": " + token.Value + "<br>");
                    }
                    await response.WriteAsync("</body></html>");
                });
            });

            // 首页
            app.Run(async context =>
            {
                // Setting DefaultAuthenticateScheme causes User to be set
                var user = context.User;

                // This is what [Authorize] calls
                // var user = await context.AuthenticateAsync();

                // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
                // var user = await context.AuthenticateAsync(MicrosoftAccountDefaults.AuthenticationScheme);

                // Deny anonymous request beyond this point.
                if (user == null || !user.Identities.Any(identity => identity.IsAuthenticated))
                {
                    // This is what [Authorize] calls
                    // The cookie middleware will handle this and redirect to /login
                    await context.ChallengeAsync();

                    // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
                    // await context.ChallengeAsync(MicrosoftAccountDefaults.AuthenticationScheme);

                    return;
                }

                // Display user information
                var response = context.Response;
                response.ContentType = "text/html; charset=utf-8";
                await response.WriteAsync("<html><body>");
                await response.WriteAsync($"<h2>Hello OpenID Connect Authentication</h2>");
                await response.WriteAsync("<a class=\"btn btn-default\" href=\"/profile\">我的信息</a>");
                await response.WriteAsync("</body></html>");
            });

        }
    }
}
