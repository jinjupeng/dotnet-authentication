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
                // ʹ��Cookies��֤
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
                // ʹ��oidc
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(o => // ����Cookies��֤
            {
                o.Events.OnRedirectToAccessDenied = context =>
                {
                    context.Response.Redirect(context.RedirectUri);
                    return Task.CompletedTask;
                };
            })
            .AddOpenIdConnect(o => // ����oidc�����ģʽ���Ƽ�
            {
                o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.ClientId = "oidc.hybrid";
                o.ClientSecret = "secret";
                // ��������Authority���ͱ���ָ��MetadataAddress
                o.Authority = "https://localhost:5001/";
                // Ĭ��ΪAuthority+".well-known/openid-configuration"
                o.MetadataAddress = "https://localhost:5001/.well-known/openid-configuration";
                //o.RequireHttpsMetadata = false;

                // ʹ�û������������oauth2��Ȩ�����һ�㣬���������id_token��һ�
                o.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                // �Ƿ�Tokens���浽AuthenticationProperties��
                o.SaveTokens = true;
                // �Ƿ��UserInfoEndpoint��ȡClaims
                o.GetClaimsFromUserInfoEndpoint = true;
                // �ڱ�ʾ���У�ʹ�õ���IdentityServer��������ClaimTypeʹ�õ���JwtClaimTypes��
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name"
                };
                // ���²������ж�Ӧ��Ĭ��ֵ��ͨ���������á�
                //o.CallbackPath = new PathString("/signin-oidc");
                //o.SignedOutCallbackPath = new PathString("/signout-callback-oidc");
                //o.RemoteSignOutPath = new PathString("/signout-oidc");
                //o.Scope.Add("openid"); // ������oauth2��Ȩ�����һ�㣬���������openid��һ��
                //o.Scope.Add("profile");
                //o.ResponseMode = OpenIdConnectResponseMode.FormPost; 

                /***********************************����¼�***********************************/
                // δ��Ȩʱ���ض���OIDC������ʱ����
                //o.Events.OnRedirectToIdentityProvider = context => Task.CompletedTask;

                // ��ȡ����Ȩ��ʱ����
                //o.Events.OnAuthorizationCodeReceived = context => Task.CompletedTask;
                // ���յ�OIDC���������ص���֤��Ϣ������Code, ID Token�ȣ�ʱ����
                //o.Events.OnMessageReceived = context => Task.CompletedTask;
                // ���յ�TokenEndpoint���ص���Ϣʱ����
                //o.Events.OnTokenResponseReceived = context => Task.CompletedTask;
                // ��֤Tokenʱ����
                //o.Events.OnTokenValidated = context => Task.CompletedTask;
                // ���յ�UserInfoEndpoint���ص���Ϣʱ����
                //o.Events.OnUserInformationReceived = context => Task.CompletedTask;
                // �����쳣ʱ����
                //o.Events.OnAuthenticationFailed = context => Task.CompletedTask;

                // �˳�ʱ���ض���OIDC������ʱ����
                //o.Events.OnRedirectToIdentityProviderForSignOut = context => Task.CompletedTask;
                // OIDC�������˳��󣬷���˻ص�ʱ����
                //o.Events.OnRemoteSignOut = context => Task.CompletedTask;
                // OIDC�������˳��󣬿ͻ����ض���ʱ����
                //o.Events.OnSignedOutCallbackRedirect = context => Task.CompletedTask;
            });
            //.AddOpenIdConnect(o => // ����oidc����ʽģʽ�����Ƽ�
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
        /// [ASP.NET Core ��֤����Ȩ[3]:OAuth & OpenID Connect��֤](https://www.cnblogs.com/RainingNight/p/oidc-authentication-in-asp-net-core.html)
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

            // �����˳�,��oidc�����������˳�
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

            // Զ���˳�����oidc���˳���oidc�˳��󣬻ص�������Ӧ���˳�ҳ��󣬱���Ӧ�����˳�
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

            // δ��Ȩҳ��
            app.Map("/Account/AccessDenied", builder =>
            {
                builder.Run(async context =>
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    var response = context.Response;
                    response.ContentType = "text/html; charset=utf-8";
                    await response.WriteAsync("<html><body>");
                    await response.WriteAsync($"<h1>Access Denied for user {context.User.Identity.Name} to resource '{context.Request.Query["ReturnUrl"]}'</h1>");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/signout\">�˳�</a>");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/\">��ҳ</a>");
                    await response.WriteAsync("</body></html>");
                });
            });


            // ����
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

            // ��֤ͨ����������Ȩʧ��
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

            // ˢ������
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
                    await response.WriteAsync("<a class=\"btn btn-link\" href=\"/signout\">�˳�</a>");
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

            // �ҵ���Ϣ
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
                    await response.WriteAsync($"<h1>��ã���ǰ��¼�û��� {(context.User.Identity.Name ?? "anonymous")}</h1>");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/refresh_token\">ˢ������</a> ");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/restricted\">��Ȩ����</a> ");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/signout\">�����˳� </a>");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/signout_remote\">Զ���˳�</a> ");
                    await response.WriteAsync($"<h2>AuthenticationType��{context.User.Identity.AuthenticationType}</h2>");
                    await response.WriteAsync("<h2>Claims:</h2>");
                    foreach (var claim in context.User.Claims)
                    {
                        await response.WriteAsync(claim.Type + ": " + claim.Value + "<br>");
                    }

                    // �ڵ�һ���н��ܹ�HandleAuthenticateOnceAsync�������ڴ˵��ò������ж����������ġ�
                    var result = await context.AuthenticateAsync();
                    await response.WriteAsync("<h2>Tokens:</h2>");
                    foreach (var token in result.Properties.GetTokens())
                    {
                        await response.WriteAsync(token.Name + ": " + token.Value + "<br>");
                    }
                    await response.WriteAsync("</body></html>");
                });
            });

            // ��ҳ
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
                await response.WriteAsync("<a class=\"btn btn-default\" href=\"/profile\">�ҵ���Ϣ</a>");
                await response.WriteAsync("</body></html>");
            });

        }
    }
}
