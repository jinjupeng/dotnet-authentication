using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;

namespace Client
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(config =>
            {
                // We check the cookie to confirm that we are authenticated
                config.DefaultAuthenticateScheme = "ClientCookie";
                // When we sign in we will deal out a cookie
                config.DefaultSignInScheme = "ClientCookie";
                // use this to check if we are allowed to do something.
                config.DefaultChallengeScheme = "OurServer";
            })
                .AddCookie("ClientCookie")
                .AddOAuth("OurServer", config =>
                {
                    config.ClientId = "client_id";
                    config.ClientSecret = "client_secret";
                    config.CallbackPath = "/oauth/callback";
                    config.AuthorizationEndpoint = "https://localhost:44382/oauth/authorize";
                    config.TokenEndpoint = "https://localhost:44382/oauth/token";
                    config.SaveTokens = true;

                    config.Events = new OAuthEvents()
                    {
                        OnCreatingTicket = context =>
                        {
                            var accessToken = context.AccessToken;
                            var base64payload = accessToken.Split('.')[1];
                            var bytes = Convert.FromBase64String(base64payload);
                            var jsonPayload = Encoding.UTF8.GetString(bytes);
                            var claims = JsonConvert.DeserializeObject<Dictionary<string, string>>(jsonPayload);

                            foreach (var claim in claims)
                            {
                                context.Identity.AddClaim(new Claim(claim.Key, claim.Value));
                            }

                            return Task.CompletedTask;
                        }
                    };
                });

            /*
             * 当使用第三方GitHub登陆时，使用Edge或Chrome浏览器会出现“Correlation failed”的问题，但使用FireFox就没问题
             * 解决方法：
             * [.Net Core外部登录中的一个坑：Correlation failed](https://www.bilibili.com/read/cv6015905/)
             */
            //services.AddAuthentication(options =>
            //{
            //    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //    options.DefaultChallengeScheme = "GitHub";
            //})
            //   .AddCookie()
            //   .AddOAuth("GitHub", options =>
            //   {
            //       options.ClientId = Configuration["GitHub:ClientId"];
            //       options.ClientSecret = Configuration["GitHub:ClientSecret"];
            //       options.CallbackPath = new PathString("/github-oauth");

            //       options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
            //       options.TokenEndpoint = "https://github.com/login/oauth/access_token";
            //       options.UserInformationEndpoint = "https://api.github.com/user";

            //       options.SaveTokens = true;

            //       options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
            //       options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
            //       options.ClaimActions.MapJsonKey("urn:github:login", "login");
            //       options.ClaimActions.MapJsonKey("urn:github:url", "html_url");
            //       options.ClaimActions.MapJsonKey("urn:github:avatar", "avatar_url");

            //       options.Events = new OAuthEvents
            //       {
            //           OnCreatingTicket = async context =>
            //           {
            //               var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
            //               request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            //               request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

            //               var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
            //               response.EnsureSuccessStatusCode();

            //               var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

            //               context.RunClaimActions(json.RootElement);
            //           }
            //       };
            //   });

            services.AddHttpClient();

            services.AddControllersWithViews()
                .AddRazorRuntimeCompilation();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
