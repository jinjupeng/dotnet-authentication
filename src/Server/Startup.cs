using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Server
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            //// Server端作为认证服务器使用
            //services.AddAuthentication("OAuth")
            //    .AddJwtBearer("OAuth", config =>
            //    {
            //        var secretBytes = Encoding.UTF8.GetBytes(Constants.Secret);
            //        var key = new SymmetricSecurityKey(secretBytes);

            //        // 从url中接收token
            //        config.Events = new JwtBearerEvents()
            //        {
            //            OnMessageReceived = context =>
            //            {
            //                // 请求url是否包含"access_token"
            //                if (context.Request.Query.ContainsKey("access_token"))
            //                {
            //                    context.Token = context.Request.Query["access_token"];
            //                }
            //                // 之后会直接验证token，如果通过直接跳转受保护页面，否则401
            //                return Task.CompletedTask;
            //            }
            //        };
            //        // 需要验证token的参数，以下配置都需要为true
            //        config.TokenValidationParameters = new TokenValidationParameters()
            //        {
            //            ClockSkew = TimeSpan.Zero,
            //            ValidIssuer = Constants.Issuer,
            //            ValidAudience = Constants.Audiance,
            //            IssuerSigningKey = key,
            //        };
            //    });

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["TokenOptions:Key"]));

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
                // here the cookie authentication option and other authentication providers will are added.
                .AddJwtBearer(options =>
                {
                    options.SaveToken = true;
                    options.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidIssuer = "MyWebsite.com",
                        ValidAudience = "MyWebsite.com",
                        IssuerSigningKey = symmetricSecurityKey
                    };
                });

            services.AddAuthorization(options =>
                options.AddPolicy("ValidAccessToken", policy =>
                {
                    policy.AuthenticationSchemes.Add(JwtBearerDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                }));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

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
