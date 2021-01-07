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

            //// Server����Ϊ��֤������ʹ��
            //services.AddAuthentication("OAuth")
            //    .AddJwtBearer("OAuth", config =>
            //    {
            //        var secretBytes = Encoding.UTF8.GetBytes(Constants.Secret);
            //        var key = new SymmetricSecurityKey(secretBytes);

            //        // ��url�н���token
            //        config.Events = new JwtBearerEvents()
            //        {
            //            OnMessageReceived = context =>
            //            {
            //                // ����url�Ƿ����"access_token"
            //                if (context.Request.Query.ContainsKey("access_token"))
            //                {
            //                    context.Token = context.Request.Query["access_token"];
            //                }
            //                // ֮���ֱ����֤token�����ͨ��ֱ����ת�ܱ���ҳ�棬����401
            //                return Task.CompletedTask;
            //            }
            //        };
            //        // ��Ҫ��֤token�Ĳ������������ö���ҪΪtrue
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
