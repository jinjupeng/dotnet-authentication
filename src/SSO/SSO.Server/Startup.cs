using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SSO.Server
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
            // 添加IdentityServer4
            services.AddIdentityServer()
                .AddDeveloperSigningCredential()// 用户登录配置
                .AddInMemoryApiResources(Config.GetApiResources()) // 存储Api资源
                .AddInMemoryClients(Config.GetClients()) // 存储客户端(模式)
                .AddTestUsers(Config.GetUsers()) // 添加登录用户(模式)	
                .AddInMemoryIdentityResources(Config.Ids); // 使用openid模式

            // 添加身份验证
            // 我们使用cookie来本地登录用户（通过“Cookies”作为DefaultScheme），并且将DefaultChallengeScheme设置为oidc。因为当我们需要用户登录时，我们将使用OpenID Connect协议。
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "Cookies";
                options.DefaultChallengeScheme = "oidc";
            })
            // 添加可以处理cookie的处理程序
            .AddCookie("Cookies")
            // 用于配置执行OpenID Connect协议的处理程序
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = "http://localhost:5005";    // 受信任令牌服务地址
                options.RequireHttpsMetadata = false;
                options.ClientId = "client-code";
                options.ClientSecret = "secret";
                options.ResponseType = "code";
                options.SaveTokens = true;  // 用于将来自IdentityServer的令牌保留在cookie中

                // 添加授权访问api的支持
                options.Scope.Add("TeamService");
                options.Scope.Add("offline_access");
            });	
            services.AddControllersWithViews();
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
            }
            // 添加IdentityServe4中间件
            app.UseIdentityServer();
            // 添加静态资源访问
            app.UseStaticFiles();

            app.UseRouting();

            // 开启身份验证
            app.UseAuthentication(); 

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
