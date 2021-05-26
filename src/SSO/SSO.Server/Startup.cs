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
            // ���IdentityServer4
            services.AddIdentityServer()
                .AddDeveloperSigningCredential()// �û���¼����
                .AddInMemoryApiResources(Config.GetApiResources()) // �洢Api��Դ
                .AddInMemoryClients(Config.GetClients()) // �洢�ͻ���(ģʽ)
                .AddTestUsers(Config.GetUsers()) // ��ӵ�¼�û�(ģʽ)	
                .AddInMemoryIdentityResources(Config.Ids); // ʹ��openidģʽ

            // ��������֤
            // ����ʹ��cookie�����ص�¼�û���ͨ����Cookies����ΪDefaultScheme�������ҽ�DefaultChallengeScheme����Ϊoidc����Ϊ��������Ҫ�û���¼ʱ�����ǽ�ʹ��OpenID ConnectЭ�顣
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "Cookies";
                options.DefaultChallengeScheme = "oidc";
            })
            // ��ӿ��Դ���cookie�Ĵ������
            .AddCookie("Cookies")
            // ��������ִ��OpenID ConnectЭ��Ĵ������
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = "http://localhost:5005";    // ���������Ʒ����ַ
                options.RequireHttpsMetadata = false;
                options.ClientId = "client-code";
                options.ClientSecret = "secret";
                options.ResponseType = "code";
                options.SaveTokens = true;  // ���ڽ�����IdentityServer�����Ʊ�����cookie��

                // �����Ȩ����api��֧��
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
            // ���IdentityServe4�м��
            app.UseIdentityServer();
            // ��Ӿ�̬��Դ����
            app.UseStaticFiles();

            app.UseRouting();

            // ���������֤
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
