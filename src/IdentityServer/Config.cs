using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Test;
using System.Collections.Generic;

namespace IdentityServer
{
    public class Config
    {
        /// <summary>
        /// 这个 Authorization Server 保护了哪些 API （资源）
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>() {
                new ApiResource("api1", "My API")
            };
        }

        public static IEnumerable<ApiScope> GetApiScopes()
        {
            return new List<ApiScope>
            {
                new ApiScope("api1", "My API")
            };
        }


        /// <summary>
        /// 哪些客户端 Client（应用） 可以使用这个 Authorization Server
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<Client> GetClients()
        {
            /*
             * 客户端代码中的ClientId和ClientSecret可以视为应用程序本身的登录名和密码，它将你的应用程序
             * 标识到IdentityServer服务器中，以便它知道哪个应用程序正在尝试与其连接。
             */
            return new List<Client>
            {
                new Client()
                {
                    ClientId="mvc",
                    AllowedGrantTypes= GrantTypes.Implicit,//模式：最简单的模式
                    ClientSecrets={//私钥
                        new Secret("secret".Sha256())
                    },
                    AllowedScopes={//可以访问的Resource
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.OpenId,
                    },
                    RedirectUris={"http://localhost:5001/signin-oidc"},//跳转登录到的客户端的地址
                    PostLogoutRedirectUris={"http://localhost:5001/signout-callback-oidc"},//跳转登出到的客户端的地址
                    RequireConsent=false//是否需要用户点击确认进行跳转
                }
            };
        }

        /// <summary>
        /// 指定可以使用 Authorization Server 授权的 Users（用户）
        /// 测试用户
        /// </summary>
        /// <returns></returns>
        public static List<TestUser> GetTestUsers()
        {
            return new List<TestUser>{
                new TestUser{
                    SubjectId="10000",
                    Username="username",
                    Password="password"
                }
            };
        }

        //定义系统中的资源
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email()
            };
        }
    }
}
