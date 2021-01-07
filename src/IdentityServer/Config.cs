using IdentityServer4.Models;
using IdentityServer4.Test;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

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

        public static IEnumerable<ApiScope> ApiScopes =>
        new List<ApiScope>
        {
            new ApiScope("api1", "My API")
        };

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
            return new[]
            {
                    new Client
                    {
                        ClientId = "client",//定义客户端 Id
                        ClientSecrets = new [] { new Secret("secret".Sha256()) },//Client用来获取token
                        AllowedGrantTypes = GrantTypes.ResourceOwnerPasswordAndClientCredentials,//这里使用的是通过用户名密码和ClientCredentials来换取token的方式. ClientCredentials允许Client只使用ClientSecrets来获取token. 这比较适合那种没有用户参与的api动作
                        //AllowedGrantTypes = GrantTypes.ClientCredentials,
                        AllowedScopes = new [] { "api1" }// 允许访问的 API 资源
                    }
            };
        }

        /// <summary>
        /// 指定可以使用 Authorization Server 授权的 Users（用户）
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<TestUser> Users()
        {
            return new[]
            {
                    new TestUser
                    {
                        SubjectId = "1",
                        Username = "admin",
                        Password = "admin"
                    }
            };
        }
    }
}
