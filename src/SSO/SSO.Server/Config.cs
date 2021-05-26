using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Test;
using System.Collections.Generic;
using System.Security.Claims;

namespace SSO.Server
{
    /// <summary>
    /// 1、Identity测试使用
    /// </summary>
    public class Config
    {
        /// <summary>
        /// 1、微服务API资源
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("TeamService", "TeamService api需要被保护")
            };
        }

        public static IEnumerable<IdentityResource> Ids => new List<IdentityResource>
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile()
        };

        /// <summary>
        /// 2、客户端
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientId = "client",

                    // 没有交互性用户，使用 clientid/secret 实现认证。
                    AllowedGrantTypes = GrantTypes.ClientCredentials,

                    // 用于认证的密码
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },
                    // 客户端有权访问的范围（Scopes）
                    AllowedScopes = { "TeamService" }
                },
                new Client
                {
                    ClientId = "client-password",
	                // 使用用户名密码交互式验证
	                AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,

	                // 用于认证的密码
	                ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },
	                // 客户端有权访问的范围（Scopes）
	                AllowedScopes = { "TeamService" }
                },                
                new Client // oauth2授权码模式
                {
                    ClientId = "oauth.code",
                    ClientName = "Server-based Client (Code)",

                    RedirectUris = { "http://localhost:5001/signin-oauth" },
                    PostLogoutRedirectUris = { "http://localhost:5001/signout-oauth" },

                    ClientSecrets = { new Secret("secret".Sha256()) },

                    AllowedGrantTypes = GrantTypes.Code,
                    AllowedScopes = { "openid", "profile", "email", "api" },
                    AllowOfflineAccess = true
                },                
                new Client // oidc混合模式
                {
                    ClientId = "oidc.hybrid",
                    ClientName = "Server-based Client (Hybrid)",

                    RedirectUris = { "http://localhost:5002/signin-oidc" },
                    FrontChannelLogoutUri = "http://localhost:5002/signout-oidc",
                    PostLogoutRedirectUris = { "http://localhost:5002/signout-callback-oidc" },

                    ClientSecrets = { new Secret("secret".Sha256()) },

                    AllowedGrantTypes = GrantTypes.Hybrid,
                    AllowedScopes = { "openid", "profile", "email", "api" },
                    AllowOfflineAccess = true,
                    AllowAccessTokensViaBrowser = true
                },
                // openid客户端
                new Client
                {
                    ClientId="client-code",
                    ClientSecrets={new Secret("secret".Sha256())},
                    AllowedGrantTypes=GrantTypes.Code,
                    RequireConsent=false,
                    RequirePkce=true,

                    RedirectUris={ "https://localhost:5006/signin-oidc"},

                    PostLogoutRedirectUris={ "https://localhost:5006/signout-callback-oidc"},

                    AllowedScopes=new List<string>{
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "TeamService" // 启用对刷新令牌的支持
                    },
                    // 增加授权访问
                    AllowOfflineAccess=true
                }	
            };
        }
        /// <summary>
        /// 客户端下面的用户
        /// </summary>
        /// <returns></returns>
        public static List<TestUser> GetUsers()
        {
            return new List<TestUser>()
            {
                new TestUser
                {
                    SubjectId="1",
                    Username="tony",
                    Password="123456"
                },
                // openid 身份验证
                new TestUser{
                    SubjectId = "818727", 
                    Username = "张三", 
                    Password = "123456",
                    Claims =
                    {
                        new Claim(JwtClaimTypes.Name, "张三"),
                        new Claim(JwtClaimTypes.GivenName, "三"),
                        new Claim(JwtClaimTypes.FamilyName, "张"),
                        new Claim(JwtClaimTypes.Email, "zhangsan@email.com"),
                        new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
                        new Claim(JwtClaimTypes.WebSite, "http://zhangsan.com"),
                        //  new Claim(JwtClaimTypes.Address, @"{ '城市': '杭州', '邮政编码': '310000' }", IdentityServer4.IdentityServerConstants.ClaimValueTypes.Json)
                    }
                }
            };
        }
    }
}
