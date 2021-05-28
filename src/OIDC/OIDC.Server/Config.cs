using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Test;
using System.Collections.Generic;
using System.Security.Claims;

namespace OIDC.Server
{
    public class Config
    {
        /// <summary>
        /// 这个 Authorization Server 保护了哪些 API （资源）
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("api", "Demo API", new[] { JwtClaimTypes.Subject, JwtClaimTypes.Email, JwtClaimTypes.Name, JwtClaimTypes.Role, JwtClaimTypes.PhoneNumber })
            };
        }

        /// <summary>
        /// 定义系统中的资源
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
            };
        }

        /// <summary>
        /// 哪些客户端 Client（应用） 可以使用这个 Authorization Server
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new Client // oauth2授权码模式
                {
                    ClientId = "oauth.code",
                    ClientName = "Server-based Client (Code)",

                    RedirectUris = { "https://localhost:5002/signin-oidc" },
                    PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },

                    ClientSecrets = { new Secret("secret".Sha256()) },
                    RequirePkce = true, // 开启pkce模式校验，默认为true
                    AllowedGrantTypes = GrantTypes.Code,
                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "api"
                    },
                    AllowOfflineAccess = true
                },
                new Client // oidc混合模式
                {
                    ClientId = "oidc.hybrid",
                    ClientName = "Server-based Client (Hybrid)",
                    RequirePkce = false, // 默认开启pkce校验，注意：混合模式必须关闭pkce的验证,否则会报错 code challenge required
                    AllowedGrantTypes = GrantTypes.Hybrid,
                    RedirectUris = { "https://localhost:5002/signin-oidc" }, // 登录成功后返回的客户端地址
                    FrontChannelLogoutUri = "https://localhost:5002/signout-oidc", // 客户端注销的返回地址
                    PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" }, // 认证中心注销登录后客户端返回的地址
                    //RequireClientSecret = false,
                    ClientSecrets = { new Secret("secret".Sha256()) },
                    RequireConsent = true,// 如果不需要显示否同意授权 页面 这里就设置为false
                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "api"
                    },
                    AllowOfflineAccess = true, // 通过刷新令牌的方式来实现长期的API访问
                    //AllowAccessTokensViaBrowser = true // 通过浏览器传输access token，一般不建议；建议只在后端服务器与认证中心服务器之间传入access_token
                },
                // OpenID Connect隐式流客户端（MVC）
                new Client
                {
                    ClientId = "oidc.implicit",
                    ClientName = "Server-based Client (Implicit)",
                    AllowedGrantTypes = GrantTypes.Implicit,//隐式方式
                    RequireConsent = true,//如果不需要显示否同意授权 页面 这里就设置为false
                    RedirectUris = { "https://localhost:5002/signin-oidc" },//登录成功后返回的客户端地址
                    FrontChannelLogoutUri = "https://localhost:5002/signout-oidc", // 客户端注销的返回地址
                    PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },//注销登录后返回的客户端地址

                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile
                    }
                }
            };
        }
        ///// <summary>
        ///// 指定可以使用 Authorization Server 授权的 Users（用户）
        ///// </summary>
        ///// <returns></returns>
        //public static List<TestUser> GetUsers()
        //{
        //    return new List<TestUser>
        //    {
        //        new TestUser{SubjectId = "001", Username = "alice", Password = "alice",
        //            Claims =
        //            {
        //                new Claim(JwtClaimTypes.Name, "Alice Smith"),
        //                new Claim(JwtClaimTypes.GivenName, "Alice"),
        //                new Claim(JwtClaimTypes.FamilyName, "Smith"),
        //                new Claim(JwtClaimTypes.Email, "AliceSmith@email.com"),
        //                new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
        //                new Claim(JwtClaimTypes.WebSite, "http://alice.com"),
        //                new Claim(JwtClaimTypes.Address, @"{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69118, 'country': 'Germany' }", IdentityServerConstants.ClaimValueTypes.Json)
        //            }
        //        },
        //        new TestUser{SubjectId = "002", Username = "bob", Password = "bob",
        //            Claims =
        //            {
        //                new Claim(JwtClaimTypes.Name, "Bob Smith"),
        //                new Claim(JwtClaimTypes.GivenName, "Bob"),
        //                new Claim(JwtClaimTypes.FamilyName, "Smith"),
        //                new Claim(JwtClaimTypes.Email, "BobSmith@email.com"),
        //                new Claim(JwtClaimTypes.EmailVerified, "true", ClaimValueTypes.Boolean),
        //                new Claim(JwtClaimTypes.WebSite, "http://bob.com"),
        //                new Claim(JwtClaimTypes.Address, @"{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69119, 'country': 'Germany' }", IdentityServerConstants.ClaimValueTypes.Json),
        //                new Claim("location", "somewhere"),
        //            }
        //        },
        //    };
        //}
    }
}
