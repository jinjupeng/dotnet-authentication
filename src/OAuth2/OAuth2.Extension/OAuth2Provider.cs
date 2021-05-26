using System;

namespace OAuth2.Extension
{

    /// <summary>
    /// OAuth2 provider wrapper.
    /// </summary>
    public class OAuth2Provider
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string AuthUri { get; set; }
        public string AccessTokenUri { get; set; }
        public string UserInfoUri { get; set; }
        public string Scope { get; set; }
        public string State { get; set; }
        public bool Offline = false;
    }
}
