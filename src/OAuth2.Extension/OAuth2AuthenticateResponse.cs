using System;

namespace OAuth2.Extension
{
    /// <summary>
    /// Authentication response object.
    /// </summary>
    public class OAuth2AuthenticateResponse
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTime Expires { get; set; }
        public string State { get; set; }
    }
}
