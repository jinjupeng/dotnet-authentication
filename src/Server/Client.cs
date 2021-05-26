using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Server
{
    public class Client
    {
        public string client_id { get; set; }
        public string client_secret { get; set; }
        public string[] redirect_uris { get; set; }
        public string scope { get; set; }
        public string logo_uri { get; set; }
        public string client_name { get; set; }
    }
}
