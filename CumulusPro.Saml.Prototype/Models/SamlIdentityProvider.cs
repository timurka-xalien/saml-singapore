using System;
using System.Collections.Generic;

namespace CumulusPro.Saml.Prototype.Models
{
    public class SamlIdentityProvider
    {
        public SamlIdentityProvider()
        {
            RegisteredDomains = new List<EmailDomain>();
        }

        public Guid Id { get; set; }

        public string EntityId { get; set; }

        public string Description { get; set; }

        public string RedirectOnLogoutUrl { get; set; }

        public bool SilentLogout { get; set; }

        public string LogoUrl { get; set; }

        public List<EmailDomain> RegisteredDomains { get; set; }
    }
}