using System;
using System.Collections.Generic;

namespace CumulusPro.Saml.Prototype.Models
{
    public class SamlIdentityProvider
    {
        public SamlIdentityProvider()
        {
            RegisteredDomains = new List<EmailDomain>();

            SingleLogoutSupported = true;
        }

        public Guid Id { get; set; }

        public string EntityId { get; set; }

        public string Description { get; set; }

        public bool SingleLogoutSupported { get; set; }

        public string LogoUrl { get; set; }

        public List<EmailDomain> RegisteredDomains { get; set; }
    }
}