using System;
using System.Collections.Generic;

namespace CumulusPro.Saml.Prototype.Models
{
    public class SamlIdentityProvider
    {
        public SamlIdentityProvider()
        {
            RegisteredDomains = new List<EmailDomain>();

            // Default configuration
            SignAuthnRequest = true;
            SingleLogoutSupported = true;
        }

        public Guid Id { get; set; }

        public string EntityId { get; set; }

        public string Description { get; set; }

        public bool SignAuthnRequest { get; set; }

        public string SingleSignOnUrl { get; set; }

        public string SingleLogoutUrl { get; set; }

        public string CertificateFile { get; set; }

        public bool SingleLogoutSupported { get; set; }

        public bool UseEmbeddedCertificate { get; set; }

        public List<EmailDomain> RegisteredDomains { get; set; }
    }
}