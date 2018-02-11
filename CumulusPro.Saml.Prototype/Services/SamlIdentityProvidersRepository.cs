using CumulusPro.Saml.Prototype.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CumulusPro.Saml.Prototype.Services
{
    public class SamlIdentityProvidersRepository
    {
        private static readonly SamlIdentityProvidersRepository _instance = new SamlIdentityProvidersRepository();
        private IEnumerable<SamlIdentityProvider> _registeredProviders;

        private SamlIdentityProvidersRepository()
        {
            CreateDefaultConfiguration();
        }

        public void CreateDefaultConfiguration()
        {
            var idpOkta = new SamlIdentityProvider
            {
                Id = Guid.NewGuid(),
                EntityId = "http://www.okta.com/exkok2qjhccpG6A4v2p6",
                Description = "Okta Identity Provider",
                LogoUrl = "https://www.okta.com/sites/all/themes/Okta/images/blog/Logos/Okta_Logo_BrightBlue_Medium.png",
                RegisteredDomains =
                {
                    new EmailDomain
                    {
                        Id = Guid.NewGuid(),
                        Domain = "okta.com"
                    },
                    new EmailDomain
                    {
                        Id = Guid.NewGuid(),
                        Domain = "adidas.com"
                    }
                }
            };

            var ipdSustainsys = new SamlIdentityProvider
            {
                Id = Guid.NewGuid(),
                EntityId = "https://sustainsys.saml2.stubidp/Metadata",
                Description = "Sustainsys Identity Provider",
                LogoUrl = "https://stubidp.sustainsys.com/content/sustainsys.png",
                RegisteredDomains =
                {
                    new EmailDomain
                    {
                        Id = Guid.NewGuid(),
                        Domain = "sustainsys.com"
                    },
                    new EmailDomain
                    {
                        Id = Guid.NewGuid(),
                        Domain = "sustain.net"
                    }
                }
            };

            _registeredProviders = new List<SamlIdentityProvider>()
            {
                idpOkta,
                ipdSustainsys,
            };
        }

        public IEnumerable<SamlIdentityProvider> GetRegisteredIdentityProviders()
        {
            // Here you need to implement some code pulling information about Identity Providers from some source
            // like DB or config
            return _registeredProviders;
        }

        private IEnumerable<string> GetRegisteredEmailDomains()
        {
            return GetRegisteredIdentityProviders()
                .SelectMany(idp => idp.RegisteredDomains.Select(d => d.Domain));
        }

        public bool IsSamlAuthenticationRequired(string emailDomain)
        {
            return GetRegisteredEmailDomains().Contains(emailDomain);
        }

        public string GetIdentityProviderEntityId(string domain)
        {
            return GetRegisteredIdentityProviders()
                .Where(idp => idp.RegisteredDomains.Any(d => d.Domain == domain))
                .Select(idp => idp.EntityId)
                .SingleOrDefault();
        }

        public static SamlIdentityProvidersRepository GetInstance()
        {
            return _instance;
        }
    }
}