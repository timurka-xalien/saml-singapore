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
            var ipdCone = new SamlIdentityProvider
            {
                Id = Guid.NewGuid(),
                EntityId = "http://cone-idp",
                Description = "Cone Identity Provider",
                RegisteredDomains =
                {
                    new EmailDomain
                    {
                        Id = Guid.NewGuid(),
                        Domain = "cone.com"
                    },
                    new EmailDomain
                    {
                        Id = Guid.NewGuid(),
                        Domain = "cone.net"
                    }
                }
            };

            var idpShib = new SamlIdentityProvider
            {
                Id = Guid.NewGuid(),
                EntityId = "https://shib-idp/",
                Description = "Shibboleth Identity Provider",
                RegisteredDomains =
                {
                    new EmailDomain
                    {
                        Id = Guid.NewGuid(),
                        Domain = "shib.com"
                    },
                    new EmailDomain
                    {
                        Id = Guid.NewGuid(),
                        Domain = "shibboleth.net"
                    }
                }
            };

            var ipdKentor = new SamlIdentityProvider
            {
                Id = Guid.NewGuid(),
                EntityId = "http://kentor-idp/Metadata",
                Description = "Kentor Identity Provider",
                RegisteredDomains =
                {
                    new EmailDomain
                    {
                        Id = Guid.NewGuid(),
                        Domain = "kentor.com"
                    },
                    new EmailDomain
                    {
                        Id = Guid.NewGuid(),
                        Domain = "kentorsome.net"
                    }
                }
            };

            _registeredProviders = new List<SamlIdentityProvider>()
            {
                ipdCone,
                idpShib,
                ipdKentor,
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