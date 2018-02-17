using CumulusPro.Saml.Prototype.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CumulusPro.Saml.Prototype.Services
{
    /// <summary>
    /// This is a reporitory of SamlIdentityProvider objects which contain additional settings of SAML IdentityProviders.
    /// These settings are required solely by our application logic and are not used by Sustainsys.
    /// I just hardcoded providers settings here for brevity. You need to load them from config file or database
    /// </summary>
    public class SamlIdentityProvidersRepository
    {
        private IEnumerable<SamlIdentityProvider> _registeredProviders;

        public SamlIdentityProvidersRepository()
        {
            PopulateRegisteredProviders();
        }

        public void PopulateRegisteredProviders()
        {
            var idpOkta = new SamlIdentityProvider
            {
                Id = Guid.NewGuid(),
                EntityId = "http://www.okta.com/exkok2qjhccpG6A4v2p6",
                Description = "Okta Identity Provider",
                LogoUrl = "https://www.okta.com/sites/all/themes/Okta/images/blog/Logos/Okta_Logo_BrightBlue_Medium.png",
                SilentLogout = true,
                RedirectOnLogoutUrl = "https://mailsamlpoc.okta.com/app/UserHome",
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
                EntityId = "https://stubidp.sustainsys.com/Metadata",
                Description = "Sustainsys Identity Provider",
                LogoUrl = "https://stubidp.sustainsys.com/content/sustainsys.png",
                SilentLogout = false,
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

            var ipdOnelogin = new SamlIdentityProvider
            {
                Id = Guid.NewGuid(),
                EntityId = "https://app.onelogin.com/saml/metadata/754212",
                Description = "Onelogin Identity Provider",
                LogoUrl = "https://www.onelogin.com/assets/img/new-logo-onelogin.svg",
                SilentLogout = true,
                RedirectOnLogoutUrl = "https://wrety-dev.onelogin.com/portal/",
                ForcedLogoutUrl = "https://wrety-dev.onelogin.com/logout",
                RegisteredDomains =
                {
                    new EmailDomain
                    {
                        Id = Guid.NewGuid(),
                        Domain = "onelogin.com"
                    }
                }
            };

            _registeredProviders = new List<SamlIdentityProvider>()
            {
                idpOkta,
                ipdSustainsys,
                ipdOnelogin
            };
        }

        public IEnumerable<SamlIdentityProvider> GetRegisteredIdentityProviders()
        {
            // Here you need to implement some code pulling information about Identity Providers from some source
            // like DB or config
            return _registeredProviders;
        }

        /// <summary>
        /// Get all supported email domains
        /// </summary>
        private IEnumerable<string> GetRegisteredEmailDomains()
        {
            return GetRegisteredIdentityProviders()
                .SelectMany(idp => idp.RegisteredDomains.Select(d => d.Domain));
        }

        /// <summary>
        /// Check if user having email at specified emailDomain have to be authenticated using SAML SSO
        /// </summary>
        public bool IsSamlAuthenticationRequired(string emailDomain)
        {
            return GetRegisteredEmailDomains().Contains(emailDomain);
        }

        public string GetIdentityProviderEntityIdByEmailDomain(string emailDomain)
        {
            return GetRegisteredIdentityProviders()
                .Where(idp => idp.RegisteredDomains.Any(d => d.Domain == emailDomain))
                .Select(idp => idp.EntityId)
                .SingleOrDefault();
        }

        public SamlIdentityProvider GetIdentityProviderByEntityId(string idpEntityId)
        {
            return GetRegisteredIdentityProviders().Single(idP => idP.EntityId == idpEntityId);
        }

        /// <summary>
        /// Returns IdentityProvider which Description contains passed search term (Case Insensitive)
        /// </summary>
        public SamlIdentityProvider FindIdentityProviderBySearchTerm(string searchTerm)
        {
            return GetRegisteredIdentityProviders()
                .SingleOrDefault(idP => idP.Description.ToLower().Contains(searchTerm.ToLower()));
        }
    }
}