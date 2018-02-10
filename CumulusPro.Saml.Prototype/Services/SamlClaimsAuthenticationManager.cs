using CumulusPro.Saml.Prototype.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;

namespace CumulusPro.Saml.Prototype.Services
{
    /// <summary>
    /// Use this class to map attributes from different Identity Providers to the single format.
    /// We do not have here any info about which IdP exactly user was authenticated by so we need
    /// to guess by analyzing some user attributes
    /// </summary>
    public class SamlClaimsAuthenticationManager : ClaimsAuthenticationManager
    {
        private const string IdentityProviderClaimType =
            @"http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider";
        private const string ExternalSaml2SsoIdentityProvider = "External SAML2 SSO IdentityProvider";

        public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
        {
            var identity = (ClaimsIdentity)incomingPrincipal.Identity;

            identity.AddClaim(new Claim(nameof(AuthenticationType), AuthenticationType.Saml.ToString()));

            if (incomingPrincipal.FindFirst(IdentityProviderClaimType) == null)
            {
                identity.AddClaim(new Claim(IdentityProviderClaimType, ExternalSaml2SsoIdentityProvider));
            }
            //     var newPrincipal = new ClaimsPrincipal(incomingPrincipal);
            //    return newPrincipal;

            return incomingPrincipal;
        }
    }
}