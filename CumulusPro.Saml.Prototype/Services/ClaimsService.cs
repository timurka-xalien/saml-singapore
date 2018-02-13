using CumulusPro.Saml.Prototype.Models;
using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;

namespace CumulusPro.Saml.Prototype.Services
{
    public class ClaimsService
    {
        private const string DefaultUserName = "Anonymous";
        private const string IdentityProviderClaimType =
            @"http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider";

        public void AddPrincipalExtraClaims(ClaimsPrincipal incomingPrincipal)
        {
            var identity = (ClaimsIdentity)incomingPrincipal.Identity;

            AddAuthenticationTypeClaim(identity);
            AddIdentityProviderClaim(identity);
            AddNameClaim(identity);
        }

        private static void AddAuthenticationTypeClaim(ClaimsIdentity identity)
        {
            // Add claim AuthenticationType to be able to determine how user was authenticated 
            identity.AddClaim(new Claim(nameof(AuthenticationType), AuthenticationType.Saml.ToString()));
        }

        private static void AddIdentityProviderClaim(ClaimsIdentity identity)
        {
            // IdP EntityId is specified as Issuer of all claims, save it as distinct IdentityProvider claim for clarity. 
            // Besides, we do need this claim either way as ASP.NET MVC uses it to generate AntiForgeryToken
            if (identity.FindFirst(IdentityProviderClaimType) == null)
            {
                var idpEntityId = identity.Claims.First().Issuer;
                identity.AddClaim(new Claim(IdentityProviderClaimType, idpEntityId));
            }
        }

        private void AddNameClaim(ClaimsIdentity identity)
        {
            var (firstName, lastName, userName) = GetUserNames(identity);

            // Add Name claim if it doesn't exist 
            if (identity.FindFirst(ClaimTypes.Name) == null)
            {
                identity.AddClaim(new Claim(ClaimTypes.Name, userName));
            }
        }

        public ApplicationUser CreateApplicationUserFromPrincipal(ClaimsPrincipal principal)
        {
            var email = principal.FindFirst(ClaimTypes.Email).Value;
            var id = GetUserId(principal, email);
            var (firstName, lastName, userName) = GetUserNames((ClaimsIdentity)principal.Identity);

            return new ApplicationUser
            {
                Id = id,
                UserName = userName,
                Email = email,
                // Add these properties if you need them
                //FirstName = firstName,
                //LastName = lastName
            };
        }

        private string GetUserId(ClaimsPrincipal principal, string email)
        {
            // ClaimTypes.NameIdentifier is used to represent user ID however different SAML IdPs may pass
            // - email
            // - user name
            // or not pass it at all
            // Update logic below according to your needs
            var id = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (id == null || id == email)
            {
                // Okta passes email as id, other IdPs may not pass Id at all
                id = Guid.NewGuid().ToString();
            }

            return id;
        }

        private (string, string, string) GetUserNames(ClaimsIdentity identity)
        {
            // SAML IdP may not pass firstName, lastName, userName
            // Update logic below according to your needs
            var firstName = identity.FindFirst(ClaimTypes.GivenName)?.Value;
            var lastName = identity.FindFirst(ClaimTypes.Surname)?.Value;
            var userName = identity.FindFirst(ClaimTypes.Name)?.Value ??
                (firstName != null || lastName != null
                    ? firstName + " " + lastName
                    : DefaultUserName);

            return (firstName, lastName, userName);
        }

        public string GetIdentityProviderEntityId(IPrincipal principal)
        {
            return ((ClaimsIdentity)principal.Identity).FindFirst(IdentityProviderClaimType)?.Value;
        }
    }
}