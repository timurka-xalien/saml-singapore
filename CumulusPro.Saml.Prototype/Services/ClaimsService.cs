using CumulusPro.Saml.Prototype.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;

namespace CumulusPro.Saml.Prototype.Services
{
    public class ClaimsService
    {
        private const string DefaultUserName = "Anonymous";

        // Onelogin uses non-standard claim types
        private const string OneloginEmailClaimType = "User.email";
        private const string OneloginFirstNameClaimType = "User.FirstName";
        private const string OneloginLastNameClaimType = "User.LastName";
        private const string OneloginRoleClaimType = "memberOf";

        private const string IdentityProviderClaimType =
            @"http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider";

        public void AddPrincipalExtraClaims(ClaimsPrincipal incomingPrincipal)
        {
            var identity = (ClaimsIdentity)incomingPrincipal.Identity;

            AddAuthenticationTypeClaim(identity);
            AddIdentityProviderClaim(identity);

            // IdentityProvider may use non-standard claim/attribute types. Add standard claim types in such case
            // Code below does not delete original non-standard claims added from SAML attributes. 
            // Change according to your needs
            EnsureStandardNamesClamesDefined(identity);
            EnsureStandardEmailClaimDefined(identity);
            EnsureStandardRolesClaimsDefined(identity);
        }

        private void AddAuthenticationTypeClaim(ClaimsIdentity identity)
        {
            // Add claim AuthenticationType to be able to determine how user was authenticated 
            identity.AddClaim(new Claim(nameof(AuthenticationType), AuthenticationType.Saml.ToString()));
        }

        private void AddIdentityProviderClaim(ClaimsIdentity identity)
        {
            // IdP EntityId is specified as Issuer of all claims, save it as distinct IdentityProvider claim for clarity. 
            // Besides, we do need this claim either way as ASP.NET MVC uses it to generate AntiForgeryToken
            if (identity.FindFirst(IdentityProviderClaimType) == null)
            {
                var idpEntityId = identity.Claims.First().Issuer;
                identity.AddClaim(new Claim(IdentityProviderClaimType, idpEntityId));
            }
        }

        private void EnsureStandardNamesClamesDefined(ClaimsIdentity identity)
        {
            var (firstName, lastName, userName) = GetUserNames(identity);

            // Add standard Name claim if it is not defined
            if (identity.FindFirst(ClaimTypes.Name) == null && userName != null)
            {
                identity.AddClaim(new Claim(ClaimTypes.Name, userName));
            }

            // Add standard FirstName claim if it is not defined
            if (identity.FindFirst(ClaimTypes.GivenName) == null && firstName != null)
            {
                identity.AddClaim(new Claim(ClaimTypes.GivenName, firstName));
            }

            // Add standard LastName claim if it is not defined
            if (identity.FindFirst(ClaimTypes.Surname) == null && lastName != null)
            {
                identity.AddClaim(new Claim(ClaimTypes.Surname, lastName));
            }
        }

        private void EnsureStandardEmailClaimDefined(ClaimsIdentity identity)
        {
            var email = GetEmail(identity);

            // Add standard Email claim if it is not defined
            if (identity.FindFirst(ClaimTypes.Email) == null)
            {
                identity.AddClaim(new Claim(ClaimTypes.Email, email));
            }
        }

        private void EnsureStandardRolesClaimsDefined(ClaimsIdentity identity)
        {
            var multipleRolesClaim = 
                identity
                    .FindAll(ClaimTypes.Role)
                    .Where(claim => claim.Value.Contains(";"))
                    .SingleOrDefault();

            // Add standard Role claim if it is not defined
            if (identity.FindFirst(ClaimTypes.Role) == null || multipleRolesClaim != null)
            {
                var roles = GetRoles(identity);

                if (multipleRolesClaim != null)
                {
                    identity.RemoveClaim(multipleRolesClaim);
                }

                identity.AddClaims(roles.Select(r => new Claim(ClaimTypes.Role, r)));
            }
        }

        public ApplicationUser CreateApplicationUserFromPrincipal(ClaimsPrincipal principal)
        {
            var identity = (ClaimsIdentity)principal.Identity;

            var email = GetEmail(identity);
            var id = GetUserId(principal, email);
            var (firstName, lastName, userName) = GetUserNames(identity);

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

        public string GetEmail(ClaimsIdentity identity)
        {
            // SAML IdP may pass email in the attributes with non-standard name
            // Update logic below according to your needs

            var email = identity.FindFirst(ClaimTypes.Email)?.Value 
                ?? identity.FindFirst(OneloginEmailClaimType)?.Value;

            if (email != null)
            {
                return email;
            }

            var name = identity.FindFirst(ClaimTypes.Name)?.Value;

            if (name?.Contains("@") == true)
            {
                return name;
            }

            throw new Exception("Identity Provider haven't passed email attribute. Please configure Identity Provider to pass user email in SAML assertion.");
        }

        private IEnumerable<string> GetRoles(ClaimsIdentity identity)
        {
            // SAML IdP may pass roles/groups in the attributes with non-standard name
            // Update logic below according to your needs
            // Use another role/group claim type if ClaimTypes.Role doesn't fit your needs

            // Get standard Role claims first
            return identity.FindAll(ClaimTypes.Role).Concat(identity.FindAll(OneloginRoleClaimType))
                   // Get OneLogin claims if any (OneLogin role claim contains list of roles separated by ;)
                   // Standard role claim also may contain multiple roles separated by ;)
                   .SelectMany(olrc => olrc.Value.Split(';'))
                   .Distinct();
        }

        private string GetUserId(ClaimsPrincipal principal, string email)
        {
            // ClaimTypes.NameIdentifier is used to represent user ID however different SAML IdPs may pass
            // - email
            // - user name
            // - actual id
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
            // or pass it in the attributes with non-standard names
            // Update logic below according to your needs

            var firstName = identity.FindFirst(ClaimTypes.GivenName)?.Value 
                ?? identity.FindFirst(OneloginFirstNameClaimType)?.Value;

            var lastName = identity.FindFirst(ClaimTypes.Surname)?.Value
                ?? identity.FindFirst(OneloginLastNameClaimType)?.Value;

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