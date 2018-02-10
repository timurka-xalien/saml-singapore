using CumulusPro.Saml.Prototype.Models;
using CumulusPro.Saml.Prototype.Services.Services;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;

namespace CumulusPro.Saml.Prototype.Services
{
    public class AuthenticationService
    {
        private static Logger _logger = LogManager.GetCurrentClassLogger();

        private IAuthenticationManager _authenticationManager;
        private ApplicationUserManager _userManager;

        public AuthenticationService(IAuthenticationManager authenticationManager, ApplicationUserManager userManager)
        {
            _userManager = userManager;
            _authenticationManager = authenticationManager;
        }

        public bool Authenticate(
            AuthenticationType authenticationType, 
            string email, 
            string password,
            IDictionary<string, string> additionalClaims = null)
        {
            _logger.Log(LogLevel.Debug, $"SAML: AuthenticationService.Authenticate: Authenticate user {email}");

            var user = FindUser(_userManager, email, password);

            if (user != null)
            {
                var identity = _userManager.CreateIdentity(user, DefaultAuthenticationTypes.ApplicationCookie);

                // Save received attributes as claims
                InitializeUserClaims(authenticationType, email, additionalClaims, identity);

                // Sign in user
                _authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = true }, identity);

                return true;
            }

            return false;
        }

        private static void InitializeUserClaims(
            AuthenticationType authenticationType, 
            string email,
            IDictionary<string, string> additionalClaims, 
            ClaimsIdentity identity)
        {
            _logger.Log(LogLevel.Debug, $"SAML: AuthenticationService.InitializeUserClaims: Initialize claims of user {identity.Name}");

            identity.AddClaim(new Claim(nameof(AuthenticationType), authenticationType.ToString()));

            if (additionalClaims != null)
            {
                identity.AddClaims(additionalClaims.Select(attr => new Claim(attr.Key, attr.Value)));
            }

            // Check if user email is present in claims or attributes under a standard claim type
            if (!identity.HasClaim(c => c.Type == ClaimTypes.Email))
            {
                // Add email claim under a standard claim type
                identity.AddClaim(new Claim(ClaimTypes.Email, email));
            }

            _logger.Log(LogLevel.Debug, $"SAML: AuthenticationService.InitializeUserClaims: Initialized claims of user {identity.Name}:\r\n" +
                Utils.SerializeToJson(identity.Claims.Select(c => new { c.Type, c.Value })));
        }

        public ApplicationUser FindUser(ApplicationUserManager userManager, string userEmail, string password = null)
        {
            var user = userManager.FindByEmail(userEmail);

            if (password == null)
            {
                return user;
            }

            var passwordIsCorrect = userManager.CheckPassword(user, password);

            if (passwordIsCorrect)
            {
                return user;
            }

            return null;
        }
    }
}