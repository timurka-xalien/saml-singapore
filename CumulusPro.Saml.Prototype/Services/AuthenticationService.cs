using CumulusPro.Saml.Prototype.Models;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using NLog;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace CumulusPro.Saml.Prototype.Services
{
    public class AuthenticationService
    {
        private ClaimsService _claimsService;
        private static Logger _logger = LogManager.GetCurrentClassLogger();

        private IAuthenticationManager _authenticationManager;
        private ApplicationUserManager _userManager;

        public AuthenticationService(IAuthenticationManager authenticationManager, ApplicationUserManager userManager)
        {
            _userManager = userManager;
            _authenticationManager = authenticationManager;
            _claimsService = new ClaimsService();
        }

        public bool AuthenticateLocal(string email, string password)
        {
            _logger.Log(LogLevel.Debug, $"SAML: AuthenticationService.Authenticate: Authenticate user {email}");

            var user = FindUser(_userManager, email, password);

            if (user != null)
            {
                var identity = _userManager.CreateIdentity(user, DefaultAuthenticationTypes.ApplicationCookie);

                identity.AddClaim(new Claim(nameof(AuthenticationType), AuthenticationType.Local.ToString()));

                // Sign in user
                _authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = true }, identity);

                return true;
            }

            return false;
        }

        public void RegisterNewUserIfNeeded(ClaimsPrincipal principal)
        {
            // Require email to be passed by SAML IdP
            // Update logic below according to your needs
            var email = principal.FindFirst(ClaimTypes.Email)?.Value;

            if (email == null)
            {
                throw new InvalidOperationException("Cannot register user. Email is missing.");
            }

            var existingUser = FindUser(_userManager, email, email);

            if (existingUser != null)
            {
                return;
            }

            _logger.Log(LogLevel.Debug, $"SAML: AuthenticationService.RegisterNewUserIfNeeded: Register user {email}");

            var newUser = _claimsService.CreateApplicationUserFromPrincipal(principal);

            // Use fake password as SAML authenticated user won't enter it on our web site and we cannot leave it empty
            var result = _userManager.Create(newUser, email);

            if (!result.Succeeded)
            {
                var errors = string.Join("\r\n", result.Errors);

                _logger.Log(LogLevel.Error, $"AuthenticationService.RegisterNewUserIfNeeded: " +
                    $"Error while registering user: {errors}");

                throw new Exception($"Failed to register user: {errors}");
            }
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
                //InitializeUserClaims(authenticationType, email, additionalClaims, identity);

                // Sign in user
                _authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = true }, identity);

                return true;
            }

            return false;
        }

        //private static void InitializeUserClaims(
        //    AuthenticationType authenticationType, 
        //    string email,
        //    IDictionary<string, string> additionalClaims, 
        //    ClaimsIdentity identity)
        //{
        //    _logger.Log(LogLevel.Debug, $"SAML: AuthenticationService.InitializeUserClaims: Initialize claims of user {identity.Name}");

        //    identity.AddClaim(new Claim(nameof(AuthenticationType), authenticationType.ToString()));

        //    if (additionalClaims != null)
        //    {
        //        identity.AddClaims(additionalClaims.Select(attr => new Claim(attr.Key, attr.Value)));
        //    }

        //    // Check if user email is present in claims or attributes under a standard claim type
        //    if (!identity.HasClaim(c => c.Type == ClaimTypes.Email))
        //    {
        //        // Add email claim under a standard claim type
        //        identity.AddClaim(new Claim(ClaimTypes.Email, email));
        //    }

        //    _logger.Log(LogLevel.Debug, $"SAML: AuthenticationService.InitializeUserClaims: Initialized claims of user {identity.Name}:\r\n" +
        //        Utils.SerializeToJson(identity.Claims.Select(c => new { c.Type, c.Value })));
        //}

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