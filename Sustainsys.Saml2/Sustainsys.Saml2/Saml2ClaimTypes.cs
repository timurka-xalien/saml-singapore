﻿namespace Sustainsys.Saml2
{
    /// <summary>
    /// Claim type constants.
    /// </summary>
    public static class Saml2ClaimTypes
    {
        internal const string ClaimTypeNamespace = "http://Sustainsys.se/Saml2";

        /// <summary>
        /// Session index is set by the idp and is used to correlate sessions
        /// during single logout.
        /// </summary>
        public const string SessionIndex = ClaimTypeNamespace + "/SessionIndex";

        /// <summary>
        /// Original subject name identifier from the SAML2 idp, that should
        /// be logged out as part of a single logout scenario.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1726:UsePreferredTerms", MessageId = "Logout")]
        public const string LogoutNameIdentifier = ClaimTypeNamespace + "/LogoutNameIdentifier";
    }
}
