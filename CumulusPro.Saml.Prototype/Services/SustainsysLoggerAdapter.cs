using NLog;
using Sustainsys.Saml2;
using System;

namespace CumulusPro.Saml.Prototype.Services
{
    public class SustainsysLoggerAdapter : ILoggerAdapter
    {
        private static Logger _logger = LogManager.GetLogger("Sustainsys library");

        public void WriteError(string message, Exception ex)
        {
            _logger.Error(ex, "SAML: " + message);
        }

        public void WriteInformation(string message)
        {
            _logger.Log(LogLevel.Debug, "SAML: " + message);
        }

        public void WriteVerbose(string message)
        {
            _logger.Log(LogLevel.Trace, "SAML: " + message);
        }
    }
}