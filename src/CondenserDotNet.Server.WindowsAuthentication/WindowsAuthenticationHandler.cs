using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features.Authentication;

namespace CondenserDotNet.Server.WindowsAuthentication
{
    public class WindowsAuthenticationHandler : IAuthenticationHandler
    {
        private readonly HttpContext _context;
        private readonly WindowsIdentity _user;
        private static readonly Task _completedTask = Task.FromResult(0);
        private static readonly string[] _supportedTokens = new[] { "NTLM", "Negotiate" };
        private const string WWWAuthenticateHeader = "WWW-Authenticate";

        public WindowsAuthenticationHandler(HttpContext context)
        {
            _context = context;
            _user = context.Features.Get<WindowsAuthFeature>().Identity;
        }

        public IAuthenticationHandler PriorHandler { get; set; }

        public Task AuthenticateAsync(AuthenticateContext context)
        {
            if (HandlesScheme(context.AuthenticationScheme))
            {
                if (_user == null)
                {
                    context.NotAuthenticated();
                }
                else
                {
                    context.Authenticated(new ClaimsPrincipal(_user), null, null);
                }
            }
            if (PriorHandler != null)
            {
                return PriorHandler.AuthenticateAsync(context);
            }
            return _completedTask;
        }

        public Task ChallengeAsync(ChallengeContext context)
        {
            if (!context.Accepted && HandlesScheme(context.AuthenticationScheme))
            {
                switch (context.Behavior)
                {
                    case ChallengeBehavior.Automatic:
                        if (_user == null)
                        {
                            goto case ChallengeBehavior.Unauthorized;
                        }
                        else
                        {
                            goto case ChallengeBehavior.Forbidden;
                        }
                    case ChallengeBehavior.Forbidden:
                        _context.Response.StatusCode = 403;
                        break;
                    case ChallengeBehavior.Unauthorized:
                        _context.Response.Headers.Add(WWWAuthenticateHeader, _supportedTokens);
                        _context.Response.StatusCode = 401;
                        break;
                }
                context.Accept();
            }
            if (PriorHandler != null)
            {
                return PriorHandler.ChallengeAsync(context);
            }
            return _completedTask;
        }

        private bool HandlesScheme(string authScheme)
        {
            if (string.CompareOrdinal(authScheme, "NTLM") == 0 || string.CompareOrdinal(authScheme, "Negotiate") == 0 || string.CompareOrdinal(authScheme, "Automatic") == 0)
            {
                return true;
            }
            return false;
        }

        public void GetDescriptions(DescribeSchemesContext context)
        {
            throw new NotImplementedException();
        }

        public Task SignInAsync(SignInContext context)
        {
            throw new NotImplementedException();
        }

        public Task SignOutAsync(SignOutContext context)
        {
            throw new NotImplementedException();
        }
    }
}
