﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using CondenserDotNet.Core.Routing;
using CondenserDotNet.Server;
using CondenserDotNet.Server.RoutingTrie;
using CondenserDotNet.Server.Websockets;
using CondenserDotNet.Server.WindowsAuthentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;

namespace PocWebsocketsSupport
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCondenser();
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseWindowsAuthentication();
            app.Use(async (context, middleware) =>
            {
                var user = await context.Authentication.AuthenticateAsync("NTLM");
                if(user == null)
                {
                    await context.Authentication.ChallengeAsync();
                }
                await middleware.Invoke();
                return;
            });
            //app.UseCondenser();
        }
    }
}