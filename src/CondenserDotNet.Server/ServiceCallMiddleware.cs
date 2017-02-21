﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using CondenserDotNet.Core;

namespace CondenserDotNet.Server
{
    public class ServiceCallMiddleware
    {
        private RequestDelegate _next;
        private ILogger _logger;
        private RoutingHost _routeData;

        public ServiceCallMiddleware(RequestDelegate next, ILoggerFactory loggerFactory, RoutingHost routeData)
        {
            _next = next;
            _logger = loggerFactory?.CreateLogger<RoutingMiddleware>();
            _routeData = routeData;
        }

        public async Task Invoke(HttpContext context)
        {
            var service = context.Features.Get<IService>();
            await service.CallService(context);
            await _next(context);
        }
    }
}