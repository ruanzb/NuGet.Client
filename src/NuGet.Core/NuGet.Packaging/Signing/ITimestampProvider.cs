// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;

namespace NuGet.Packaging.Signing
{
    public interface ITimestampProvider
    {
        // Sign and timestamp a file.
        Task<Signature> CreateSignatureAsync(Signature signature, ILogger logger, CancellationToken token);
    }
}
