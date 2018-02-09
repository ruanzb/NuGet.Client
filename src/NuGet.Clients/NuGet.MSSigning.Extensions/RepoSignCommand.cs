// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using NuGet.CommandLine;
using NuGet.Commands;
using NuGet.Common;
using NuGet.Packaging.Signing;

namespace NuGet.MSSigning.Extensions
{
    [Command(typeof(NuGetMSSignCommand), "reposign", "RepoSignCommandDescription",
       MinArgs = 1,
       MaxArgs = 1,
       UsageSummaryResourceName = "RepoSignCommandUsageSummary",
       UsageExampleResourceName = "RepoSignCommandUsageExamples",
       UsageDescriptionResourceName = "RepoSignCommandUsageDescription")]
    public class RepoSignCommand : MSSignCommand
    {
        private readonly List<string> _owners = new List<string>();

        [Option(typeof(NuGetMSSignCommand), "RepoSignCommandOwnersDescription")]
        public IList<string> Owners
        {
            get { return _owners; }
        }

        [Option(typeof(NuGetMSSignCommand), "RepoSignCommandV3ServiceIndexUrlDescription")]
        public string V3ServiceIndexUrl { get; set; }

        public override async Task ExecuteCommandAsync()
        {
            var signRequest = GetSignRequest();
            var packages = GetPackages();
            var signCommandRunner = new SignCommandRunner();
            var result = await signCommandRunner.ExecuteCommandAsync(
                packages, signRequest, Timestamper, Console, OutputDirectory, Overwrite, CancellationToken.None);


            if (result != 0)
            {
                throw new ExitCodeException(exitCode: result);
            }
        }

        private RepositorySignPackageRequest GetSignRequest()
        {
            ValidatePackagePath();
            WarnIfNoTimestamper(Console);
            ValidateCertificateInputs();
            EnsureOutputDirectory();

            var signingSpec = SigningSpecifications.V1;
            var signatureHashAlgorithm = ValidateAndParseHashAlgorithm(HashAlgorithm, nameof(HashAlgorithm), signingSpec);
            var timestampHashAlgorithm = ValidateAndParseHashAlgorithm(TimestampHashAlgorithm, nameof(TimestampHashAlgorithm), signingSpec);
            var certCollection = GetCertificateCollection();
            var certificate = GetCertificate(certCollection);
            var privateKey = GetPrivateKey(certificate);

            // Set signaturePlacement to countersignature for now, we should let signCommandRunner to decide primary or countersignature.
            var request = new RepositorySignPackageRequest(
                certificate,
                signatureHashAlgorithm,
                timestampHashAlgorithm,
                SignaturePlacement.Countersignature,
                UriUtility.CreateSourceUri(V3ServiceIndexUrl, UriKind.Absolute),
                new ReadOnlyCollection<string>(Owners));

            request.PrivateKey = privateKey;
            request.AdditionalCertificates.AddRange(certCollection);

            return request;
        }
    }
}
