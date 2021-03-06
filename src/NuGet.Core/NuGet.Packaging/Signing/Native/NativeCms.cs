// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace NuGet.Packaging.Signing
{
    internal class NativeCms : IDisposable
    {
        private SafeCryptMsgHandle _handle;
        private bool _detached;

        private NativeCms(SafeCryptMsgHandle handle, bool detached)
        {
            _handle = handle;
            _detached = detached;
        }

        internal byte[] GetPrimarySignatureSignatureValue()
        {
            return GetByteArrayAttribute(CMSG_GETPARAM_TYPE.CMSG_ENCRYPTED_DIGEST, index: 0);
        }

        private byte[] GetByteArrayAttribute(CMSG_GETPARAM_TYPE param, uint index)
        {
            uint valueLength = 0;

            NativeUtilities.ThrowIfFailed(NativeMethods.CryptMsgGetParam(
                _handle,
                param,
                index,
                null,
                ref valueLength));

            var data = new byte[(int)valueLength];

            NativeUtilities.ThrowIfFailed(NativeMethods.CryptMsgGetParam(
                _handle,
                param,
                index,
                data,
                ref valueLength));

            return data;
        }

        internal byte[] GetRepositoryCountersignatureSignatureValue()
        {
            var repositoryCountersignature = GetRepositoryCountersignature();

            if (repositoryCountersignature == null)
            {
                return null;
            }

            var countersignatureSignatureValue = new byte[repositoryCountersignature.Value.EncryptedHash.cbData];

            Marshal.Copy(
                repositoryCountersignature.Value.EncryptedHash.pbData,
                countersignatureSignatureValue,
                startIndex: 0,
                length: countersignatureSignatureValue.Length);

            return countersignatureSignatureValue;
        }

        private unsafe CMSG_SIGNER_INFO? GetRepositoryCountersignature()
        {
            const uint primarySignerInfoIndex = 0;
            uint unsignedAttributeCount = 0;
            var pointer = IntPtr.Zero;

            NativeUtilities.ThrowIfFailed(NativeMethods.CryptMsgGetParam(
                _handle,
                CMSG_GETPARAM_TYPE.CMSG_SIGNER_UNAUTH_ATTR_PARAM,
                primarySignerInfoIndex,
                pointer,
                ref unsignedAttributeCount));

            if (unsignedAttributeCount == 0)
            {
                return null;
            }

            using (var retainer = new HeapBlockRetainer())
            {
                pointer = retainer.Alloc((int)unsignedAttributeCount);

                NativeUtilities.ThrowIfFailed(NativeMethods.CryptMsgGetParam(
                    _handle,
                    CMSG_GETPARAM_TYPE.CMSG_SIGNER_UNAUTH_ATTR_PARAM,
                    primarySignerInfoIndex,
                    pointer,
                    ref unsignedAttributeCount));

                var unsignedAttributes = Marshal.PtrToStructure<CRYPT_ATTRIBUTES>(pointer);

                for (var i = 0; i < unsignedAttributes.cAttr; ++i)
                {
                    var attributePointer = new IntPtr(
                        (long)unsignedAttributes.rgAttr + (i * Marshal.SizeOf<CRYPT_ATTRIBUTE_STRING>()));
                    var attribute = Marshal.PtrToStructure<CRYPT_ATTRIBUTE_STRING>(attributePointer);

                    if (!string.Equals(attribute.pszObjId, Oids.Countersignature, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    for (var j = 0; j < attribute.cValue; ++j)
                    {
                        var attributeValuePointer = new IntPtr(
                            (long)attribute.rgValue + (j * Marshal.SizeOf<CRYPT_INTEGER_BLOB>()));
                        var attributeValue = Marshal.PtrToStructure<CRYPT_INTEGER_BLOB>(attributeValuePointer);
                        uint cbSignerInfo = 0;

                        NativeUtilities.ThrowIfFailed(NativeMethods.CryptDecodeObject(
                            NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                            new IntPtr(NativeMethods.PKCS7_SIGNER_INFO),
                            attributeValue.pbData,
                            attributeValue.cbData,
                            dwFlags: 0,
                            pvStructInfo: IntPtr.Zero,
                            pcbStructInfo: new IntPtr(&cbSignerInfo)));

                        var counterSignerInfoPointer = retainer.Alloc((int)cbSignerInfo);

                        NativeUtilities.ThrowIfFailed(NativeMethods.CryptDecodeObject(
                            NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                            new IntPtr(NativeMethods.PKCS7_SIGNER_INFO),
                            attributeValue.pbData,
                            attributeValue.cbData,
                            dwFlags: 0,
                            pvStructInfo: counterSignerInfoPointer,
                            pcbStructInfo: new IntPtr(&cbSignerInfo)));

                        var counterSignerInfo = Marshal.PtrToStructure<CMSG_SIGNER_INFO>(counterSignerInfoPointer);

                        if (IsRepositoryCounterSignerInfo(counterSignerInfo))
                        {
                            return counterSignerInfo;
                        }
                    }
                }
            }

            return null;
        }

        private static bool IsRepositoryCounterSignerInfo(CMSG_SIGNER_INFO counterSignerInfo)
        {
            var signedAttributes = counterSignerInfo.AuthAttrs;

            for (var i = 0; i < signedAttributes.cAttr; ++i)
            {
                var signedAttributePointer = new IntPtr(
                    (long)signedAttributes.rgAttr + (i * Marshal.SizeOf<CRYPT_ATTRIBUTE_STRING>()));
                var signedAttribute = Marshal.PtrToStructure<CRYPT_ATTRIBUTE_STRING>(signedAttributePointer);

                if (string.Equals(signedAttribute.pszObjId, Oids.CommitmentTypeIndication, StringComparison.Ordinal) &&
                    IsRepositoryCounterSignerInfo(signedAttribute))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsRepositoryCounterSignerInfo(CRYPT_ATTRIBUTE_STRING commitmentTypeIndicationAttribute)
        {
            for (var i = 0; i < commitmentTypeIndicationAttribute.cValue; ++i)
            {
                var attributeValuePointer = new IntPtr(
                    (long)commitmentTypeIndicationAttribute.rgValue + (i * Marshal.SizeOf<CRYPT_INTEGER_BLOB>()));
                var attributeValue = Marshal.PtrToStructure<CRYPT_INTEGER_BLOB>(attributeValuePointer);
                var bytes = new byte[attributeValue.cbData];

                Marshal.Copy(attributeValue.pbData, bytes, startIndex: 0, length: bytes.Length);

                var commitmentTypeIndication = CommitmentTypeIndication.Read(bytes);

                if (string.Equals(
                    commitmentTypeIndication.CommitmentTypeId.Value,
                    Oids.CommitmentTypeIdentifierProofOfReceipt,
                    StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }

        internal static NativeCms Decode(byte[] input, bool detached)
        {
            var handle = NativeMethods.CryptMsgOpenToDecode(
                CMSG_ENCODING.Any,
                detached ? CMSG_OPENTODECODE_FLAGS.CMSG_DETACHED_FLAG : CMSG_OPENTODECODE_FLAGS.None,
                0u,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }

            if (!NativeMethods.CryptMsgUpdate(handle, input, (uint)input.Length, fFinal: true))
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }

            return new NativeCms(handle, detached);
        }

        internal void AddCertificates(IEnumerable<byte[]> encodedCertificates)
        {
            foreach (var cert in encodedCertificates)
            {
                using (var hb = new HeapBlockRetainer())
                {
                    var unmanagedCert = hb.Alloc(cert.Length);
                    Marshal.Copy(cert, 0, unmanagedCert, cert.Length);
                    var blob = new CRYPT_INTEGER_BLOB()
                    {
                        cbData = (uint)cert.Length,
                        pbData = unmanagedCert
                    };

                    var unmanagedBlob = hb.Alloc(Marshal.SizeOf(blob));
                    Marshal.StructureToPtr(blob, unmanagedBlob, fDeleteOld: false);

                    if (!NativeMethods.CryptMsgControl(
                        _handle,
                        dwFlags: 0,
                        dwCtrlType: CMSG_CONTROL_TYPE.CMSG_CTRL_ADD_CERT,
                        pvCtrlPara: unmanagedBlob))
                    {
                        Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                    }
                }
            }
        }

        internal unsafe void AddTimestamp(byte[] timeStampCms)
        {
            using (var hb = new HeapBlockRetainer())
            {
                var unmanagedTimestamp = hb.Alloc(timeStampCms.Length);
                Marshal.Copy(timeStampCms, 0, unmanagedTimestamp, timeStampCms.Length);
                var blob = new CRYPT_INTEGER_BLOB()
                {
                    cbData = (uint)timeStampCms.Length,
                    pbData = unmanagedTimestamp
                };
                var unmanagedBlob = hb.Alloc(Marshal.SizeOf(blob));
                Marshal.StructureToPtr(blob, unmanagedBlob, fDeleteOld: false);

                var attr = new CRYPT_ATTRIBUTE()
                {
                    pszObjId = hb.AllocAsciiString(Oids.SignatureTimeStampTokenAttribute),
                    cValue = 1,
                    rgValue = unmanagedBlob
                };
                var unmanagedAttr = hb.Alloc(Marshal.SizeOf(attr));
                Marshal.StructureToPtr(attr, unmanagedAttr, fDeleteOld: false);

                uint encodedLength = 0;
                if (!NativeMethods.CryptEncodeObjectEx(
                    dwCertEncodingType: NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                    lpszStructType: new IntPtr(NativeMethods.PKCS_ATTRIBUTE),
                    pvStructInfo: unmanagedAttr,
                    dwFlags: 0,
                    pEncodePara: IntPtr.Zero,
                    pvEncoded: IntPtr.Zero,
                    pcbEncoded: ref encodedLength))
                {
                    var err = Marshal.GetLastWin32Error();
                    if (err != NativeMethods.ERROR_MORE_DATA)
                    {
                        Marshal.ThrowExceptionForHR(NativeMethods.GetHRForWin32Error(err));
                    }
                }

                var unmanagedEncoded = hb.Alloc((int)encodedLength);
                if (!NativeMethods.CryptEncodeObjectEx(
                    dwCertEncodingType: NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                    lpszStructType: new IntPtr(NativeMethods.PKCS_ATTRIBUTE),
                    pvStructInfo: unmanagedAttr,
                    dwFlags: 0,
                    pEncodePara: IntPtr.Zero,
                    pvEncoded: unmanagedEncoded,
                    pcbEncoded: ref encodedLength))
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }

                var addAttr = new CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA()
                {
                    dwSignerIndex = 0,
                    BLOB = new CRYPT_INTEGER_BLOB()
                    {
                        cbData = encodedLength,
                        pbData = unmanagedEncoded
                    }
                };
                addAttr.cbSize = (uint)Marshal.SizeOf(addAttr);
                var unmanagedAddAttr = hb.Alloc(Marshal.SizeOf(addAttr));
                Marshal.StructureToPtr(addAttr, unmanagedAddAttr, fDeleteOld: false);

                if (!NativeMethods.CryptMsgControl(
                    _handle,
                    dwFlags: 0,
                    dwCtrlType: CMSG_CONTROL_TYPE.CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR,
                    pvCtrlPara: unmanagedAddAttr))
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }
            }
        }

        internal byte[] Encode()
        {
            return GetByteArrayAttribute(CMSG_GETPARAM_TYPE.CMSG_ENCODED_MESSAGE, index: 0);
        }

        public void Dispose()
        {
            _handle.Dispose();
        }
    }
}