// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package efi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	efi "github.com/canonical/go-efilib"
)

// CheckPEImageKnownBySystem checks whether the supplied PE image has
// at least one Authenticode signature or a hash that is authorized by
// the host's authorized signature database (the UEFI "db" variable).
//
// This function is intended for checking that the current system is
// "aware" of any certificate used by the image or the image itself.
// It does not verify that the system would accept that image. In
// particular, this does **not** verify that:
//  * the Authenticode signature is valid the image.
//  * the signature is correctly signed by by the issuer certificate.
//  * that the hash of the image is not revoked.
//  * that the signature hash is not revoked.
//  * that the signing chain is not revoked.
//
// This is intended to be used during boot asset updates to verify that a new
// image has new enough authorized signature database, so that it will
// be able to load the images when secure boot is enforced, without the
// need of an update.
//
// For example, a shim binary signed only by a newer Microsoft UEFI CA will not
// be loadable on older hardware whose db only contains the older CA. Similarly,
// an image whose digest is not in db (if digest-based authorization is used) will
// not be loadable.
//
// The image is known if:
//   - At least one of its Authenticode signatures chains to an X.509 certificate
//     authority that is enrolled in db, OR
//   - The PE image digest matches a digest entry in db, where the PE image digest
//     is computed for the hash algorithm implied by the EFI_SIGNATURE_LIST type
//     (e.g., CertSHA256Guid implies SHA256, CertSHA384Guid implies SHA384).
//
// For digest-based authorization, the function computes the PE image digest for
// each digest algorithm present in db and checks for a match against the
// corresponding signature list entries. This allows an image to be verified
// against digest entries regardless of the hash algorithm used by its
// Authenticode signature. Note that EDK II for instance  does not
// verify hashes algorithms not listed by Authenticode signatures if at
// least one signature exists.
//
// The context must provide access to the EFI variable backend via go-efilib's
// context mechanism. In general, pass the result of
// [HostEnvironment.VarContext] or [efi.DefaultVarContext].
//
// Possible error conditions:
//   - The image cannot be opened or is not a valid PE binary.
//   - The host's db variable cannot be read (eg, if EFI variables are unavailable).
//   - No signature on the image is authorized by the host's db.
func CheckPEImageKnownBySystem(ctx context.Context, image Image) error {
	// Extract signatures from the image, and check for the presence of at
	// least one signature before doing any further work, to give a more
	// specific error if the image is not signed at all.
	pei, err := openPeImage(image)
	if err != nil {
		return fmt.Errorf("cannot open image: %w", err)
	}

	defer pei.Close()

	imageSigs, err := pei.SecureBootSignatures()
	if err != nil {
		return fmt.Errorf("cannot obtain secure boot signatures for image: %w", err)
	}

	db, err := efi.ReadSignatureDatabaseVariable(ctx, Db)
	if err != nil {
		return fmt.Errorf("cannot read authorized signature database: %w", err)
	}

	digests := newImageDigestCache(pei)

	// TODO: For revocation checks, we should check the image
	// against entries of siglists of type EFI_CERT_SHA*_GUID in
	// dbx.

	for _, sigList := range db {
		// Check for X.509 certificate-based authorization
		if sigList.Type == efi.CertX509Guid {
			for _, sigEntry := range sigList.Signatures {
				cert, err := x509.ParseCertificate(sigEntry.Data)
				if err != nil {
					continue
				}

				for _, imageSig := range imageSigs {
					// TODO: For revocation check, we would need to verify that any certificate chain is not
					// in dbx. Specifically all signature data against entries of type EFI_CERT_X509_SHA256,
					// EFI_CERT_X509_SHA384, EFI_CERT_X509_SHA512. And certificates for type EFI_CERT_X509_GUID.
					if imageSig.CertWithIDLikelyTrustAnchor(efi.NewX509CertIDFromCertificate(cert)) {
						// If the signature chains to a trusted certificate, then the image is authorized.
						return nil
					}
				}
			}
		} else {
			alg := efiSignatureListTypeToDigestAlg(sigList.Type)
			if alg == crypto.Hash(0) {
				// Skip unrecognized signature list types since we cannot use them for verification
				continue
			}

			// Check for digest-based authorization
			digest, err := digests.digestForAlg(alg)
			if err != nil {
				return err
			}

			for _, sigEntry := range sigList.Signatures {
				if bytes.Equal(sigEntry.Data, digest) {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("cannot find any secure boot signature that is trusted by the current host's authorized signature database")
}

type imageDigestCache struct {
	pei     peImageHandle
	digests map[crypto.Hash][]byte
}

	func newImageDigestCache(pei peImageHandle) *imageDigestCache {
	return &imageDigestCache{
		pei:     pei,
		digests: make(map[crypto.Hash][]byte),
	}
}

func (c *imageDigestCache) digestForAlg(alg crypto.Hash) ([]byte, error) {
	if digest, exists := c.digests[alg]; exists {
		return digest, nil
	}

	digest, err := c.pei.ImageDigest(alg)
	if err != nil {
		return nil, fmt.Errorf("cannot compute image digest with %v: %w", alg, err)
	}

	c.digests[alg] = digest
	return digest, nil
}

func efiSignatureListTypeToDigestAlg(guid efi.GUID) crypto.Hash {
	switch guid {
	case efi.CertSHA1Guid:
		return crypto.SHA1
	case efi.CertSHA224Guid:
		return crypto.SHA224
	case efi.CertSHA256Guid:
		return crypto.SHA256
	case efi.CertSHA384Guid:
		return crypto.SHA384
	case efi.CertSHA512Guid:
		return crypto.SHA512
	default:
		return crypto.Hash(0)
	}
}
