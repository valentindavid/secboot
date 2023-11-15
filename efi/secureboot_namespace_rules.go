// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
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
	"crypto/x509"
	"fmt"
	"os"

	"github.com/snapcore/snapd/snapdenv"
	"golang.org/x/xerrors"
)

// vendorAuthorityGetter provides a way for an imageLoadHandler created by
// secureBootNamespaceRules to supplement the CA's associated with a secure
// boot namespace in the case where the associated image contains a delegated
// signing authority (eg, shim's vendor certificate). This allows the extra
// authorities to become part of the same namespace and permits components
// signed by these extra authorities to be recognized by the same set of
// rules without having to embed multiple certificates.
type vendorAuthorityGetter interface {
	VendorAuthorities() ([]*x509.Certificate, error)
}

// secureBootAuthorityIdentity corresponds to the identify of a secure boot
// authority. A secure boot namespace has one or more of these.
type secureBootAuthorityIdentity struct {
	subject            []byte
	subjectKeyId       []byte
	publicKeyAlgorithm x509.PublicKeyAlgorithm
}

// withAuthority adds the specified secure boot authority to a secureBootNamespaceRules.
func withAuthority(subject, subjectKeyId []byte, publicKeyAlgorithm x509.PublicKeyAlgorithm) secureBootNamespaceOption {
	return func(ns *secureBootNamespaceRules) {
		ns.authorities = append(ns.authorities, &secureBootAuthorityIdentity{
			subject:            subject,
			subjectKeyId:       subjectKeyId,
			publicKeyAlgorithm: publicKeyAlgorithm})
	}
}

// withAuthority adds the specified secure boot authority to a secureBootNamespaceRules,
// only during testing.
func withAuthorityOnlyForTesting(subject, subjectKeyId []byte, publicKeyAlgorithm x509.PublicKeyAlgorithm) secureBootNamespaceOption {
	if !snapdenv.Testing() {
		return func(_ *secureBootNamespaceRules) {}
	}
	return withAuthority(subject, subjectKeyId, publicKeyAlgorithm)
}

// withImageRule adds the specified rule to a secureBootNamespaceRules.
func withImageRule(name string, match imagePredicate, create newImageLoadHandlerFn) secureBootNamespaceOption {
	return func(ns *secureBootNamespaceRules) {
		ns.rules = append(ns.rules, newImageRule(name, match, create))
	}
}

// withImageRule adds the specified rule to a secureBootNamespaceRules,
// only during testing.
func withImageRuleOnlyForTesting(name string, match imagePredicate, create newImageLoadHandlerFn) secureBootNamespaceOption {
	if !snapdenv.Testing() {
		return func(_ *secureBootNamespaceRules) {}
	}
	return withImageRule(name, match, create)
}

type secureBootNamespaceOption func(*secureBootNamespaceRules)

// secureBootNamespaceRules is used to construct an imageLoadHandler from a
// peImageHandle using a set of rules that are scoped to a secure boot
// hierarchy.
type secureBootNamespaceRules struct {
	authorities []*secureBootAuthorityIdentity
	*imageRules
}

// newSecureBootNamespaceRules constructs a secure boot namespace with the specified
// options.
func newSecureBootNamespaceRules(name string, options ...secureBootNamespaceOption) *secureBootNamespaceRules {
	out := &secureBootNamespaceRules{
		imageRules: newImageRules(name + " secure boot namespace"),
	}
	for _, option := range options {
		option(out)
	}
	return out
}

func (r *secureBootNamespaceRules) AddAuthorities(certs ...*x509.Certificate) {
	for _, cert := range certs {
		found := false
		for _, authority := range r.authorities {
			if bytes.Equal(authority.subject, cert.RawSubject) &&
				bytes.Equal(authority.subjectKeyId, cert.SubjectKeyId) &&
				authority.publicKeyAlgorithm == cert.PublicKeyAlgorithm {
				found = true
				break
			}
		}
		if !found {
			r.authorities = append(r.authorities, &secureBootAuthorityIdentity{
				subject:            cert.RawSubject,
				subjectKeyId:       cert.SubjectKeyId,
				publicKeyAlgorithm: cert.PublicKeyAlgorithm,
			})
		}
	}
}

func (r *secureBootNamespaceRules) NewImageLoadHandler(image peImageHandle) (imageLoadHandler, error) {
	// This may return no signatures, but that's ok - in the case, we just return
	// errNoHandler.
	fmt.Fprintf(os.Stderr, "secureBootNamespaceRules.NewImageLoadHandler A\n")

	sigs, err := image.SecureBootSignatures()
	if err != nil {
		// Reject any image with a badly formed security directory entry
		fmt.Fprintf(os.Stderr, "secureBootNamespaceRules.NewImageLoadHandler B\n")
		return nil, xerrors.Errorf("cannot obtain secure boot signatures: %w", err)
	}

	for _, authority := range r.authorities {
		fmt.Fprintf(os.Stderr, "secureBootNamespaceRules.NewImageLoadHandler C\n")
		cert := &x509.Certificate{
			RawSubject:         authority.subject,
			SubjectKeyId:       authority.subjectKeyId,
			PublicKeyAlgorithm: authority.publicKeyAlgorithm}
		for _, sig := range sigs {
			fmt.Fprintf(os.Stderr, "secureBootNamespaceRules.NewImageLoadHandler D\n")
			if !sig.CertLikelyTrustAnchor(cert) {
				fmt.Fprintf(os.Stderr, "secureBootNamespaceRules.NewImageLoadHandler E\n")
				continue
			}

			handler, err := r.imageRules.NewImageLoadHandler(image)
			if err != nil {
				fmt.Fprintf(os.Stderr, "secureBootNamespaceRules.NewImageLoadHandler F\n")
				return nil, err
			}

			if v, ok := handler.(vendorAuthorityGetter); ok {
				fmt.Fprintf(os.Stderr, "secureBootNamespaceRules.NewImageLoadHandler G\n")
				certs, err := v.VendorAuthorities()
				if err != nil {
					fmt.Fprintf(os.Stderr, "secureBootNamespaceRules.NewImageLoadHandler H\n")
					return nil, xerrors.Errorf("cannot obtain vendor authorities: %w", err)
				}
				r.AddAuthorities(certs...)
			}
			fmt.Fprintf(os.Stderr, "secureBootNamespaceRules.NewImageLoadHandler I\n")

			return handler, nil
		}
		fmt.Fprintf(os.Stderr, "secureBootNamespaceRules.NewImageLoadHandler K\n")
	}
	fmt.Fprintf(os.Stderr, "secureBootNamespaceRules.NewImageLoadHandler L\n")

	return nil, errNoHandler
}
