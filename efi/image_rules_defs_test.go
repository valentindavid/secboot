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

package efi_test

import (
	efi "github.com/canonical/go-efilib"

	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/efitest"
	"github.com/snapcore/secboot/internal/testutil"
)

type imageRulesDefsSuite struct {
	mockShimImageHandleMixin
	mockGrubImageHandleMixin
}

func (s *imageRulesDefsSuite) SetUpTest(c *C) {
	s.mockShimImageHandleMixin.SetUpTest(c)
	s.mockGrubImageHandleMixin.SetUpTest(c)
}

func (s *imageRulesDefsSuite) TearDownTest(c *C) {
	s.mockShimImageHandleMixin.TearDownTest(c)
	s.mockGrubImageHandleMixin.TearDownTest(c)
}

var _ = Suite(&imageRulesDefsSuite{})

func (s *imageRulesDefsSuite) TestMSNewImageLoadHandlerUbuntuShim15_7(c *C) {
	// Verify we get a correctly configured shimLoadHandler for the Ubuntu shim 15.7
	image := newMockUbuntuShimImage15_7(c)

	rules := MakeMicrosoftUEFICASecureBootNamespaceRules()
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimHasSbatVerification|ShimFixVariableAuthorityEventsMatchSpec|ShimVendorCertContainsDb|ShimHasSbatRevocationManagement)
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "MokListRT", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, ShimGuid)},
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n"), []byte("sbat,1,2022052400\ngrub,2\n")})
}

func (s *imageRulesDefsSuite) TestMSNewImageLoadHandlerUbuntuShim15_4(c *C) {
	// Verify we get a correctly configured shimLoadHandler for the Ubuntu shim 15.4
	image := newMockUbuntuShimImage15_4(c)

	rules := MakeMicrosoftUEFICASecureBootNamespaceRules()
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimHasSbatVerification|ShimFixVariableAuthorityEventsMatchSpec)
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{[]byte("sbat,1,2021030218\n"), []byte("sbat,1,2021030218\n")})
}

func (s *imageRulesDefsSuite) TestMSNewImageLoadHandlerUbuntuShim15WithFixes1(c *C) {
	// Verify we get a correctly configured shimLoadHandler for the Ubuntu shim 15 with
	// the required fixes (1.41+15+1552672080.a4a1fbe-0ubuntu1)
	image := newMockUbuntuShimImage15a(c)

	rules := MakeMicrosoftUEFICASecureBootNamespaceRules()
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimFlags(0))
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{})
}

func (s *imageRulesDefsSuite) TestMSNewImageLoadHandlerUbuntuShim15WithFixes2(c *C) {
	// Verify we get a correctly configured shimLoadHandler for the Ubuntu shim 15 with
	// the required fixes (1.40.4+15+1552672080.a4a1fbe-0ubuntu2)
	image := newMockUbuntuShimImage15b(c)

	rules := MakeMicrosoftUEFICASecureBootNamespaceRules()
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimFlags(0))
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "Shim", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, efi.GUID{})},
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{})
}

func (s *imageRulesDefsSuite) TestMSNewImageLoadHandlerUbuntuGrubSbat(c *C) {
	// Verify we get a correctly configured grubLoadHandler for the Ubuntu grub
	image := newMockUbuntuGrubImage3(c)

	rules := MakeMicrosoftUEFICASecureBootNamespaceRules()
	rules.AddAuthorities(testutil.ParseCertificate(c, canonicalCACert))
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &GrubLoadHandler{})

	c.Check(handler.(*GrubLoadHandler).Flags, Equals, GrubChainloaderUsesShimProtocol)
}

func (s *imageRulesDefsSuite) TestMSNewImageLoadHandlerUbuntuGrubNoSbat(c *C) {
	// Verify we get a correctly configured grubLoadHandler for the Ubuntu grub (pre-SBAT)
	image := newMockUbuntuGrubImage1(c)

	rules := MakeMicrosoftUEFICASecureBootNamespaceRules()
	rules.AddAuthorities(testutil.ParseCertificate(c, canonicalCACert))
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &GrubLoadHandler{})

	c.Check(handler.(*GrubLoadHandler).Flags, Equals, GrubChainloaderUsesShimProtocol)
}

func (s *imageRulesDefsSuite) TestMSNewImageLoadHandlerUbuntuUKISbat(c *C) {
	// Verify that we get a ubuntuCoreUKIHandler for an Ubuntu Core kernel image
	image := newMockUbuntuKernelImage3(c)

	rules := MakeMicrosoftUEFICASecureBootNamespaceRules()
	rules.AddAuthorities(testutil.ParseCertificate(c, canonicalCACert))
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &UbuntuCoreUKILoadHandler{})
}

func (s *imageRulesDefsSuite) TestMSNewImageLoadHandlerUbuntuUKINoSbat(c *C) {
	// Verify that we get a ubuntuCoreUKIHandler for an Ubuntu Core kernel image (pre-SBAT)
	image := newMockUbuntuKernelImage1(c)

	rules := MakeMicrosoftUEFICASecureBootNamespaceRules()
	rules.AddAuthorities(testutil.ParseCertificate(c, canonicalCACert))
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &UbuntuCoreUKILoadHandler{})
}

func (s *imageRulesDefsSuite) TestMSNewImageLoadHandlerUbuntuGrubRecognized(c *C) {
	// Verify that the Canonical CA cert is recognized as part of the MS UEFI CA namespace
	// after creating a handler for Ubuntu shim.
	image := newMockUbuntuShimImage15_7(c)

	rules := MakeMicrosoftUEFICASecureBootNamespaceRules()
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	// Verify that looking up Ubuntu grub returns a correctly configured load handler
	// (not from the fallback namespace)
	image2 := newMockUbuntuGrubImage3(c)
	handler, err = rules.NewImageLoadHandler(image2.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &GrubLoadHandler{})

	c.Check(handler.(*GrubLoadHandler).Flags, Equals, GrubChainloaderUsesShimProtocol)
}

func (s *imageRulesDefsSuite) TestFallbackNewImageLoadHandlerShim(c *C) {
	// verify that shim is recognized by the fallback rules
	image := newMockUbuntuShimImage15_7(c)

	rules := MakeFallbackImageRules()
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &ShimLoadHandler{})

	shimHandler := handler.(*ShimLoadHandler)
	c.Check(shimHandler.Flags, Equals, ShimHasSbatVerification|ShimFixVariableAuthorityEventsMatchSpec|ShimVendorCertContainsDb|ShimHasSbatRevocationManagement)
	c.Check(shimHandler.VendorDb, DeepEquals, &SecureBootDB{
		Name:     efi.VariableDescriptor{Name: "MokListRT", GUID: ShimGuid},
		Contents: efi.SignatureDatabase{efitest.NewSignatureListX509(c, canonicalCACert, ShimGuid)},
	})
	c.Check(shimHandler.SbatLevel, DeepEquals, ShimSbatLevel{[]byte("sbat,1,2022111500\nshim,2\ngrub,3\n"), []byte("sbat,1,2022052400\ngrub,2\n")})
}

func (s *imageRulesDefsSuite) TestFallbackNewImageLoadHandlerUbuntuGrub(c *C) {
	// verify that grub is recognized by the fallback rules
	image := newMockUbuntuGrubImage1(c)

	rules := MakeFallbackImageRules()
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &GrubLoadHandler{})
	c.Check(handler.(*GrubLoadHandler).Flags, Equals, GrubChainloaderUsesShimProtocol)
}

func (s *imageRulesDefsSuite) TestFallbackNewImageLoadHandlerGrub(c *C) {
	// verify that grub is recognized by the fallback rules
	image := newMockImage().
		addSection("mods", nil).
		withGrubPrefix("/EFI/debian")

	rules := MakeFallbackImageRules()
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &GrubLoadHandler{})
	c.Check(handler.(*GrubLoadHandler), DeepEquals, new(GrubLoadHandler))
}
func (s *imageRulesDefsSuite) TestFallbackNewImageLoadHandlerNull(c *C) {
	// verify that an unrecognized leaf image is recognized by the fallback rules
	image := newMockImage()

	rules := MakeFallbackImageRules()
	handler, err := rules.NewImageLoadHandler(image.newPeImageHandle())
	c.Assert(err, IsNil)
	c.Assert(handler, testutil.ConvertibleTo, &NullLoadHandler{})
}
