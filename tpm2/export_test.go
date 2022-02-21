// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package tpm2

import (
	"crypto/ecdsa"

	"github.com/canonical/go-tpm2"
)

// Export constants for testing
const (
	CurrentMetadataVersion = currentMetadataVersion
	LockNVHandle           = lockNVHandle
	SrkTemplateHandle      = srkTemplateHandle
)

// Export variables and unexported functions for testing
var (
	ComputeDynamicPolicy                    = computeDynamicPolicy
	ComputeV0PinNVIndexPostInitAuthPolicies = computeV0PinNVIndexPostInitAuthPolicies
	CreatePcrPolicyCounter                  = createPcrPolicyCounter
	ComputeV1PcrPolicyCounterAuthPolicies   = computeV1PcrPolicyCounterAuthPolicies
	ComputeV1PcrPolicyRefFromCounterContext = computeV1PcrPolicyRefFromCounterContext
	ComputeV1PcrPolicyRefFromCounterName    = computeV1PcrPolicyRefFromCounterName
	ComputeSnapModelDigest                  = computeSnapModelDigest
	ComputeStaticPolicy                     = computeStaticPolicy
	CreateTPMPublicAreaForECDSAKey          = createTPMPublicAreaForECDSAKey
	ErrSessionDigestNotFound                = errSessionDigestNotFound
	ExecutePolicySession                    = executePolicySession
	IncrementPcrPolicyCounterTo             = incrementPcrPolicyCounterTo
	IsDynamicPolicyDataError                = isDynamicPolicyDataError
	IsStaticPolicyDataError                 = isStaticPolicyDataError
	NewPcrPolicyCounterHandleV1             = newPcrPolicyCounterHandleV1
	NewPolicyOrDataV0                       = newPolicyOrDataV0
	NewPolicyOrTree                         = newPolicyOrTree
	ReadKeyDataV0                           = readKeyDataV0
	ReadKeyDataV1                           = readKeyDataV1
	ReadKeyDataV2                           = readKeyDataV2
)

// Alias some unexported types for testing. These are required in order to pass these between functions in tests, or to access
// unexported members of some unexported types.
type DynamicPolicyData = dynamicPolicyData

func (d *DynamicPolicyData) PCRSelection() tpm2.PCRSelectionList {
	return d.pcrSelection
}

func (d *DynamicPolicyData) PCROrData() PolicyOrData_v0 {
	return d.pcrOrData
}

func (d *DynamicPolicyData) PolicyCount() uint64 {
	return d.policyCount
}

func (d *DynamicPolicyData) SetPolicyCount(c uint64) {
	d.policyCount = c
}

func (d *DynamicPolicyData) AuthorizedPolicy() tpm2.Digest {
	return d.authorizedPolicy
}

func (d *DynamicPolicyData) AuthorizedPolicySignature() *tpm2.Signature {
	return d.authorizedPolicySignature
}

type DynamicPolicyDataRaw_v0 = dynamicPolicyDataRaw_v0
type GoSnapModelHasher = goSnapModelHasher
type KeyData = keyData
type KeyData_v0 = keyData_v0
type KeyData_v1 = keyData_v1
type KeyData_v2 = keyData_v2
type KeyDataError = keyDataError
type PcrPolicyCounterHandle = pcrPolicyCounterHandle

type PolicyOrData_v0 = policyOrData_v0

func (t PolicyOrData_v0) Resolve() (out *PolicyOrTree, err error) {
	return t.resolve()
}

type PolicyOrDataNode_v0 = policyOrDataNode_v0

type PolicyOrNode = policyOrNode

func (n *PolicyOrNode) Parent() *PolicyOrNode {
	return n.parent
}

func (n *PolicyOrNode) Digests() tpm2.DigestList {
	return n.digests
}

func (n *PolicyOrNode) Contains(digest tpm2.Digest) bool {
	return n.contains(digest)
}

type PolicyOrTree = policyOrTree

func (t *PolicyOrTree) LeafNodes() []*PolicyOrNode {
	return t.leafNodes
}

func (t *PolicyOrTree) ExecuteAssertions(tpm *tpm2.TPMContext, session tpm2.SessionContext) error {
	return t.executeAssertions(tpm, session)
}

type SnapModelHasher = snapModelHasher

type StaticPolicyData = staticPolicyData

func (d *StaticPolicyData) AuthPublicKey() *tpm2.Public {
	return d.authPublicKey
}

func (d *StaticPolicyData) PcrPolicyCounterHandle() tpm2.Handle {
	return d.pcrPolicyCounterHandle
}

func (d *StaticPolicyData) SetPcrPolicyCounterHandle(h tpm2.Handle) {
	d.pcrPolicyCounterHandle = h
}

func (d *StaticPolicyData) V0PinIndexAuthPolicies() tpm2.DigestList {
	return d.v0PinIndexAuthPolicies
}

type StaticPolicyDataRaw_v0 = staticPolicyDataRaw_v0
type StaticPolicyDataRaw_v1 = staticPolicyDataRaw_v1

// Export some helpers for testing.
type MockPolicyPCRParam struct {
	PCR     int
	Alg     tpm2.HashAlgorithmId
	Digests tpm2.DigestList
}

// MakeMockPolicyPCRValuesFull computes a slice of tpm2.PCRValues for every combination of supplied PCR values.
func MakeMockPolicyPCRValuesFull(params []MockPolicyPCRParam) (out []tpm2.PCRValues) {
	indices := make([]int, len(params))
	advanceIndices := func() bool {
		for i := range params {
			indices[i]++
			if indices[i] < len(params[i].Digests) {
				break
			}
			indices[i] = 0
			if i == len(params)-1 {
				return false
			}
		}
		return true
	}

	for {
		v := make(tpm2.PCRValues)
		for i := range params {
			v.SetValue(params[i].Alg, params[i].PCR, params[i].Digests[indices[i]])
		}
		out = append(out, v)

		if len(params) == 0 {
			break
		}

		if !advanceIndices() {
			break
		}
	}
	return
}

func NewDynamicPolicyComputeParams(key *ecdsa.PrivateKey, signAlg tpm2.HashAlgorithmId, pcrs tpm2.PCRSelectionList,
	pcrDigests tpm2.DigestList, policyCounterName tpm2.Name, policyCount uint64) *dynamicPolicyComputeParams {
	return &dynamicPolicyComputeParams{
		key:               key,
		signAlg:           signAlg,
		pcrs:              pcrs,
		pcrDigests:        pcrDigests,
		policyCounterName: policyCounterName,
		policyCount:       policyCount}
}

func NewStaticPolicyComputeParams(key *tpm2.Public, pcrPolicyCounterPub *tpm2.NVPublic) *staticPolicyComputeParams {
	return &staticPolicyComputeParams{key: key, pcrPolicyCounterPub: pcrPolicyCounterPub}
}

func (k *SealedKeyObject) Validate(tpm *tpm2.TPMContext, authPrivateKey PolicyAuthKey, session tpm2.SessionContext) error {
	if _, err := k.validateData(tpm, session); err != nil {
		return err
	}

	authKey, err := createECDSAPrivateKeyFromTPM(k.data.StaticPolicy().authPublicKey, tpm2.ECCParameter(authPrivateKey))
	if err != nil {
		return err
	}

	return k.validateAuthKey(authKey)
}

func ValidateKeyDataFile(tpm *tpm2.TPMContext, keyFile string, authPrivateKey PolicyAuthKey, session tpm2.SessionContext) error {
	k, err := ReadSealedKeyObjectFromFile(keyFile)
	if err != nil {
		return err
	}

	return k.Validate(tpm, authPrivateKey, session)
}
