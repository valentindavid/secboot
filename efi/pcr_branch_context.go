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
	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/tcglog-parser"

	secboot_tpm2 "github.com/snapcore/secboot/tpm2"
)

// pcrBranchContext contains the context associated with a branch of a EFI PCR profile
// generation
type pcrBranchContext interface {
	pcrProfileContext
	Params() *loadParams       // access the externally supplied parameters for this branch
	Vars() varReadWriter       // access the variable state for this branch
	FwContext() *fwContext     // access the platform firmware state for this branch
	ShimContext() *shimContext // access the shim state for this branch

	ResetPCR(pcr int)                                                 // reset the specified PCR for this branch
	ExtendPCR(pcr int, digest tpm2.Digest)                            // extend the specified PCR for this branch
	MeasureVariable(pcr int, guid efi.GUID, name string, data []byte) // measure the specified variable for this branch
}

type pcrBranchCtx struct {
	pcrProfileContext
	branch *secboot_tpm2.PCRProtectionProfileBranch
	params loadParams
	vars   varBranch
	fc     fwContext
	sc     shimContext
}

// newRootPcrBranchCtx creates a new root pcrBranchCtx from the supplied arguments.
func newRootPcrBranchCtx(pc pcrProfileContext, branch *secboot_tpm2.PCRProtectionProfileBranch, params *loadParams, vars *varBranch) *pcrBranchCtx {
	return &pcrBranchCtx{
		pcrProfileContext: pc,
		branch:            branch,
		params:            *params,
		vars:              *vars}
}

// newSubBranch creates a new pcrBranchContext for a new branch at the specified branch point.
// The specified branch point should be associated with the pcrBranchPointCtx returned from
// a previous call to pcrBranchContext.AddBranchPoint on this context.
//
// The returned context is based on a copy of this one, with its own copy of the varBranch,
// fwContext and shimContext fields so that they can be mutated without affecting the state
// of ancestor branch contexts.
func (c *pcrBranchCtx) newSubBranch(bp *secboot_tpm2.PCRProtectionProfileBranchPoint, params *loadParams) *pcrBranchCtx {
	newCtx := *c
	newCtx.branch = bp.AddBranch()
	newCtx.params = *params
	return &newCtx
}

func (c *pcrBranchCtx) Params() *loadParams {
	return &c.params
}

func (c *pcrBranchCtx) Vars() varReadWriter {
	return &c.vars
}

func (c *pcrBranchCtx) FwContext() *fwContext {
	return &c.fc
}

func (c *pcrBranchCtx) ShimContext() *shimContext {
	return &c.sc
}

func (c *pcrBranchCtx) ResetPCR(pcr int) {
	c.branch.AddPCRValue(c.PCRAlg(), pcr, make(tpm2.Digest, c.PCRAlg().Size()))
}

func (c *pcrBranchCtx) ExtendPCR(pcr int, digest tpm2.Digest) {
	c.branch.ExtendPCR(c.PCRAlg(), pcr, digest)
}

func (c *pcrBranchCtx) MeasureVariable(pcr int, guid efi.GUID, name string, data []byte) {
	c.branch.ExtendPCR(
		c.PCRAlg(),
		pcr,
		tcglog.ComputeEFIVariableDataDigest(c.PCRAlg().GetHash(), name, guid, data))
}

type pcrBranchPointCtx struct {
	bp        *secboot_tpm2.PCRProtectionProfileBranchPoint
	parentCtx *pcrBranchCtx
}

// AddBranchPoint returns a new branch point for this branch, to which sub-branches
// can be added.
func (c *pcrBranchCtx) AddBranchPoint() *pcrBranchPointCtx {
	return &pcrBranchPointCtx{
		bp:        c.branch.AddBranchPoint(),
		parentCtx: c}
}

// AddBranch adds a new branch to this branch point with the supplied parameters, returning
// a new branch context.
func (c *pcrBranchPointCtx) AddBranch(params *loadParams) *pcrBranchCtx {
	return c.parentCtx.newSubBranch(c.bp, params)
}
