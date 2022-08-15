/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package multichannel

import (
	"github.com/hxx258456/fabric-gm/bccsp"
	"github.com/hxx258456/fabric-gm/common/channelconfig"
	"github.com/hxx258456/fabric-gm/common/ledger/blockledger"
	"github.com/hxx258456/fabric-gm/common/policies"
	"github.com/hxx258456/fabric-gm/internal/pkg/identity"
	"github.com/hxx258456/fabric-gm/orderer/common/blockcutter"
	"github.com/hxx258456/fabric-gm/orderer/common/msgprocessor"
	"github.com/hxx258456/fabric-gm/orderer/common/types"
	"github.com/hxx258456/fabric-gm/orderer/consensus"
	"github.com/hxx258456/fabric-gm/protoutil"
	cb "github.com/hxx258456/fabric-protos-go-gm/common"
	"github.com/pkg/errors"
)

// ChainSupport holds the resources for a particular channel.
type ChainSupport struct {
	*ledgerResources
	msgprocessor.Processor
	*BlockWriter
	consensus.Chain
	cutter blockcutter.Receiver
	identity.SignerSerializer
	BCCSP bccsp.BCCSP

	// NOTE: It makes sense to add this to the ChainSupport since the design of Registrar does not assume
	// that there is a single consensus type at this orderer node and therefore the resolution of
	// the consensus type too happens only at the ChainSupport level.
	consensus.MetadataValidator

	// The registrar is not aware of the exact type that the Chain is, e.g. etcdraft, inactive, or follower.
	// Therefore, we let each chain report its cluster relation and status through this interface. Non cluster
	// type chains (solo, kafka) are assigned a static reporter.
	consensus.StatusReporter
}

func newChainSupport(
	registrar *Registrar,
	ledgerResources *ledgerResources,
	consenters map[string]consensus.Consenter,
	signer identity.SignerSerializer,
	blockcutterMetrics *blockcutter.Metrics,
	bccsp bccsp.BCCSP,
) (*ChainSupport, error) {
	// Read in the last block and metadata for the channel
	lastBlock := blockledger.GetBlock(ledgerResources, ledgerResources.Height()-1)
	metadata, err := protoutil.GetConsenterMetadataFromBlock(lastBlock)
	// Assuming a block created with cb.NewBlock(), this should not
	// error even if the orderer metadata is an empty byte slice
	if err != nil {
		return nil, errors.Wrapf(err, "error extracting orderer metadata for channel: %s", ledgerResources.ConfigtxValidator().ChannelID())
	}

	// Construct limited support needed as a parameter for additional support
	cs := &ChainSupport{
		ledgerResources:  ledgerResources,
		SignerSerializer: signer,
		cutter: blockcutter.NewReceiverImpl(
			ledgerResources.ConfigtxValidator().ChannelID(),
			ledgerResources,
			blockcutterMetrics,
		),
		BCCSP: bccsp,
	}

	// Set up the msgprocessor
	cs.Processor = msgprocessor.NewStandardChannel(cs, msgprocessor.CreateStandardChannelFilters(cs, registrar.config), bccsp)

	// Set up the block writer
	cs.BlockWriter = newBlockWriter(lastBlock, registrar, cs)

	// Set up the consenter
	consenterType := ledgerResources.SharedConfig().ConsensusType()
	consenter, ok := consenters[consenterType]
	if !ok {
		return nil, errors.Errorf("error retrieving consenter of type: %s", consenterType)
	}

	cs.Chain, err = consenter.HandleChain(cs, metadata)
	if err != nil {
		return nil, errors.Wrapf(err, "error creating consenter for channel: %s", cs.ChannelID())
	}

	cs.MetadataValidator, ok = cs.Chain.(consensus.MetadataValidator)
	if !ok {
		cs.MetadataValidator = consensus.NoOpMetadataValidator{}
	}

	cs.StatusReporter, ok = cs.Chain.(consensus.StatusReporter)
	if !ok { // Non-cluster types: solo, kafka
		cs.StatusReporter = consensus.StaticStatusReporter{ClusterRelation: types.ClusterRelationNone, Status: types.StatusActive}
	}

	logger.Debugf("[channel: %s] Done creating channel support resources", cs.ChannelID())

	return cs, nil
}

func newChainSupportForJoin(
	joinBlock *cb.Block,
	registrar *Registrar,
	ledgerResources *ledgerResources,
	consenters map[string]consensus.Consenter,
	signer identity.SignerSerializer,
	blockcutterMetrics *blockcutter.Metrics,
	bccsp bccsp.BCCSP,
) (*ChainSupport, error) {

	if joinBlock.Header.Number == 0 {
		err := ledgerResources.Append(joinBlock)
		if err != nil {
			return nil, errors.Wrap(err, "error appending join block to the ledger")
		}
		return newChainSupport(registrar, ledgerResources, consenters, signer, blockcutterMetrics, bccsp)
	}

	// Construct limited support needed as a parameter for additional support
	cs := &ChainSupport{
		ledgerResources:  ledgerResources,
		SignerSerializer: signer,
		cutter: blockcutter.NewReceiverImpl(
			ledgerResources.ConfigtxValidator().ChannelID(),
			ledgerResources,
			blockcutterMetrics,
		),
		BCCSP: bccsp,
	}

	// Set up the msgprocessor
	cs.Processor = msgprocessor.NewStandardChannel(cs, msgprocessor.CreateStandardChannelFilters(cs, registrar.config), bccsp)
	// No BlockWriter, this will be created when the chain gets converted from follower.Chain to etcdraft.Chain
	cs.BlockWriter = nil //TODO change embedding of BlockWriter struct to interface, and put here a NoOp implementation or one that panics if used

	// Get the consenter
	consenterType := ledgerResources.SharedConfig().ConsensusType()
	consenter, ok := consenters[consenterType]
	if !ok {
		return nil, errors.Errorf("error retrieving consenter of type: %s", consenterType)
	}

	var err error
	cs.Chain, err = consenter.JoinChain(cs, joinBlock)
	if err != nil {
		return nil, err
	}

	cs.MetadataValidator, ok = cs.Chain.(consensus.MetadataValidator)
	if !ok {
		cs.MetadataValidator = consensus.NoOpMetadataValidator{}
	}

	cs.StatusReporter, ok = cs.Chain.(consensus.StatusReporter)
	if !ok { // Non-cluster types: solo, kafka
		cs.StatusReporter = consensus.StaticStatusReporter{ClusterRelation: types.ClusterRelationNone, Status: types.StatusActive}
	}

	logger.Debugf("[channel: %s] Done creating channel support resources for join", cs.ChannelID())

	return cs, nil
}

// Block returns a block with the following number,
// or nil if such a block doesn't exist.
func (cs *ChainSupport) Block(number uint64) *cb.Block {
	if cs.Height() <= number {
		return nil
	}
	return blockledger.GetBlock(cs.Reader(), number)
}

func (cs *ChainSupport) Reader() blockledger.Reader {
	return cs
}

// Signer returns the SignerSerializer for this channel.
func (cs *ChainSupport) Signer() identity.SignerSerializer {
	return cs
}

func (cs *ChainSupport) start() {
	cs.Chain.Start()
}

// BlockCutter returns the blockcutter.Receiver instance for this channel.
func (cs *ChainSupport) BlockCutter() blockcutter.Receiver {
	return cs.cutter
}

// Validate passes through to the underlying configtx.Validator
func (cs *ChainSupport) Validate(configEnv *cb.ConfigEnvelope) error {
	return cs.ConfigtxValidator().Validate(configEnv)
}

// ProposeConfigUpdate validates a config update using the underlying configtx.Validator
// and the consensus.MetadataValidator.
func (cs *ChainSupport) ProposeConfigUpdate(configtx *cb.Envelope) (*cb.ConfigEnvelope, error) {
	env, err := cs.ConfigtxValidator().ProposeConfigUpdate(configtx)
	if err != nil {
		return nil, err
	}

	bundle, err := cs.CreateBundle(cs.ChannelID(), env.Config)
	if err != nil {
		return nil, err
	}

	if err = checkResources(bundle); err != nil {
		return nil, errors.Wrap(err, "config update is not compatible")
	}

	if err = cs.ValidateNew(bundle); err != nil {
		return nil, err
	}

	oldOrdererConfig, ok := cs.OrdererConfig()
	if !ok {
		logger.Panic("old config is missing orderer group")
	}

	// we can remove this check since this is being validated in checkResources earlier
	newOrdererConfig, ok := bundle.OrdererConfig()
	if !ok {
		return nil, errors.New("new config is missing orderer group")
	}

	if err = cs.ValidateConsensusMetadata(oldOrdererConfig, newOrdererConfig, false); err != nil {
		return nil, errors.Wrap(err, "consensus metadata update for channel config update is invalid")
	}
	return env, nil
}

// ChannelID passes through to the underlying configtx.Validator
func (cs *ChainSupport) ChannelID() string {
	return cs.ConfigtxValidator().ChannelID()
}

// ConfigProto passes through to the underlying configtx.Validator
func (cs *ChainSupport) ConfigProto() *cb.Config {
	return cs.ConfigtxValidator().ConfigProto()
}

// Sequence passes through to the underlying configtx.Validator
func (cs *ChainSupport) Sequence() uint64 {
	return cs.ConfigtxValidator().Sequence()
}

// Append appends a new block to the ledger in its raw form,
// unlike WriteBlock that also mutates its metadata.
func (cs *ChainSupport) Append(block *cb.Block) error {
	return cs.ledgerResources.ReadWriter.Append(block)
}

// VerifyBlockSignature verifies a signature of a block.
// It has an optional argument of a configuration envelope
// which would make the block verification to use validation rules
// based on the given configuration in the ConfigEnvelope.
// If the config envelope passed is nil, then the validation rules used
// are the ones that were applied at commit of previous blocks.
func (cs *ChainSupport) VerifyBlockSignature(sd []*protoutil.SignedData, envelope *cb.ConfigEnvelope) error {
	policyMgr := cs.PolicyManager()
	// If the envelope passed isn't nil, we should use a different policy manager.
	if envelope != nil {
		bundle, err := channelconfig.NewBundle(cs.ChannelID(), envelope.Config, cs.BCCSP)
		if err != nil {
			return err
		}
		policyMgr = bundle.PolicyManager()
	}
	policy, exists := policyMgr.GetPolicy(policies.BlockValidation)
	if !exists {
		return errors.Errorf("policy %s wasn't found", policies.BlockValidation)
	}
	err := policy.EvaluateSignedData(sd)
	if err != nil {
		return errors.Wrap(err, "block verification failed")
	}
	return nil
}
