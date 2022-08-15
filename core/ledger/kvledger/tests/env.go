/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tests

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hxx258456/fabric-gm/bccsp"
	"github.com/hxx258456/fabric-gm/bccsp/sw"
	"github.com/hxx258456/fabric-gm/common/ledger/blkstorage"
	"github.com/hxx258456/fabric-gm/common/ledger/util"
	"github.com/hxx258456/fabric-gm/common/metrics/disabled"
	"github.com/hxx258456/fabric-gm/core/chaincode/lifecycle"
	"github.com/hxx258456/fabric-gm/core/common/privdata"
	"github.com/hxx258456/fabric-gm/core/container/externalbuilder"
	"github.com/hxx258456/fabric-gm/core/ledger"
	"github.com/hxx258456/fabric-gm/core/ledger/kvledger"
	"github.com/hxx258456/fabric-gm/core/ledger/ledgermgmt"
	corepeer "github.com/hxx258456/fabric-gm/core/peer"
	"github.com/hxx258456/fabric-gm/core/scc/lscc"
	"github.com/hxx258456/fabric-gm/internal/fileutil"
	"github.com/hxx258456/fabric-gm/msp"
	"github.com/hxx258456/fabric-gm/msp/mgmt"
	"github.com/hxx258456/fabric-gm/protoutil"
	"github.com/hxx258456/fabric-protos-go-gm/common"
	"github.com/hxx258456/fabric-protos-go-gm/peer"
	"github.com/stretchr/testify/assert"
)

type rebuildable uint8

const (
	rebuildableStatedb       rebuildable = 1
	rebuildableBlockIndex    rebuildable = 2
	rebuildableConfigHistory rebuildable = 4
	rebuildableHistoryDB     rebuildable = 8
	rebuildableBookkeeper    rebuildable = 16
)

type env struct {
	assert      *assert.Assertions
	initializer *ledgermgmt.Initializer
	ledgerMgr   *ledgermgmt.LedgerMgr
}

func newEnv(t *testing.T) *env {
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)
	return newEnvWithInitializer(t, &ledgermgmt.Initializer{
		HashProvider: cryptoProvider,
		EbMetadataProvider: &externalbuilder.MetadataProvider{
			DurablePath: "testdata",
		},
	})
}

func newEnvWithInitializer(t *testing.T, initializer *ledgermgmt.Initializer) *env {
	populateMissingsWithTestDefaults(t, initializer)

	return &env{
		assert:      assert.New(t),
		initializer: initializer,
	}
}

func (e *env) cleanup() {
	if e.ledgerMgr != nil {
		e.ledgerMgr.Close()
	}
	// Ignore RemoveAll error because when a test mounts a dir to a couchdb container,
	// the mounted dir cannot be deleted in CI builds. This has no impact to CI because it gets a new VM for each build.
	// When running the test locally (macOS and linux VM), the mounted dirs are deleted without any error.
	os.RemoveAll(e.initializer.Config.RootFSPath)
}

func (e *env) closeAllLedgersAndRemoveDirContents(flags rebuildable) {
	if e.ledgerMgr != nil {
		e.ledgerMgr.Close()
	}
	defer e.initLedgerMgmt()

	if flags&rebuildableBlockIndex == rebuildableBlockIndex {
		indexPath := e.getBlockIndexDBPath()
		logger.Infof("Deleting blockstore indexdb path [%s]", indexPath)
		e.verifyNonEmptyDirExists(indexPath)
		e.assert.NoError(fileutil.RemoveContents(indexPath))
	}

	if flags&rebuildableStatedb == rebuildableStatedb {
		statedbPath := e.getLevelstateDBPath()
		logger.Infof("Deleting statedb path [%s]", statedbPath)
		e.verifyNonEmptyDirExists(statedbPath)
		e.assert.NoError(fileutil.RemoveContents(statedbPath))
	}

	if flags&rebuildableConfigHistory == rebuildableConfigHistory {
		configHistoryPath := e.getConfigHistoryDBPath()
		logger.Infof("Deleting configHistory db path [%s]", configHistoryPath)
		e.verifyNonEmptyDirExists(configHistoryPath)
		e.assert.NoError(fileutil.RemoveContents(configHistoryPath))
	}

	if flags&rebuildableBookkeeper == rebuildableBookkeeper {
		bookkeeperPath := e.getBookkeeperDBPath()
		logger.Infof("Deleting bookkeeper db path [%s]", bookkeeperPath)
		e.verifyNonEmptyDirExists(bookkeeperPath)
		e.assert.NoError(fileutil.RemoveContents(bookkeeperPath))
	}

	if flags&rebuildableHistoryDB == rebuildableHistoryDB {
		historyPath := e.getHistoryDBPath()
		logger.Infof("Deleting history db path [%s]", historyPath)
		e.verifyNonEmptyDirExists(historyPath)
		e.assert.NoError(fileutil.RemoveContents(historyPath))
	}

	e.verifyRebuilableDirEmpty(flags)
}

func (e *env) verifyRebuilablesExist(flags rebuildable) {
	if flags&rebuildableBlockIndex == rebuildableBlockIndex {
		e.verifyNonEmptyDirExists(e.getBlockIndexDBPath())
	}
	if flags&rebuildableStatedb == rebuildableStatedb {
		e.verifyNonEmptyDirExists(e.getLevelstateDBPath())
	}
	if flags&rebuildableConfigHistory == rebuildableConfigHistory {
		e.verifyNonEmptyDirExists(e.getConfigHistoryDBPath())
	}
	if flags&rebuildableBookkeeper == rebuildableBookkeeper {
		e.verifyNonEmptyDirExists(e.getBookkeeperDBPath())
	}
	if flags&rebuildableHistoryDB == rebuildableHistoryDB {
		e.verifyNonEmptyDirExists(e.getHistoryDBPath())
	}
}

func (e *env) verifyRebuilableDirEmpty(flags rebuildable) {
	if flags&rebuildableStatedb == rebuildableStatedb {
		e.verifyDirEmpty(e.getLevelstateDBPath())
	}
	if flags&rebuildableBlockIndex == rebuildableBlockIndex {
		e.verifyDirEmpty(e.getBlockIndexDBPath())
	}
	if flags&rebuildableConfigHistory == rebuildableConfigHistory {
		e.verifyDirEmpty(e.getConfigHistoryDBPath())
	}
	if flags&rebuildableBookkeeper == rebuildableBookkeeper {
		e.verifyDirEmpty(e.getBookkeeperDBPath())
	}
	if flags&rebuildableHistoryDB == rebuildableHistoryDB {
		e.verifyDirEmpty(e.getHistoryDBPath())
	}
}

func (e *env) verifyNonEmptyDirExists(path string) {
	empty, err := util.DirEmpty(path)
	e.assert.NoError(err)
	e.assert.False(empty)
}

func (e *env) verifyDirEmpty(path string) {
	empty, err := util.DirEmpty(path)
	e.assert.NoError(err)
	e.assert.True(empty)
}

func (e *env) initLedgerMgmt() {
	e.ledgerMgr = ledgermgmt.NewLedgerMgr(e.initializer)
}

func (e *env) closeLedgerMgmt() {
	e.ledgerMgr.Close()
}

func (e *env) getLevelstateDBPath() string {
	return kvledger.StateDBPath(e.initializer.Config.RootFSPath)
}

func (e *env) getBlockIndexDBPath() string {
	return filepath.Join(kvledger.BlockStorePath(e.initializer.Config.RootFSPath), blkstorage.IndexDir)
}

func (e *env) getConfigHistoryDBPath() string {
	return kvledger.ConfigHistoryDBPath(e.initializer.Config.RootFSPath)
}

func (e *env) getHistoryDBPath() string {
	return kvledger.HistoryDBPath(e.initializer.Config.RootFSPath)
}

func (e *env) getBookkeeperDBPath() string {
	return kvledger.BookkeeperDBPath(e.initializer.Config.RootFSPath)
}

func populateMissingsWithTestDefaults(t *testing.T, initializer *ledgermgmt.Initializer) {
	if initializer.CustomTxProcessors == nil {
		initializer.CustomTxProcessors = map[common.HeaderType]ledger.CustomTxProcessor{}
	}

	if initializer.DeployedChaincodeInfoProvider == nil {
		initializer.DeployedChaincodeInfoProvider = &lscc.DeployedCCInfoProvider{}
	}

	if initializer.MembershipInfoProvider == nil {
		identityDeserializerFactory := func(chainID string) msp.IdentityDeserializer {
			return mgmt.GetManagerForChain(chainID)
		}
		cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
		assert.NoError(t, err)
		mspID := "test-mspid"
		membershipInfoProvider := privdata.NewMembershipInfoProvider(mspID, createSelfSignedData(cryptoProvider), identityDeserializerFactory)
		initializer.MembershipInfoProvider = membershipInfoProvider
	}

	if initializer.MetricsProvider == nil {
		initializer.MetricsProvider = &disabled.Provider{}
	}

	if initializer.Config == nil || initializer.Config.RootFSPath == "" {
		rootPath, err := ioutil.TempDir("/tmp", "ledgersData")
		if err != nil {
			t.Fatalf("Failed to create root directory: %s", err)
		}

		initializer.Config = &ledger.Config{
			RootFSPath: rootPath,
		}
	}

	if initializer.Config.StateDBConfig == nil {
		initializer.Config.StateDBConfig = &ledger.StateDBConfig{
			StateDatabase: "goleveldb",
		}
	}

	if initializer.Config.HistoryDBConfig == nil {
		initializer.Config.HistoryDBConfig = &ledger.HistoryDBConfig{
			Enabled: true,
		}
	}

	if initializer.Config.PrivateDataConfig == nil {
		initializer.Config.PrivateDataConfig = &ledger.PrivateDataConfig{
			MaxBatchSize:                        5000,
			BatchesInterval:                     1000,
			PurgeInterval:                       100,
			DeprioritizedDataReconcilerInterval: 120 * time.Minute,
		}
	}
	if initializer.Config.SnapshotsConfig == nil {
		initializer.Config.SnapshotsConfig = &ledger.SnapshotsConfig{
			RootDir: filepath.Join(initializer.Config.RootFSPath, "snapshots"),
		}
	}
}

func createSelfSignedData(cryptoProvider bccsp.BCCSP) protoutil.SignedData {
	sID := mgmt.GetLocalSigningIdentityOrPanic(cryptoProvider)
	msg := make([]byte, 32)
	sig, err := sID.Sign(msg)
	if err != nil {
		logger.Panicf("Failed creating self signed data because message signing failed: %v", err)
	}
	peerIdentity, err := sID.Serialize()
	if err != nil {
		logger.Panicf("Failed creating self signed data because peer identity couldn't be serialized: %v", err)
	}
	return protoutil.SignedData{
		Data:      msg,
		Signature: sig,
		Identity:  peerIdentity,
	}
}

// deployedCCInfoProviderWrapper is a wrapper type that overrides ChaincodeImplicitCollections
type deployedCCInfoProviderWrapper struct {
	*lifecycle.ValidatorCommitter
	orgMSPIDs []string
}

// AllCollectionsConfigPkg overrides the same method in lifecycle.AllCollectionsConfigPkg.
// It is basically a copy of lifecycle.AllCollectionsConfigPkg and invokes ImplicitCollections in the wrapper.
// This method is called when the unit test code gets private data code path.
func (dc *deployedCCInfoProviderWrapper) AllCollectionsConfigPkg(channelName, chaincodeName string, qe ledger.SimpleQueryExecutor) (*peer.CollectionConfigPackage, error) {
	chaincodeInfo, err := dc.ChaincodeInfo(channelName, chaincodeName, qe)
	if err != nil {
		return nil, err
	}
	explicitCollectionConfigPkg := chaincodeInfo.ExplicitCollectionConfigPkg

	implicitCollections, _ := dc.ImplicitCollections(channelName, "", nil)

	var combinedColls []*peer.CollectionConfig
	if explicitCollectionConfigPkg != nil {
		combinedColls = append(combinedColls, explicitCollectionConfigPkg.Config...)
	}
	for _, implicitColl := range implicitCollections {
		c := &peer.CollectionConfig{}
		c.Payload = &peer.CollectionConfig_StaticCollectionConfig{StaticCollectionConfig: implicitColl}
		combinedColls = append(combinedColls, c)
	}
	return &peer.CollectionConfigPackage{
		Config: combinedColls,
	}, nil
}

// ImplicitCollections overrides the same method in lifecycle.ValidatorCommitter.
// It constructs static collection config using known mspids from the sample ledger.
// This method is called when the unit test code gets collection configuration.
func (dc *deployedCCInfoProviderWrapper) ImplicitCollections(channelName, chaincodeName string, qe ledger.SimpleQueryExecutor) ([]*peer.StaticCollectionConfig, error) {
	collConfigs := make([]*peer.StaticCollectionConfig, 0, len(dc.orgMSPIDs))
	for _, mspID := range dc.orgMSPIDs {
		collConfigs = append(collConfigs, dc.ValidatorCommitter.GenerateImplicitCollectionForOrg(mspID))
	}
	return collConfigs, nil
}

func createDeployedCCInfoProvider(orgMSPIDs []string) ledger.DeployedChaincodeInfoProvider {
	deployedCCInfoProvider := &lifecycle.ValidatorCommitter{
		CoreConfig: &corepeer.Config{},
		Resources: &lifecycle.Resources{
			Serializer: &lifecycle.Serializer{},
		},
		LegacyDeployedCCInfoProvider: &lscc.DeployedCCInfoProvider{},
	}
	return &deployedCCInfoProviderWrapper{
		ValidatorCommitter: deployedCCInfoProvider,
		orgMSPIDs:          orgMSPIDs,
	}
}
