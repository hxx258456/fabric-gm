/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blkstorage

import (
	"os"

	"github.com/hxx258456/fabric-gm/common/flogging"
	"github.com/hxx258456/fabric-gm/common/ledger/dataformat"
	"github.com/hxx258456/fabric-gm/common/ledger/util"
	"github.com/hxx258456/fabric-gm/common/ledger/util/leveldbhelper"
	"github.com/hxx258456/fabric-gm/common/metrics"
	"github.com/hxx258456/fabric-gm/core/ledger"
	"github.com/pkg/errors"
)

var logger = flogging.MustGetLogger("blkstorage")

// IndexableAttr represents an indexable attribute
type IndexableAttr string

// constants for indexable attributes
const (
	IndexableAttrBlockNum        = IndexableAttr("BlockNum")
	IndexableAttrBlockHash       = IndexableAttr("BlockHash")
	IndexableAttrTxID            = IndexableAttr("TxID")
	IndexableAttrBlockNumTranNum = IndexableAttr("BlockNumTranNum")
)

// IndexConfig - a configuration that includes a list of attributes that should be indexed
type IndexConfig struct {
	AttrsToIndex []IndexableAttr
}

// SnapshotInfo captures some of the details about the snapshot
type SnapshotInfo struct {
	LedgerID          string
	LastBlockNum      uint64
	LastBlockHash     []byte
	PreviousBlockHash []byte
}

// Contains returns true iff the supplied parameter is present in the IndexConfig.AttrsToIndex
func (c *IndexConfig) Contains(indexableAttr IndexableAttr) bool {
	for _, a := range c.AttrsToIndex {
		if a == indexableAttr {
			return true
		}
	}
	return false
}

var (
	// ErrNotFoundInIndex is used to indicate missing entry in the index
	ErrNotFoundInIndex = ledger.NotFoundInIndexErr("")

	// ErrAttrNotIndexed is used to indicate that an attribute is not indexed
	ErrAttrNotIndexed = errors.New("attribute not indexed")
)

// BlockStoreProvider provides handle to block storage - this is not thread-safe
type BlockStoreProvider struct {
	conf            *Conf
	indexConfig     *IndexConfig
	leveldbProvider *leveldbhelper.Provider
	stats           *stats
}

// NewProvider constructs a filesystem based block store provider
func NewProvider(conf *Conf, indexConfig *IndexConfig, metricsProvider metrics.Provider) (*BlockStoreProvider, error) {
	dbConf := &leveldbhelper.Conf{
		DBPath:         conf.getIndexDir(),
		ExpectedFormat: dataFormatVersion(indexConfig),
	}

	p, err := leveldbhelper.NewProvider(dbConf)
	if err != nil {
		return nil, err
	}

	dirPath := conf.getChainsDir()
	if _, err := os.Stat(dirPath); err != nil {
		if !os.IsNotExist(err) { // NotExist is the only permitted error type
			return nil, errors.Wrapf(err, "failed to read ledger directory %s", dirPath)
		}

		logger.Info("Creating new file ledger directory at", dirPath)
		if err = os.MkdirAll(dirPath, 0755); err != nil {
			return nil, errors.Wrapf(err, "failed to create ledger directory: %s", dirPath)
		}
	}

	stats := newStats(metricsProvider)
	return &BlockStoreProvider{conf, indexConfig, p, stats}, nil
}

// Open opens a block store for given ledgerid.
// If a blockstore is not existing, this method creates one
// This method should be invoked only once for a particular ledgerid
func (p *BlockStoreProvider) Open(ledgerid string) (*BlockStore, error) {
	indexStoreHandle := p.leveldbProvider.GetDBHandle(ledgerid)
	return newBlockStore(ledgerid, p.conf, p.indexConfig, indexStoreHandle, p.stats)
}

// BootstrapFromSnapshottedTxIDs initializes blockstore from a previously generated snapshot
// Any failure during bootstrapping the blockstore may leave the partial loaded data
// on disk. The consumer, such as peer is expected to keep track of failures and cleanup the
// data explicitly.
func (p *BlockStoreProvider) BootstrapFromSnapshottedTxIDs(
	snapshotDir string, snapshotInfo *SnapshotInfo) (*BlockStore, error) {
	indexStoreHandle := p.leveldbProvider.GetDBHandle(snapshotInfo.LedgerID)
	if err := bootstrapFromSnapshottedTxIDs(snapshotDir, snapshotInfo, p.conf, indexStoreHandle); err != nil {
		return nil, err
	}
	return newBlockStore(snapshotInfo.LedgerID, p.conf, p.indexConfig, indexStoreHandle, p.stats)
}

// Exists tells whether the BlockStore with given id exists
func (p *BlockStoreProvider) Exists(ledgerid string) (bool, error) {
	exists, _, err := util.FileExists(p.conf.getLedgerBlockDir(ledgerid))
	return exists, err
}

// Remove block index and blocks for the given ledgerid (channelID). It is not an error if the channel does not exist.
// This function is not error safe. If this function returns an error or a crash takes place, it is highly likely
// that the data for this ledger is left in an inconsistent state. Opening the ledger again or reusing the previously
// opened ledger can show unknown behavior.
func (p *BlockStoreProvider) Remove(ledgerid string) error {
	exists, err := p.Exists(ledgerid)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	dbHandle := p.leveldbProvider.GetDBHandle(ledgerid)
	if err := dbHandle.DeleteAll(); err != nil {
		return err
	}
	dbHandle.Close()
	if err := os.RemoveAll(p.conf.getLedgerBlockDir(ledgerid)); err != nil {
		return err
	}
	return syncDir(p.conf.getChainsDir())
}

// List lists the ids of the existing ledgers
func (p *BlockStoreProvider) List() ([]string, error) {
	return util.ListSubdirs(p.conf.getChainsDir())
}

// Close closes the BlockStoreProvider
func (p *BlockStoreProvider) Close() {
	p.leveldbProvider.Close()
}

func dataFormatVersion(indexConfig *IndexConfig) string {
	// in version 2.0 we merged three indexable into one `IndexableAttrTxID`
	if indexConfig.Contains(IndexableAttrTxID) {
		return dataformat.CurrentFormat
	}
	return dataformat.PreviousFormat
}
