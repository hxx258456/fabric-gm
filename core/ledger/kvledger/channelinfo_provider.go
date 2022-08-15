/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kvledger

import (
	cb "gitee.com/zhaochuninhefei/fabric-protos-go-gm/common"
	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/ledger/queryresult"
	"github.com/hxx258456/fabric-gm/bccsp/factory"
	"github.com/hxx258456/fabric-gm/common/channelconfig"
	commonledger "github.com/hxx258456/fabric-gm/common/ledger"
	"github.com/hxx258456/fabric-gm/common/ledger/blkstorage"
	"github.com/hxx258456/fabric-gm/core/ledger"
	"github.com/hxx258456/fabric-gm/core/ledger/kvledger/txmgmt/statedb"
	"github.com/hxx258456/fabric-gm/protoutil"
	"github.com/pkg/errors"
)

type channelInfoProvider struct {
	channelName string
	blockStore  *blkstorage.BlockStore
	ledger.DeployedChaincodeInfoProvider
}

// NamespacesAndCollections returns namespaces and their collections for the channel.
func (p *channelInfoProvider) NamespacesAndCollections(vdb statedb.VersionedDB) (map[string][]string, error) {
	mspIDs, err := p.getAllMSPIDs()
	if err != nil {
		return nil, err
	}
	implicitCollNames := make([]string, len(mspIDs))
	for i, mspID := range mspIDs {
		implicitCollNames[i] = p.GenerateImplicitCollectionForOrg(mspID).Name
	}
	chaincodesInfo, err := p.AllChaincodesInfo(p.channelName, &simpleQueryExecutor{vdb})
	if err != nil {
		return nil, err
	}

	retNamespaces := map[string][]string{}
	// iterate each chaincode, add implicit collections and explicit collections
	for _, ccInfo := range chaincodesInfo {
		ccName := ccInfo.Name
		retNamespaces[ccName] = []string{}
		for _, implicitCollName := range implicitCollNames {
			retNamespaces[ccName] = append(retNamespaces[ccName], implicitCollName)
		}
		if ccInfo.ExplicitCollectionConfigPkg == nil {
			continue
		}
		for _, config := range ccInfo.ExplicitCollectionConfigPkg.Config {
			collConfig := config.GetStaticCollectionConfig()
			if collConfig != nil {
				retNamespaces[ccName] = append(retNamespaces[ccName], collConfig.Name)
			}
		}
	}

	// add lifecycle management namespaces with implicit collections (not applicable to legacy lifecycle)
	for _, ns := range p.Namespaces() {
		retNamespaces[ns] = []string{}
		if ns == "lscc" {
			continue
		}
		for _, implicitCollName := range implicitCollNames {
			retNamespaces[ns] = append(retNamespaces[ns], implicitCollName)
		}
	}

	// add namespace ""
	retNamespaces[""] = []string{}
	return retNamespaces, nil
}

// getAllMSPIDs retrieves the MSPIDs of application organizations in all the channel configurations,
// including current and previous channel configurations.
func (p *channelInfoProvider) getAllMSPIDs() ([]string, error) {
	blockchainInfo, err := p.blockStore.GetBlockchainInfo()
	if err != nil {
		return nil, err
	}
	if blockchainInfo.Height == 0 {
		return nil, nil
	}

	// Iterate over the config blocks to get all the channel configs, extract MSPIDs and add to mspidsMap
	mspidsMap := map[string]struct{}{}
	blockNum := blockchainInfo.Height - 1
	for {
		configBlock, err := p.mostRecentConfigBlockAsOf(blockNum)
		if err != nil {
			return nil, err
		}

		mspids, err := channelconfig.ExtractMSPIDsForApplicationOrgs(configBlock, factory.GetDefault())
		if err != nil {
			return nil, err
		}
		for _, mspid := range mspids {
			if _, ok := mspidsMap[mspid]; !ok {
				mspidsMap[mspid] = struct{}{}
			}
		}

		if configBlock.Header.Number == 0 {
			break
		}
		blockNum = configBlock.Header.Number - 1
	}

	mspids := make([]string, 0, len(mspidsMap))
	for mspid := range mspidsMap {
		mspids = append(mspids, mspid)
	}
	return mspids, nil
}

// mostRecentConfigBlockAsOf fetches the most recent config block at or below the blockNum
func (p *channelInfoProvider) mostRecentConfigBlockAsOf(blockNum uint64) (*cb.Block, error) {
	block, err := p.blockStore.RetrieveBlockByNumber(blockNum)
	if err != nil {
		return nil, err
	}
	configBlockNum, err := protoutil.GetLastConfigIndexFromBlock(block)
	if err != nil {
		return nil, err
	}
	return p.blockStore.RetrieveBlockByNumber(configBlockNum)
}

// simpleQueryExecutor implements ledger.SimpleQueryExecutor interface
type simpleQueryExecutor struct {
	statedb.VersionedDB
}

func (sqe *simpleQueryExecutor) GetState(ns string, key string) ([]byte, error) {
	versionedValue, err := sqe.VersionedDB.GetState(ns, key)
	if err != nil {
		return nil, err
	}
	var value []byte
	if versionedValue != nil {
		value = versionedValue.Value
	}
	return value, nil
}

func (sqe *simpleQueryExecutor) GetStateRangeScanIterator(ns string, startKey string, endKey string) (commonledger.ResultsIterator, error) {
	dbItr, err := sqe.VersionedDB.GetStateRangeScanIterator(ns, startKey, endKey)
	if err != nil {
		return nil, err
	}
	itr := &resultsItr{ns: ns, dbItr: dbItr}
	return itr, nil
}

// GetPrivateDataHash is not implemented and should not be called
func (sqe *simpleQueryExecutor) GetPrivateDataHash(namespace, collection, key string) ([]byte, error) {
	return nil, errors.New("not implemented yet")
}

type resultsItr struct {
	ns    string
	dbItr statedb.ResultsIterator
}

// Next implements method in interface ledger.ResultsIterator
func (itr *resultsItr) Next() (commonledger.QueryResult, error) {
	queryResult, err := itr.dbItr.Next()
	if err != nil {
		return nil, err
	}
	// itr.updateRangeQueryInfo(queryResult)
	if queryResult == nil {
		return nil, nil
	}
	versionedKV := queryResult.(*statedb.VersionedKV)
	return &queryresult.KV{Namespace: versionedKV.Namespace, Key: versionedKV.Key, Value: versionedKV.Value}, nil
}

// Close implements method in interface ledger.ResultsIterator
func (itr *resultsItr) Close() {
	itr.dbItr.Close()
}
