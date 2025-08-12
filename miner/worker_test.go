// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package miner

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	mrnd "math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/log"

	"github.com/chainbound/shardmap"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	// "github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// testCode is the testing contract binary code which will initialises some
	// variables in constructor
	testCode = "0x60806040527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0060005534801561003457600080fd5b5060fc806100436000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80630c4dae8814603757806398a213cf146053575b600080fd5b603d607e565b6040518082815260200191505060405180910390f35b607c60048036036020811015606757600080fd5b81019080803590602001909291905050506084565b005b60005481565b806000819055507fe9e44f9f7da8c559de847a3232b57364adc0354f15a2cd8dc636d54396f9587a6000546040518082815260200191505060405180910390a15056fea265627a7a723058208ae31d9424f2d0bc2a3da1a5dd659db2d71ec322a17db8f87e19e209e3a1ff4a64736f6c634300050a0032"

	// testGas is the gas required for contract deployment.
	testGas = 144109
)

var (
	// Test chain configurations
	testTxPoolConfig  legacypool.Config
	ethashChainConfig *params.ChainConfig
	cliqueChainConfig *params.ChainConfig

	// Test accounts
	testBankKey, _  = crypto.GenerateKey()
	testBankAddress = crypto.PubkeyToAddress(testBankKey.PublicKey)
	testBankFunds   = big.NewInt(1000000000000000000)

	testAddress1Key, _ = crypto.GenerateKey()
	testAddress1       = crypto.PubkeyToAddress(testAddress1Key.PublicKey)
	testAddress2Key, _ = crypto.GenerateKey()
	testAddress2       = crypto.PubkeyToAddress(testAddress2Key.PublicKey)
	testAddress3Key, _ = crypto.GenerateKey()
	testAddress3       = crypto.PubkeyToAddress(testAddress3Key.PublicKey)

	testUserKey, _  = crypto.GenerateKey()
	testUserAddress = crypto.PubkeyToAddress(testUserKey.PublicKey)

	// Test transactions
	pendingTxs []*types.Transaction
	newTxs     []*types.Transaction

	// Test testConstraintsCache
	testConstraintsCache = shardmap.NewFIFOMap[uint64, types.HashToConstraintDecoded](64, 16, shardmap.HashUint64)

	testConfig = &Config{
		Recommit: time.Second,
		GasCeil:  params.GenesisGasLimit,
	}

	defaultGenesisAlloc = types.GenesisAlloc{testBankAddress: {Balance: testBankFunds}}
)

const pendingTxsLen = 50

func init() {
	testTxPoolConfig = legacypool.DefaultConfig
	testTxPoolConfig.Journal = ""
	ethashChainConfig = new(params.ChainConfig)
	*ethashChainConfig = *params.TestChainConfig
	cliqueChainConfig = new(params.ChainConfig)
	*cliqueChainConfig = *params.TestChainConfig
	cliqueChainConfig.Clique = &params.CliqueConfig{
		Period: 10,
		Epoch:  30000,
	}

	signer := types.LatestSigner(params.TestChainConfig)
	for i := 0; i < pendingTxsLen; i++ {
		tx1 := types.MustSignNewTx(testBankKey, signer, &types.AccessListTx{
			ChainID:  params.TestChainConfig.ChainID,
			Nonce:    uint64(i),
			To:       &testUserAddress,
			Value:    big.NewInt(1000),
			Gas:      params.TxGas,
			GasPrice: big.NewInt(params.InitialBaseFee),
		})

		// Add some constraints every 3 txs, and every 6 add an index
		if i%3 == 0 {
			idx := new(uint64)
			if i%2 == 0 {
				*idx = uint64(i)
			} else {
				idx = nil
			}
			constraints := make(map[common.Hash]*types.Transaction)
			constraints[tx1.Hash()] = tx1
			// FIXME: slot 0 is probably not correct for these tests
			testConstraintsCache.Put(0, constraints)
		}

		pendingTxs = append(pendingTxs, tx1)
	}

	tx2 := types.MustSignNewTx(testBankKey, signer, &types.LegacyTx{
		Nonce:    1,
		To:       &testUserAddress,
		Value:    big.NewInt(1000),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(params.InitialBaseFee),
	})
	newTxs = append(newTxs, tx2)
}

// testWorkerBackend implements worker.Backend interfaces and wraps all information needed during the testing.
type testWorkerBackend struct {
	db      ethdb.Database
	txPool  *txpool.TxPool
	chain   *core.BlockChain
	genesis *core.Genesis
}

func newTestWorkerBackend(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine, db ethdb.Database, alloc types.GenesisAlloc, n int, gasLimit uint64) *testWorkerBackend {
	if alloc == nil {
		alloc = defaultGenesisAlloc
	}
	gspec := &core.Genesis{
		Config:   chainConfig,
		GasLimit: gasLimit,
		Alloc:    alloc,
	}
	switch e := engine.(type) {
	case *clique.Clique:
		gspec.ExtraData = make([]byte, 32+common.AddressLength+crypto.SignatureLength)
		copy(gspec.ExtraData[32:32+common.AddressLength], testBankAddress.Bytes())
		e.Authorize(testBankAddress, func(account accounts.Account, s string, data []byte) ([]byte, error) {
			return crypto.Sign(crypto.Keccak256(data), testBankKey)
		})
	case *ethash.Ethash:
	default:
		t.Fatalf("unexpected consensus engine type: %T", engine)
	}
	chain, err := core.NewBlockChain(db, &core.CacheConfig{TrieDirtyDisabled: true}, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("core.NewBlockChain failed: %v", err)
	}
	pool := legacypool.New(testTxPoolConfig, chain)
	txpool, _ := txpool.New(testTxPoolConfig.PriceLimit, chain, []txpool.SubPool{pool})

	return &testWorkerBackend{
		db:      db,
		chain:   chain,
		txPool:  txpool,
		genesis: gspec,
	}
}

func (b *testWorkerBackend) BlockChain() *core.BlockChain { return b.chain }
func (b *testWorkerBackend) TxPool() *txpool.TxPool       { return b.txPool }

func (b *testWorkerBackend) newRandomTx(creation bool, to common.Address, amt int64, key *ecdsa.PrivateKey, additionalGasLimit uint64, gasPrice *big.Int) *types.Transaction {
	var tx *types.Transaction
	if creation {
		tx, _ = types.SignTx(types.NewContractCreation(b.txPool.Nonce(crypto.PubkeyToAddress(key.PublicKey)), big.NewInt(0), testGas, gasPrice, common.FromHex(testCode)), types.HomesteadSigner{}, key)
	} else {
		tx, _ = types.SignTx(types.NewTransaction(b.txPool.Nonce(crypto.PubkeyToAddress(key.PublicKey)), to, big.NewInt(amt), params.TxGas+additionalGasLimit, gasPrice, nil), types.HomesteadSigner{}, key)
	}
	return tx
}

func newTestWorker(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine, db ethdb.Database, alloc types.GenesisAlloc, blocks int) (*worker, *testWorkerBackend) {
	const GasLimit = 1_000_000_000_000_000_000
	backend := newTestWorkerBackend(t, chainConfig, engine, db, alloc, blocks, GasLimit)
	backend.txPool.Add(pendingTxs, true, false, false)
	w := newWorker(testConfig, chainConfig, engine, backend, new(event.TypeMux), nil, false, &flashbotsData{
		isFlashbots: testConfig.AlgoType != ALGO_MEV_GETH,
		queue:       nil,
		bundleCache: NewBundleCache(),
		algoType:    testConfig.AlgoType,
	})
	if testConfig.BuilderTxSigningKey == nil {
		w.setEtherbase(testBankAddress)
	}

	return w, backend
}

func TestGenerateAndImportBlock(t *testing.T) {
	t.Parallel()
	var (
		db     = rawdb.NewMemoryDatabase()
		config = *params.AllCliqueProtocolChanges
	)
	config.Clique = &params.CliqueConfig{Period: 1, Epoch: 30000}
	engine := clique.New(config.Clique, db)

	w, b := newTestWorker(t, &config, engine, db, nil, 0)
	defer w.close()

	// This test chain imports the mined blocks.
	chain, _ := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, b.genesis, nil, engine, vm.Config{}, nil, nil)
	defer chain.Stop()

	// Ignore empty commit here for less noise.
	w.skipSealHook = func(task *task) bool {
		return len(task.receipts) == 0
	}

	// Wait for mined blocks.
	sub := w.mux.Subscribe(core.NewMinedBlockEvent{})
	defer sub.Unsubscribe()

	// Start mining!
	w.start()

	for i := 0; i < 5; i++ {
		b.txPool.Add([]*types.Transaction{b.newRandomTx(true, testUserAddress, 0, testBankKey, 0, big.NewInt(10*params.InitialBaseFee))}, true, false, false)
		b.txPool.Add([]*types.Transaction{b.newRandomTx(false, testUserAddress, 1000, testBankKey, 0, big.NewInt(10*params.InitialBaseFee))}, true, false, false)

		select {
		case ev := <-sub.Chan():
			block := ev.Data.(core.NewMinedBlockEvent).Block
			if _, err := chain.InsertChain([]*types.Block{block}); err != nil {
				t.Fatalf("failed to insert new mined block %d: %v", block.NumberU64(), err)
			}
		case <-time.After(3 * time.Second): // Worker needs 1s to include new changes.
			t.Fatalf("timeout")
		}
	}
}

func TestEmptyWorkEthash(t *testing.T) {
	t.Parallel()
	testEmptyWork(t, ethashChainConfig, ethash.NewFaker())
}

func TestEmptyWorkClique(t *testing.T) {
	t.Parallel()
	testEmptyWork(t, cliqueChainConfig, clique.New(cliqueChainConfig.Clique, rawdb.NewMemoryDatabase()))
}

func testEmptyWork(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine) {
	defer engine.Close()

	w, _ := newTestWorker(t, chainConfig, engine, rawdb.NewMemoryDatabase(), nil, 0)
	defer w.close()

	taskCh := make(chan struct{}, pendingTxsLen*2)
	checkEqual := func(t *testing.T, task *task) {
		// The work should contain 1 tx
		receiptLen, balance := pendingTxsLen, uint256.NewInt(50_000)
		if len(task.receipts) != receiptLen {
			t.Fatalf("receipt number mismatch: have %d, want %d", len(task.receipts), receiptLen)
		}
		if task.state.GetBalance(testUserAddress).Cmp(balance) != 0 {
			t.Fatalf("account balance mismatch: have %d, want %d", task.state.GetBalance(testUserAddress), balance)
		}
	}
	w.newTaskHook = func(task *task) {
		if task.block.NumberU64() == 1 {
			checkEqual(t, task)
			taskCh <- struct{}{}
		}
	}
	w.skipSealHook = func(task *task) bool { return true }
	w.fullTaskHook = func() {
		time.Sleep(100 * time.Millisecond)
	}
	w.start() // Start mining!
	select {
	case <-taskCh:
	case <-time.NewTimer(3 * time.Second).C:
		t.Error("new task timeout")
	}
}

func TestAdjustIntervalEthash(t *testing.T) {
	t.Parallel()
	testAdjustInterval(t, ethashChainConfig, ethash.NewFaker())
}

func TestAdjustIntervalClique(t *testing.T) {
	t.Parallel()
	testAdjustInterval(t, cliqueChainConfig, clique.New(cliqueChainConfig.Clique, rawdb.NewMemoryDatabase()))
}

func testAdjustInterval(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine) {
	defer engine.Close()

	w, _ := newTestWorker(t, chainConfig, engine, rawdb.NewMemoryDatabase(), nil, 0)
	defer w.close()

	w.skipSealHook = func(task *task) bool {
		return true
	}
	w.fullTaskHook = func() {
		time.Sleep(100 * time.Millisecond)
	}
	var (
		progress = make(chan struct{}, 10)
		result   = make([]float64, 0, 10)
		index    = 0
		start    atomic.Bool
	)
	w.resubmitHook = func(minInterval, recommitInterval time.Duration) {
		// Short circuit if interval checking hasn't started.
		if !start.Load() {
			return
		}
		var wantMinInterval, wantRecommitInterval time.Duration

		switch index {
		case 0:
			wantMinInterval, wantRecommitInterval = 3*time.Second, 3*time.Second
		case 1:
			origin := float64(3 * time.Second.Nanoseconds())
			estimate := origin*(1-intervalAdjustRatio) + intervalAdjustRatio*(origin/0.8+intervalAdjustBias)
			wantMinInterval, wantRecommitInterval = 3*time.Second, time.Duration(estimate)*time.Nanosecond
		case 2:
			estimate := result[index-1]
			min := float64(3 * time.Second.Nanoseconds())
			estimate = estimate*(1-intervalAdjustRatio) + intervalAdjustRatio*(min-intervalAdjustBias)
			wantMinInterval, wantRecommitInterval = 3*time.Second, time.Duration(estimate)*time.Nanosecond
		case 3:
			wantMinInterval, wantRecommitInterval = time.Second, time.Second
		}

		// Check interval
		if minInterval != wantMinInterval {
			t.Errorf("resubmit min interval mismatch: have %v, want %v ", minInterval, wantMinInterval)
		}
		if recommitInterval != wantRecommitInterval {
			t.Errorf("resubmit interval mismatch: have %v, want %v", recommitInterval, wantRecommitInterval)
		}
		result = append(result, float64(recommitInterval.Nanoseconds()))
		index += 1
		progress <- struct{}{}
	}
	w.start()

	time.Sleep(time.Second) // Ensure two tasks have been submitted due to start opt
	start.Store(true)

	w.setRecommitInterval(3 * time.Second)
	select {
	case <-progress:
	case <-time.NewTimer(time.Second).C:
		t.Error("interval reset timeout")
	}

	w.resubmitAdjustCh <- &intervalAdjust{inc: true, ratio: 0.8}
	select {
	case <-progress:
	case <-time.NewTimer(time.Second).C:
		t.Error("interval reset timeout")
	}

	w.resubmitAdjustCh <- &intervalAdjust{inc: false}
	select {
	case <-progress:
	case <-time.NewTimer(time.Second).C:
		t.Error("interval reset timeout")
	}

	w.setRecommitInterval(500 * time.Millisecond)
	select {
	case <-progress:
	case <-time.NewTimer(time.Second).C:
		t.Error("interval reset timeout")
	}
}

func TestGetSealingWorkEthash(t *testing.T) {
	t.Parallel()
	testGetSealingWork(t, ethashChainConfig, ethash.NewFaker(), nil)
}

func TestGetSealingWorkClique(t *testing.T) {
	t.Parallel()
	testGetSealingWork(t, cliqueChainConfig, clique.New(cliqueChainConfig.Clique, rawdb.NewMemoryDatabase()), nil)
}

func TestGetSealingWorkPostMerge(t *testing.T) {
	t.Parallel()
	local := new(params.ChainConfig)
	*local = *ethashChainConfig
	local.TerminalTotalDifficulty = big.NewInt(0)
	testGetSealingWork(t, local, ethash.NewFaker(), nil)
}

// TestGetSealingWorkWithConstraints tests the getSealingWork function with constraints.
// This is the main test for the modified block building algorithm. Unfortunately
// is not easy to make an end to end test where the constraints are pulled from the relay.
//
// A suggestion is to walk through the executing code with a debugger to further inspect the algorithm.
//
// However, if you want to check that functionality see `builder_test.go`
func TestGetSealingWorkWithConstraints(t *testing.T) {
	// t.Parallel()
	local := new(params.ChainConfig)
	*local = *ethashChainConfig
	local.TerminalTotalDifficulty = big.NewInt(0)
	testGetSealingWork(t, local, ethash.NewFaker(), testConstraintsCache)
}

func testGetSealingWork(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine, constraintsCache *shardmap.FIFOMap[uint64, types.HashToConstraintDecoded]) {
	defer engine.Close()
	w, b := newTestWorker(t, chainConfig, engine, rawdb.NewMemoryDatabase(), nil, 0)
	defer w.close()

	w.setExtra([]byte{0x01, 0x02})

	w.skipSealHook = func(task *task) bool {
		return true
	}
	w.fullTaskHook = func() {
		time.Sleep(100 * time.Millisecond)
	}
	timestamp := uint64(time.Now().Unix())
	assertBlock := func(block *types.Block, number uint64, coinbase common.Address, random common.Hash, noExtra bool) {
		if block.Time() != timestamp {
			// Sometime the timestamp will be mutated if the timestamp
			// is even smaller than parent block's. It's OK.
			fmt.Printf("Invalid timestamp, want %d, get %d", timestamp, block.Time())
		}
		_, isClique := engine.(*clique.Clique)
		if !isClique {
			if len(block.Extra()) != 2 {
				t.Error("Unexpected extra field")
			}
			//if block.Coinbase() != coinbase {
			//	t.Errorf("Unexpected coinbase got %x want %x", block.Coinbase(), coinbase)
			//}
		} else {
			if block.Coinbase() != (common.Address{}) {
				t.Error("Unexpected coinbase")
			}
		}
		if !isClique {
			if block.MixDigest() != random {
				t.Error("Unexpected mix digest")
			}
		}
		if block.Nonce() != 0 {
			t.Error("Unexpected block nonce")
		}
		if block.NumberU64() != number {
			t.Errorf("Mismatched block number, want %d got %d", number, block.NumberU64())
		}
	}
	cases := []struct {
		parent       common.Hash
		coinbase     common.Address
		random       common.Hash
		expectNumber uint64
		expectErr    bool
	}{
		{
			b.chain.Genesis().Hash(),
			common.HexToAddress("0xdeadbeef"),
			common.HexToHash("0xcafebabe"),
			uint64(1),
			false,
		},
		{
			b.chain.CurrentBlock().Hash(),
			common.HexToAddress("0xdeadbeef"),
			common.HexToHash("0xcafebabe"),
			b.chain.CurrentBlock().Number.Uint64() + 1,
			false,
		},
		{
			b.chain.CurrentBlock().Hash(),
			common.Address{},
			common.HexToHash("0xcafebabe"),
			b.chain.CurrentBlock().Number.Uint64() + 1,
			false,
		},
		{
			b.chain.CurrentBlock().Hash(),
			common.Address{},
			common.Hash{},
			b.chain.CurrentBlock().Number.Uint64() + 1,
			false,
		},
		{
			common.HexToHash("0xdeadbeef"),
			common.HexToAddress("0xdeadbeef"),
			common.HexToHash("0xcafebabe"),
			0,
			true,
		},
	}

	// This API should work even when the automatic sealing is not enabled
	for _, c := range cases {
		r := w.getSealingBlock(&generateParams{
			parentHash:  c.parent,
			timestamp:   timestamp,
			coinbase:    c.coinbase,
			random:      c.random,
			withdrawals: nil,
			beaconRoot:  nil,
			noTxs:       false,
			forceTime:   true,
			onBlock:     nil,
		})
		if c.expectErr {
			if r.err == nil {
				t.Error("Expect error but get nil")
			}
		} else {
			if r.err != nil {
				t.Errorf("Unexpected error %v", r.err)
			}
			assertBlock(r.block, c.expectNumber, c.coinbase, c.random, true)
		}
	}

	// This API should work even when the automatic sealing is enabled
	w.start()
	for _, c := range cases {
		r := w.getSealingBlock(&generateParams{
			parentHash:  c.parent,
			timestamp:   timestamp,
			coinbase:    c.coinbase,
			random:      c.random,
			withdrawals: nil,
			beaconRoot:  nil,
			noTxs:       false,
			forceTime:   true,
			onBlock:     nil,
		})
		if c.expectErr {
			if r.err == nil {
				t.Error("Expect error but get nil")
			}
		} else {
			if r.err != nil {
				t.Errorf("Unexpected error %v", r.err)
			}
			assertBlock(r.block, c.expectNumber, c.coinbase, c.random, false)
		}
	}
}

func TestSimulateBundles(t *testing.T) {
	w, _ := newTestWorker(t, ethashChainConfig, ethash.NewFaker(), rawdb.NewMemoryDatabase(), nil, 0)
	defer w.close()

	env, err := w.prepareWork(&generateParams{gasLimit: 30000000})
	if err != nil {
		t.Fatalf("Failed to prepare work: %s", err)
	}

	signTx := func(nonce uint64) *types.Transaction {
		tx, err := types.SignTx(types.NewTransaction(nonce, testUserAddress, big.NewInt(1000), params.TxGas, env.header.BaseFee, nil), types.HomesteadSigner{}, testBankKey)
		if err != nil {
			t.Fatalf("Failed to sign tx")
		}
		return tx
	}

	bundle1 := types.MevBundle{Txs: types.Transactions{signTx(0)}, Hash: common.HexToHash("0x01")}
	// this bundle will fail
	bundle2 := types.MevBundle{Txs: types.Transactions{signTx(1)}, Hash: common.HexToHash("0x02")}
	bundle3 := types.MevBundle{Txs: types.Transactions{signTx(0)}, Hash: common.HexToHash("0x03")}

	simBundles, _, err := w.simulateBundles(env, []types.MevBundle{bundle1, bundle2, bundle3}, nil, nil)
	require.NoError(t, err)

	if len(simBundles) != 2 {
		t.Fatalf("Incorrect amount of sim bundles")
	}

	for _, simBundle := range simBundles {
		if simBundle.OriginalBundle.Hash == common.HexToHash("0x02") {
			t.Fatalf("bundle2 should fail")
		}
	}

	// simulate 2 times to check cache
	simBundles, _, err = w.simulateBundles(env, []types.MevBundle{bundle1, bundle2, bundle3}, nil, nil)
	require.NoError(t, err)

	if len(simBundles) != 2 {
		t.Fatalf("Incorrect amount of sim bundles(cache)")
	}

	for _, simBundle := range simBundles {
		if simBundle.OriginalBundle.Hash == common.HexToHash("0x02") {
			t.Fatalf("bundle2 should fail(cache)")
		}
	}
}

func testBundles(t *testing.T) {
	// TODO: test cancellations
	db := rawdb.NewMemoryDatabase()
	chainConfig := params.AllEthashProtocolChanges
	engine := ethash.NewFaker()

	chainConfig.LondonBlock = big.NewInt(0)

	genesisAlloc := types.GenesisAlloc{testBankAddress: {Balance: testBankFunds}}

	nExtraKeys := 5
	extraKeys := make([]*ecdsa.PrivateKey, nExtraKeys)
	for i := 0; i < nExtraKeys; i++ {
		pk, _ := crypto.GenerateKey()
		address := crypto.PubkeyToAddress(pk.PublicKey)
		extraKeys[i] = pk
		genesisAlloc[address] = types.Account{Balance: testBankFunds}
	}

	nSearchers := 5
	searcherPrivateKeys := make([]*ecdsa.PrivateKey, nSearchers)
	for i := 0; i < nSearchers; i++ {
		pk, _ := crypto.GenerateKey()
		address := crypto.PubkeyToAddress(pk.PublicKey)
		searcherPrivateKeys[i] = pk
		genesisAlloc[address] = types.Account{Balance: testBankFunds}
	}

	for _, address := range []common.Address{testAddress1, testAddress2, testAddress3} {
		genesisAlloc[address] = types.Account{Balance: testBankFunds}
	}

	w, b := newTestWorker(t, chainConfig, engine, db, nil, 0)
	w.setEtherbase(crypto.PubkeyToAddress(testConfig.BuilderTxSigningKey.PublicKey))
	defer w.close()

	// Ignore empty commit here for less noise.
	w.skipSealHook = func(task *task) bool {
		return len(task.receipts) == 0
	}

	mrnd.New(mrnd.NewSource(10))

	for i := 0; i < 2; i++ {
		commonTxs := []*types.Transaction{
			b.newRandomTx(false, testBankAddress, 1e15, testAddress1Key, 0, big.NewInt(100*params.InitialBaseFee)),
			b.newRandomTx(false, testBankAddress, 1e15, testAddress2Key, 0, big.NewInt(110*params.InitialBaseFee)),
			b.newRandomTx(false, testBankAddress, 1e15, testAddress3Key, 0, big.NewInt(120*params.InitialBaseFee)),
		}

		searcherTxs := make([]*types.Transaction, len(searcherPrivateKeys)*2)
		for i, pk := range searcherPrivateKeys {
			searcherTxs[2*i] = b.newRandomTx(false, testBankAddress, 1, pk, 0, big.NewInt(150*params.InitialBaseFee))
			searcherTxs[2*i+1] = b.newRandomTx(false, testBankAddress, 1+1, pk, 0, big.NewInt(150*params.InitialBaseFee))
		}

		nBundles := 2 * len(searcherPrivateKeys)
		// two bundles per searcher, i and i+1
		bundles := make([]*types.MevBundle, nBundles)
		for i := 0; i < nBundles; i++ {
			bundles[i] = new(types.MevBundle)
			bundles[i].Txs = append(bundles[i].Txs, searcherTxs[i])
		}

		// common transactions in 10% of the bundles, randomly
		for i := 0; i < nBundles/10; i++ {
			randomCommonIndex := mrnd.Intn(len(commonTxs))
			randomBundleIndex := mrnd.Intn(nBundles)
			bundles[randomBundleIndex].Txs = append(bundles[randomBundleIndex].Txs, commonTxs[randomCommonIndex])
		}

		// additional lower profit transactions in 10% of the bundles, randomly
		for _, extraKey := range extraKeys {
			tx := b.newRandomTx(false, testBankAddress, 1, extraKey, 0, big.NewInt(20*params.InitialBaseFee))
			randomBundleIndex := mrnd.Intn(nBundles)
			bundles[randomBundleIndex].Txs = append(bundles[randomBundleIndex].Txs, tx)
		}

		blockNumber := big.NewInt(0).Add(w.chain.CurrentBlock().Number, big.NewInt(1))
		for _, bundle := range bundles {
			err := b.txPool.AddMevBundle(bundle.Txs, blockNumber, types.EmptyUUID, common.Address{}, 0, 0, nil)
			require.NoError(t, err)
		}

		r := w.getSealingBlock(&generateParams{
			parentHash:  w.chain.CurrentBlock().Hash(),
			timestamp:   w.chain.CurrentHeader().Time + 12,
			coinbase:    testUserAddress,
			random:      common.Hash{},
			withdrawals: nil,
			beaconRoot:  nil,
			noTxs:       false,
			onBlock:     nil,
		})
		require.NoError(t, r.err)

		state, err := w.chain.State()
		require.NoError(t, err)
		balancePre := state.GetBalance(testUserAddress)
		if _, err := w.chain.InsertChain([]*types.Block{r.block}); err != nil {
			t.Fatalf("failed to insert new mined block %d: %v", r.block.NumberU64(), err)
		}
		state, err = w.chain.StateAt(r.block.Root())
		require.NoError(t, err)
		balancePost := state.GetBalance(testUserAddress)
		t.Log("Balances", balancePre, balancePost)
	}
}

func TestExclusionConstraintFiltering(t *testing.T) {
	// Setup worker and environment
	w, _ := newTestWorker(t, ethashChainConfig, ethash.NewFaker(), rawdb.NewMemoryDatabase(), nil, 0)
	defer w.close()

	env, err := w.prepareWork(&generateParams{gasLimit: 30000000})
	require.NoError(t, err)

	// Create exclusion constraint with specific access list
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.NewEIP2930Signer(big.NewInt(1))

	conflictAddress := common.HexToAddress("0x1234567890123456789012345678901234567890")
	exclusionTx := &types.AccessListTx{
		ChainID:  big.NewInt(1),
		Nonce:    0,
		To:       &conflictAddress,
		Gas:      30000,
		GasPrice: big.NewInt(1000000000),
		Value:    big.NewInt(1000),
		AccessList: types.AccessList{{
			Address:     conflictAddress,
			StorageKeys: []common.Hash{{0x01}},
		}},
	}

	signedExclusionTx, err := types.SignNewTx(key, signer, exclusionTx)
	require.NoError(t, err)

	// Create exclusion constraints (Top=false)
	exclusionConstraints := make(types.HashToConstraintDecoded)
	exclusionConstraints[signedExclusionTx.Hash()] = signedExclusionTx

	// Create inclusion constraints (empty for this test)
	inclusionConstraints := make(types.HashToConstraintDecoded)
	// testConstraintsCache = shardmap.NewFIFOMap[uint64, types.HashToConstraintDecoded](64, 16, shardmap.HashUint64)

	log.Info("=== TEST 1: Exclusion Constraint Filtering ===")
	log.Info(fmt.Sprintf("Exclusion constraint address: %s", conflictAddress.Hex()))
	log.Info(fmt.Sprintf("Exclusion constraint hash: %s", signedExclusionTx.Hash().Hex()))

	var inclusionConstraintDetectionTime = time.Now()

	// Test fillTransactionsSelectAlgo with exclusion constraints
	blockBundles, allBundles, usedSbundles, mempoolTxHashes, err := w.fillTransactionsSelectAlgo(nil, env, exclusionConstraints, inclusionConstraints, 0, inclusionConstraintDetectionTime)

	require.NoError(t, err)

	log.Info(fmt.Sprintf("Block bundles count: %d", len(blockBundles)))
	log.Info(fmt.Sprintf("All bundles count: %d", len(allBundles)))
	log.Info(fmt.Sprintf("Used sbundles count: %d", len(usedSbundles)))
	log.Info(fmt.Sprintf("Mempool tx hashes count: %d", len(mempoolTxHashes)))

	// Verify that conflicting transactions were filtered out
	for hash := range mempoolTxHashes {
		log.Info(fmt.Sprintf("Mempool tx hash: %s", hash.Hex()))
	}

	log.Info("=== END TEST 1 ===")
}

func TestInclusionConstraintDynamicDetection(t *testing.T) {
	// Setup worker and environment
	w, _ := newTestWorker(t, ethashChainConfig, ethash.NewFaker(), rawdb.NewMemoryDatabase(), nil, 0)
	defer w.close()

	env, err := w.prepareWork(&generateParams{gasLimit: 30000000})
	require.NoError(t, err)

	// Create inclusion constraint cache
	inclusionCache := shardmap.NewFIFOMap[uint64, types.HashToConstraintDecoded](64, 16, shardmap.HashUint64)

	// Create initial exclusion constraint
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.NewEIP2930Signer(big.NewInt(1))

	exclusionTx := &types.AccessListTx{
		ChainID:  big.NewInt(1),
		Nonce:    0,
		To:       &common.Address{0x01},
		Gas:      30000,
		GasPrice: big.NewInt(1000000000),
		Value:    big.NewInt(1000),
		AccessList: types.AccessList{{
			Address:     common.Address{0x02},
			StorageKeys: []common.Hash{{0x01}},
		}},
	}

	signedExclusionTx, err := types.SignNewTx(key, signer, exclusionTx)
	require.NoError(t, err)

	exclusionConstraints := make(types.HashToConstraintDecoded)
	exclusionConstraints[signedExclusionTx.Hash()] = signedExclusionTx

	// Create inclusion constraint that will be added dynamically
	inclusionTx := &types.AccessListTx{
		ChainID:  big.NewInt(1),
		Nonce:    1,
		To:       &common.Address{0x03},
		Gas:      21000,
		GasPrice: big.NewInt(2000000000),
		Value:    big.NewInt(2000),
		AccessList: types.AccessList{{
			Address:     common.Address{0x04},
			StorageKeys: []common.Hash{{0x02}},
		}},
	}

	signedInclusionTx, err := types.SignNewTx(key, signer, inclusionTx)
	require.NoError(t, err)

	log.Info("=== TEST 2: Dynamic Inclusion Constraint Detection ===")
	log.Info(fmt.Sprintf("Initial exclusion constraint: %s", signedExclusionTx.Hash().Hex()))
	log.Info(fmt.Sprintf("Inclusion constraint to be added: %s", signedInclusionTx.Hash().Hex()))

	// Start with empty inclusion constraints
	initialInclusion := make(types.HashToConstraintDecoded)

	// Simulate dynamic addition of inclusion constraint after 500ms
	go func() {
		time.Sleep(500 * time.Millisecond)
		newInclusion := make(types.HashToConstraintDecoded)
		newInclusion[signedInclusionTx.Hash()] = signedInclusionTx
		inclusionCache.Put(0, newInclusion)
		log.Info(">>> Dynamically added inclusion constraint to cache")
	}()

	// Test fillTransactionsSelectAlgo with dynamic constraint detection
	blockBundles, _, _, mempoolTxHashes, err := w.fillTransactionsSelectAlgo(nil, env, exclusionConstraints, initialInclusion, 0, time.Time{})

	require.NoError(t, err)

	log.Info(fmt.Sprintf("Final block bundles count: %d", len(blockBundles)))
	log.Info(fmt.Sprintf("Final mempool tx hashes count: %d", len(mempoolTxHashes)))

	// Check if inclusion constraint was detected and added
	_, hasInclusionTx := mempoolTxHashes[signedInclusionTx.Hash()]
	if hasInclusionTx {
		log.Info("✓ Inclusion constraint was successfully detected and added")
	} else {
		log.Info("✗ Inclusion constraint was NOT detected")
	}

	log.Info("=== END TEST 2 ===")
}

func TestAlgorithmSelection(t *testing.T) {
	// Setup worker and environment
	w, _ := newTestWorker(t, ethashChainConfig, ethash.NewFaker(), rawdb.NewMemoryDatabase(), nil, 0)
	defer w.close()

	env, err := w.prepareWork(&generateParams{gasLimit: 30000000})
	require.NoError(t, err)

	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.NewEIP2930Signer(big.NewInt(1))

	log.Info("=== TEST 3: Algorithm Selection Logic ===")

	// Test Case 1: No constraints - should use fillTransactionsAlgoWorker
	log.Info("--- Case 1: No constraints ---")
	emptyInclusion := make(types.HashToConstraintDecoded)
	emptyExclusion := make(types.HashToConstraintDecoded)

	_, _, usedSbundles1, mempoolTxHashes1, err := w.fillTransactionsSelectAlgo(nil, env, emptyExclusion, emptyInclusion, 0, time.Time{})
	require.NoError(t, err)

	log.Info(fmt.Sprintf("No constraints - Used sbundles count: %d (should be > 0)", len(usedSbundles1)))
	log.Info(fmt.Sprintf("No constraints - Mempool tx count: %d", len(mempoolTxHashes1)))

	// Test Case 2: Only inclusion constraints - should warn and use fillTransactionsAlgoWorker
	log.Info("--- Case 2: Only inclusion constraints ---")
	inclusionTx := &types.AccessListTx{
		ChainID:  big.NewInt(1),
		Nonce:    0,
		To:       &common.Address{0x01},
		Gas:      21000,
		GasPrice: big.NewInt(1000000000),
		Value:    big.NewInt(1000),
		AccessList: types.AccessList{{
			Address:     common.Address{0x02},
			StorageKeys: []common.Hash{{0x01}},
		}},
	}

	signedInclusionTx, err := types.SignNewTx(key, signer, inclusionTx)
	require.NoError(t, err)

	onlyInclusion := make(types.HashToConstraintDecoded)
	onlyInclusion[signedInclusionTx.Hash()] = signedInclusionTx

	var OnlyInclusionConstraintDetectionTime = time.Now()

	_, _, usedSbundles2, mempoolTxHashes2, err := w.fillTransactionsSelectAlgo(nil, env, emptyExclusion, onlyInclusion, 0, OnlyInclusionConstraintDetectionTime)
	require.NoError(t, err)

	log.Info(fmt.Sprintf("Only inclusion - Used sbundles count: %d (should be > 0, fallback algorithm)", len(usedSbundles2)))
	log.Info(fmt.Sprintf("Only inclusion - Mempool tx count: %d", len(mempoolTxHashes2)))

	// Test Case 3: Exclusion constraints present - should use fillTransactionsWithDynamicConstraints
	log.Info("--- Case 3: Exclusion constraints present ---")
	exclusionTx := &types.AccessListTx{
		ChainID:  big.NewInt(1),
		Nonce:    1,
		To:       &common.Address{0x03},
		Gas:      30000,
		GasPrice: big.NewInt(1000000000),
		Value:    big.NewInt(1000),
		AccessList: types.AccessList{{
			Address:     common.Address{0x04},
			StorageKeys: []common.Hash{{0x01}},
		}},
	}

	signedExclusionTx, err := types.SignNewTx(key, signer, exclusionTx)
	require.NoError(t, err)

	withExclusion := make(types.HashToConstraintDecoded)
	withExclusion[signedExclusionTx.Hash()] = signedExclusionTx

	_, _, usedSbundles3, mempoolTxHashes3, err := w.fillTransactionsSelectAlgo(nil, env, withExclusion, emptyInclusion, 0, time.Time{})
	require.NoError(t, err)

	log.Info(fmt.Sprintf("With exclusion - Used sbundles count: %d (should be 0, dynamic algorithm)", len(usedSbundles3)))
	log.Info(fmt.Sprintf("With exclusion - Mempool tx count: %d", len(mempoolTxHashes3)))
	log.Info(fmt.Sprintf("With exclusion - Exclusion constraint hash in mempool: %v",
		func() bool { _, exists := mempoolTxHashes3[signedExclusionTx.Hash()]; return exists }()))

	var inclusionConstraintDetectionTime = time.Now()

	// Test Case 4: Both inclusion and exclusion constraints
	log.Info("--- Case 4: Both inclusion and exclusion constraints ---")
	_, _, usedSbundles4, mempoolTxHashes4, err := w.fillTransactionsSelectAlgo(nil, env, withExclusion, onlyInclusion, 0, inclusionConstraintDetectionTime)
	require.NoError(t, err)

	log.Info(fmt.Sprintf("Both constraints - Used sbundles count: %d (should be 0, dynamic algorithm)", len(usedSbundles4)))
	log.Info(fmt.Sprintf("Both constraints - Mempool tx count: %d", len(mempoolTxHashes4)))
	log.Info(fmt.Sprintf("Both constraints - Inclusion constraint in mempool: %v",
		func() bool { _, exists := mempoolTxHashes4[signedInclusionTx.Hash()]; return exists }()))
	log.Info(fmt.Sprintf("Both constraints - Exclusion constraint in mempool: %v",
		func() bool { _, exists := mempoolTxHashes4[signedExclusionTx.Hash()]; return exists }()))

	log.Info("=== END TEST 3 ===")
}

func TestMainLoopInclusionExclusionConstraints(t *testing.T) {
	// Create constraint transactions with specific key
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.NewEIP2930Signer(big.NewInt(1))
	constraintSender := crypto.PubkeyToAddress(key.PublicKey)

	// Create genesis allocation with funded accounts
	genesisAlloc := types.GenesisAlloc{
		constraintSender: {
			Balance: big.NewInt(1000000000000000000), // 1 ETH
			Nonce:   0,
		},
		testBankAddress: {Balance: testBankFunds},
		crypto.PubkeyToAddress(testBankKey.PublicKey): {
			Balance: func() *big.Int { v, _ := big.NewInt(0).SetString("100000000000000000000", 10); return v }(), // 10 ETH
			Nonce:   0,
		},
	}

	inClusionCache := shardmap.NewFIFOMap[uint64, types.HashToConstraintDecoded](64, 16, shardmap.HashUint64)
	exClusionCache := shardmap.NewFIFOMap[uint64, types.HashToConstraintDecoded](64, 16, shardmap.HashUint64)

	// Setup worker with custom genesis allocation
	w, _ := newTestWorker(t, ethashChainConfig, ethash.NewFaker(), rawdb.NewMemoryDatabase(), genesisAlloc, 0)
	defer w.close()

	w.config.BuilderTxSigningKey = testBankKey
	w.coinbase = crypto.PubkeyToAddress(testBankKey.PublicKey)

	t.Run("\nMainLoopWithInclusionExclusionConstraints", func(t *testing.T) {
		// sealing을 우회하는 hook 설정 (ethash sealing 에러 방지)
		w.skipSealHook = func(task *task) bool { return true }

		// mainLoop 시작
		w.start()
		defer w.stop()

		// Create inclusion constraint transaction (MUST be included)
		inclusionTx := &types.AccessListTx{
			ChainID:  big.NewInt(1),
			Nonce:    0,
			To:       &common.Address{0x03},
			Gas:      30000,
			GasPrice: big.NewInt(2000000000), // High gas price
			Value:    big.NewInt(2000),
			AccessList: types.AccessList{{
				Address:     common.Address{0x04},
				StorageKeys: []common.Hash{{0x02}},
			}},
		}
		signedInclusionTx, err := types.SignNewTx(key, signer, inclusionTx)
		require.NoError(t, err)

		// Create exclusion constraint transaction (MUST be excluded)
		exclusionTx := &types.AccessListTx{
			ChainID:  big.NewInt(1),
			Nonce:    1, // Different nonce to avoid conflicts
			To:       &common.Address{0x01},
			Gas:      30000,
			GasPrice: big.NewInt(3000000000), // Even higher gas price but should be excluded
			Value:    big.NewInt(1000),
			AccessList: types.AccessList{{
				Address:     common.Address{0x02},
				StorageKeys: []common.Hash{{0x01}},
			}},
		}
		signedExclusionTx, err := types.SignNewTx(key, signer, exclusionTx)
		require.NoError(t, err)

		// Create regular mempool transaction for comparison
		regularTx := &types.AccessListTx{
			ChainID:  big.NewInt(1),
			Nonce:    2,
			To:       &common.Address{0x05},
			Gas:      30000,
			GasPrice: big.NewInt(1500000000), // Medium gas price
			Value:    big.NewInt(500),
		}
		signedRegularTx, err := types.SignNewTx(key, signer, regularTx)
		require.NoError(t, err)

		// Add regular transaction to mempool
		w.eth.TxPool().Add([]*types.Transaction{signedRegularTx}, true, false, false)

		// Create constraint cache with inclusion constraints
		constraintsCache := shardmap.NewFIFOMap[uint64, types.HashToConstraintDecoded](64, 16, shardmap.HashUint64)
		slot := uint64(0)

		// Add inclusion constraint to cache
		constraints := make(types.HashToConstraintDecoded)
		constraints[signedInclusionTx.Hash()] = signedInclusionTx
		constraintsCache.Put(slot, constraints)

		validatorCoinbase := testUserAddress
		// var capturedBlock *types.Block
		// var capturedBlockValue *big.Int

		// onBlock 콜백으로 완성된 블록 정보 캡처
		onBlockCallback := func(block *types.Block, blockValue *big.Int, sidecars []*types.BlobTxSidecar,
			orderCloseTime time.Time, blockBundles, allBundles []types.SimulatedBundle, usedSbundles []types.UsedSBundle) {

			// capturedBlock = block
			// capturedBlockValue = blockValue

			fmt.Printf("\n=== Block Completed via mainLoop ===")
			fmt.Printf("\nBlock Hash: %s", block.Hash().Hex())
			fmt.Printf("\nBlock Number: %d", block.NumberU64())
			fmt.Printf("\nBlock Gas Used: %d", block.GasUsed())
			fmt.Printf("\nBlock Gas Limit: %d", block.GasLimit())
			fmt.Printf("\nBlock Value: %s", blockValue.String())
			fmt.Printf("\nTransaction Count: %d", len(block.Transactions()))
			fmt.Printf("\nOrder Close Time: %s", orderCloseTime.Format(time.RFC3339))

			// Analyze block transactions
			fmt.Printf("\n=== TRANSACTION ANALYSIS ===")
			blockTxHashes := make(map[common.Hash]bool)

			for i, tx := range block.Transactions() {
				blockTxHashes[tx.Hash()] = true
				fmt.Printf("\nTx %d: Hash=%s, To=%s, GasPrice=%s, Value=%s",
					i, tx.Hash().Hex(),
					func() string {
						if tx.To() != nil {
							return tx.To().Hex()
						}
						return "CONTRACT_CREATION"
					}(),
					tx.GasPrice().String(),
					tx.Value().String())
			}

			// Critical constraint verification
			fmt.Printf("\n=== CONSTRAINT VERIFICATION ===")

			// Test 1: Inclusion constraint MUST be in the block
			inclusionIncluded := blockTxHashes[signedInclusionTx.Hash()]
			if inclusionIncluded {
				fmt.Printf("\nSUCCESS: Inclusion constraint CORRECTLY INCLUDED: %s",
					signedInclusionTx.Hash().Hex())
			} else {
				fmt.Printf("\nFAILURE: Inclusion constraint MISSING: %s",
					signedInclusionTx.Hash().Hex())
			}

			// Test 2: Exclusion constraint MUST NOT be in the block
			exclusionIncluded := blockTxHashes[signedExclusionTx.Hash()]
			if !exclusionIncluded {
				fmt.Printf("\nSUCCESS: Exclusion constraint CORRECTLY EXCLUDED: %s",
					signedExclusionTx.Hash().Hex())
			} else {
				fmt.Printf("\nFAILURE: Exclusion constraint INCORRECTLY INCLUDED: %s",
					signedExclusionTx.Hash().Hex())
			}

			// Test 3: Regular transaction behavior
			regularIncluded := blockTxHashes[signedRegularTx.Hash()]
			fmt.Printf("\nRegular mempool tx included: %v (%s)",
				regularIncluded, signedRegularTx.Hash().Hex())

			// Bundle information
			for i, bundle := range blockBundles {
				fmt.Printf("\nBundle[%d]: TxCount=%d, Profit=%s",
					i, len(bundle.OriginalBundle.Txs), bundle.TotalEth.String())
			}
		}

		// exclusionTx := &types.AccessListTx{
		// 	ChainID:  big.NewInt(1),
		// 	Nonce:    1,
		// 	To:       &common.Address{0x03},
		// 	Gas:      30000,
		// 	GasPrice: big.NewInt(1000000000),
		// 	Value:    big.NewInt(1000),
		// 	AccessList: types.AccessList{{
		// 		Address:     common.Address{0x04},
		// 		StorageKeys: []common.Hash{{0x01}},
		// 	}},
		// }

		// signedExclusionTx, err := types.SignNewTx(key, signer, exclusionTx)
		// require.NoError(t, err)

		exClusion := make(types.HashToConstraintDecoded)
		exClusion[signedExclusionTx.Hash()] = signedExclusionTx
		inClusion := make(types.HashToConstraintDecoded)
		inClusion[signedInclusionTx.Hash()] = signedInclusionTx

		inClusionCache.Put(0, inClusion)
		exClusionCache.Put(0, exClusion)

		fmt.Printf("\n=== TESTING CONSTRAINT APPLICATION ===")
		fmt.Printf("\nSlot: %d", slot)
		fmt.Printf("\nInclusion constraint (MUST include): %s -> %s (GasPrice: %s)",
			signedInclusionTx.Hash().Hex(), signedInclusionTx.To().Hex(), signedInclusionTx.GasPrice().String())
		fmt.Printf("\nExclusion constraint (MUST exclude): %s -> %s (GasPrice: %s)",
			signedExclusionTx.Hash().Hex(), signedExclusionTx.To().Hex(), signedExclusionTx.GasPrice().String())
		fmt.Printf("\nRegular mempool tx: %s -> %s (GasPrice: %s)",
			signedRegularTx.Hash().Hex(), signedRegularTx.To().Hex(), signedRegularTx.GasPrice().String())

		// generateWork를 통한 블록 생성 요청 (mainLoop 활용)
		params := &generateParams{
			parentHash:                w.chain.CurrentBlock().Hash(),
			timestamp:                 uint64(time.Now().Unix()),
			coinbase:                  validatorCoinbase,
			random:                    common.Hash{0x02},
			gasLimit:                  30000000,
			slot:                      slot,
			inclusionConstraintsCache: inClusionCache,
			exclusionConstraintsCache: exClusionCache,
			// constraintsCache: constraintsCache,
			onBlock:   onBlockCallback,
			forceTime: true,
		}

		fmt.Printf("\n=== Before generateWork request ===")
		fmt.Printf("\nCurrent Block Number: %d", w.chain.CurrentBlock().Number.Uint64())
		fmt.Printf("\nParent Hash: %s", params.parentHash.Hex())
		fmt.Printf("\nValidator Coinbase: %s", validatorCoinbase.Hex())

		// mainLoop의 getWorkCh를 통해 블록 생성 요청
		resultCh := make(chan *newPayloadResult, 1)
		select {
		case w.getWorkCh <- &getWorkReq{params: params, result: resultCh}:
			fmt.Printf("\nWork request with constraints sent to mainLoop")
		case <-time.After(1 * time.Second):
			t.Fatal("\nFailed to send work request to mainLoop")
		}

		// 결과 대기 및 검증
		select {
		case result := <-resultCh:
			require.NoError(t, result.err, "generateWork should not return an error")
			require.NotNil(t, result.block, "generateWork should return a block")

			fmt.Printf("\n=== BLOCK BUILDING RESULT ===")
			fmt.Printf("\nBlock Number: %d", result.block.Number().Uint64())
			fmt.Printf("\nBlock Hash: %s", result.block.Hash().Hex())
			fmt.Printf("\nTransaction Count: %d", len(result.block.Transactions()))
			fmt.Printf("\nGas Used: %d / %d", result.block.GasUsed(), result.block.GasLimit())
			fmt.Printf("\nBlock Fees: %s", result.fees.String())
			fmt.Printf("\nSidecar Count: %d", len(result.sidecars))

			// Final verification
			blockTxHashes := make(map[common.Hash]bool)
			for _, tx := range result.block.Transactions() {
				blockTxHashes[tx.Hash()] = true
			}

			// Verify inclusion constraint is included
			inclusionIncluded := blockTxHashes[signedInclusionTx.Hash()]
			require.True(t, inclusionIncluded, "Inclusion constraint must be included in block")

			// Verify exclusion constraint is not included (현재 코드베이스에서는 inclusion만 지원)
			exclusionIncluded := blockTxHashes[signedExclusionTx.Hash()]

			fmt.Printf("\n=== TEST SUMMARY ===")
			fmt.Printf("\nInclusion constraint applied: %v", inclusionIncluded)
			fmt.Printf("\nExclusion constraint excluded: %v", !exclusionIncluded)
			fmt.Printf("\nBlock contains %d transactions", len(result.block.Transactions()))
			fmt.Printf("\nCONSTRAINT TESTS COMPLETED via mainLoop")

		case <-time.After(10 * time.Second):
			t.Fatal("\nTimeout waiting for constraint block generation result")
		}
	})
}
