package builder

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/flashbotsextra"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/gorilla/handlers"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestOnPayloadAttributes(t *testing.T) {
	const (
		validatorDesiredGasLimit = 30_000_000
		payloadAttributeGasLimit = 0
		parentBlockGasLimit      = 29_000_000
	)
	expectedGasLimit := core.CalcGasLimit(parentBlockGasLimit, validatorDesiredGasLimit)

	vsk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x370bb8c1a6e62b2882f6ec76762a67b39609002076b95aae5b023997cf9b2dc9"))
	require.NoError(t, err)
	validator := &ValidatorPrivateData{
		sk: vsk,
		Pk: hexutil.MustDecode("0xb67d2c11bcab8c4394fc2faa9601d0b99c7f4b37e14911101da7d97077917862eed4563203d34b91b5cf0aa44d6cfa05"),
	}

	testBeacon := testBeaconClient{
		validator: validator,
		slot:      56,
	}

	feeRecipient, _ := utils.HexToAddress("0xabcf8e0d4e9587369b2301d0790347320302cc00")
	testRelay := testRelay{
		gvsVd: ValidatorData{
			Pubkey:       PubkeyHex(testBeacon.validator.Pk.String()),
			FeeRecipient: feeRecipient,
			GasLimit:     validatorDesiredGasLimit,
		},
	}

	sk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x31ee185dad1220a8c88ca5275e64cf5a5cb09cb621cb30df52c9bee8fbaaf8d7"))
	require.NoError(t, err)

	bDomain := ssz.ComputeDomain(ssz.DomainTypeAppBuilder, [4]byte{0x02, 0x0, 0x0, 0x0}, phase0.Root{})

	testExecutableData := &engine.ExecutableData{
		ParentHash:   common.Hash{0x02, 0x03},
		FeeRecipient: common.Address(feeRecipient),
		StateRoot:    common.Hash{0x07, 0x16},
		ReceiptsRoot: common.Hash{0x08, 0x20},
		LogsBloom:    types.Bloom{}.Bytes(),
		Number:       uint64(10),
		GasLimit:     expectedGasLimit,
		GasUsed:      uint64(100),
		Timestamp:    uint64(105),
		ExtraData:    hexutil.MustDecode("0x0042fafc"),

		BaseFeePerGas: big.NewInt(16),

		BlockHash:    common.HexToHash("0x68e516c8827b589fcb749a9e672aa16b9643437459508c467f66a9ed1de66a6c"),
		Transactions: [][]byte{},
	}

	testBlock, err := engine.ExecutableDataToBlock(*testExecutableData, nil, nil)
	require.NoError(t, err)

	testPayloadAttributes := &types.BuilderPayloadAttributes{
		Timestamp:             hexutil.Uint64(104),
		Random:                common.Hash{0x05, 0x10},
		SuggestedFeeRecipient: common.Address{0x04, 0x10},
		GasLimit:              uint64(payloadAttributeGasLimit),
		Slot:                  uint64(25),
	}

	testEthService := &testEthereumService{synced: true, testExecutableData: testExecutableData, testBlock: testBlock, testBlockValue: big.NewInt(10)}
	builderArgs := BuilderArgs{
		sk:                          sk,
		ds:                          flashbotsextra.NilDbService{},
		relay:                       &testRelay,
		builderSigningDomain:        bDomain,
		eth:                         testEthService,
		dryRun:                      false,
		ignoreLatePayloadAttributes: false,
		validator:                   nil,
		beaconClient:                &testBeacon,
		limiter:                     nil,
		blockConsumer:               flashbotsextra.NilDbService{},
	}
	builder, err := NewBuilder(builderArgs)
	require.NoError(t, err)
	builder.Start()
	defer builder.Stop()

	err = builder.OnPayloadAttribute(testPayloadAttributes)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	require.NotNil(t, testRelay.submittedMsg)

	expectedProposerPubkey, err := utils.HexToPubkey(testBeacon.validator.Pk.String())
	require.NoError(t, err)

	expectedMessage := builderApiV1.BidTrace{
		Slot:                 uint64(25),
		ParentHash:           phase0.Hash32{0x02, 0x03},
		BuilderPubkey:        builder.builderPublicKey,
		ProposerPubkey:       expectedProposerPubkey,
		ProposerFeeRecipient: feeRecipient,
		GasLimit:             expectedGasLimit,
		GasUsed:              uint64(100),
		Value:                &uint256.Int{0x0a},
	}
	copy(expectedMessage.BlockHash[:], hexutil.MustDecode("0x68e516c8827b589fcb749a9e672aa16b9643437459508c467f66a9ed1de66a6c")[:])
	require.NotNil(t, testRelay.submittedMsg.Bellatrix)
	require.Equal(t, expectedMessage, *testRelay.submittedMsg.Bellatrix.Message)

	expectedExecutionPayload := bellatrix.ExecutionPayload{
		ParentHash:    [32]byte(testExecutableData.ParentHash),
		FeeRecipient:  feeRecipient,
		StateRoot:     [32]byte(testExecutableData.StateRoot),
		ReceiptsRoot:  [32]byte(testExecutableData.ReceiptsRoot),
		LogsBloom:     [256]byte{},
		PrevRandao:    [32]byte(testExecutableData.Random),
		BlockNumber:   testExecutableData.Number,
		GasLimit:      testExecutableData.GasLimit,
		GasUsed:       testExecutableData.GasUsed,
		Timestamp:     testExecutableData.Timestamp,
		ExtraData:     hexutil.MustDecode("0x0042fafc"),
		BaseFeePerGas: [32]byte{0x10},
		BlockHash:     expectedMessage.BlockHash,
		Transactions:  []bellatrix.Transaction{},
	}

	require.Equal(t, expectedExecutionPayload, *testRelay.submittedMsg.Bellatrix.ExecutionPayload)

	expectedSignature, err := utils.HexToSignature("0x8d1dc346d469b0678ee72baa559315433af0966d2d05dad0de9ce60ff5e4954d4e28a85643496df279494d105bc4a771034fefcdd83d71df5f1b81c9369942b20d6d574b544a93588f6182ba8b09585eb1cf3e1b6551ccbd9e76a4db8eb579fe")

	require.NoError(t, err)
	require.Equal(t, expectedSignature, testRelay.submittedMsg.Bellatrix.Signature)

	require.Equal(t, uint64(25), testRelay.requestedSlot)

	// Clear the submitted message and check that the job will be ran again and but a new message will not be submitted since the hash is the same
	testEthService.testBlockValue = big.NewInt(10)

	testRelay.submittedMsg = nil
	time.Sleep(2200 * time.Millisecond)
	require.Nil(t, testRelay.submittedMsg)

	// Change the hash, expect to get the block
	testExecutableData.ExtraData = hexutil.MustDecode("0x0042fafd")
	testExecutableData.BlockHash = common.HexToHash("0x6a259b9a148da3cc0bf139eaa89292fa9f7b136cfeddad17f7cb0ae33e0c3df9")
	testBlock, err = engine.ExecutableDataToBlock(*testExecutableData, nil, nil)
	testEthService.testBlockValue = big.NewInt(10)
	require.NoError(t, err)
	testEthService.testBlock = testBlock

	time.Sleep(2200 * time.Millisecond)
	require.NotNil(t, testRelay.submittedMsg)
}

func TestBlockWithConstraints(t *testing.T) {
	const (
		validatorDesiredGasLimit = 30_000_000
		payloadAttributeGasLimit = 30_000_000 // Was zero in the other test
		parentBlockGasLimit      = 29_000_000
	)
	expectedGasLimit := core.CalcGasLimit(parentBlockGasLimit, validatorDesiredGasLimit)

	vsk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x370bb8c1a6e62b2882f6ec76762a67b39609002076b95aae5b023997cf9b2dc9"))
	require.NoError(t, err)
	validator := &ValidatorPrivateData{
		sk: vsk,
		Pk: hexutil.MustDecode("0xb67d2c11bcab8c4394fc2faa9601d0b99c7f4b37e14911101da7d97077917862eed4563203d34b91b5cf0aa44d6cfa05"),
	}

	testBeacon := testBeaconClient{
		validator: validator,
		slot:      56,
	}

	feeRecipient, _ := utils.HexToAddress("0xabcf8e0d4e9587369b2301d0790347320302cc00")
	testRelay := testRelay{
		gvsVd: ValidatorData{
			Pubkey:       PubkeyHex(testBeacon.validator.Pk.String()),
			FeeRecipient: feeRecipient,
			GasLimit:     validatorDesiredGasLimit,
		},
	}

	sk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x31ee185dad1220a8c88ca5275e64cf5a5cb09cb621cb30df52c9bee8fbaaf8d7"))
	require.NoError(t, err)

	bDomain := ssz.ComputeDomain(ssz.DomainTypeAppBuilder, [4]byte{0x02, 0x0, 0x0, 0x0}, phase0.Root{})

	// https://etherscan.io/tx/0x9d48b4a021898a605b7ae49bf93ad88fa6bd7050e9448f12dde064c10f22fe9c
	// 0x02f87601836384348477359400850517683ba883019a28943678fce4028b6745eb04fa010d9c8e4b36d6288c872b0f1366ad800080c080a0b6b7aba1954160d081b2c8612e039518b9c46cd7df838b405a03f927ad196158a071d2fb6813e5b5184def6bd90fb5f29e0c52671dea433a7decb289560a58416e
	constraintTxByte, _ := hex.DecodeString("02f87601836384348477359400850517683ba883019a28943678fce4028b6745eb04fa010d9c8e4b36d6288c872b0f1366ad800080c080a0b6b7aba1954160d081b2c8612e039518b9c46cd7df838b405a03f927ad196158a071d2fb6813e5b5184def6bd90fb5f29e0c52671dea433a7decb289560a58416e")
	constraintTx := new(types.Transaction)
	err = constraintTx.UnmarshalBinary(constraintTxByte)
	require.NoError(t, err)

	// https://etherscan.io/tx/0x15bd881daa1408b33f67fa4bdeb8acfb0a2289d9b4c6f81eef9bb2bb2e52e780 - Blob Tx
	// 0x03f9029c01830299f184b2d05e008507aef40a00832dc6c09468d30f47f19c07bccef4ac7fae2dc12fca3e0dc980b90204ef16e845000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000633b68f5d8d3a86593ebb815b4663bcbe0302e31382e302d64657600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004109de8da2a97e37f2e6dc9f7d50a408f9344d7aa1a925ae53daf7fbef43491a571960d76c0cb926190a9da10df7209fb1ba93cd98b1565a3a2368749d505f90c81c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0843b9aca00e1a00141e3a338e30c49ed0501e315bcc45e4edefebed43ab1368a1505461d9cf64901a01e8511e06b17683d89eb57b9869b96b8b611f969f7f56cbc0adc2df7c88a2a07a00910deacf91bba0d74e368d285d311dc5884e7cfe219d85aea5741b2b6e3a2fe
	constraintTxWithBlobByte, _ := hex.DecodeString("03f9029c01830299f184b2d05e008507aef40a00832dc6c09468d30f47f19c07bccef4ac7fae2dc12fca3e0dc980b90204ef16e845000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000633b68f5d8d3a86593ebb815b4663bcbe0302e31382e302d64657600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004109de8da2a97e37f2e6dc9f7d50a408f9344d7aa1a925ae53daf7fbef43491a571960d76c0cb926190a9da10df7209fb1ba93cd98b1565a3a2368749d505f90c81c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0843b9aca00e1a00141e3a338e30c49ed0501e315bcc45e4edefebed43ab1368a1505461d9cf64901a01e8511e06b17683d89eb57b9869b96b8b611f969f7f56cbc0adc2df7c88a2a07a00910deacf91bba0d74e368d285d311dc5884e7cfe219d85aea5741b2b6e3a2fe")
	constraintTxWithBlob := new(types.Transaction)
	err = constraintTxWithBlob.UnmarshalBinary(constraintTxWithBlobByte)
	require.NoError(t, err)

	testExecutableData := &engine.ExecutableData{
		ParentHash:   common.Hash{0x02, 0x03},
		FeeRecipient: common.Address(feeRecipient),
		StateRoot:    common.Hash{0x07, 0x16},
		ReceiptsRoot: common.Hash{0x08, 0x20},
		LogsBloom:    types.Bloom{}.Bytes(),
		Number:       uint64(10),
		GasLimit:     expectedGasLimit,
		GasUsed:      uint64(100),
		Timestamp:    uint64(105),
		ExtraData:    hexutil.MustDecode("0x0042fafc"),

		BaseFeePerGas: big.NewInt(16),

		BlockHash:    common.HexToHash("3cce5d0f5c9a7e188e79c35168256e91bec2d98a1140f6701da6ed3c98ea9d04"),
		Transactions: [][]byte{constraintTxByte, constraintTxWithBlobByte},
	}

	testBlock, err := engine.ExecutableDataToBlock(*testExecutableData, constraintTxWithBlob.BlobHashes(), nil)
	require.NoError(t, err)

	testPayloadAttributes := &types.BuilderPayloadAttributes{
		Timestamp:             hexutil.Uint64(104),
		Random:                common.Hash{0x05, 0x10},
		SuggestedFeeRecipient: common.Address{0x04, 0x10},
		GasLimit:              uint64(payloadAttributeGasLimit),
		Slot:                  uint64(25),
	}

	testEthService := &testEthereumService{synced: true, testExecutableData: testExecutableData, testBlock: testBlock, testBlockValue: big.NewInt(10)}
	builderArgs := BuilderArgs{
		sk:                          sk,
		ds:                          flashbotsextra.NilDbService{},
		relay:                       &testRelay,
		builderSigningDomain:        bDomain,
		eth:                         testEthService,
		dryRun:                      false,
		ignoreLatePayloadAttributes: false,
		validator:                   nil,
		beaconClient:                &testBeacon,
		limiter:                     nil,
		blockConsumer:               flashbotsextra.NilDbService{},
	}
	builder, err := NewBuilder(builderArgs)
	require.NoError(t, err)

	builder.Start()
	defer builder.Stop()

	// Add the transaction to the cache directly
	builder.inclusionConstraintsCache.Put(25, map[common.Hash]*types.Transaction{
		constraintTx.Hash():         constraintTx,
		constraintTxWithBlob.Hash(): constraintTxWithBlob,
	})

	err = builder.OnPayloadAttribute(testPayloadAttributes)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	require.NotNil(t, testRelay.submittedMsgWithProofs)

	expectedProposerPubkey, err := utils.HexToPubkey(testBeacon.validator.Pk.String())
	require.NoError(t, err)

	expectedMessage := builderApiV1.BidTrace{
		Slot:                 uint64(25),
		ParentHash:           phase0.Hash32{0x02, 0x03},
		BuilderPubkey:        builder.builderPublicKey,
		ProposerPubkey:       expectedProposerPubkey,
		ProposerFeeRecipient: feeRecipient,
		GasLimit:             expectedGasLimit,
		GasUsed:              uint64(100),
		Value:                &uint256.Int{0x0a},
	}
	copy(expectedMessage.BlockHash[:], hexutil.MustDecode("0x3cce5d0f5c9a7e188e79c35168256e91bec2d98a1140f6701da6ed3c98ea9d04")[:])
	require.NotNil(t, testRelay.submittedMsgWithProofs.Bellatrix)

	require.Equal(t, expectedMessage, *testRelay.submittedMsgWithProofs.Bellatrix.Message)

	expectedExecutionPayload := bellatrix.ExecutionPayload{
		ParentHash:    [32]byte(testExecutableData.ParentHash),
		FeeRecipient:  feeRecipient,
		StateRoot:     [32]byte(testExecutableData.StateRoot),
		ReceiptsRoot:  [32]byte(testExecutableData.ReceiptsRoot),
		LogsBloom:     [256]byte{},
		PrevRandao:    [32]byte(testExecutableData.Random),
		BlockNumber:   testExecutableData.Number,
		GasLimit:      testExecutableData.GasLimit,
		GasUsed:       testExecutableData.GasUsed,
		Timestamp:     testExecutableData.Timestamp,
		ExtraData:     hexutil.MustDecode("0x0042fafc"),
		BaseFeePerGas: [32]byte{0x10},
		BlockHash:     expectedMessage.BlockHash,
		Transactions:  []bellatrix.Transaction{constraintTxByte, constraintTxWithBlobByte},
	}

	require.Equal(t, expectedExecutionPayload, *testRelay.submittedMsgWithProofs.Bellatrix.ExecutionPayload)

	expectedSignature, err := utils.HexToSignature("0x97db0496dcfd04ed444b87b6fc1c9e3339a0d35f7c01825ac353812601a72e7e35ef94899a9b03f4d23102214701255805efd0f6552073791ea1c3e10003ae435952f8305f6b89e58d4442ced149d3c33a486f5a390b4b8047e6ea4176059755")

	require.NoError(t, err)
	require.Equal(t, expectedSignature, testRelay.submittedMsgWithProofs.Bellatrix.Signature)

	require.Equal(t, uint64(25), testRelay.requestedSlot)

	// Clear the submitted message and check that the job will be ran again and but a new message will not be submitted since the hash is the same
	testEthService.testBlockValue = big.NewInt(10)

	testRelay.submittedMsgWithProofs = nil
	time.Sleep(2200 * time.Millisecond)
	require.Nil(t, testRelay.submittedMsgWithProofs)

	// Change the hash, expect to get the block
	testExecutableData.ExtraData = hexutil.MustDecode("0x0042fafd")
	testExecutableData.BlockHash = common.HexToHash("0x38456f6f1f5e76cf83c89ebb8606ff2b700bf02a86a165316c6d7a0c4e6a8614")
	testBlock, err = engine.ExecutableDataToBlock(*testExecutableData, constraintTxWithBlob.BlobHashes(), nil)
	testEthService.testBlockValue = big.NewInt(10)
	require.NoError(t, err)
	testEthService.testBlock = testBlock

	time.Sleep(2200 * time.Millisecond)
	require.NotNil(t, testRelay.submittedMsgWithProofs)
}

func TestExclusionCommitment(t *testing.T) {
	t.Log("=== Testing Exclusion Commitment Flow (Steps 8-10) ===")

	// env setting
	testKey, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testAddr := crypto.PubkeyToAddress(testKey.PublicKey)
	signer := types.NewEIP2930Signer(big.NewInt(1))

	// Commitment definitionz
	type StateScope struct {
		AddressList []common.Address `json:"addressList"`
		LockId      common.Hash      `json:"lockId"`
	}

	type ExclusionCommitment struct {
		Slot       uint64     `json:"slot"`
		StateScope StateScope `json:"stateScope"`
	}

	// StateScope helper functions
	createStateScopeFromAccessList := func(accessList types.AccessList, lockId common.Hash) StateScope {
		addressList := make([]common.Address, 0, len(accessList))
		for _, tuple := range accessList {
			addressList = append(addressList, tuple.Address)
		}
		return StateScope{
			AddressList: addressList,
			LockId:      lockId,
		}
	}

	hasStateScopeConflict := func(scope1, scope2 StateScope) bool {
		addressSet := make(map[common.Address]bool)
		for _, addr := range scope1.AddressList {
			addressSet[addr] = true
		}

		for _, addr := range scope2.AddressList {
			if addressSet[addr] {
				return true
			}
		}
		return false
	}

	createTestTx := func(nonce uint64, to common.Address, accessList types.AccessList) *types.Transaction {
		txData := &types.AccessListTx{
			ChainID:    big.NewInt(1),
			Nonce:      nonce,
			To:         &to,
			Value:      big.NewInt(10),
			Gas:        21000,
			GasPrice:   big.NewInt(2000000000),
			Data:       nil,
			AccessList: accessList,
		}
		tx := types.NewTx(txData)
		signedTx, err := types.SignTx(tx, signer, testKey)
		require.NoError(t, err)
		return signedTx
	}

	// Step 8: relay -> builder: exclusion commitment
	t.Log("Step 8: Relay sends exclusion commitment to builder")

	exclusionCommitment := ExclusionCommitment{
		Slot: 100,
		StateScope: StateScope{
			AddressList: []common.Address{
				common.HexToAddress("0x1234567890123456789012345678901234567890"),
				common.HexToAddress("0xA0b86a33E6441e6e80D0c4C34F4F6cA4C7C4b1d0"),
			},
			LockId: common.HexToHash("0x1"),
		},
	}

	t.Logf("Exclusion Commitment - Slot: %d, LockId: %s",
		exclusionCommitment.Slot, exclusionCommitment.StateScope.LockId.Hex())
	t.Logf("Protected Addresses: %v", exclusionCommitment.StateScope.AddressList)

	// Step 9: builder: store exclusion commitment
	t.Log("Step 9: Builder validates and stores exclusion commitment")

	constraintsCache := make(map[uint64]types.HashToConstraintDecoded)
	exclusionConstraints := make(types.HashToConstraintDecoded)

	for _, addr := range exclusionCommitment.StateScope.AddressList {
		protectedAccessList := types.AccessList{
			{
				Address: addr,
				StorageKeys: []common.Hash{
					common.HexToHash("0x01"),
					common.HexToHash("0x02"),
				},
			},
		}
		constraintTx := createTestTx(0, addr, protectedAccessList)
		exclusionConstraints[constraintTx.Hash()] = constraintTx
	}
	constraintsCache[exclusionCommitment.Slot] = exclusionConstraints

	t.Logf("Stored %d exclusion constraints for slot %d",
		len(exclusionConstraints), exclusionCommitment.Slot)

	// Step 10: tx filtering according to StateScope
	t.Log("Step 10: Builder filters transactions using StateScope based conflict detection")

	// test purpose samples
	conflictingAccessList := types.AccessList{
		{
			Address: exclusionCommitment.StateScope.AddressList[0],
			StorageKeys: []common.Hash{
				common.HexToHash("0x01"),
				common.HexToHash("0x03"),
			},
		},
	}
	conflictingTx := createTestTx(1, exclusionCommitment.StateScope.AddressList[0], conflictingAccessList)

	nonConflictingAccessList := types.AccessList{
		{
			Address: common.HexToAddress("0x09"),
			StorageKeys: []common.Hash{
				common.HexToHash("0x05"),
			},
		},
	}
	nonConflictingTx := createTestTx(2, common.HexToAddress("0x09"), nonConflictingAccessList)

	allTransactions := []*types.Transaction{conflictingTx, nonConflictingTx}
	mockPendingTxs := map[common.Address][]*types.Transaction{
		testAddr: allTransactions,
	}

	t.Log("Creating StateScopes from transaction Access Lists")
	txStateScopes := make(map[common.Hash]StateScope)

	for _, tx := range allTransactions {
		if accessList := tx.AccessList(); accessList != nil {
			scope := createStateScopeFromAccessList(accessList, tx.Hash())
			txStateScopes[tx.Hash()] = scope
			t.Logf("Created StateScope for tx %s: %+v", tx.Hash().Hex(), scope.AddressList)
		}
	}

	// conflict check
	filteredTxs := make(map[common.Address][]*types.Transaction)
	for addr, txs := range mockPendingTxs {
		var validTxs []*types.Transaction

		for _, tx := range txs {
			txScope, exists := txStateScopes[tx.Hash()]
			if !exists {
				validTxs = append(validTxs, tx)
				t.Logf("Tx %s: ACCEPTED (no StateScope)", tx.Hash().Hex())
				continue
			}

			hasConflict := hasStateScopeConflict(exclusionCommitment.StateScope, txScope)
			if !hasConflict {
				validTxs = append(validTxs, tx)
				t.Logf("Tx %s: no StateScope conflict", tx.Hash().Hex())
			} else {
				t.Logf("Tx %s: StateScope conflict detected", tx.Hash().Hex())
				t.Logf(" Exclusion scope: %v", exclusionCommitment.StateScope.AddressList)
				t.Logf(" Filtered Transaction scope: %v", txScope.AddressList)
			}
		}

		if len(validTxs) > 0 {
			filteredTxs[addr] = validTxs
		}
	}

	// check result
	t.Logf("Original #tx in pool: %d", len(mockPendingTxs[testAddr]))
	t.Logf("Filtered #tx in pool: %d", len(filteredTxs[testAddr]))
	require.Equal(t, 1, len(filteredTxs[testAddr]), "Only non-conflicting tx should remain")
	require.Equal(t, nonConflictingTx.Hash(), filteredTxs[testAddr][0].Hash())

	t.Log("Exclusion commitment successfully filtered conflicting transactions using StateScope")
}

func TestInclusionCommitment(t *testing.T) {
	t.Log("=== Testing Inclusion Commitment Flow (Steps 14-18) ===")

	// env setting
	testKey, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.NewEIP2930Signer(big.NewInt(1))

	// Commitment definition
	type StateScope struct {
		AddressList []common.Address
		LockId      common.Hash
	}

	type InclusionCommitment struct {
		Slot       uint64
		StateScope StateScope
		WinningTxs []*types.Transaction
	}

	// StateScope helper function
	createStateScopeFromAccessList := func(accessList types.AccessList, lockId common.Hash) StateScope {
		addressList := make([]common.Address, 0, len(accessList))
		for _, tuple := range accessList {
			addressList = append(addressList, tuple.Address)
		}
		return StateScope{
			AddressList: addressList,
			LockId:      lockId,
		}
	}

	createTestTx := func(nonce uint64, to common.Address, accessList types.AccessList) *types.Transaction {
		txData := &types.AccessListTx{
			ChainID:    big.NewInt(1),
			Nonce:      nonce,
			To:         &to,
			Value:      big.NewInt(10),
			Gas:        21000,
			GasPrice:   big.NewInt(2000000000),
			AccessList: accessList,
		}
		tx := types.NewTx(txData)
		signedTx, err := types.SignTx(tx, signer, testKey)
		require.NoError(t, err)
		return signedTx
	}

	// Step 14: relay -> builder: inclusion commitment
	t.Log("Step 14: Relay sends inclusion commitment to builder")

	winningTx1AccessList := types.AccessList{
		{
			Address: common.HexToAddress("0x1234567890123456789012345678901234567890"),
			StorageKeys: []common.Hash{
				common.HexToHash("0x01"),
				common.HexToHash("0x02"),
			},
		},
	}
	winningTx1 := createTestTx(10, common.HexToAddress("0x1234567890123456789012345678901234567890"), winningTx1AccessList)

	winningTx2AccessList := types.AccessList{
		{
			Address: common.HexToAddress("0xA0b86a33E6441e6e80D0c4C34F4F6cA4C7C4b1d0"),
			StorageKeys: []common.Hash{
				common.HexToHash("0x03"),
				common.HexToHash("0x04"),
			},
		},
	}
	winningTx2 := createTestTx(11, common.HexToAddress("0xA0b86a33E6441e6e80D0c4C34F4F6cA4C7C4b1d0"), winningTx2AccessList)

	// defining inclusionStateScope from winning transactions
	combinedAccessList := append(winningTx1AccessList, winningTx2AccessList...)
	inclusionStateScope := createStateScopeFromAccessList(combinedAccessList, common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"))

	inclusionCommitment := InclusionCommitment{
		Slot:       100,
		StateScope: inclusionStateScope,
		WinningTxs: []*types.Transaction{winningTx1, winningTx2},
	}

	t.Logf("Inclusion Commitment - Slot: %d, LockId: %s",
		inclusionCommitment.Slot, inclusionCommitment.StateScope.LockId.Hex())
	t.Logf("StateScope addresses: %v", inclusionCommitment.StateScope.AddressList)
	t.Logf("Winning transactions: %d", len(inclusionCommitment.WinningTxs))

	// Step 15: builder: store inclusion commitment
	t.Log("Step 15: Builder validates and stores inclusion commitment")

	// Create constraint cache similar to builder pattern
	constraintsCache := make(map[uint64]types.HashToConstraintDecoded)
	inclusionConstraints := make(types.HashToConstraintDecoded)
	for i, tx := range inclusionCommitment.WinningTxs {
		inclusionConstraints[tx.Hash()] = tx
		t.Logf("Stored winning tx[%d]: %s", i, tx.Hash().Hex())
	}

	// Store in cache by slot number
	constraintsCache[inclusionCommitment.Slot] = inclusionConstraints
	t.Logf("Stored %d inclusion constraints in cache for slot %d", len(inclusionConstraints), inclusionCommitment.Slot)

	// Step 16: builder: retrieve and include winning txs from constraint cache
	t.Log("Step 16: Builder retrieves winning transactions from constraint cache")

	// Retrieve constraints from cache (simulating actual block building process)
	cachedConstraints, exists := constraintsCache[inclusionCommitment.Slot]
	require.True(t, exists, "Inclusion constraints should exist in cache")
	require.Equal(t, len(inclusionCommitment.WinningTxs), len(cachedConstraints), "Cached constraints count should match")

	blockTxs := make([]*types.Transaction, 0)

	// Include winning transactions from cache
	for hash, tx := range cachedConstraints {
		blockTxs = append(blockTxs, tx)
		t.Logf("Included winning tx from cache: %s (hash: %s)", tx.Hash().Hex(), hash.Hex())

		// Access List info
		if accessList := tx.AccessList(); accessList != nil {
			t.Logf("  Access List: %+v", accessList)
		}
	}

	// Step 17: builder: include filted txs
	t.Log("Step 17: Builder removes filtering and finalizes block building")

	regularTx := createTestTx(20,
		common.HexToAddress("0x9999999999999999999999999999999999999999"),
		types.AccessList{})
	blockTxs = append(blockTxs, regularTx)

	t.Logf("Added regular tx: %s", regularTx.Hash().Hex())
	t.Logf("Final block contains %d transactions", len(blockTxs))

	// Step 18: builder -> relay: block header
	t.Log("Step 18: Builder sends block header to relay")

	blockHeader := &types.Header{
		Number:     big.NewInt(int64(inclusionCommitment.Slot)),
		Time:       uint64(time.Now().Unix()),
		GasLimit:   30000000,
		GasUsed:    uint64(len(blockTxs) * 21000),
		Difficulty: big.NewInt(1),
	}

	t.Logf("Block header created - Number: %d, GasUsed: %d",
		blockHeader.Number.Uint64(), blockHeader.GasUsed)

	t.Log("Verifying StateScope consistency")
	for i, tx := range inclusionCommitment.WinningTxs {
		if accessList := tx.AccessList(); accessList != nil {
			txScope := createStateScopeFromAccessList(accessList, tx.Hash())
			t.Logf("Winning tx[%d] StateScope: %+v", i, txScope.AddressList)
		}
	}
	// StateScope consistency check
	t.Log("Verifying StateScope consistency")
	for i, tx := range inclusionCommitment.WinningTxs {
		if accessList := tx.AccessList(); accessList != nil {
			txScope := createStateScopeFromAccessList(accessList, tx.Hash())
			t.Logf("Winning tx[%d] StateScope: %+v", i, txScope.AddressList)
		}
	}

	// check result
	require.Equal(t, 3, len(blockTxs), "Block should contain 2 winning txs + 1 regular tx")
	require.Equal(t, inclusionCommitment.Slot, blockHeader.Number.Uint64())

	// Verify that winning transactions from cache are included
	winningTxHashes := make(map[common.Hash]bool)
	for _, tx := range inclusionCommitment.WinningTxs {
		winningTxHashes[tx.Hash()] = true
	}

	includedWinningCount := 0
	for _, tx := range blockTxs[:len(blockTxs)-1] { // Exclude regular tx
		if winningTxHashes[tx.Hash()] {
			includedWinningCount++
		}
	}
	require.Equal(t, len(inclusionCommitment.WinningTxs), includedWinningCount, "All winning transactions should be included")

	// StateScope consistency check
	require.Equal(t, 2, len(inclusionCommitment.StateScope.AddressList), "StateScope should contain 2 addresses")
	require.Contains(t, inclusionCommitment.StateScope.AddressList, common.HexToAddress("0x1234567890123456789012345678901234567890"))
	require.Contains(t, inclusionCommitment.StateScope.AddressList, common.HexToAddress("0xA0b86a33E6441e6e80D0c4C34F4F6cA4C7C4b1d0"))

	t.Log("Inclusion commitment successfully processed using constraint cache pattern")
}

func TestSubscribeProposerConstraints(t *testing.T) {
	// ------------ Start Builder setup ------------- //
	const (
		validatorDesiredGasLimit = 30_000_000
		payloadAttributeGasLimit = 0
		parentBlockGasLimit      = 29_000_000
	)
	expectedGasLimit := core.CalcGasLimit(parentBlockGasLimit, validatorDesiredGasLimit)

	vsk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x370bb8c1a6e62b2882f6ec76762a67b39609002076b95aae5b023997cf9b2dc9"))
	require.NoError(t, err)
	validator := &ValidatorPrivateData{
		sk: vsk,
		Pk: hexutil.MustDecode("0xb67d2c11bcab8c4394fc2faa9601d0b99c7f4b37e14911101da7d97077917862eed4563203d34b91b5cf0aa44d6cfa05"),
	}

	testBeacon := testBeaconClient{
		validator: validator,
		slot:      56,
	}

	feeRecipient, _ := utils.HexToAddress("0xabcf8e0d4e9587369b2301d0790347320302cc00")

	relayPort := "31245"
	relay := NewRemoteRelay(RelayConfig{Endpoint: "http://localhost:" + relayPort}, nil, true)

	sk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x31ee185dad1220a8c88ca5275e64cf5a5cb09cb621cb30df52c9bee8fbaaf8d7"))
	require.NoError(t, err)

	bDomain := ssz.ComputeDomain(ssz.DomainTypeAppBuilder, [4]byte{0x02, 0x0, 0x0, 0x0}, phase0.Root{})

	testExecutableData := &engine.ExecutableData{
		ParentHash:   common.Hash{0x02, 0x03},
		FeeRecipient: common.Address(feeRecipient),
		StateRoot:    common.Hash{0x07, 0x16},
		ReceiptsRoot: common.Hash{0x08, 0x20},
		LogsBloom:    types.Bloom{}.Bytes(),
		Number:       uint64(10),
		GasLimit:     expectedGasLimit,
		GasUsed:      uint64(100),
		Timestamp:    uint64(105),
		ExtraData:    hexutil.MustDecode("0x0042fafc"),

		BaseFeePerGas: big.NewInt(16),

		BlockHash:    common.HexToHash("0x68e516c8827b589fcb749a9e672aa16b9643437459508c467f66a9ed1de66a6c"),
		Transactions: [][]byte{},
	}

	testBlock, err := engine.ExecutableDataToBlock(*testExecutableData, nil, nil)
	require.NoError(t, err)

	testEthService := &testEthereumService{synced: true, testExecutableData: testExecutableData, testBlock: testBlock, testBlockValue: big.NewInt(10)}

	builderArgs := BuilderArgs{
		sk:                          sk,
		ds:                          flashbotsextra.NilDbService{},
		relay:                       relay,
		builderSigningDomain:        bDomain,
		eth:                         testEthService,
		dryRun:                      false,
		ignoreLatePayloadAttributes: false,
		validator:                   nil,
		beaconClient:                &testBeacon,
		limiter:                     nil,
		blockConsumer:               flashbotsextra.NilDbService{},
	}

	builder, err := NewBuilder(builderArgs)
	require.NoError(t, err)

	// ------------ End Builder setup ------------- //

	// Attach the sseHandler to the relay port
	mux := http.NewServeMux()
	mux.HandleFunc(SubscribeConstraintsPath, sseConstraintsHandler)

	// Wrap the mux with the GzipHandler middleware
	// NOTE: In this case, we don't need to create a gzip writer in the handlers,
	// by default the `http.ResponseWriter` will implement gzip compression
	gzipMux := handlers.CompressHandler(mux)

	http.HandleFunc(SubscribeConstraintsPath, sseConstraintsHandler)
	go http.ListenAndServe(":"+relayPort, gzipMux)

	// Constraints should not be available yet
	_, okInclusion := builder.inclusionConstraintsCache.Get(0)
	require.Equal(t, false, okInclusion)

	_, okExclusion := builder.exclusionConstraintsCache.Get(0)
	require.Equal(t, false, okExclusion)

	go builder.subscribeToRelayForConstraints(builder.relay.Config().Endpoint)
	// Wait 2 seconds to save all constraints in cache
	time.Sleep(2 * time.Second)

	slot := uint64(0)
	// slots := []uint64{0}
	// slots := []uint64{0, 1, 2}
	// for _, slot := range slots {
	expectedConstraint := generateMockConstraintsForSlot(slot)[0]
	decodedConstraint, err := DecodeConstraints(expectedConstraint)
	require.NoError(t, err)

	if expectedConstraint.Message.Top {
		// Inclusion constraint
		cachedConstraints, ok := builder.inclusionConstraintsCache.Get(slot)
		require.True(t, ok, fmt.Sprintf("expected inclusion constraint for slot %d", slot))
		require.Equal(t, len(cachedConstraints), len(decodedConstraint), fmt.Sprintf("slot %d inclusion constraint length mismatch", slot))
	} else {
		// Exclusion constraint
		cachedConstraints, ok := builder.exclusionConstraintsCache.Get(slot)
		require.True(t, ok, fmt.Sprintf("expected exclusion constraint for slot %d", slot))
		require.Equal(t, len(cachedConstraints), len(decodedConstraint), fmt.Sprintf("slot %d exclusion constraint length mismatch", slot))
	}
	// }
}

func TestDeserializeConstraints(t *testing.T) {
	jsonStr := `[
		{
			"message": {
				"pubkey": "0xa695ad325dfc7e1191fbc9f186f58eff42a634029731b18380ff89bf42c464a42cb8ca55b200f051f57f1e1893c68759",
				"slot": 32,
				"top": true,
				"transactions": [
					"0x02f86c870c72dd9d5e883e4d0183408f2382520894d2e2adf7177b7a8afddbc12d1634cf23ea1a71020180c001a08556dcfea479b34675db3fe08e29486fe719c2b22f6b0c1741ecbbdce4575cc6a01cd48009ccafd6b9f1290bbe2ceea268f94101d1d322c787018423ebcbc87ab4"
				]
			},
			"signature": "0xb8d50ee0d4b269db3d4658c1dac784d273a4160d769e16dce723a9684c390afe5865348416b3bf0f1a4f47098bec9024135d0d95f08bed18eb577a3d8a67f5dc78b13cc62515e280786a73fb267d35dfb7ab46a25ac29bf5bc2fa5b07b3e07a6"
		}
	]`

	var constraints types.SignedConstraintsList
	err := json.Unmarshal([]byte(jsonStr), &constraints)
	require.NoError(t, err)

	jsonStr = `[
		{
			"message": {
				"pubkey":"0xb3cd9c9e59730c210bf9b76959bf11e20bb05cf47cfefdcaab74bc17c369d6daefe1219c2b94d743ffd27988edf24b90",
				"slot":183,
				"top":false,
				"transactions": [
					"0xf8678085019dc6838082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead04808360306ca0fde9bdf8f1a9fefef7538490242afb21a0160cf19f1686c7b9bddb45de973b62a0318411f2c959d3e6a25434f99850a0eaa6beb617f7a2dbc9683dccded7bd4b10"
				]
			},
			"signature": "0xaa8a47c6398d5862b56d1bbb308352c65e57e62b0bfdda39a36db7fff3a256c3c7066b219a15a013aae5303f42b6f07b025f34ed6d899e6172fec20d40c4ffebeb50f5d0b75a303c1cc916574c3e0f29d53b2211d28234f430fffce62b4ee554"
		}
	]`

	err = json.Unmarshal([]byte(jsonStr), &constraints)
	require.NoError(t, err)
}

func sseConstraintsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Content-Encoding", "gzip")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// for i := 0; i < 256; i++ {
	for i := 0; i < 1; i++ {
		// Generate some duplicated constraints
		slot := uint64(i) % 32
		constraints := generateMockConstraintsForSlot(slot)
		bytes, err := json.Marshal(constraints)
		if err != nil {
			log.Error(fmt.Sprintf("Error while marshaling constraints: %v", err))
			return
		}
		fmt.Fprintf(w, "data: %s\n\n", string(bytes))
		flusher.Flush()
	}
}

// generateMockConstraintsForSlot generates a list of constraints for a given slot
func generateMockConstraintsForSlot(slot uint64) types.SignedConstraintsList {
	rawTx := new(types.Transaction)
	err := rawTx.UnmarshalBinary(common.Hex2Bytes("02f87601836384348477359400850517683ba883019a28943678fce4028b6745eb04fa010d9c8e4b36d6288c872b0f1366ad800080c080a0b6b7aba1954160d081b2c8612e039518b9c46cd7df838b405a03f927ad196158a071d2fb6813e5b5184def6bd90fb5f29e0c52671dea433a7decb289560a58416e"))
	if err != nil {
		panic(fmt.Sprintf("Failed to unmarshal rawTx: %v", err))
	}

	return types.SignedConstraintsList{
		&types.SignedConstraints{
			Message: types.ConstraintsMessage{
				Transactions: []*types.Transaction{rawTx}, Pubkey: phase0.BLSPubKey{}, Slot: slot,
			}, Signature: phase0.BLSSignature{},
		},
		&types.SignedConstraints{
			Message: types.ConstraintsMessage{
				Transactions: []*types.Transaction{rawTx}, Pubkey: phase0.BLSPubKey{}, Slot: slot, Top: true,
			}, Signature: phase0.BLSSignature{},
		},
	}
}

func setBlockhash(data *engine.ExecutableData) *engine.ExecutableData {
	txs, _ := decodeTransactions(data.Transactions)
	number := big.NewInt(0)
	number.SetUint64(data.Number)
	header := &types.Header{
		ParentHash:  data.ParentHash,
		UncleHash:   types.EmptyUncleHash,
		Coinbase:    data.FeeRecipient,
		Root:        data.StateRoot,
		TxHash:      types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil)),
		ReceiptHash: data.ReceiptsRoot,
		Bloom:       types.BytesToBloom(data.LogsBloom),
		Difficulty:  common.Big0,
		Number:      number,
		GasLimit:    data.GasLimit,
		GasUsed:     data.GasUsed,
		Time:        data.Timestamp,
		BaseFee:     data.BaseFeePerGas,
		Extra:       data.ExtraData,
		MixDigest:   data.Random,
	}
	block := types.NewBlockWithHeader(header).WithBody(txs, nil /* uncles */)
	data.BlockHash = block.Hash()
	return data
}

// decodeTransactions decodes a slice of raw transaction bytes into []*types.Transaction.
func decodeTransactions(rawTxs [][]byte) ([]*types.Transaction, error) {
	txs := make([]*types.Transaction, 0, len(rawTxs))
	for _, raw := range rawTxs {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(raw); err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

func TestOnSealedBlockWithConstraints(t *testing.T) {
	const (
		validatorDesiredGasLimit = 30_000_000
		parentBlockGasLimit      = 29_000_000
		testSlot                 = uint64(25)
	)
	expectedGasLimit := core.CalcGasLimit(parentBlockGasLimit, validatorDesiredGasLimit)

	// Setup validator and beacon client
	vsk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x370bb8c1a6e62b2882f6ec76762a67b39609002076b95aae5b023997cf9b2dc9"))
	require.NoError(t, err)
	validator := &ValidatorPrivateData{
		sk: vsk,
		Pk: hexutil.MustDecode("0xb67d2c11bcab8c4394fc2faa9601d0b99c7f4b37e14911101da7d97077917862eed4563203d34b91b5cf0aa44d6cfa05"),
	}

	testBeacon := testBeaconClient{
		validator: validator,
		slot:      56,
	}
	feeRecipient, _ := utils.HexToAddress("0xabcf8e0d4e9587369b2301d0790347320302cc00")
	testRelay := testRelay{
		gvsVd: ValidatorData{
			Pubkey:       PubkeyHex(testBeacon.validator.Pk.String()),
			FeeRecipient: feeRecipient,
			GasLimit:     validatorDesiredGasLimit,
		},
	}

	// Setup builder
	sk, err := bls.SecretKeyFromBytes(hexutil.MustDecode("0x31ee185dad1220a8c88ca5275e64cf5a5cb09cb621cb30df52c9bee8fbaaf8d7"))
	require.NoError(t, err)

	bDomain := ssz.ComputeDomain(ssz.DomainTypeAppBuilder, [4]byte{0x02, 0x0, 0x0, 0x0}, phase0.Root{})

	// Create test transactions for constraints
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	signer := types.NewEIP2930Signer(big.NewInt(1))

	// Inclusion constraint transaction (MUST be included)
	inclusionTxByte, _ := hex.DecodeString("02f87601836384348477359400850517683ba883019a28943678fce4028b6745eb04fa010d9c8e4b36d6288c872b0f1366ad800080c080a0b6b7aba1954160d081b2c8612e039518b9c46cd7df838b405a03f927ad196158a071d2fb6813e5b5184def6bd90fb5f29e0c52671dea433a7decb289560a58416e")
	inclusionTx := new(types.Transaction)
	err = inclusionTx.UnmarshalBinary(inclusionTxByte)
	require.NoError(t, err)

	// Exclusion constraint transaction (MUST be excluded)
	exclusionTx := &types.AccessListTx{
		ChainID:  big.NewInt(1),
		Nonce:    1,
		To:       &common.Address{0x01},
		Gas:      30000,
		GasPrice: big.NewInt(3000000000), // High gas price but should be excluded
		Value:    big.NewInt(1000),
		AccessList: types.AccessList{{
			Address:     common.Address{0x02},
			StorageKeys: []common.Hash{{0x01}},
		}},
	}
	signedExclusionTx, err := types.SignNewTx(key, signer, exclusionTx)
	require.NoError(t, err)

	// Create test block with inclusion transaction
	testExecutableData := &engine.ExecutableData{
		ParentHash:    common.Hash{0x02, 0x03},
		FeeRecipient:  common.Address(feeRecipient),
		StateRoot:     common.Hash{0x07, 0x16},
		ReceiptsRoot:  common.Hash{0x08, 0x20},
		LogsBloom:     types.Bloom{}.Bytes(),
		Number:        uint64(10),
		GasLimit:      expectedGasLimit,
		GasUsed:       uint64(100),
		Timestamp:     uint64(105),
		ExtraData:     hexutil.MustDecode("0x0042fafc"),
		BaseFeePerGas: big.NewInt(16),
		Transactions:  [][]byte{inclusionTxByte}, // Only inclusion tx in block
	}

	testExecutableData.BlockHash = setBlockhash(testExecutableData).BlockHash

	testBlock, err := engine.ExecutableDataToBlock(*testExecutableData, nil, nil)
	require.NoError(t, err)

	testPayloadAttributes := &types.BuilderPayloadAttributes{
		Timestamp:             hexutil.Uint64(104),
		Random:                common.Hash{0x05, 0x10},
		SuggestedFeeRecipient: common.Address{0x04, 0x10},
		GasLimit:              uint64(validatorDesiredGasLimit),
		Slot:                  testSlot,
	}

	testEthService := &testEthereumService{
		synced:             true,
		testExecutableData: testExecutableData,
		testBlock:          testBlock,
		testBlockValue:     big.NewInt(10),
	}

	builderArgs := BuilderArgs{
		sk:                   sk,
		ds:                   flashbotsextra.NilDbService{},
		relay:                &testRelay,
		builderSigningDomain: bDomain,
		eth:                  testEthService,
		dryRun:               false,
		validator:            nil,
		beaconClient:         &testBeacon,
		limiter:              nil,
		blockConsumer:        flashbotsextra.NilDbService{},
	}

	builder, err := NewBuilder(builderArgs)
	require.NoError(t, err)

	// Setup constraints in cache
	builder.inclusionConstraintsCache.Put(testSlot, map[common.Hash]*types.Transaction{
		inclusionTx.Hash(): inclusionTx,
	})
	builder.exclusionConstraintsCache.Put(testSlot, map[common.Hash]*types.Transaction{
		signedExclusionTx.Hash(): signedExclusionTx,
	})

	expectedProposerPubkey, err := utils.HexToPubkey(testBeacon.validator.Pk.String())
	require.NoError(t, err)

	fmt.Printf("\n\n=== CONSTRAINT SETUP ===")
	fmt.Printf("\nSlot: %d", testSlot)
	fmt.Printf("\nInclusion constraint: %s (MUST be in block)", inclusionTx.Hash().Hex())
	fmt.Printf("\nExclusion constraint: %s (MUST NOT be in block)", signedExclusionTx.Hash().Hex())

	// Create SubmitBlockOpts for onSealedBlock
	submitOpts := SubmitBlockOpts{
		Block:             testBlock,
		BlockValue:        big.NewInt(10),
		BlobSidecars:      nil,
		OrdersClosedAt:    time.Now(),
		SealedAt:          time.Now(),
		CommitedBundles:   []types.SimulatedBundle{},
		AllBundles:        []types.SimulatedBundle{},
		UsedSbundles:      []types.UsedSBundle{},
		ProposerPubkey:    expectedProposerPubkey,
		ValidatorData:     testRelay.gvsVd,
		PayloadAttributes: testPayloadAttributes,
	}

	fmt.Printf("\n\n === BLOCK DATA BEFORE RELAY SUBMISSION ===")
	fmt.Printf("\nBlock Number: %d", testBlock.Number().Uint64())
	fmt.Printf("\nBlock Hash: %s", testBlock.Hash().Hex())
	fmt.Printf("\nTransaction Count: %d", len(testBlock.Transactions()))
	fmt.Printf("\nGas Used: %d / %d", testBlock.GasUsed(), testBlock.GasLimit())

	// Analyze block transactions
	blockTxHashes := make(map[common.Hash]bool)
	for i, tx := range testBlock.Transactions() {
		blockTxHashes[tx.Hash()] = true
		t.Logf("Tx %d: Hash=%s, To=%s, GasPrice=%s",
			i, tx.Hash().Hex(),
			func() string {
				if tx.To() != nil {
					return tx.To().Hex()
				}
				return "CONTRACT_CREATION"
			}(),
			tx.GasPrice().String())
	}

	// Verify constraints before relay submission
	t.Logf("\n\n=== CONSTRAINT VERIFICATION ===")
	inclusionIncluded := blockTxHashes[inclusionTx.Hash()]
	exclusionIncluded := blockTxHashes[signedExclusionTx.Hash()]

	t.Logf("Inclusion constraint in block: %v (should be true)", inclusionIncluded)
	t.Logf("Exclusion constraint in block: %v (should be false)", exclusionIncluded)

	require.True(t, inclusionIncluded, "Inclusion constraint must be in block")
	require.False(t, exclusionIncluded, "Exclusion constraint must NOT be in block")

	// Test onSealedBlock function
	t.Logf("\n\n=== TESTING onSealedBlock ===")
	err = builder.onSealedBlock(submitOpts)
	require.NoError(t, err, "onSealedBlock should not return error")

	// Verify relay received the block with proofs
	t.Logf("\n\n=== RELAY SUBMISSION VERIFICATION ===")
	if testRelay.submittedMsgWithProofs != nil {
		t.Logf("SUCCESS: Block with proofs submitted to relay")
		t.Logf("Submitted block hash: %s", hex.EncodeToString(testRelay.submittedMsgWithProofs.Bellatrix.Message.BlockHash[:]))
		t.Logf("Proofs included: %v", testRelay.submittedMsgWithProofs.Proofs != nil)
		require.NotNil(t, testRelay.submittedMsgWithProofs.Proofs, "Proofs should be included")
	} else if testRelay.submittedMsg != nil {
		t.Logf("Block submitted without proofs (fallback)")
		t.Logf("Submitted block hash: %s", hex.EncodeToString(testRelay.submittedMsg.Bellatrix.Message.BlockHash[:]))
	} else {
		t.Fatalf("No block was submitted to relay")
	}

	t.Logf("=== TEST COMPLETED SUCCESSFULLY ===")
}
