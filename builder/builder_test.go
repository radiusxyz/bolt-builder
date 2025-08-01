package builder

import (
	"crypto/ecdsa"
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
	builder.constraintsCache.Put(25, map[common.Hash]*types.Transaction{
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

func TestAccessListExclusionConstraints(t *testing.T) {
	const (
		validatorDesiredGasLimit = 30_000_000
		payloadAttributeGasLimit = 30_000_000
		parentBlockGasLimit      = 29_000_000
	)

	// <cite>eth/block-validation/api_test.go:53-57</cite>에서 정의된 테스트 키 사용
	testKey, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testAddr := crypto.PubkeyToAddress(testKey.PublicKey)

	// Access List가 있는 트랜잭션 생성 (EIP-2930)
	accessListTx := types.AccessList{
		{
			Address: common.HexToAddress("0x1234567890123456789012345678901234567890"),
			StorageKeys: []common.Hash{
				common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
				common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002"),
			},
		},
	}

	// Access List 트랜잭션 생성
	txData := &types.AccessListTx{
		ChainID:    big.NewInt(1),
		Nonce:      0,
		To:         &common.Address{0x16},
		Value:      big.NewInt(10),
		Gas:        21000,
		GasPrice:   big.NewInt(2000000000),
		AccessList: accessListTx, // 포인터 제거
	}

	tx := types.NewTx(txData)

	// 트랜잭션 서명
	signer := types.NewEIP2930Signer(big.NewInt(1))
	signedTx, err := types.SignTx(tx, signer, testKey)
	require.NoError(t, err)

	// Block Validation API를 사용하여 Access List 추출 테스트
	t.Run("ExtractAccessListFromTransaction", func(t *testing.T) {
		// 트랜잭션에서 Access List 추출
		extractedAccessList := signedTx.AccessList()
		require.NotNil(t, extractedAccessList)
		require.Equal(t, 1, len(extractedAccessList)) // 포인터 역참조 제거

		accessTuple := extractedAccessList[0] // 포인터 역참조 제거
		require.Equal(t, common.HexToAddress("0x1234567890123456789012345678901234567890"), accessTuple.Address)
		require.Equal(t, 2, len(accessTuple.StorageKeys))

		t.Logf("Extracted Access List: %+v", extractedAccessList) // 포인터 역참조 제거
	})

	// Exclusion Constraint 정의 및 테스트
	t.Run("ExclusionConstraintFiltering", func(t *testing.T) {
		// Exclusion Constraint 정의 (임시 구조체)
		type StateScope struct {
			AccessList types.AccessList `json:"accessList"`
			LockId     common.Hash      `json:"lockId"`
		}

		type ExclusionConstraint struct {
			Type       string     `json:"type"`
			StateScope StateScope `json:"stateScope"`
		}

		// 충돌하는 StateScope 정의
		conflictingStateScope := StateScope{
			AccessList: types.AccessList{
				{
					Address: common.HexToAddress("0x1234567890123456789012345678901234567890"),
					StorageKeys: []common.Hash{
						common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
					},
				},
			},
			LockId: common.HexToHash("0xabcd1234"),
		}

		exclusionConstraint := ExclusionConstraint{
			Type:       "exclusion",
			StateScope: conflictingStateScope,
		}

		t.Logf("Exclusion Constraint: %+v", exclusionConstraint)

		// Access List 충돌 검사 함수
		hasConflict := func(tx *types.Transaction, stateScope StateScope) bool {
			txAccessList := tx.AccessList()
			if txAccessList == nil {
				return false
			}

			for _, txAccess := range txAccessList { // 포인터 역참조 제거
				for _, scopeAccess := range stateScope.AccessList {
					if txAccess.Address == scopeAccess.Address {
						// 스토리지 키 충돌 검사
						for _, txKey := range txAccess.StorageKeys {
							for _, scopeKey := range scopeAccess.StorageKeys {
								if txKey == scopeKey {
									return true
								}
							}
						}
					}
				}
			}
			return false
		}

		// 충돌 검사 테스트
		conflict := hasConflict(signedTx, conflictingStateScope)
		require.True(t, conflict, "Transaction should conflict with exclusion constraint")
		t.Logf("Conflict detected: %v", conflict)

		// 충돌하지 않는 트랜잭션 생성
		nonConflictingAccessList := types.AccessList{
			{
				Address: common.HexToAddress("0x9876543210987654321098765432109876543210"),
				StorageKeys: []common.Hash{
					common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000003"),
				},
			},
		}

		nonConflictingTxData := &types.AccessListTx{
			ChainID:    big.NewInt(1),
			Nonce:      1,
			To:         &common.Address{0x17},
			Value:      big.NewInt(20),
			Gas:        21000,
			GasPrice:   big.NewInt(2000000000),
			AccessList: nonConflictingAccessList, // 포인터 제거
		}

		nonConflictingTx := types.NewTx(nonConflictingTxData)
		signedNonConflictingTx, err := types.SignTx(nonConflictingTx, signer, testKey)
		require.NoError(t, err)

		noConflict := hasConflict(signedNonConflictingTx, conflictingStateScope)
		require.False(t, noConflict, "Non-conflicting transaction should not conflict")
		t.Logf("No conflict detected: %v", !noConflict)
	})

	// 트랜잭션 풀 필터링 시뮬레이션
	t.Run("TransactionPoolFiltering", func(t *testing.T) {
		// 모의 트랜잭션 풀 데이터
		mockPendingTxs := map[common.Address][]*types.Transaction{
			testAddr: {signedTx}, // 충돌하는 트랜잭션
		}

		// Exclusion constraint 기반 필터링 함수
		filterByExclusionConstraints := func(
			pending map[common.Address][]*types.Transaction,
			exclusionConstraints map[common.Hash]types.AccessList,
		) map[common.Address][]*types.Transaction {
			filtered := make(map[common.Address][]*types.Transaction)

			for addr, txs := range pending {
				var validTxs []*types.Transaction

				for _, tx := range txs {
					hasConflict := false
					txAccessList := tx.AccessList()

					if txAccessList != nil {
						for _, exclusionAccessList := range exclusionConstraints {
							for _, txAccess := range txAccessList { // 포인터 역참조 제거
								for _, exclusionAccess := range exclusionAccessList {
									if txAccess.Address == exclusionAccess.Address {
										// 스토리지 키 충돌 검사
										for _, txKey := range txAccess.StorageKeys {
											for _, exclusionKey := range exclusionAccess.StorageKeys {
												if txKey == exclusionKey {
													hasConflict = true
													break
												}
											}
											if hasConflict {
												break
											}
										}
									}
									if hasConflict {
										break
									}
								}
								if hasConflict {
									break
								}
							}
							if hasConflict {
								break
							}
						}
					}

					if !hasConflict {
						validTxs = append(validTxs, tx)
					}
				}

				if len(validTxs) > 0 {
					filtered[addr] = validTxs
				}
			}

			return filtered
		}

		// Exclusion constraints 정의
		exclusionConstraints := map[common.Hash]types.AccessList{
			common.HexToHash("0xabcd1234"): {
				{
					Address: common.HexToAddress("0x1234567890123456789012345678901234567890"),
					StorageKeys: []common.Hash{
						common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
					},
				},
			},
		}

		// 필터링 실행
		filteredTxs := filterByExclusionConstraints(mockPendingTxs, exclusionConstraints)

		// 결과 검증
		require.Empty(t, filteredTxs, "Conflicting transactions should be filtered out")
		t.Logf("Original transactions: %d", len(mockPendingTxs[testAddr]))
		t.Logf("Filtered transactions: %d", len(filteredTxs))
	})
}

func TestAccessListExclusionConstraints2(t *testing.T) {
	t.Log("=== Starting Enhanced Access List Exclusion Constraints Test ===")

	type StateScope struct {
		AccessList types.AccessList `json:"accessList"`
		LockId     common.Hash      `json:"lockId"`
	}

	type ExclusionConstraint struct {
		Type       string     `json:"type"`
		StateScope StateScope `json:"stateScope"`
	}

	// 테스트 키 설정
	testKey, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testAddr := crypto.PubkeyToAddress(testKey.PublicKey)
	signer := types.NewEIP2930Signer(big.NewInt(1))

	// 헬퍼 함수
	createAccessListTx := func(key *ecdsa.PrivateKey, nonce uint64, address common.Address, storageKeys []common.Hash) *types.Transaction {
		txData := &types.AccessListTx{
			ChainID:    big.NewInt(1),
			Nonce:      nonce,
			To:         &common.Address{0x16},
			Value:      big.NewInt(10),
			Gas:        21000,
			GasPrice:   big.NewInt(2000000000),
			AccessList: types.AccessList{{Address: address, StorageKeys: storageKeys}},
		}

		tx := types.NewTx(txData)
		signedTx, err := types.SignTx(tx, signer, key)
		require.NoError(t, err)
		return signedTx
	}

	checkAccessListConflict := func(tx *types.Transaction, stateScope StateScope) bool {
		txAccessList := tx.AccessList()
		if txAccessList == nil {
			return false
		}

		for _, txAccess := range txAccessList {
			for _, scopeAccess := range stateScope.AccessList {
				if txAccess.Address == scopeAccess.Address {
					for _, txKey := range txAccess.StorageKeys {
						for _, scopeKey := range scopeAccess.StorageKeys {
							if txKey == scopeKey {
								return true
							}
						}
					}
				}
			}
		}
		return false
	}

	getTotalTxCount := func(txMap map[common.Address][]*types.Transaction) int {
		total := 0
		for _, txs := range txMap {
			total += len(txs)
		}
		return total
	}

	filterByExclusionConstraints := func(
		pending map[common.Address][]*types.Transaction,
		exclusionConstraints map[common.Hash]types.AccessList,
	) map[common.Address][]*types.Transaction {
		filtered := make(map[common.Address][]*types.Transaction)

		for addr, txs := range pending {
			var validTxs []*types.Transaction

			for _, tx := range txs {
				hasConflict := false
				txAccessList := tx.AccessList()

				if txAccessList != nil {
					for _, exclusionAccessList := range exclusionConstraints {
						for _, txAccess := range txAccessList {
							for _, exclusionAccess := range exclusionAccessList {
								if txAccess.Address == exclusionAccess.Address {
									for _, txKey := range txAccess.StorageKeys {
										for _, exclusionKey := range exclusionAccess.StorageKeys {
											if txKey == exclusionKey {
												hasConflict = true
												break
											}
										}
										if hasConflict {
											break
										}
									}
								}
								if hasConflict {
									break
								}
							}
							if hasConflict {
								break
							}
						}
						if hasConflict {
							break
						}
					}
				}

				if !hasConflict {
					validTxs = append(validTxs, tx)
				}
			}

			if len(validTxs) > 0 {
				filtered[addr] = validTxs
			}
		}

		return filtered
	}

	t.Run("RealisticConstraintScenario", func(t *testing.T) {  
        t.Log("--- Step 1: Proposer Sets Exclusion Constraint First ---")  
          
        // 먼저 proposer가 exclusion constraint를 설정  
        exclusionStateScope := StateScope{  
            AccessList: types.AccessList{  
                {  
                    Address: common.HexToAddress("0x1234567890123456789012345678901234567890"),  
                    StorageKeys: []common.Hash{  
                        common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),  
                        common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002"),  
                    },  
                },  
            },  
            LockId: common.HexToHash("0x1"),  // auction identifier
        }  
  
        exclusionConstraint := ExclusionConstraint{  
            Type:       "exclusion",  
            StateScope: exclusionStateScope,  
        }  
  
        t.Logf("Proposer sets Exclusion Constraint:")  
        t.Logf("  Type: %s", exclusionConstraint.Type)  
        t.Logf("  LockId: %s", exclusionStateScope.LockId.Hex())  
        t.Logf("  Protected Address: %s", exclusionStateScope.AccessList[0].Address.Hex())  
        t.Logf("  Protected Storage Keys:")  
        for i, key := range exclusionStateScope.AccessList[0].StorageKeys {  
            t.Logf("    [%d] %s", i, key.Hex())  
        }  
  
        t.Log("--- Step 2: MEV Searchers Submit Bundles ---")  
          
        // 이제 MEV searcher들이 번들을 제출 (일부는 충돌, 일부는 충돌하지 않음)  
          
        // 1. 충돌하는 트랜잭션 (constraint와 동일한 주소/키 접근)  
        conflictingTx := createAccessListTx(testKey, 0,  
            common.HexToAddress("0x1234567890123456789012345678901234567890"),  
            []common.Hash{  
                common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"), // 충돌!  
                common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000003"),  
            })  
          
        // 2. 부분적으로 충돌하는 트랜잭션  
        partialConflictTx := createAccessListTx(testKey, 1,  
            common.HexToAddress("0x1234567890123456789012345678901234567890"),  
            []common.Hash{  
                common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002"), // 충돌!  
                common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000004"),  
            })  
          
        // 3. 충돌하지 않는 트랜잭션  
        nonConflictTx := createAccessListTx(testKey, 2,  
            common.HexToAddress("0x9876543210987654321098765432109876543210"), // 다른 주소  
            []common.Hash{  
                common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000005"),  
            })  
  
        t.Log("MEV Searchers submit the following transactions:")  
        transactions := []*types.Transaction{conflictingTx, partialConflictTx, nonConflictTx}  
          
        for i, tx := range transactions {  
            t.Logf("  Bundle[%d]: Hash=%s, Nonce=%d", i, tx.Hash().Hex(), tx.Nonce())  
            accessList := tx.AccessList()  
            if accessList != nil && len(accessList) > 0 {  
                for j, entry := range accessList {  
                    t.Logf("    Access[%d]: Address=%s", j, entry.Address.Hex())  
                    for k, key := range entry.StorageKeys {  
                        t.Logf("      Key[%d]: %s", k, key.Hex())  
                    }  
                }  
            }  
        }  
  
        t.Log("--- Step 3: Builder Performs Conflict Detection ---")  
          
        // Builder가 constraint와 비교하여 충돌 검사 수행  
        checkAccessListConflict := func(tx *types.Transaction, stateScope StateScope) bool {  
            txAccessList := tx.AccessList()  
            if txAccessList == nil {  
                return false  
            }  
  
            for _, txAccess := range txAccessList {  
                for _, scopeAccess := range stateScope.AccessList {  
                    if txAccess.Address == scopeAccess.Address {  
                        for _, txKey := range txAccess.StorageKeys {  
                            for _, scopeKey := range scopeAccess.StorageKeys {  
                                if txKey == scopeKey {  
                                    return true  
                                }  
                            }  
                        }  
                    }  
                }  
            }  
            return false  
        }  
  
        t.Log("Conflict detection results:")  
        validTransactions := []*types.Transaction{}  
        rejectedTransactions := []*types.Transaction{}  
          
        for i, tx := range transactions {  
            hasConflict := checkAccessListConflict(tx, exclusionStateScope)  
            if hasConflict {  
                rejectedTransactions = append(rejectedTransactions, tx)  
                t.Logf("  Bundle[%d]: REJECTED (conflicts with constraint)", i)  
                  
                // 충돌 상세 분석  
                txAccessList := tx.AccessList()  
                for _, txAccess := range txAccessList {  
                    for _, protectedAccess := range exclusionStateScope.AccessList {  
                        if txAccess.Address == protectedAccess.Address {  
                            for _, txKey := range txAccess.StorageKeys {  
                                for _, protectedKey := range protectedAccess.StorageKeys {  
                                    if txKey == protectedKey {  
                                        t.Logf("    Conflict: Address=%s, Key=%s",   
                                            txAccess.Address.Hex(), txKey.Hex())  
                                    }  
                                }  
                            }  
                        }  
                    }  
                }  
            } else {  
                validTransactions = append(validTransactions, tx)  
                t.Logf("  Bundle[%d]: ACCEPTED (no conflict)", i)  
            }  
        }  
  
        t.Log("--- Step 4: Final Block Building Results ---")  
          
        t.Logf("Summary:")  
        t.Logf("  Total submitted bundles: %d", len(transactions))  
        t.Logf("  Accepted bundles: %d", len(validTransactions))  
        t.Logf("  Rejected bundles: %d", len(rejectedTransactions))  
          
        t.Log("Accepted transactions for block inclusion:")  
        for i, tx := range validTransactions {  
            t.Logf("  [%d] Hash=%s", i, tx.Hash().Hex())  
        }  
          
        t.Log("Rejected transactions (constraint violations):")  
        for i, tx := range rejectedTransactions {  
            t.Logf("  [%d] Hash=%s", i, tx.Hash().Hex())  
        }  
  
        // 검증  
        require.Equal(t, 1, len(validTransactions), "Only non-conflicting transaction should be accepted")  
        require.Equal(t, 2, len(rejectedTransactions), "Two conflicting transactions should be rejected")  
    })  

	// 여러 개의 트랜잭션 생성 (다양한 Access List 패턴)
	t.Log("Step 1: Creating test transactions with different Access List patterns")

	// 1. 충돌하는 트랜잭션
	conflictingTx := createAccessListTx(testKey, 0,
		common.HexToAddress("0x1234567890123456789012345678901234567890"),
		[]common.Hash{
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002"),
		})

	// 2. 부분적으로 충돌하는 트랜잭션
	partialConflictTx := createAccessListTx(testKey, 1,
		common.HexToAddress("0x1234567890123456789012345678901234567890"),
		[]common.Hash{
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000003"),
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"), // 충돌
		})

	// 3. 충돌하지 않는 트랜잭션
	nonConflictTx := createAccessListTx(testKey, 2,
		common.HexToAddress("0x9876543210987654321098765432109876543210"),
		[]common.Hash{
			common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000005"),
		})

	t.Run("DetailedTransactionPoolAnalysis", func(t *testing.T) {
		t.Log("--- Step 2: Current Transaction Pool Contents ---")

		// 모의 트랜잭션 풀 데이터 생성
		mockPendingTxs := map[common.Address][]*types.Transaction{
			testAddr: {conflictingTx, partialConflictTx, nonConflictTx},
		}

		// 현재 TX Pool 내용 출력
		t.Logf("Transaction Pool contains %d addresses", len(mockPendingTxs))
		for addr, txs := range mockPendingTxs {
			t.Logf("Address %s has %d transactions:", addr.Hex(), len(txs))
			for i, tx := range txs {
				t.Logf("  Tx[%d]: Hash=%s, Nonce=%d, To=%s",
					i, tx.Hash().Hex(), tx.Nonce(), tx.To().Hex())

				// Access List 상세 출력
				accessList := tx.AccessList()
				if accessList != nil && len(accessList) > 0 {
					t.Logf("    Access List (%d entries):", len(accessList))
					for j, entry := range accessList {
						t.Logf("      [%d] Address: %s", j, entry.Address.Hex())
						t.Logf("          Storage Keys (%d):", len(entry.StorageKeys))
						for k, key := range entry.StorageKeys {
							t.Logf("            [%d] %s", k, key.Hex())
						}
					}
				} else {
					t.Logf("    No Access List")
				}
			}
		}

		t.Log("--- Step 3: Exclusion Constraint Definition ---")

		// Exclusion Constraint 정의
		exclusionStateScope := StateScope{
			AccessList: types.AccessList{
				{
					Address: common.HexToAddress("0x1234567890123456789012345678901234567890"),
					StorageKeys: []common.Hash{
						common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
						common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002"),
					},
				},
			},
			LockId: common.HexToHash("0xabcd1234"),
		}

		t.Logf("Exclusion Constraint LockId: %s", exclusionStateScope.LockId.Hex())
		t.Logf("Protected Access List (%d entries):", len(exclusionStateScope.AccessList))
		for i, entry := range exclusionStateScope.AccessList {
			t.Logf("  [%d] Protected Address: %s", i, entry.Address.Hex())
			t.Logf("      Protected Storage Keys (%d):", len(entry.StorageKeys))
			for j, key := range entry.StorageKeys {
				t.Logf("        [%d] %s", j, key.Hex())
			}
		}

		t.Log("--- Step 4: Conflict Detection Analysis ---")

		// 각 트랜잭션에 대해 충돌 검사 수행
		conflictResults := make(map[common.Hash]bool)

		for addr, txs := range mockPendingTxs {
			t.Logf("Analyzing transactions from address %s:", addr.Hex())
			for i, tx := range txs {
				hasConflict := checkAccessListConflict(tx, exclusionStateScope)
				conflictResults[tx.Hash()] = hasConflict

				t.Logf("  Tx[%d] Hash=%s: Conflict=%v", i, tx.Hash().Hex(), hasConflict)

				if hasConflict {
					// 충돌 상세 분석
					t.Logf("    Conflict Details:")
					txAccessList := tx.AccessList()
					if txAccessList != nil {
						for _, txAccess := range txAccessList {
							for _, protectedAccess := range exclusionStateScope.AccessList {
								if txAccess.Address == protectedAccess.Address {
									t.Logf("      Address conflict: %s", txAccess.Address.Hex())
									for _, txKey := range txAccess.StorageKeys {
										for _, protectedKey := range protectedAccess.StorageKeys {
											if txKey == protectedKey {
												t.Logf("        Storage key conflict: %s", txKey.Hex())
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		t.Log("--- Step 5: Filtering Results ---")

		// 필터링 실행
		exclusionConstraints := map[common.Hash]types.AccessList{
			exclusionStateScope.LockId: exclusionStateScope.AccessList,
		}

		filteredTxs := filterByExclusionConstraints(mockPendingTxs, exclusionConstraints)

		t.Logf("Filtering Summary:")
		t.Logf("  Original transactions: %d", getTotalTxCount(mockPendingTxs))
		t.Logf("  Filtered transactions: %d", getTotalTxCount(filteredTxs))
		t.Logf("  Removed transactions: %d", getTotalTxCount(mockPendingTxs)-getTotalTxCount(filteredTxs))

		t.Log("Remaining transactions after filtering:")
		for addr, txs := range filteredTxs {
			t.Logf("  Address %s: %d transactions", addr.Hex(), len(txs))
			for i, tx := range txs {
				t.Logf("    [%d] Hash=%s (No conflict)", i, tx.Hash().Hex())
			}
		}

		t.Log("Removed transactions:")
		for addr, originalTxs := range mockPendingTxs {
			filteredTxsForAddr, exists := filteredTxs[addr]
			if !exists {
				filteredTxsForAddr = []*types.Transaction{}
			}

			for _, originalTx := range originalTxs {
				found := false
				for _, filteredTx := range filteredTxsForAddr {
					if originalTx.Hash() == filteredTx.Hash() {
						found = true
						break
					}
				}
				if !found {
					t.Logf("    Removed: Hash=%s (Conflict detected)", originalTx.Hash().Hex())
				}
			}
		}
	})

	// 기본 Access List 추출 테스트
	t.Run("ExtractAccessListFromTransaction", func(t *testing.T) {
		t.Log("--- Testing Access List Extraction ---")

		extractedAccessList := conflictingTx.AccessList()
		require.NotNil(t, extractedAccessList)
		require.Equal(t, 1, len(extractedAccessList))

		accessTuple := extractedAccessList[0]
		require.Equal(t, common.HexToAddress("0x1234567890123456789012345678901234567890"), accessTuple.Address)
		require.Equal(t, 2, len(accessTuple.StorageKeys))

		t.Logf("Extracted Access List: %+v", extractedAccessList)
	})
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
	_, ok := builder.constraintsCache.Get(0)
	require.Equal(t, false, ok)

	go builder.subscribeToRelayForConstraints(builder.relay.Config().Endpoint)
	// Wait 2 seconds to save all constraints in cache
	time.Sleep(2 * time.Second)

	slots := []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	for _, slot := range slots {
		cachedConstraints, ok := builder.constraintsCache.Get(slot)
		require.Equal(t, true, ok)

		expectedConstraint := generateMockConstraintsForSlot(slot)[0]
		decodedConstraint, err := DecodeConstraints(expectedConstraint)
		require.NoError(t, err)

		// Compare the keys of the cachedConstraints and decodedConstraint maps
		require.Equal(t, len(cachedConstraints), len(decodedConstraint), "The number of keys in both maps should be the same")
		for key := range cachedConstraints {
			_, ok := decodedConstraint[key]
			require.True(t, ok, fmt.Sprintf("Key %s found in cachedConstraints but not in decodedConstraint", key.String()))
			require.Equal(t, cachedConstraints[key].Data(), decodedConstraint[key].Data(), "The decodedConstraint Tx should be equal to the cachedConstraints Tx")
		}
		for key := range decodedConstraint {
			_, ok := cachedConstraints[key]
			require.True(t, ok, fmt.Sprintf("Key %s found in decodedConstraint but not in cachedConstraints", key.String()))
		}
	}
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

	for i := 0; i < 256; i++ {
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
	}
}
