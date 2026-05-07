package systemcontracts

import (
	libcommon "github.com/ledgerwatch/erigon-lib/common"
)

var (
	// Mainnet contracts
	// Pre-PoS deploy block (all 5 contracts deployed in the same tx batch): 14115624
	kubPosMainnetStakeManagerRecords []libcommon.CodeRecord = []libcommon.CodeRecord{
		{
			BlockNumber: 14115624,
			CodeHash:    libcommon.HexToHash("2597d35349905301461edd94aad876c701cadd298a3aa7846c1b565d681312e4"), // Pre-PoS (deploy)
		},
		{
			BlockNumber: 25677934,
			CodeHash:    libcommon.HexToHash("b55c1bd656d20f94ce19b7642196e8394042ddaf2135f24f3f95ab59f032acef"), // Lausanne
		},
		{
			BlockNumber: 31237946,
			CodeHash:    libcommon.HexToHash("87b163e0ca62c738e4319573129b3ba3699b42f1d58a571776f218c40c56e9a1"), // Basel
		},
	}
	kubPosMainnetSlashManagerRecords []libcommon.CodeRecord = []libcommon.CodeRecord{
		{
			BlockNumber: 14115624,
			CodeHash:    libcommon.HexToHash("8dffdb975547abadb304be30234bdac2e7f9fcf008b290051e2edcd669f4e0df"), // Pre-PoS (deploy)
		},
		{
			BlockNumber: 25677934,
			CodeHash:    libcommon.HexToHash("b0e67b0e7cceb1d29d1ecad739da6248020d9b35fbfe4674c1cf46a3574e6e48"), // Lausanne
		},
		{
			BlockNumber: 31237946,
			CodeHash:    libcommon.HexToHash("2faa8894d764d36fe0c00e9cb859bf45011ac73cc5c58356839ea5d98eb615a7"), // Basel
		},
	}
	kubPosMainnetStakeManagerStorageRecords []libcommon.CodeRecord = []libcommon.CodeRecord{
		{
			BlockNumber: 14115624,
			CodeHash:    libcommon.HexToHash("456e4b696e7ee8933825f6888a0c990c243dc45632286468d150d3de11ab0c52"), // Pre-PoS (deploy)
		},
		{
			BlockNumber: 25677934,
			CodeHash:    libcommon.HexToHash("4144eec9835f45dd46845dd1920ba433455023a799740800dc1c0adc541fd1c3"), // Lausanne
		},
		{
			BlockNumber: 31237946,
			CodeHash:    libcommon.HexToHash("1bec380c958b50241117ac41486b9c49e4610a5bdd1729da47a3c58d70ea9f2b"), // Basel
		},
	}
	kubPosMainnetNftContractRecords []libcommon.CodeRecord = []libcommon.CodeRecord{
		{
			BlockNumber: 14115624,
			CodeHash:    libcommon.HexToHash("8a0fac59d73925406622edcb6483c8c09edc5c7c7e3c55805b552044dfd0dc4d"), // Pre-PoS (deploy)
		},
		{
			BlockNumber: 31237946,
			CodeHash:    libcommon.HexToHash("3a7a849d24d9e6f76c9f8d25bb47652564f557b3355d21cf6274263d2c50267d"), // Basel
		},
	}
	kubPosMainnetBKCValidatorSetRecords []libcommon.CodeRecord = []libcommon.CodeRecord{
		{
			BlockNumber: 14115624,
			CodeHash:    libcommon.HexToHash("6c87a265164de18dddd0ebcd20246d0406cc93e7dd92192a108814ccf3bf2ea9"), // Pre-PoS (deploy)
		},
		{
			BlockNumber: 31237946,
			CodeHash:    libcommon.HexToHash("41880b7d8c0c2545abfaa4b0d5609a87fb745727a36776fc148964399568412b"), // Basel
		},
	}

	// Testnet contracts
	// Pre-PoS deploy block (all 5 contracts deployed in the same tx batch): 11712666
	kubPosTestnetStakeManagerRecords []libcommon.CodeRecord = []libcommon.CodeRecord{
		{
			BlockNumber: 11712666,
			CodeHash:    libcommon.HexToHash("57a9dd2e75df9f1949c2b6ef36498e4c41af66b98b871bd9937c46a5b0de6ffe"), // Pre-PoS (deploy)
		},
		{
			BlockNumber: 22835041,
			CodeHash:    libcommon.HexToHash("b55c1bd656d20f94ce19b7642196e8394042ddaf2135f24f3f95ab59f032acef"), // Lausanne
		},
		{
			BlockNumber: 27929040,
			CodeHash:    libcommon.HexToHash("87b163e0ca62c738e4319573129b3ba3699b42f1d58a571776f218c40c56e9a1"), // Basel
		},
	}
	kubPosTestnetSlashManagerRecords []libcommon.CodeRecord = []libcommon.CodeRecord{
		{
			BlockNumber: 11712666,
			CodeHash:    libcommon.HexToHash("577b68832c6778d4653a1042aa6b358d24364004958811db0664870583dd1c30"), // Pre-PoS (deploy)
		},
		{
			BlockNumber: 22835041,
			CodeHash:    libcommon.HexToHash("b0e67b0e7cceb1d29d1ecad739da6248020d9b35fbfe4674c1cf46a3574e6e48"), // Lausanne
		},
		{
			BlockNumber: 27929040,
			CodeHash:    libcommon.HexToHash("2faa8894d764d36fe0c00e9cb859bf45011ac73cc5c58356839ea5d98eb615a7"), // Basel
		},
	}
	kubPosTestnetStakeManagerStorageRecords []libcommon.CodeRecord = []libcommon.CodeRecord{
		{
			BlockNumber: 11712666,
			CodeHash:    libcommon.HexToHash("7def64ba6b2c753932221a13131d177977d8668f802c000d00edf165b9140b0d"), // Pre-PoS (deploy)
		},
		{
			BlockNumber: 22835041,
			CodeHash:    libcommon.HexToHash("4144eec9835f45dd46845dd1920ba433455023a799740800dc1c0adc541fd1c3"), // Lausanne
		},
		{
			BlockNumber: 27929040,
			CodeHash:    libcommon.HexToHash("1bec380c958b50241117ac41486b9c49e4610a5bdd1729da47a3c58d70ea9f2b"), // Basel
		},
	}
	kubPosTestnetNftContractRecords []libcommon.CodeRecord = []libcommon.CodeRecord{
		{
			BlockNumber: 11712666,
			CodeHash:    libcommon.HexToHash("60ada3767fe5608fb09cc0483dd99e5879ad02feb45cd54a4b7283816b7f8bb4"), // Pre-PoS (deploy)
		},
		{
			BlockNumber: 27929040,
			CodeHash:    libcommon.HexToHash("3a7a849d24d9e6f76c9f8d25bb47652564f557b3355d21cf6274263d2c50267d"), // Basel
		},
	}
	kubPosTestnetBKCValidatorSetRecords []libcommon.CodeRecord = []libcommon.CodeRecord{
		{
			BlockNumber: 11712666,
			CodeHash:    libcommon.HexToHash("85a3b7e7ac3310e25f218475589efc85173fe4afc393660ceb98bc9f1b4bd64f"), // Pre-PoS (deploy)
		},
		{
			BlockNumber: 27929040,
			CodeHash:    libcommon.HexToHash("41880b7d8c0c2545abfaa4b0d5609a87fb745727a36776fc148964399568412b"), // Basel
		},
	}
)
