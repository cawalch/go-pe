package pe

// DOS & PE Signatures.
const (
	DOSMagic = 0x5A4D // "MZ"
	PEMagic  = 0x00004550 // "PE\0\0"
)

// Optional Header Magic.
const (
	OptionalHeaderMagicPE32  = 0x10b // 32-bit executable
	OptionalHeaderMagicPE32P = 0x20b // 64-bit executable (PE32+)
	OptionalHeaderMagicROM   = 0x107 // ROM image
)

// Data Directory Indices.
const (
	DataDirectoryExport         = 0
	DataDirectoryImport         = 1
	DataDirectoryResource       = 2
	DataDirectoryException      = 3
	DataDirectoryCertificate    = 4
	DataDirectoryBaseReloc      = 5
	DataDirectoryDebug          = 6
	DataDirectoryArchitecture   = 7
	DataDirectoryGlobalPtr      = 8
	DataDirectoryTLS            = 9
	DataDirectoryLoadConfig     = 10
	DataDirectoryBoundImport    = 11
	DataDirectoryIAT            = 12
	DataDirectoryDelayImport    = 13
	DataDirectoryCLRRuntime     = 14
	DataDirectoryReserved       = 15
	NumberOfDataDirectories     = 16
)

// Machine Types (COFF File Header).
const (
	MachineUnknown   = 0x0
	MachineI386      = 0x14c
	MachineR3000     = 0x162
	MachineR4000     = 0x166
	MachineR10000    = 0x168
	MachineWCEMIPSV2 = 0x169
	MachineAlpha     = 0x184
	MachineSH3       = 0x1a2
	MachineSH3DSP    = 0x1a3
	MachineSH3E      = 0x1a4
	MachineSH4       = 0x1a6
	MachineSH5       = 0x1a8
	MachineARM       = 0x1c0
	MachineThumb     = 0x1c2
	MachineARMNT     = 0x1c4
	MachineAM33      = 0x1d3
	MachinePowerPC   = 0x1f0
	MachinePowerPCFP = 0x1f1
	MachineIA64      = 0x200
	MachineMIPS16    = 0x266
	MachineAlpha64   = 0x284
	MachineMIPSFPU   = 0x366
	MachineMIPSFPU16 = 0x466
	MachineTriCore   = 0x520
	MachineCEF       = 0xcef
	MachineEBC       = 0xebc
	MachineAMD64     = 0x8664
	MachineM32R      = 0x9041
	MachineARM64     = 0xaa64
	MachineCEE       = 0xc0ee
)

// Subsystems.
const (
	SubsystemUnknown                = 0
	SubsystemNative                 = 1
	SubsystemWindowsGUI             = 2
	SubsystemWindowsCUI             = 3
	SubsystemOS2CUI                 = 5
	SubsystemPOSIXCUI               = 7
	SubsystemNativeWindows          = 8
	SubsystemWindowsCEGUI           = 9
	SubsystemEFIApplication         = 10
	SubsystemEFIBootServiceDriver   = 11
	SubsystemEFIRuntimeDriver       = 12
	SubsystemEFIROM                 = 13
	SubsystemXBOX                   = 14
	SubsystemWindowsBootApplication = 16
)

// Characteristics (COFF File Header).
const (
	CharacteristicsRelocsStripped       = 0x0001
	CharacteristicsExecutableImage      = 0x0002
	CharacteristicsLineNumsStripped     = 0x0004
	CharacteristicsLocalSymsStripped    = 0x0008
	CharacteristicsAggressiveWsTrim     = 0x0010
	CharacteristicsLargeAddressAware    = 0x0020
	CharacteristicsBytesReversedLo      = 0x0080
	Characteristics32BitMachine         = 0x0100
	CharacteristicsDebugStripped        = 0x0200
	CharacteristicsRemovableRunFromSwap = 0x0400
	CharacteristicsNetRunFromSwap       = 0x0800
	CharacteristicsSystem               = 0x1000
	CharacteristicsDLL                  = 0x2000
	CharacteristicsUpSystemOnly         = 0x4000
	CharacteristicsBytesReversedHi      = 0x8000
)

// Section Characteristics.
const (
	SectionTypeNoPad            = 0x00000008
	SectionCntCode              = 0x00000020
	SectionCntInitializedData   = 0x00000040
	SectionCntUninitializedData = 0x00000080
	SectionLnkOther             = 0x00000100
	SectionLnkInfo              = 0x00000200
	SectionLnkRemove            = 0x00000800
	SectionLnkCOMDAT            = 0x00001000
	SectionGPRel                = 0x00008000
	SectionMemPurgeable         = 0x00020000
	SectionMemLocked            = 0x00040000
	SectionMemPreload           = 0x00080000
	SectionAlign1Bytes          = 0x00100000
	SectionAlign2Bytes          = 0x00200000
	SectionAlign4Bytes          = 0x00300000
	SectionAlign8Bytes          = 0x00400000
	SectionAlign16Bytes         = 0x00500000
	SectionAlign32Bytes         = 0x00600000
	SectionAlign64Bytes         = 0x00700000
	SectionAlign128Bytes        = 0x00800000
	SectionAlign256Bytes        = 0x00900000
	SectionAlign512Bytes        = 0x00A00000
	SectionAlign1024Bytes       = 0x00B00000
	SectionAlign2048Bytes       = 0x00C00000
	SectionAlign4096Bytes       = 0x00D00000
	SectionAlign8192Bytes       = 0x00E00000
	SectionLnkNRelocOvfl        = 0x01000000
	SectionMemDiscardable       = 0x02000000
	SectionMemNotCached         = 0x04000000
	SectionMemNotPaged          = 0x08000000
	SectionMemShared            = 0x10000000
	SectionMemExecute           = 0x20000000
	SectionMemRead              = 0x40000000
	SectionMemWrite             = 0x80000000
)
