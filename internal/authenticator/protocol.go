package authenticator

// CTAP 2.0 command and status bytes. Keep their assigned wire values explicit.
// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
const (
	cmdMakeCredential = 0x01
	cmdGetAssertion   = 0x02
	cmdGetInfo        = 0x04
)

const (
	statusOK                   = 0x00
	statusInvalidCommand       = 0x01
	statusInvalidParameter     = 0x02
	statusInvalidLength        = 0x03
	statusChannelBusy          = 0x06
	statusInvalidCBOR          = 0x12
	statusMissingParameter     = 0x14
	statusCredentialExcluded   = 0x19
	statusUnsupportedAlgorithm = 0x26
	statusOperationDenied      = 0x27
	statusKeyStoreFull         = 0x28
	statusUnsupportedOption    = 0x2b
	statusInvalidOption        = 0x2c
	statusKeepaliveCancel      = 0x2d
	statusNoCredentials        = 0x2e
	statusUserActionTimeout    = 0x2f
	statusPINAuthInvalid       = 0x33
	statusRequestTooLarge      = 0x39
	statusOther                = 0x7f // CTAP1_ERR_OTHER is also defined for CTAP2 responses.
)

// WebAuthn authenticator data flags; a silent probe has none of these bits set.
const (
	flagUserPresent            = 0x01
	flagUserVerified           = 0x04
	flagAttestedCredentialData = 0x40
)

// Integer request keys. Keep in sync with the request types' CBOR tags.
const (
	makeClientDataHash        = 0x01
	makeRP                    = 0x02
	makeUser                  = 0x03
	makePubKeyCredParams      = 0x04
	makeExcludeList           = 0x05
	makeOptions               = 0x07
	makePINAuth               = 0x08
	makePINProtocol           = 0x09
	makeEnterpriseAttestation = 0x0a

	assertionRPID           = 0x01
	assertionClientDataHash = 0x02
	assertionAllowList      = 0x03
	assertionOptions        = 0x05
	assertionPINAuth        = 0x06
	assertionPINProtocol    = 0x07
)

// Integer keys in CTAP response maps.
const (
	infoVersions   = 0x01
	infoAAGUID     = 0x03
	infoOptions    = 0x04
	infoMaxMsgSize = 0x05

	makeFormat       = 0x01
	makeAuthData     = 0x02
	makeAttStatement = 0x03

	assertionCredential = 0x01
	assertionAuthData   = 0x02
	assertionSignature  = 0x03
	assertionUser       = 0x04
)

// COSE EC2 key labels and ES256/P-256 identifiers.
const (
	coseKeyType   = 1
	coseAlgorithm = 3
	coseCurve     = -1
	coseX         = -2
	coseY         = -3
	coseEC2       = 2
	coseES256     = -7
	coseP256      = 1
)

const (
	cborMajorTypeShift  = 5
	cborMajorTypeMap    = 5
	aaguidSize          = 16
	p256CoordinateSize  = 32
	p256Bits            = 256
	authDataCounterSize = 4
)

// Implementation limits, independent of the credential store's capacity.
const (
	maxMessage        = 7609 // CTAPHID: 57 initial + 128 * 59 continuation bytes.
	credentialIDSize  = 32
	maxUserIDSize     = 64
	maxRPIDSize       = 253
	maxCredentialList = 64
)
