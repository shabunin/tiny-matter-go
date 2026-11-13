package credentials

import (
	"io"

	"github.com/shabunin/tiny-matter-go/crypto/p256"
	"github.com/shabunin/tiny-matter-go/tlv"
)

var oidOrganization = []byte{0x55, 0x04, 0x0A}

// NewCSR returns a PKCS #10 certificate signing request (DER) for key, with
// subject O=CSR as the Matter SDK uses.
func NewCSR(rand io.Reader, key *p256.PrivateKey) ([]byte, error) {
	info := der(derSequence,
		[]byte{derInteger, 1, 0},
		der(derSequence, der(derSet, der(derSequence, der(derOID, oidOrganization), der(derUTF8String, []byte("CSR"))))),
		der(derSequence,
			der(derSequence, der(derOID, oidECPublicKey), der(derOID, oidPrime256v1)),
			der(derBitString, []byte{0}, key.PublicKey().Bytes())),
		[]byte{0xA0, 0x00}, // no attributes
	)
	sig, err := key.SignMessage(rand, info)
	if err != nil {
		return nil, err
	}
	return der(derSequence, info,
		der(derSequence, der(derOID, oidECDSAWithSHA256)),
		der(derBitString, []byte{0}, SignatureToDER(sig))), nil
}

// AttestationElements encodes the attestation-elements structure
// (spec 11.18.4.7) returned by AttestationRequest.
func AttestationElements(cd, nonce []byte, timestamp uint32, firmwareInfo []byte) []byte {
	w := tlv.NewWriter(make([]byte, 0, len(cd)+64))
	w.StartStruct(tlv.Anonymous)
	w.PutBytes(tlv.ContextTag(1), cd)
	w.PutBytes(tlv.ContextTag(2), nonce)
	w.PutUint(tlv.ContextTag(3), uint64(timestamp))
	if firmwareInfo != nil {
		w.PutBytes(tlv.ContextTag(4), firmwareInfo)
	}
	w.EndContainer()
	return w.Bytes()
}

// NOCSRElements encodes the nocsr-elements structure (spec 11.18.4.9)
// returned by CSRRequest.
func NOCSRElements(csr, nonce []byte) []byte {
	w := tlv.NewWriter(make([]byte, 0, len(csr)+48))
	w.StartStruct(tlv.Anonymous)
	w.PutBytes(tlv.ContextTag(1), csr)
	w.PutBytes(tlv.ContextTag(2), nonce)
	w.EndContainer()
	return w.Bytes()
}

// SignWithChallenge signs elements || attestationChallenge with the DAC key,
// as AttestationResponse and CSRResponse require.
func SignWithChallenge(rand io.Reader, dac *p256.PrivateKey, elements []byte, challenge []byte) ([]byte, error) {
	msg := make([]byte, 0, len(elements)+len(challenge))
	msg = append(append(msg, elements...), challenge...)
	return dac.SignMessage(rand, msg)
}
