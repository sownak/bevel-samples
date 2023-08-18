package common

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
)

// Identity encapsulates a chaincode invokers identity
type Identity struct {
	Organization string
	Cert         *x509.Certificate
}

// GetInvokerIdentity returns an Identity for the user invoking the transaction
func GetInvokerIdentity(stub shim.ChaincodeStubInterface) (*Identity, error) {
	var err error

	callerCert, _ := stub.GetCreator()
	certBlock, _ := pem.Decode(callerCert)

	if certBlock == nil {
		fmt.Printf("Failed to decode certificate")
		return nil, nil
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Printf("Error getting client certificate: %s\n", err.Error())
		return nil, err
	}

	mspid := cert.Issuer.Organization[0]

	return &Identity{Organization: mspid, Cert: cert}, nil
}

// CanInvoke returns true or false depending on whether the Identity can invoke the supplied transaction
func (id *Identity) CanInvoke(function string) bool {
	switch function {
	case "createProduct":
		return id.isManufacturer()
	default:
		return false
	}
}

func (id *Identity) isManufacturer() bool {
	for _, org := range id.Cert.Subject.OrganizationalUnit {
		if org == "Manufacturer" || org == "manufacturer" {
			return true
		}
	}
	return false
}
