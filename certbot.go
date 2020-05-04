package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path"
	"time"

	"gopkg.in/robfig/cron.v3"
	"gopkg.in/yaml.v3"
)

// CertBotConfig xx
type CertBotConfig struct {
	BaseDirs []string `yaml:"baseDirs"`
	Subject  struct {
		Organisation  string `yaml:"organisation"`
		Country       string `yaml:"country"`
		Province      string `yaml:"province"`
		Locality      string `yaml:"locality"`
		StreetAddress string `yaml:"streetAdress"`
		PostalCode    string `yaml:"postalCode"`
	} `yaml:"caSubject"`
}

func getYamlConfig() ([]string, pkix.Name) {
	basedir, exists := os.LookupEnv(CertBotConfigDirectory)
	if !exists {
		log.Panic("no config directory")
	}
	yamlFile, err := ioutil.ReadFile(basedir)
	if err != nil {
		log.Panic("can not read config file: " + err.Error())
	}

	var config CertBotConfig

	errUnmarshal := yaml.Unmarshal(yamlFile, &config)
	if errUnmarshal != nil {
		log.Panic("no valid yaml: " + errUnmarshal.Error())
	}

	var subject = pkix.Name{
		Organization:  []string{config.Subject.Organisation},
		Country:       []string{config.Subject.Country},
		Province:      []string{config.Subject.Province},
		Locality:      []string{config.Subject.Locality},
		StreetAddress: []string{config.Subject.StreetAddress},
		PostalCode:    []string{config.Subject.PostalCode},
	}
	return config.BaseDirs, subject
}

func getCA(certSubject pkix.Name) *x509.Certificate {
	t := time.Now()
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(t.Year())),
		Subject:               certSubject,
		NotBefore:             t,
		NotAfter:              t.AddDate(0, 0, 30),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	return ca
}

func getCertificate(certSubject pkix.Name) *x509.Certificate {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject:      certSubject,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 30),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	return cert
}

func pemEncode(baseDir string, gen []byte, privKey *rsa.PrivateKey) error {
	fileCert, err := os.OpenFile(path.Join(baseDir, "cert.pem"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	fileKey, err := os.OpenFile(path.Join(baseDir, "key.pem"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer fileCert.Close()
	defer fileKey.Close()

	errCert := pem.Encode(fileCert, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: gen,
	})

	if errCert != nil {
		return errCert
	}

	errKey := pem.Encode(fileKey, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	if errKey != nil {
		return errKey
	}

	return nil
}

func generateKeys(baseDir string, subject pkix.Name) error {
	ca := getCA(subject)
	cert := getCertificate(subject)

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	if err := pemEncode(baseDir, caBytes, caPrivKey); err != nil {
		return err
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		return err
	}

	if err := pemEncode(baseDir, certBytes, certPrivKey); err != nil {
		return err
	}

	return nil
}

func verifyOrReNewCert(baseDir string, subject pkix.Name) func() {
	return func() {
		caCert, err := ioutil.ReadFile(path.Join(baseDir, "cert.pem"))
		if err != nil {
			log.Panic(err.Error())
		} else {
			roots := x509.NewCertPool()
			ok := roots.AppendCertsFromPEM(caCert)
			if !ok {
				log.Panic("failed to parse root certificate")
			}

			block, _ := pem.Decode(caCert)
			if block == nil {
				log.Panic("failed to parse certificate PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Panic("failed to parse certificate: " + err.Error())
			}

			tNow := cert.NotBefore
			dNow := time.Date(tNow.Year(), tNow.Month(), tNow.Day(), 0, 0, 0, 0, time.UTC)
			tEnd := cert.NotBefore
			dEnd := time.Date(tEnd.Year(), tEnd.Month(), tEnd.Day(), 0, 0, 0, 0, time.UTC)
			days := dNow.Sub(dEnd) / 24

			if days <= 2 {
				err := generateKeys(baseDir, subject)
				if err != nil {
					log.Panic("faild to renew cert and key")
				}
			} else {
				opts := x509.VerifyOptions{
					Roots: roots,
				}

				if _, err := cert.Verify(opts); err != nil {
					log.Panic("failed to verify certificate: " + err.Error())
				}
			}
		}
	}
}

func startAsCron(spec string, funcs []func()) *cron.Cron {
	logger := cron.PrintfLogger(log.New(os.Stdout, "certbot", log.LstdFlags))
	c := cron.New(
		cron.WithLocation(time.UTC),
		cron.WithLogger(logger),
		cron.WithChain(
			cron.SkipIfStillRunning(logger),
		),
	)
	for _, f := range funcs {
		c.AddFunc(spec, f)
	}
	return c
}

// StartCertBot xx
func StartCertBot() {
	baseDirs, subject := getYamlConfig()
	for _, dir := range baseDirs {
		errMkdir := os.MkdirAll(dir, os.ModePerm)
		if errMkdir != nil {
			log.Fatal("Could not init dirs...", errMkdir.Error())
		}
		err := generateKeys(dir, subject)
		if err != nil {
			log.Fatal("Could not init certbot...", err.Error())
		}
	}

	var jobs []func()

	for _, dir := range baseDirs {
		jobs = append(jobs, verifyOrReNewCert(dir, subject))
	}

	job := startAsCron("@daily", jobs)

	defer job.Stop()
}

//serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
//if err != nil {
//	return nil, nil, err
//}
//serverTLSConf = &tls.Config{
//	Certificates: []tls.Certificate{serverCert},
//}
//certpool := x509.NewCertPool()
//certpool.AppendCertsFromPEM(caPEM.Bytes())
//clientTLSConf = &tls.Config{
//	RootCAs: certpool,
//}
