package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"path/filepath"
)

var subjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

func main() {
	// cria uma pool de certificados usados para verificar o certificado do cliente
	caPool := x509.NewCertPool()
	files, err := filepath.Glob("./ICP-CAs/*.crt")
	if err != nil {
		log.Fatalf("Não foi possível listar os certificados ICP-Brasil, %v", err)
	}

	// adicionamos todos os certificados do ICP Brasil a pool
	for _, f := range files {
		addCertToPool(caPool, f)
	}

	// carregamos o certificado e chave do servidor
	serverCert, err := ioutil.ReadFile("./localhost.cert")
	if err != nil {
		log.Fatalf("Não foi possível ler o arquivo de certificado do servidor, %v", err)
	}

	serverKey, err := ioutil.ReadFile("./localhost.key")
	if err != nil {
		log.Fatalf("Não foi possível ler o arquivo de key de certificado do servidor, %v", err)
	}

	// criamos uma um par com os dados carregados
	httpServerCert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		log.Fatalf("Não foi possível criar o par certificado para o servidor, %v", err)
	}

	// criamos nossa aplicação
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {

		if request.TLS != nil {
			log.Println("TLS PeerCertificates:")

			_, _ = writer.Write([]byte("Request TLS\n"))
			_, _ = fmt.Fprintf(writer, "%d certificados\n\n", len(request.TLS.PeerCertificates))

			for _, cert := range request.TLS.PeerCertificates {
				subject := cert.Subject
				issuer := cert.Issuer
				log.Printf("Subject: /C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s\n", subject.Country, subject.Province, subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.CommonName)
				log.Printf("Issuer: /C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s\n", issuer.Country, issuer.Province, issuer.Locality, issuer.Organization, issuer.OrganizationalUnit, issuer.CommonName)

				_, _ = fmt.Fprintf(writer, "Subject: /C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s\n", subject.Country, subject.Province, subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.CommonName)
				_, _ = fmt.Fprintf(writer, "Issuer: /C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s\n", issuer.Country, issuer.Province, issuer.Locality, issuer.Organization, issuer.OrganizationalUnit, issuer.CommonName)

				// Extrai dados do certificado
				// Se você não precisa disso, pode ignorar
				extractCertData(cert, writer)
			}
		} else {
			// Normalmente o código não chega aqui
			_, _ = writer.Write([]byte("TLS == nil"))
		}
	})

	// criamos um servidor http (80) para redirecionar para https
	go func() {
		if err := http.ListenAndServe(":80", http.HandlerFunc(redirectToTLS)); err != nil {
			log.Fatalf("Ocorreu um erro ao criar o servidor de redirecionamento HTTP -> HTTPS, %v", err)
		}
	}()

	// criamos nosso servidor HTTP
	s := http.Server{
		Handler: mux,
	}

	// criamos as configurações TLS
	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		Certificates: []tls.Certificate{httpServerCert},
	}

	// iniciamos o "servidor"
	listener, err := tls.Listen("tcp", ":443", tlsConfig)
	if err != nil {
		log.Fatalf("Não foi possível iniciar o servidor, %v", err)
	}

	for {
		// aceitamos a conexão
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Não foi possível aceitar uma conexão, %v\n", err)
			continue
		}

		// temos que executar como goroutine porque chamamos o http.Server.Serve
		go func() {
			log.Printf("Nova conexão de %s\n", conn.RemoteAddr())

			// conseguimos a conexão TLS e iniciamos o handshake
			// como a gente solicita o handshake para toda nova conexão
			// estamos efetivamente fazendo um server TLS renegotiation
			// se o cliente não informar o certificado correto ou não informar um certificado
			// ele será solicitado novamente, exibindo a "caixa" de seleção do navegador
			tlsConn := conn.(*tls.Conn)
			err = tlsConn.Handshake()

			if err != nil {
				log.Printf("Erro ao fazer o handshake da conexão, %v\n", err)
				_ = tlsConn.Close()
				return
			}

			// precisamos agora passar para nosso servidor HTTP lidar com as rotas
			// e tudo mais, para isso criamos um listener que implementa a interface net.Listener
			// com a conexão que acabamos de fazer o handshake
			err = s.Serve(&renegotiationListener{
				conn: conn,
			})
			if err != nil {
				log.Printf("Não foi possível servir uma conexão, %v\n", err)
			}
		}()
	}
}

type renegotiationListener struct {
	conn net.Conn
}

func (r *renegotiationListener) Accept() (net.Conn, error) {
	return r.conn, nil
}

func (r renegotiationListener) Close() error {
	return r.conn.Close()
}

func (r renegotiationListener) Addr() net.Addr {
	return r.conn.RemoteAddr()
}

func addCertToPool(caPool *x509.CertPool, name string) {
	cert, err := ioutil.ReadFile(name)
	if err != nil {
		log.Printf("Não foi possível ler o arquivo de certificado %s, %v\n", name, err)
	}

	if ok := caPool.AppendCertsFromPEM(cert); !ok {
		log.Printf("Não foi possível adicionar o certificado %s a pool de certificados\n", name)
	} else {
		log.Printf("Adicionado certificado %s a pool de CA\n", name)
	}
}

func redirectToTLS(writer http.ResponseWriter, request *http.Request) {
	u := request.URL
	u.Host = net.JoinHostPort(request.Host, "443")
	u.Scheme = "https"
	http.Redirect(writer, request, u.String(), http.StatusMovedPermanently)
}

// CONSEGUINDO DADOS DO CERTIFICADO
// http://publicacao.certificadodigital.com.br/repositorio/pc/politica-a1.pdf
// http://publicacao.certificadodigital.com.br/repositorio/pc/politica-a3.pdf seção 7.1.2.3 página 22.
func extractCertData(cert *x509.Certificate, writer http.ResponseWriter) {
	for _, ext := range cert.Extensions {
		// subjectAltName é obrigatário para certificados do ICP-Brasil
		if ext.Id.Equal(subjectAltName) {

			otherNames, email, err := getClientCertInfo(ext)
			if err != nil {
				log.Printf("Não foi possível conseguir os dados do certificado, %v\n", err)
				break
			}

			fmt.Printf("\nDados do certificado\n")
			_, _ = fmt.Fprintf(writer, "\nDados do certificado\n")

			if isForCNPJ(otherNames) {
				fmt.Printf("Certificado para Pessoa Jurídica\n")
				_, _ = fmt.Fprintf(writer, "Certificado para Pessoa Jurídica\n")
			} else {
				fmt.Printf("Certificado para Pessoa Física\n")
				_, _ = fmt.Fprintf(writer, "Certificado para Pessoa Física\n")
			}

			fmt.Printf("Email do certificado: %s\n", email)
			_, _ = fmt.Fprintf(writer, "Email do certificado: %s\n", email)

			for _, name := range otherNames {
				fmt.Printf("OID = %s\n", name.TypeID.String())

				// não implementado os OID de PF
				switch name.TypeID.String() {
				case "2.16.76.1.3.4": // CNPJ
					fmt.Printf("Data de nascimento: %s\n", name.Value.Bytes[2:10])
					_, _ = fmt.Fprintf(writer, "Data de nascimento: %s\n", name.Value.Bytes[2:10])

					fmt.Printf("CPF: %s\n", name.Value.Bytes[10:21])
					_, _ = fmt.Fprintf(writer, "CPF: %s\n", name.Value.Bytes[10:21])

					fmt.Printf("Número de Identificação Social NIS (PIS, PASEP ou CI): %s\n", name.Value.Bytes[21:32])
					_, _ = fmt.Fprintf(writer, "Número de Identificação Social NIS (PIS, PASEP ou CI): %s\n", name.Value.Bytes[21:32])

					fmt.Printf("RG: %s\n", name.Value.Bytes[32:47])
					_, _ = fmt.Fprintf(writer, "RG: %s\n", name.Value.Bytes[32:47])

					fmt.Printf("Órgão expedidor do RG e respectiva unidade da federação: %s\n", name.Value.Bytes[47:53])
					_, _ = fmt.Fprintf(writer, "Órgão expedidor do RG e respectiva unidade da federação: %s\n", name.Value.Bytes[47:53])
				case "2.16.76.1.3.2": // Nome do responsável pelo certificado
					fmt.Printf("Nome do responsável pelo certificado: %s\n", name.Value.Bytes[2:])
					_, _ = fmt.Fprintf(writer, "Nome do responsável pelo certificado: %s\n", name.Value.Bytes[2:])
				case "2.16.76.1.3.3": // Número de CNPJ
					fmt.Printf("Número do Cadastro Nacional de Pessoa Jurídica (CNPJ): %s\n", name.Value.Bytes[2:])
					_, _ = fmt.Fprintf(writer, "Número do Cadastro Nacional de Pessoa Jurídica (CNPJ): %s\n", name.Value.Bytes[2:])

				}
			}

			fmt.Printf("\n")
			_, _ = fmt.Fprintf(writer, "\n")
		}
	}
}

type otherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue `asn1:"explicit"`
}

func getClientCertInfo(ext pkix.Extension) (otherNames []otherName, email string, err error) {
	var altName asn1.RawValue
	_, _ = asn1.Unmarshal(ext.Value, &altName)

	if altName.Class == asn1.ClassUniversal && altName.Tag == asn1.TagSequence {
		data := altName.Bytes

		for len(data) > 0 {
			var v asn1.RawValue
			data, err = asn1.Unmarshal(data, &v)
			if err != nil {
				return
			}

			switch v.Tag {
			case 0:
				var oName otherName
				_, err = asn1.UnmarshalWithParams(v.FullBytes, &oName, "tag:0")
				if err != nil {
					return
				}
				otherNames = append(otherNames, oName)
			case 1:
				email = string(v.Bytes)
			}
		}
	}

	return otherNames, email, nil
}

func isForCNPJ(otherNames []otherName) bool {
	for _, name := range otherNames {
		// 2.16.76.1.3.4 deve estar presente num certificado para CNPJ
		if name.TypeID.String() == "2.16.76.1.3.4" {
			return true
		}
	}

	return false
}
