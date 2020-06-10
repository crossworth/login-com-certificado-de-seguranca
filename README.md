### Exemplo de servidor que exige certificado válido ICP-Brasil em Golang

Um exemplo de servidor em Golang que exige um certificado ICP-Brasil válido.
Você pode baixar os certificados ACs [clicando aqui](https://www.iti.gov.br/repositorio/repositorio-ac-raiz/84-repositorio/489-certificados-das-acs-da-icp-brasil-arquivo-unico-compactado).

Você pode utilizar o [mkcert](https://github.com/FiloSottile/mkcert) para criar um certificado para o servidor local.
Ou utilizar o certificado de localhost, instalando o `rootCA` da pasta `self-signed-cert`.


#### Como utilizar

Você pode verificar o código fonte de dois exemplos de código nas pastas `simples` e `solicita-certificado-ao-cancelar`.

*Os códigos são apenas de exemplo e não devem ser utilizados em produção. Os códigos devem ser utilizados apenas para
entender o comportamento, existem muitos pontos que podem ser melhorados nele, também não é implementado todo o processo
de decode dos dados adicionados do certificado e-CPF, apenas e-CNPJ, porém lendo os comentários e verificando a forma efetuada
você deve conseguir adaptar para o seu caso de uso.*

**simples**: O arquivo `simples.go` contém um exemplo simples de uso, onde apenas é solicitado o certificado de cliente (e verificado).
Exibindo informações caso o certificado seja válido.
Caso o certificado não seja informado e/ou inválido, o navegador do cliente irá apresentar uma mensagem de erro padrão
relacionado ao erro encontrado no servidor.


Para o cliente pode selecionar novamente o certificado, ele deve fechar completamente o navegador. Limpar cache ou 
iniciar uma nova janela anónima não parece surtir efeito.


**solicita-certificado-ao-cancelar**: Uma desvantagem do processo simples é que o cliente, ao clicar em um certificado
incorreto ou mesmo clicar em cancelar é obrigado a fechar completamente o navegador para poder fazer informar o certificado correto.
Isso ocorre devido a conexão TLS ser re-utilizada. Não é feito o processo de handshake novamente, dessa forma, o navegador
não sabe que o servidor está solicitando novamente o certificado. A forma de solucionar isso é fazendo o `TLS renegotiation`.
Basicamente fazendo o handshake novamente. Em GO não encontrei uma forma fácil de fazer isso utilizando diretamente o
`http.Server`. Para solucionar o problema eu crio um listener TCP, lido com handshake manualmente e passo uma listener
que utiliza a conexão já pronta.


Como o processo envolve solicitar o certificado na conexão TLS, não existe uma forma fácil de fazer a solicitação de certificado
em apenas 1 rota. Talvez configurando um `reverse proxy` seja possível.


#### Executando os exemplos

Com GO instalado e o certificado de localhost devidamente configurado (utilizando o mkcert), basta executar os comandos.

- simples: `go run simples/main.go`

- solicita-certificado-ao-cancelar: `go run solicita-certificado-ao-cancelar/solicita-certificado-ao-cancelar.go`


##### Firefox
O navegador Firefox não apresenta a tela de solicitação de certificados, pelo menos não apresentou em meus testes.
O motivo disso é o fato do certificado root do ICP-Brasil não estar presente no `cert store` do navegador.


Para mais informações veja o link: https://bugzilla.mozilla.org/show_bug.cgi?id=438825


É importante observar que dependendo da empresa que emitiu o certificado, é possível que o Firefox aceite o certificado.
Provavelmente o certificado deve ser primeiro importado na lista de certificados pessoais do navegador.
