### Exemplo de servidor que exige certificado válido ICP-Brasil em Golang

Um exemplo de servidor em Golang que exige um certificado ICP-Brasil válido.
Você pode baixar os certificados ACs [clicando aqui](https://www.iti.gov.br/repositorio/repositorio-ac-raiz/84-repositorio/489-certificados-das-acs-da-icp-brasil-arquivo-unico-compactado).

Você pode utilizar o [mkcert](https://github.com/FiloSottile/mkcert) para criar um certificado para o servidor local.
Ou utilizar o certificado de localhost, instalando o `rootCA` da pasta `self-signed-cert`.
