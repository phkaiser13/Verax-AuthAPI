<p align="center"> <strong>Um serviço de identidade agnóstico, seguro e flexível.</strong> <br /> Construído com FastAPI e PostgreSQL para servir como um provedor de identidade (IdP) centralizado para qualquer aplicação. </p>

<p align="center"> <a href="https://github.com/SEU_USUARIO/SEU_REPOSITORIO/actions"> <img src="https://img.shields.io/github/actions/workflow/status/SEU_USUARIO/SEU_REPOSITORIO/main.yml?branch=main&style=for-the-badge" alt="Status do Build"> </a> <a href="https://github.com/SEU_USUARIO/SEU_REPOSITORIO/blob/master/LICENSE"> <img src="https://img.shields.io/github/license/SEU_USUARIO/SEU_REPOSITORIO?style=for-the-badge&color=blue" alt="Licença"> </a> <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python 3.10+"> <img src="https://img.shields.io/badge/FastAPI-0.119.1-05998b?style=for-the-badge&logo=fastapi" alt="FastAPI"> </p>

💡 Conceito Central: Autenticação vs. Autorização
Esta API foi projetada com uma filosofia fundamental: a rigorosa separação entre Autenticação (provar quem você é) e Autorização (definir o que você pode fazer).

Esta API (Auth API) cuida da Autenticação:

Gerencia com segurança o registro, login e dados do usuário.

Verifica identidades via email, reset de senha e bloqueio de conta.

Fornece um "cofre" de metadados (metadata) flexível para cada usuário.

Sua Aplicação (ex: VR Sales) cuida da Autorização:

Você define quais roles ou permissions existem.

Você usa a API de Gerenciamento (/mgmt) para escrever esses dados no "cofre" metadata do usuário (ex: {"roles": ["admin"], "store_id": 123}).

Você solicita esses dados (scopes) durante o login para que sejam injetados no JWT.

Este design oferece flexibilidade total, permitindo que qualquer sistema utilize um serviço de identidade robusto enquanto mantém controle total sobre sua própria lógica de negócios e permissões.

✨ Features
✅ Gerenciamento de Identidade: Registro de usuário e recuperação de perfil.

✅ Fluxo de Tokens (JWT): Login com access_token e refresh_token.

✅ Segurança de Senha: Hashing de senha forte (Bcrypt).

✅ Verificação de Email: Fluxo completo de ativação de conta por email.

✅ Recuperação de Senha: Fluxo seguro de "esqueci minha senha".

✅ Proteção de Login: Rate Limiting (SlowAPI) e Bloqueio de Conta (Account Lockout).

✅ Autorização Agnóstica (Claims): Injeta roles, permissions ou qualquer outro dado customizado no JWT.

✅ API de Gerenciamento (Management): Endpoints seguros (sistema-para-sistema) para gerenciar metadados de usuários.

✅ Async: Totalmente assíncrono (FastAPI, SQLAlchemy 2.0, AsyncPG).

🚀 Começando
📋 Pré-requisitos
Python 3.10+

PostgreSQL (Servidor rodando)

Servidor SMTP ou serviço de email (ex: Mailtrap.io para desenvolvimento).

1. Instalação
Clone o repositório:

Bash

git clone https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
cd SEU_REPOSITORIO
Crie e ative um ambiente virtual:

Bash

python -m venv venv
source venv/bin/activate   # (Linux/macOS)
.\venv\Scripts\activate    # (Windows)
Instale as dependências:

Bash

pip install -r requirements.txt
2. Configuração
Crie um banco de dados PostgreSQL (ex: auth_db).

Copie o arquivo de exemplo .env.example (se você tiver um) para .env. Se não, crie um arquivo .env e adicione as seguintes variáveis:

Ini, TOML

# String de conexão (use asyncpg)
DATABASE_URL="postgresql+asyncpg://USUARIO:SENHA@localhost:5432/auth_db"

# Chaves Secretas (use 'openssl rand -hex 32' para gerar)
SECRET_KEY="SUA_CHAVE_SECRETA_FORTE_AQUI"
REFRESH_SECRET_KEY="UMA_CHAVE_SECRETA_DIFERENTE_E_FORTE_AQUI"

# Chave da API de Gerenciamento (use 'openssl rand -hex 64')
INTERNAL_API_KEY="sk_live_UMA_CHAVE_SECRETA_MUITO_FORTE_PARA_SISTEMAS"

# Configurações de Email (Exemplo com Mailtrap)
EMAIL_HOST="sandbox.smtp.mailtrap.io"
EMAIL_PORT=2525
EMAIL_USERNAME="SEU_USUARIO_MAILTRAP"
EMAIL_PASSWORD="SUA_SENHA_MAILTRAP"
EMAIL_FROM="no-reply@suaauthapi.com"
EMAIL_FROM_NAME="Auth API"
EMAIL_USE_TLS=true
EMAIL_USE_SSL=false

# URLs do SEU Frontend
VERIFICATION_URL_BASE="http://localhost:3000/verify-email"
RESET_PASSWORD_URL_BASE="http://localhost:3000/reset-password"

# Configurações de Segurança
LOGIN_MAX_FAILED_ATTEMPTS=5
LOGIN_LOCKOUT_MINUTES=15
3. Criar Tabelas do Banco
Para desenvolvimento, você pode usar o script inicial para criar todas as tabelas.

⚠️ Atenção: Este script DELETA todas as tabelas existentes antes de criá-las. Não use em produção.

Bash

python -m app.db.initial_data
(Para produção, recomenda-se o uso de alembic para gerenciar migrações de banco de dados. Veja o Roadmap).

4. Rodar o Servidor
Use o Uvicorn para rodar a aplicação:

Bash

# O --reload monitora mudanças nos arquivos (ótimo para dev)
# Rodando na porta 8001 como solicitado
uvicorn main:app --host 0.0.0.0 --port 8001 --reload
A API estará disponível em http://localhost:8001 🚀. A documentação interativa (Swagger UI) estará em http://localhost:8001/docs.

🛠️ Fluxo de Integração (Tutorial)
Este é o guia passo-a-passo de como um desenvolvedor deve integrar esta Auth API em seu sistema (ex: um E-commerce).

Passo 1: ✍️ Registrar o Usuário (Frontend/Backend)
O usuário se registra no seu sistema. Seu backend faz uma chamada para a Auth API.

POST /api/v1/users/

Bash

curl -X 'POST' \
  'http://localhost:8001/api/v1/users/' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "novo_usuario@meusistema.com",
  "password": "Password123!",
  "full_name": "Nome do Usuário"
}'
Resultado: O usuário é criado com is_active: false e is_verified: false. Um email de verificação é enviado para o usuário.

Passo 2: 📧 Ativar o Usuário (Usuário)
O usuário clica no link em seu email. O link aponta para o seu frontend (VERIFICATION_URL_BASE), que extrai o token e chama a Auth API:

GET /api/v1/auth/verify-email/{token}

Resultado: O usuário é atualizado para is_active: true e is_verified: true. A conta agora está pronta para login.

Passo 3: 🔑 Definir Roles e Permissões (Backend-para-Backend)
Esta é a mágica. O backend do seu sistema (E-commerce) decide quais permissões esse novo usuário tem. Ele usa a API de Gerenciamento (/mgmt) para salvar esses dados.

PATCH /api/v1/mgmt/users/novo_usuario@meusistema.com/metadata

Bash

curl -X 'PATCH' \
  'http://localhost:8001/api/v1/mgmt/users/novo_usuario@meusistema.com/metadata' \
  -H 'accept: application/json' \
  -H 'X-API-Key: sk_live_UMA_CHAVE_SECRETA_MUITO_FORTE...' \
  -H 'Content-Type: application/json' \
  -d '{
  "roles": ["user", "beta_tester"],
  "permissions": ["read:products", "write:cart"],
  "ecommerce_user_id": 4567
}'
Resultado: A Auth API armazena este JSON no campo metadata do usuário, sem entender o que roles ou ecommerce_user_id significam.

Passo 4: 🎟️ Login com Scopes (Frontend)
Quando o usuário faz login no seu frontend, você pede os "scopes" (claims) que sua aplicação precisa.

POST /api/v1/auth/token

Bash

# Note: Esta rota usa application/x-www-form-urlencoded
curl -X 'POST' \
  'http://localhost:8001/api/v1/auth/token' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=novo_usuario@meusistema.com&password=Password123!&scope=roles+permissions'
Parâmetro scope: Nós pedimos roles e permissions. A API irá buscar esses campos no metadata do usuário e injetá-los no JWT.

Passo 5: 🛡️ Usar o JWT (Frontend/Backend)
Seu frontend recebe o access_token. O payload desse token (decodificado) será:

JSON

{
  "sub": "123", // O ID do usuário na Auth API
  "exp": 1678886400,
  "token_type": "access",
  "roles": ["user", "beta_tester"], // <--- Injetado!
  "permissions": ["read:products", "write:cart"] // <--- Injetado!
}
Agora, quando seu frontend faz uma chamada para o backend do seu E-commerce (ex: GET /api/products), ele envia este token.

O backend do seu E-commerce só precisa:

Pegar a SECRET_KEY do .env.

Validar a assinatura do JWT.

Olhar os claims (ex: token_data["roles"]) e aplicar sua própria lógica de autorização.

Você nunca mais precisará consultar o banco de dados para saber as permissões de um usuário a cada requisição.

📚 Referência da API
A API é dividida em três seções principais. Para detalhes completos dos endpoints e schemas, veja a documentação interativa em /docs.

1. 🔑 Authentication (/api/v1/auth)
Descrição: Endpoints públicos para o ciclo de vida da autenticação.

Endpoints Chave:

POST /token: Login para obter tokens JWT.

POST /refresh: Obter um novo access_token usando um refresh_token.

POST /logout: Revogar um refresh_token.

GET /verify-email/{token}: Ativar uma conta.

POST /forgot-password: Iniciar o fluxo de reset de senha.

POST /reset-password: Definir uma nova senha com um token.

GET /me: Obter os dados do usuário logado (requer token).

2. 👤 User Management (/api/v1/users)
Descrição: Endpoints públicos para gerenciamento de usuários.

Endpoints Chave:

POST /: Registrar um novo usuário (envia email de verificação).

GET /: Listar usuários (pode requerer proteção de admin).

PUT /me: Atualizar os dados do próprio usuário logado.

3. ⚙️ Internal Management (/api/v1/mgmt)
Descrição: Endpoints privados para gerenciamento sistema-para-sistema.

Proteção: Requer o INTERNAL_API_KEY no header X-API-Key.

Endpoints Chave:

PUT /users/{id_ou_email}/metadata: Sobrescreve todo o metadata de um usuário.

PATCH /users/{id_ou_email}/metadata: Mescla (Atualiza) o metadata de um usuário (preferencial).

🤝 Contribuição
Contribuições são muito bem-vindas! Sinta-se à vontade para abrir uma issue ou enviar um pull request.

Faça um Fork do projeto.

Crie sua Feature Branch (git checkout -b feature/MinhaFeatureIncrivel).

Faça o Commit de suas mudanças (git commit -m 'feat: Adiciona MinhaFeatureIncrivel').

Faça o Push para a Branch (git push origin feature/MinhaFeatureIncrivel).

Abra um Pull Request.

📜 Licença
Este projeto está licenciado sob a Licença MIT. Veja o arquivo LICENSE para mais detalhes.
