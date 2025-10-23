
<p align="center">
    <a href="https://github.com/SEU_USUARIO/SEU_REPOSITORIO/blob/main/LICENSE" target="_blank">
        <img src="https://img.shields.io/github/license/SEU_USUARIO/SEU_REPOSITORIO?style=for-the-badge&color=brightgreen" alt="License">
    </a>
    <a href="https://github.com/SEU_USUARIO/SEU_REPOSITORIO/stargazers" target="_blank">
        <img src="https://img.shields.io/github/stars/SEU_USUARIO/SEU_REPOSITORIO?style=for-the-badge&color=blue" alt="Stars">
    </a>
    <a href="https://github.com/SEU_USUARIO/SEU_REPOSITORIO/graphs/contributors" target="_blank">
        <img src="https://img.shields.io/github/contributors/SEU_USUARIO/SEU_REPOSITORIO?style=for-the-badge&color=orange" alt="Contributors">
    </a>
</p>

Um serviço de identidade agnóstico, seguro e flexível.
Construído com FastAPI e PostgreSQL para servir como um provedor de identidade (IdP) centralizado para qualquer aplicação.





💡 Conceito Central: Autenticação vs. Autorização
Esta API foi projetada com uma filosofia fundamental: a rigorosa separação entre Autenticação (provar quem você é) e Autorização (definir o que você pode fazer).

Esta API (Auth API) cuida da Autenticação:

Gerencia com segurança o registro, login e dados do usuário.

Verifica identidades via email, reset de senha e bloqueio de conta.

Fornece um "cofre" de custom_claims (claims customizados) flexível para cada usuário.

Emite tokens JWT contendo Claims Padrão OIDC (iss, aud, sub, email, etc.) para maior compatibilidade.

Sua Aplicação (ex: VR Sales) cuida da Autorização:

Você define quais roles ou permissions existem no seu sistema.

Você usa a API de Gerenciamento (/mgmt) para escrever esses dados no "cofre" custom_claims do usuário na API Auth (ex: {"roles": ["admin"], "store_id": 123}).

Você solicita esses dados (scopes) durante o login para que sejam injetados no JWT, junto com os claims OIDC padrão.

Você valida o JWT e interpreta os claims (padrão e customizados) para aplicar sua lógica de negócios.

Este design oferece flexibilidade total, permitindo que qualquer sistema utilize um serviço de identidade robusto enquanto mantém controle total sobre sua própria lógica de negócios e permissões.

✨ Features
✅ Gerenciamento de Identidade: Registro de usuário e recuperação de perfil.

✅ Fluxo de Tokens (JWT): Login com access_token e refresh_token (com rotação).

✅ Claims JWT Padrão OIDC: Tokens incluem iss, aud, sub, iat, exp, email, email_verified, name para interoperabilidade.

✅ Segurança de Senha: Hashing de senha forte (Bcrypt).

✅ Verificação de Email: Fluxo completo de ativação de conta por email (via SendGrid).

✅ Recuperação de Senha: Fluxo seguro de "esqueci minha senha".

✅ Proteção de Login: Rate Limiting (SlowAPI) e Bloqueio de Conta (Account Lockout).

✅ Autorização Agnóstica (Custom Claims): Injeta roles, permissions, store_id ou qualquer outro dado customizado no JWT via scope.

✅ API de Gerenciamento (Management): Endpoints seguros (sistema-para-sistema) para gerenciar custom_claims de usuários.

✅ RBAC Interno: Endpoints da própria API protegidos por roles (ex: "admin-only").

✅ Migrações de Banco de Dados: Gerenciamento de schema seguro com Alembic (sem perda de dados).

✅ Agnóstica de Banco de Dados: Código compatível com PostgreSQL, SQLite, MySQL (requer driver async apropriado).

✅ Async: Totalmente assíncrono (FastAPI, SQLAlchemy 2.0, AsyncPG/AioSQLite/AioMySQL).

🚀 Começando
📋 Pré-requisitos
Python 3.10+

Um servidor de banco de dados SQL rodando (ex: PostgreSQL, MySQL) ou SQLite.

O driver async apropriado para seu banco (ex: asyncpg para PostgreSQL, aiosqlite para SQLite, aiomysql para MySQL).

Uma conta SendGrid:

Uma Chave de API (API Key) do SendGrid.

Um "Remetente Verificado" (Verified Sender) configurado no SendGrid.

1. Instalação
Clone o repositório:

Bash

git clone https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
cd SEU_REPOSITORIO
Crie e ative um ambiente virtual:

Bash

python -m venv venv
source venv/bin/activate # (Linux/macOS)
.\venv\Scripts\activate # (Windows)
Instale as dependências:

Bash

pip install -r requirements.txt
# Instale o driver async do seu banco, se ainda não estiver listado:
# pip install asyncpg # Para PostgreSQL
# pip install aiosqlite # Para SQLite
# pip install aiomysql # Para MySQL
2. Configuração
Crie um banco de dados (ex: auth_db).

Crie um arquivo .env na raiz do projeto e adicione/ajuste as seguintes variáveis:

Ini, TOML

# --- Banco de Dados ---
# AJUSTE com o driver async correto e suas credenciais
DATABASE_URL="postgresql+asyncpg://USUARIO:SENHA@localhost:5432/auth_db"
# Exemplo SQLite: DATABASE_URL="sqlite+aiosqlite:///./auth.db"
# Exemplo MySQL: DATABASE_URL="mysql+aiomysql://USUARIO:SENHA@localhost:3306/auth_db"

# --- Chaves Secretas (use 'openssl rand -hex 32' para gerar) ---
SECRET_KEY="SUA_CHAVE_SECRETA_FORTE_AQUI"
REFRESH_SECRET_KEY="UMA_CHAVE_SECRETA_DIFERENTE_E_FORTE_AQUI"
ALGORITHM="HS256"

# --- Chave da API de Gerenciamento (use 'openssl rand -hex 64') ---
INTERNAL_API_KEY="sk_live_UMA_CHAVE_SECRETA_MUITO_FORTE_PARA_SISTEMAS"

# --- Configurações de Email (SendGrid) ---
SENDGRID_API_KEY="SG.SUA_CHAVE_API_SENDGRID_AQUI"
EMAIL_FROM="seu_email_verificado@sendgrid.com"
EMAIL_FROM_NAME="Auth API"

# --- URLs do SEU Frontend ---
VERIFICATION_URL_BASE="http://localhost:3000/verify-email"
RESET_PASSWORD_URL_BASE="http://localhost:3000/reset-password"

# --- Configurações de Segurança (Account Lockout) ---
LOGIN_MAX_FAILED_ATTEMPTS=5
LOGIN_LOCKOUT_MINUTES=15

# --- Configurações OIDC JWT Claims ---
JWT_ISSUER="http://localhost:8001" # URL base da sua API Auth
JWT_AUDIENCE="vrsales-api" # ID da sua API principal (ex: VRSales)
3. Migrar o Banco de Dados (Alembic)
Este projeto usa Alembic para gerenciar o schema do banco de dados de forma segura.

Para criar todas as tabelas pela primeira vez ou aplicar novas alterações de schema, rode:

Bash

alembic upgrade head
Isso criará/atualizará as tabelas users, refresh_tokens e alembic_version no banco de dados configurado no .env.

4. Rodar o Servidor
Use o Uvicorn para rodar a aplicação:

Bash

# O --reload monitora mudanças nos arquivos (ótimo para dev)
uvicorn main:app --host 0.0.0.0 --port 8001 --reload
A API estará disponível em http://localhost:8001 🚀. A documentação interativa (Swagger UI) estará em http://localhost:8001/docs.

### 🐳 Rodando com Docker (Recomendado)
Para uma experiência mais isolada e consistente, você pode usar o Docker.

**Pré-requisitos:**
- Docker e Docker Compose instalados.

**Passos:**

1.  **Configure o `.env`:**
    Copie ou renomeie `.env.example` para `.env` e preencha as variáveis como descrito na seção "Configuração" acima. A única diferença é que o `DATABASE_URL` deve apontar para o serviço do banco de dados do Docker:
    ```
    DATABASE_URL="postgresql+asyncpg://user:password@db:5432/auth_db"
    ```

2.  **Build e Run:**
    Suba os serviços (API e banco de dados) em background:
    ```bash
    docker-compose up --build -d
    ```

3.  **Aplicar Migrações:**
    Execute as migrações do Alembic dentro do container da aplicação:
    ```bash
    docker-compose exec app alembic upgrade head
    ```

A API estará disponível em `http://localhost:8001` e o banco de dados em `localhost:5432`.

**Para parar os serviços:**
```bash
docker-compose down
```

🌐 Compatibilidade Universal: Como Funciona?
Esta API foi desenhada para ser compatível com qualquer sistema ou linguagem de programação moderna. Isso é possível graças a três pilares:

REST API (HTTP + JSON):

A API se comunica usando os padrões universais da web: HTTP para requisições e JSON para dados.

Qualquer linguagem (C, C++, C#, Java, Python, Go, Rust, JavaScript, etc.) que possua uma biblioteca para fazer chamadas HTTP e manipular JSON pode interagir com esta API.

Você não precisa de bibliotecas Python específicas no seu sistema cliente (ex: VRSales em C#). Você só precisa de um cliente HTTP padrão.

Tokens JWT Padronizados:

A API emite JSON Web Tokens (JWTs) para representar a sessão do usuário. JWT é um padrão aberto (RFC 7519).

Qualquer linguagem possui bibliotecas maduras para validar JWTs (verificar assinatura usando a SECRET_KEY compartilhada) e extrair os claims (informações) de dentro dele.

Seu sistema cliente (VRSales) não precisa chamar a API Auth a cada requisição. Ele apenas valida o JWT que o frontend envia, tornando a verificação rápida e offline.

Claims OIDC Padrão + Custom Claims:

Os JWTs emitidos contêm claims padrão do OpenID Connect (OIDC) como iss (emissor), aud (audiência), sub (ID do usuário), exp (expiração), email, name, etc. Bibliotecas OIDC em qualquer linguagem já sabem como interpretar esses claims.

Além disso, você pode injetar seus próprios custom_claims (como roles, store_id, permissions) no JWT.

Isso significa que o seu sistema cliente (VRSales), após validar o JWT, tem imediatamente todas as informações de que precisa (quem é o usuário e o que ele pode fazer) sem precisar consultar o banco de dados da API Auth novamente.

Em resumo: A API Auth funciona como um "cartório digital". Qualquer sistema pode pedir a ela para verificar a identidade de um usuário (/token). A API Auth devolve um "documento autenticado" (o JWT) que contém informações padrão (OIDC) e informações específicas (custom claims). Qualquer sistema que confie na assinatura da API Auth (usando a SECRET_KEY) pode ler esse documento e tomar suas próprias decisões de autorização.

🛠️ Fluxo de Integração (Tutorial)
Este é o guia passo-a-passo de como um desenvolvedor deve integrar esta Auth API em seu sistema (ex: um E-commerce).

Passo 1: ✍️ Registrar o Usuário (Backend Cliente -> API Auth)
O usuário se registra no seu sistema (ex: E-commerce). O backend do seu sistema faz uma chamada para a Auth API.

POST /api/v1/users/

Bash

curl -X 'POST' \
'http://localhost:8001/api/v1/users/' \
-H 'accept: application/json' \
-H 'Content-Type: application/json' \
-d '{
"email": "novo_usuario@meusistema.com",
"password": "Password123!",
"full_name": "Nome Completo"
}'
Resultado: O usuário é criado na API Auth com is_active: false. Um email de verificação é enviado.

Passo 2: 📧 Ativar o Usuário (Usuário -> Frontend -> API Auth)
O usuário clica no link em seu email. O link aponta para o seu frontend (VERIFICATION_URL_BASE), que extrai o token da URL e chama a API Auth:

GET /api/v1/auth/verify-email/{token}

Resultado: O usuário na API Auth é atualizado para is_active: true, is_verified: true.

Passo 3: 🔑 Definir Roles e Claims (Backend Cliente -> API Auth)
O backend do seu sistema (E-commerce) decide quais permissões (roles, store_id, etc.) esse novo usuário tem. Ele usa a API de Gerenciamento (/mgmt) da API Auth, autenticando-se com a INTERNAL_API_KEY.

PATCH /api/v1/mgmt/users/{id_ou_email}/claims

Bash

curl -X 'PATCH' \
'http://localhost:8001/api/v1/mgmt/users/novo_usuario@meusistema.com/claims' \
-H 'accept: application/json' \
-H 'X-API-Key: sk_live_UMA_CHAVE_SECRETA_MUITO_FORTE...' \
-H 'Content-Type: application/json' \
-d '{
"roles": ["user", "beta_tester"],
"permissions": ["read:products", "write:cart"],
"ecommerce_user_id": 4567
}'
Resultado: A API Auth armazena este JSON no campo custom_claims do usuário.

Passo 4: 🎟️ Login com Scopes (Frontend -> API Auth)
Quando o usuário faz login no seu frontend, o frontend chama diretamente a API Auth, pedindo os scopes (claims customizados) que sua aplicação precisa ver no token.

POST /api/v1/auth/token

Bash

# Frontend envia como application/x-www-form-urlencoded
curl -X 'POST' \
'http://localhost:8001/api/v1/auth/token' \
-H 'accept: application/json' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-d 'username=novo_usuario@meusistema.com&password=Password123!&scope=roles+permissions+ecommerce_user_id'
Parâmetro scope: Pedimos roles, permissions e ecommerce_user_id. A API Auth irá buscar esses campos no custom_claims e injetá-los no JWT, junto com os claims OIDC padrão.

Passo 5: 🛡️ Usar o JWT (Frontend -> Backend Cliente)
O frontend recebe o access_token da API Auth. O payload desse token (decodificado) será algo como:

JSON

{
"iss": "http://localhost:8001",
"aud": "vrsales-api",
"sub": "123", // ID do usuário na API Auth
"exp": 1678886400,
"iat": 1678882800,
"email": "novo_usuario@meusistema.com",
"email_verified": true,
"name": "Nome Completo",
"token_type": "access",
"roles": ["user", "beta_tester"], // Veio do custom_claims via scope
"permissions": ["read:products", "write:cart"], // Veio do custom_claims via scope
"ecommerce_user_id": 4567 // Veio do custom_claims via scope
}
Agora, quando o frontend faz uma chamada para o backend do seu E-commerce (ex: GET /api/products), ele envia este access_token no header Authorization: Bearer

O backend do seu E-commerce só precisa:

Pegar a SECRET_KEY do seu próprio .env (que deve ser a mesma da API Auth).

Validar a assinatura, a expiração, o iss (issuer) e o aud (audience) do JWT.

Olhar os claims (ex: token_data["roles"], token_data["store_id"], token_data["sub"]) e aplicar sua própria lógica de autorização.

Seu backend E-commerce nunca mais precisará consultar o banco de dados da API Auth para saber quem é o usuário ou o que ele pode fazer a cada requisição. Toda a informação necessária está segura dentro do JWT.

📚 Referência da API
A API é dividida em três seções principais. Para detalhes completos dos endpoints e schemas, veja a documentação interativa em /docs.

1. 🔑 Authentication (/api/v1/auth)
Descrição: Endpoints públicos para o ciclo de vida da autenticação.

Endpoints Chave:

POST /token: Login para obter tokens JWT (pode receber scope, retorna claims OIDC + scopes).

POST /refresh: Obter um novo access_token usando um refresh_token (o novo token não contém custom claims).

POST /logout: Revogar um refresh_token.

GET /verify-email/{token}: Ativar uma conta.

POST /forgot-password: Iniciar o fluxo de reset de senha.

POST /reset-password: Definir uma nova senha com um token.

GET /me: Obter os dados do usuário logado (requer token).

2. 👤 User Management (/api/v1/users)
Descrição: Endpoints para gerenciamento de usuários.

Endpoints Chave:

POST /: Registrar um novo usuário (envia email de verificação).

GET /: Listar usuários (Protegido, requer role 'admin').

GET /{user_id}: Buscar um usuário por ID (Protegido, requer role 'admin').

PUT /me: Atualizar os dados do próprio usuário logado.

3. ⚙️ Internal Management (/api/v1/mgmt)
Descrição: Endpoints privados para gerenciamento sistema-para-sistema.

Proteção: Requer o INTERNAL_API_KEY no header X-API-Key.

Endpoints Chave:

PATCH /users/{id_ou_email}/claims: Mescla (Atualiza) os custom_claims de um usuário (preferencial).

🤝 Contribuição
Contribuições são muito bem-vindas! Sinta-se à vontade para abrir uma issue ou enviar um pull request.

Faça um Fork do projeto.

Crie sua Feature Branch (git checkout -b feature/MinhaFeatureIncrivel).

Faça o Commit de suas mudanças (git commit -m 'feat: Adiciona MinhaFeatureIncrivel').

Faça o Push para a Branch (git push origin feature/MinhaFeatureIncrivel).

Abra um Pull Request.

📜 Licença
Este projeto está licenciado sob a Licença MIT. Veja o arquivo LICENSE para mais detalhes.
