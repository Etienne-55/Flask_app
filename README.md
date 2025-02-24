# Projeto Back-end: API Flask com Autenticação e Gerenciamento de Posts
Este projeto é uma API desenvolvida em Flask que permite a autenticação de usuários, criação e gerenciamento de posts, além de funcionalidades de administração. Ele foi projetado para demonstrar habilidades em desenvolvimento de APIs RESTful, autenticação JWT e interação com banco de dados.

## Funcionalidades

### Autenticação
- **Login**: Autenticação de usuários com geração de token JWT.

### Usuários
- **Criação de usuário**: Registro de novos usuários.
- **Edição de usuário**: Atualização de email e senha.
- **Buscar usuário por ID**: Retorna os detalhes de um usuário específico.
- **Listar usuários**: Retorna a lista de todos os usuários (apenas para administradores).
- **Deletar usuário**: Exclusão de um usuário (apenas pelo próprio usuário ou admin).

### Posts
- **Criação de post**: Cria um novo post associado ao usuário autenticado.
- **Edição de post**: Atualiza o conteúdo de um post (apenas pelo autor ou admin).
- **Buscar post por ID**: Retorna os detalhes de um post específico.
- **Listar todos os posts**: Retorna todos os posts com informações do autor (id e nome do usuário).
- **Listar posts por ID de usuário**: Retorna todos os posts de um usuário específico.
- **Deletar post**: Exclui um post (apenas pelo autor ou admin).

### Regras de Administração
Apenas administradores podem:
- Editar ou deletar usuários que não sejam eles mesmos.
- Editar ou deletar posts que não sejam deles.

## Tecnologias Utilizadas
- **Flask**: Framework web para Python.
- **Flask-RESTX**: Extensão para criar APIs RESTful com documentação Swagger integrada.
- **Flask-JWT-Extended**: Para autenticação baseada em JWT (JSON Web Tokens).
- **SQLAlchemy**: ORM para interação com o banco de dados.
- **MySQL**: Banco de dados relacional (pode ser substituído por SQLite para testes locais).
- **Docker**: Para conteinerização e facilidade de deploy.

## Pré-requisitos
- Python 3.8 ou superior.
- MySQL ou SQLite instalado.
- Pipenv instalado (`pip install pipenv`).
- Docker (opcional, para rodar o projeto em um container).

## Configuração do Projeto

### Clone o repositório:
```bash
git clone https://github.com/Etienne-55/Flask_app.git
cd Flask_app
```

### Instale as dependências:
```bash
pipenv install
```

### Configure o banco de dados:
- Crie um banco de dados MySQL (ou use SQLite para testes locais).
- Configure as variáveis de ambiente no arquivo `.env`:
```plaintext
FLASK_APP=app.py
FLASK_ENV=development
DATABASE_URL=mysql+pymysql://usuario:senha@localhost/nome_do_banco
JWT_SECRET_KEY=sua_chave_secreta_jwt
```

### Execute as migrações do banco de dados:
```bash
pipenv run flask db init
pipenv run flask db migrate
pipenv run flask db upgrade
```

### Execute o servidor Flask:
```bash
pipenv run flask run
```

### Acesse a documentação da API:
Abra o navegador e acesse [http://127.0.0.1:5000/docs](http://127.0.0.1:5000/docs) para visualizar a documentação Swagger.
