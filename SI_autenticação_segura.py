import hashlib
import hmac
import secrets
import sqlite3
from contextlib import closing
from getpass import getpass
from pathlib import Path

BANCO = Path(__file__).with_name("usuarios_scrypt.sqlite")


def criar_tabela(banco):
    banco.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            nome TEXT PRIMARY KEY NOT NULL,
            salt BLOB NOT NULL,
            hash_senha BLOB NOT NULL
        )
    """)


def gerar_hash(senha, salt):
    return hashlib.scrypt(
        senha.encode("utf-8"), salt=salt,
        n=2**15, r=8, p=3, maxmem=64 * 1024**2, dklen=32
    )


def cadastrar(banco, nome, senha):
    nome = nome.strip()
    if not nome:
        return "Informe o nome do usuário."
    if len(senha) < 6:
        return "A senha deve ter pelo menos 6 caracteres."

    salt = secrets.token_bytes(16)
    hash_senha = gerar_hash(senha, salt)

    try:
        with banco:
            banco.execute(
                "INSERT INTO usuarios (nome, salt, hash_senha) VALUES (?, ?, ?)",
                (nome, salt, hash_senha),
            )
    except sqlite3.IntegrityError:
        return "Esse nome de usuário já está cadastrado."

    return "Usuário cadastrado com sucesso."


def autenticar(banco, nome, senha):
    registro = banco.execute(
        "SELECT salt, hash_senha FROM usuarios WHERE nome = ?",
        (nome.strip(),),
    ).fetchone()

    if registro is None:
        return False

    salt, hash_guardado = registro
    hash_digitado = gerar_hash(senha, salt)
    return hmac.compare_digest(hash_digitado, hash_guardado)


def main():
    with closing(sqlite3.connect(BANCO)) as banco:
        criar_tabela(banco)

        while True:
            print("\n1 - Cadastrar | 2 - Entrar | 0 - Sair")
            opcao = input("Escolha: ").strip()

            if opcao == "0":
                break
            if opcao not in ("1", "2"):
                print("Opção inválida.")
                continue

            nome = input("Usuário: ")
            senha = getpass("Senha: ")

            if opcao == "1":
                print(cadastrar(banco, nome, senha))
            elif autenticar(banco, nome, senha):
                print("Login aprovado.")
            else:
                print("Usuário ou senha inválidos.")


if __name__ == "__main__":
    main()
