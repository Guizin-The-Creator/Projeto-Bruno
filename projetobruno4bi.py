from pymongo import MongoClient
from tkinter import Tk, Text, Button, Entry, Label, StringVar, OptionMenu, messagebox
import ttkbootstrap as ttk
from cryptography.fernet import Fernet, InvalidToken
import time

# Função para gerar chave de criptografia
def gerar_chave():
    return Fernet.generate_key()

# Função para criptografar uma mensagem
def criptografar_mensagem(mensagem, chave):
    f = Fernet(chave)
    return f.encrypt(mensagem.encode())

# Função para descriptografar uma mensagem
def descriptografar_mensagem(mensagem_criptografada, chave):
    try:
        f = Fernet(chave)
        return f.decrypt(mensagem_criptografada).decode()
    except InvalidToken:
        print(f"Erro: A chave fornecida '{chave}' é inválida ou a mensagem foi alterada.")
        return None

# Função para armazenar mensagens criptografadas no MongoDB
def armazenar_mensagem(mensagem_criptografada, remetente, destinatario, id_conversa):
    _, mensagens, _ = conectar_mongo()
    if mensagens is not None:
        mensagens.insert_one({
            "mensagem": mensagem_criptografada,
            "remetente": remetente,
            "destinatario": destinatario,
            "id_conversa": id_conversa,
            "timestamp": time.time()
        })
    else:
        print("Erro ao acessar a coleção de mensagens no MongoDB.")

# Função para recuperar mensagens recebidas por um usuário
def recuperar_mensagens(destinatario, chave):
    _, mensagens, _ = conectar_mongo()
    if mensagens is not None:
        mensagens_recebidas = mensagens.find({"destinatario": destinatario})

        print(f"Mensagens recebidas por {destinatario}:")
        for msg in mensagens_recebidas:
            mensagem_criptografada = msg['mensagem']
            try:
                mensagem_descriptografada = descriptografar_mensagem(mensagem_criptografada, chave)
                print(f"{msg['remetente']} para {destinatario}: {mensagem_descriptografada}")
            except InvalidToken:
                print("Erro: chave de criptografia inválida para esta mensagem.")
    else:
        print("Erro ao acessar a coleção de mensagens no MongoDB.")
def notificar_nova_mensagem(remetente, destinatario):
    print(f"Nova mensagem de {remetente} para {destinatario} (conteúdo não exposto).")

# Função para gerar ou recuperar chave de sessão dinâmica para uma conversa
def gerar_ou_recuperar_chave(remetente, destinatario):
    _, _, chaves = conectar_mongo()
    if chaves is not None:
        chave_entrada = chaves.find_one({
            "$or": [
                {"remetente": remetente, "destinatario": destinatario},
                {"remetente": destinatario, "destinatario": remetente}
            ]
        })

        if chave_entrada:
            return chave_entrada['chave']

        chave = gerar_chave()
        chaves.insert_one({
            "remetente": remetente,
            "destinatario": destinatario,
            "chave": chave
        })
        return chave
    else:
        print("Erro ao acessar a coleção de chaves no MongoDB.")
    return None

# Função para conectar ao MongoDB
def conectar_mongo():
    try:
        URI = 'mongodb+srv://brunoeliabe7:eliabedugrau@cluster0.c9jsc.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'
        client = MongoClient(URI, serverSelectionTimeoutMS=5000)
        client.server_info()
        db = client['chat_app']
        return db['usuarios'], db['mensagens'], db['chaves']
    except Exception as e:
        print("Erro de conexão com o MongoDB:", e)
        return None, None, None

# Função para registrar o usuário
def registrar_usuario(usuario, senha_criptografada, chave):
    usuarios, _, _ = conectar_mongo()
    if usuarios is not None:
        if usuarios.find_one({"usuario": usuario}):
            print("Usuário já existe!")
        else:
            usuarios.insert_one({"usuario": usuario, "senha": senha_criptografada, "chave": chave})
            print(f"Usuário {usuario} registrado com sucesso!")
    else:
        print("Erro ao acessar a coleção de usuários no MongoDB.")

# Função para verificar credenciais do usuário
def verificar_credenciais(usuario, senha):
    usuarios, _, _ = conectar_mongo()
    if usuarios is not None:
        user_data = usuarios.find_one({"usuario": usuario})
        if user_data:
            chave = user_data.get("chave")
            senha_criptografada = user_data["senha"]
            if chave is None:
                print("Chave de criptografia não encontrada para este usuário.")
                return False
            senha_descriptografada = descriptografar_mensagem(senha_criptografada, chave)
            return senha == senha_descriptografada
    return False

# Tela de Login
class LoginApp(ttk.Window):
    def __init__(self, iniciar_chat):
        super().__init__(title="Login e Registro", size=(400, 300))
        self.iniciar_chat = iniciar_chat
        
        Label(self, text="Usuário:").grid(row=0, column=0)
        self.entry_usuario = Entry(self, width=40)
        self.entry_usuario.grid(row=0, column=1, padx=10, pady=10)
        
        Label(self, text="Senha:").grid(row=1, column=0)
        self.entry_senha = Entry(self, show="*", width=40)
        self.entry_senha.grid(row=1, column=1, padx=10, pady=10)
        
        Button(self, text="Login", command=self.login_usuario).grid(row=2, column=0, padx=10, pady=10)
        Button(self, text="Registrar", command=self.registrar_usuario).grid(row=2, column=1, padx=10, pady=10)

    def login_usuario(self):
        usuario = self.entry_usuario.get()
        senha = self.entry_senha.get()

        if verificar_credenciais(usuario, senha):
            chave = gerar_ou_recuperar_chave(usuario, "admin")
            recuperar_mensagens(usuario, chave)  
            self.iniciar_chat(usuario)
            self.destroy()
        else:
            print("Usuário ou senha incorretos.")

    def registrar_usuario(self):
        usuario = self.entry_usuario.get()
        senha = self.entry_senha.get()

        if usuario and senha:
            chave = gerar_chave()
            senha_criptografada = criptografar_mensagem(senha, chave)
            registrar_usuario(usuario, senha_criptografada, chave)
            self.iniciar_chat(usuario)
            self.destroy()
        else:
            messagebox.showerror("Erro de Registro", "Usuário e senha são obrigatórios")

# Interface Principal do Chat
class ChatApp(ttk.Window):
    def __init__(self, usuario):
        super().__init__(title="App de Mensagens", size=(500, 600))
        self.usuario = usuario

        # Área de texto para mostrar as mensagens
        self.mensagem_text = Text(self, height=10, width=50)
        self.mensagem_text.grid(row=0, column=0, padx=10, pady=10, columnspan=2)

        # Campo para digitar as mensagens
        self.entry_mensagem = Entry(self, width=40)
        self.entry_mensagem.grid(row=1, column=0, padx=10, pady=10)

        # Botão para enviar a mensagem
        self.botao_enviar = Button(self, text="Enviar", command=self.enviar_mensagem)
        self.botao_enviar.grid(row=1, column=1, padx=10, pady=10)

        # Botão para ver o histórico de mensagens
        self.botao_historico = Button(self, text="Ver Histórico", command=self.ver_historico)
        self.botao_historico.grid(row=2, column=0, columnspan=2, pady=10)

        # Recuperar a lista de usuários registrados do banco de dados
        self.usuarios_registrados = self.obter_usuarios_registrados()

        # Campo para selecionar o destinatário entre os usuários registrados
        self.destinatario_var = StringVar(self)
        if self.usuarios_registrados:
            self.destinatario_var.set(self.usuarios_registrados[0])  # Definir o primeiro usuário como destinatário padrão
        else:
            self.destinatario_var.set("")  # Caso não haja usuários, defina uma string vazia
        Label(self, text="Destinatário:").grid(row=3, column=0)
        self.opcao_destinatario = OptionMenu(self, self.destinatario_var, *self.usuarios_registrados)
        self.opcao_destinatario.grid(row=3, column=1)

        # Chave de criptografia para a conversa
        self.chave = gerar_ou_recuperar_chave(self.usuario, self.destinatario_var.get())

    def obter_usuarios_registrados(self):
        """Recupera a lista de usuários registrados no MongoDB"""
        usuarios, _, _ = conectar_mongo()
        if usuarios is not None:
            usuarios_registrados = [user['usuario'] for user in usuarios.find()]
            usuarios_registrados.remove(self.usuario)  # Remove o próprio usuário da lista de destinatários
            return usuarios_registrados
        else:
            return []

    def enviar_mensagem(self):
        destinatario = self.destinatario_var.get()
        mensagem = self.entry_mensagem.get()
        if mensagem and self.chave and self.usuario != destinatario:
            # Criptografando e armazenando a mensagem
            mensagem_criptografada = criptografar_mensagem(mensagem, self.chave)
            armazenar_mensagem(mensagem_criptografada, self.usuario, destinatario, "conversa1")
            # Exibe a mensagem no campo de texto
            self.mensagem_text.insert("end", f"{self.usuario} para {destinatario}: {mensagem}\n")
            # Notifica nova mensagem
            notificar_nova_mensagem(self.usuario, destinatario)
            # Limpa o campo de entrada
            self.entry_mensagem.delete(0, "end")

    def ver_historico(self):
        # Limpa a área de mensagens para exibir o histórico
        self.mensagem_text.delete(1.0, "end")  
        if self.chave:
            # Conecta ao MongoDB para recuperar as mensagens
            _, mensagens, _ = conectar_mongo()
            if mensagens is not None:
                # Recupera as mensagens da conversa com o destinatário
                mensagens_recebidas = mensagens.find({
                    "$or": [
                        {"remetente": self.usuario, "destinatario": self.destinatario_var.get()},
                        {"remetente": self.destinatario_var.get(), "destinatario": self.usuario}
                    ]
                })

                # Exibe as mensagens descriptografadas no campo de texto
                for msg in mensagens_recebidas:
                    mensagem_criptografada = msg['mensagem']
                    try:
                        # Tenta descriptografar a mensagem
                        mensagem_descriptografada = descriptografar_mensagem(mensagem_criptografada, self.chave)
                        if mensagem_descriptografada:
                            # Exibe a mensagem no campo de texto
                            self.mensagem_text.insert("end", f"{msg['remetente']} para {msg['destinatario']}: {mensagem_descriptografada}\n")
                    except InvalidToken:
                        print("Erro: chave de criptografia inválida para esta mensagem.")

if __name__ == "__main__":
    def iniciar_chat(usuario):
        chat_app = ChatApp(usuario)
        chat_app.mainloop()
        
    login_app = LoginApp(iniciar_chat)
    login_app.mainloop()
