import tkinter as tk
from tkinter import messagebox
import bcrypt
import mysql.connector

# Función para verificar la contraseña


def verificar_password(password, hash_password):
    return bcrypt.checkpw(contraseña.encode('utf-8'), hash_password)

# Función para registrar un nuevo usuario


def registrar_usuario():
    usuario = entry_usuario_registro.get()
    password = entry_password_registro.get()

    # Verificar si el usuario ya existe en la base de datos
    cursor.execute("SELECT * FROM usuarios WHERE usuario = %s", (usuario,))
    if cursor.fetchone():
        messagebox.showerror("Error", "El usuario ya existe")
    else:
        # Generar el hash de la contraseña
        salt = bcrypt.gensalt()
        hash_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Insertar el usuario y el hash de la contraseña en la base de datos
        cursor.execute("INSERT INTO usuarios (usuario, password) VALUES (%s, %s)", (usuario, hash_password))
        conexion.commit()
        messagebox.showinfo("Registro exitoso", "El usuario se registró correctamente")

        # Borrar los datos introducidos en los campos de texto
        entry_usuario_registro.delete(0, tk.END)
        entry_password_registro.delete(0, tk.END)

# Función para iniciar sesión


def iniciar_sesion():
    usuario = entry_usuario_inicio.get()
    password = entry_password_inicio.get()

    # Verificar si el usuario existe en la base de datos
    cursor.execute("SELECT contraseña FROM usuarios WHERE usuario = %s", (usuario,))
    resultado = cursor.fetchone()
    if resultado:
        hash_password = resultado[0]

        # Verificar la contraseña
        if verificar_password(password, hash_password):
            messagebox.showinfo("Inicio de sesión exitoso", "Bienvenido, " + usuario)
        else:
            messagebox.showerror("Error", "Contraseña incorrecta")
    else:
        messagebox.showerror("Error", "El usuario no existe")

    # Borrar los datos introducidos en los campos de texto
    entry_usuario_inicio.delete(0, tk.END)
    entry_password_inicio.delete(0, tk.END)

# Crear la ventana principal


ventana = tk.Tk()
ventana.title("Aplicación de inicio de sesión y registro")

# Establecer la conexión con la base de datos
conexion = mysql.connector.connect(
    host="localhost",
    user="tu_usuario",
    password="tu_password",
    database="nombre_base_de_datos"
)
cursor = conexion.cursor()

# Crear la tabla de usuarios si no existe
cursor.execute("CREATE TABLE IF NOT EXISTS usuarios (usuario VARCHAR(255), contraseña VARCHAR(255))")

# Apartado de inicio de sesión
label_inicio = tk.Label(ventana, text="Inicio de sesión")
label_inicio.pack()

label_usuario_inicio = tk.Label(ventana, text="Usuario:")
label_usuario_inicio.pack()

entry_usuario_inicio = tk.Entry(ventana)
entry_usuario_inicio.pack()

label_password_inicio = tk.Label(ventana, text="Contraseña:")
label_password_inicio.pack()

entry_password_inicio = tk.Entry(ventana, show="*")
entry_password_inicio.pack()

boton_inicio_sesion = tk.Button(ventana, text="Iniciar sesión", command=iniciar_sesion)
boton_inicio_sesion.pack()

# Apartado de registro
label_registro = tk.Label(ventana, text="Registro")
label_registro.pack()

label_usuario_registro = tk.Label(ventana, text="Usuario:")
label_usuario_registro.pack()

entry_usuario_registro = tk.Entry(ventana)
entry_usuario_registro.pack()

label_password_registro = tk.Label(ventana, text="Contraseña:")
label_password_registro.pack()

entry_password_registro = tk.Entry(ventana, show="*")
entry_password_registro.pack()

boton_registro = tk.Button(ventana, text="Registrarse", command=registrar_usuario)
boton_registro.pack()

# Ejecutar la ventana principal
ventana.mainloop()
