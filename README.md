# Hacking Tools Project

Este es un proyecto académico diseñado como parte de mis estudios. Su objetivo principal es explorar y aprender conceptos relacionados con redes, seguridad y manejo de contraseñas. **No debe ser utilizado con fines malintencionados o en entornos reales**, ya que carece de las medidas de seguridad y validaciones necesarias para un software profesional.

---

## Funcionalidades Principales

### 1. Redes
- **Escanear red**: Permite analizar un rango de direcciones IP y descubrir dispositivos conectados.
- **Escanear puertos**: Realiza un escaneo de puertos abiertos en una dirección IP objetivo. Admite:
  - Escaneo de todos los puertos.
  - Escaneo de un rango de puertos definido por el usuario.
  - Escaneo de un puerto específico.
- **Escanear redes Wi-Fi**: Detecta redes Wi-Fi disponibles en el área.

### 2. Seguridad
- **Keylogger**: Incluye funcionalidades relacionadas con la captura de entradas de teclado.
  - Generación de un ejecutable.
  - Ejecución directa del keylogger.
- **Crackear contraseñas**:
  - **Ataque de diccionario**: Intenta encontrar una contraseña utilizando un archivo de palabras predefinidas.
  - **Ataque por fuerza bruta**: Genera combinaciones de caracteres hasta encontrar la contraseña.
- **Escaneo de vulnerabilidades**: Utiliza herramientas como `nmap` para identificar posibles debilidades en un sistema.
- **Sniffer de red**: Monitorea paquetes de datos en una red.
- **Búsqueda de información WHOIS**: Consulta información pública sobre un dominio o IP.

### 3. Contraseñas
- **Generador de contraseñas**: Crea contraseñas seguras de acuerdo a las especificaciones del usuario.
- **Cifrador/Descifrador de archivos**:
  - Cifra archivos utilizando algoritmos de cifrado simétrico.
  - Descifra archivos en base a la clave generada.
- **Generador de hash**: Convierte texto en un hash utilizando algoritmos como MD5, SHA-1 o SHA-256.

### 4. Otras Herramientas
- **Espacio para futuras herramientas**: Se incluirán más funcionalidades en el futuro como parte del aprendizaje continuo.

---

## Requisitos del Sistema
- **Sistema Operativo**: Windows o Linux.
- **Python**: Versión 3.7 o superior.
- **Dependencias adicionales**:
  - `nmap` (para escaneo de vulnerabilidades).
  - Bibliotecas de Python especificadas en `requirements.txt` (en desarrollo).

---

## Instalación
1. Clona este repositorio:
   ```bash
   https://github.com/BrandonMieres/HackingTools.git
   ```
2. Instala las dependencias necesarias:
   ```bash
   pip install -r requirements.txt
   ```
3. Ejecuta el programa principal:
   ```bash
   python main.py
   ```

---

## Nota Importante
Este proyecto es puramente educativo y no debe ser usado en un contexto profesional o para actividades no éticas. Todas las pruebas deben realizarse en entornos controlados y con permiso explícito.

---

## Autor
Desarrollado por **Brandon Mieres** como parte de mis estudios en seguridad informática y redes.

