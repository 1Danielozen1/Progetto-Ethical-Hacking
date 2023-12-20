# Progetto-Ethical-Hacking

La velocità del programma è basta sulla velocità della CPU del PC attaccato.
è consigliato eseguire il programma da chiavetta per evitare eventuali errori legati ai nomi delle cartelle presenti sul PC della vittima.

COMANDO PER LA COMPILAZIONE IN .EXE (il file verrà salvato in una cartella chiamata "dist") :
pyinstaller --onefile --noconsole ProgettoEthical-Hacking.py\

## FUNZIONAMENTO
- l’attaccante inserisce la chiavetta con il programma nel computer dell’attaccato.

- L’attaccato esegue il programma di pulizia del computer “Glary Utilities” che è in realtà il nostro malware.

- Mentre Glary Utilities Carica, il malware si esegue in background prendendo indirizzo MAC, IP, Sistema operativo e geolocalizzazione e inviandole su Discord tramite un Webhook discord.

- Una volta inviate queste prime informazioni il malware prende password e nomi di tutte le reti WIFI e di tutti I siti memorizzati sul browser e scattando uno screenshot, impacchettando poi il tutto in una zip e inviandola.

- Infine l’Utente ignaro rimane con il programma su cui aveva cliccato (Glary Utilities), senza aver ricevuto nemmeno una notifica dall’antivirus.

- Nel caso in cui la connessione sia assente salva le informazioni in una cartella all’interno della chiavetta.
