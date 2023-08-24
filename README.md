# OPC UA Covert Channel Analysis

## Inhalt
- 4 OPC UA Covert Channel mit Sender und Receiver:
    - covert_channel_storage1_RU  -- Reserved / Unused       
    - covert_channel_storage2_UDM -- User-Data Value Modulation
    - covert_channel_timing1_RT -- Retransmissions       
    - covert_channel_timing2_IPT -- Inter-Paket-Times 
 
- 1 Network Analyse Tool
    - network_analysis_cc.py

- 1 OPC UA Server Instanz
    - opcua_server.py

- 1 OPC UA Client Instanz
    - opcua_client.py

- Ergebnisse der parametrisierten Tests in Form von PCAP Dateien


 

## Nutzung

- Deployment des OPC UA Servers:  
   `
   python3 opcua_server.py -i [eigene IP-Adresse]
    `
   
- Verbinden des OPC UA Clienten mit dem Server und Starten der Datendarstellung:  
    `
   python3 opcua_client.py -i [IP-Adresse des Servers]
    `

- Analyse der Covert Channel:

   - Initiale Auswertung des Netzwerkverkehrs mithilfe Initialisierungsmodus des Analysetools:  
   `python3 network_analysis_cc.py -i`

   - Starten der Netzwerkanalyse:  
   `python3 network_analysis_cc.py`

- Einbetten der Covert Channel:
    - Sender:    
        - `sudo -E python3 covert_channel_storage1_RU.py`
        - `sudo -E python3 covert_channel_storage2_UDM.py`
        - `sudo -E python3 covert_channel_timing1_IPT.py`
        - `sudo -E python3 covert_channel_timing2_RT.py`
    - Receiver:
        - `sudo -E python3 covert_channel_storage1_RU_receiver.py`
        - `sudo -E python3 covert_channel_storage2_UDM_receiver.py`
        - `sudo -E python3 covert_channel_timing1_IPT_receiver.py`
        - `sudo -E python3 covert_channel_timing2_RT_receiver.py`

Zum korrekten Lesen einer versteckten Nachricht ist der Covert Channel Receiver VOR dem Covert Channel Sender zu starten!
       
   


