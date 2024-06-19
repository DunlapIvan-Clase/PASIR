import csv

# Ficheros
input_file = 'all_traffic.csv'
output_file = 'network_logs.csv'


with open(output_file, 'w', newline='') as csvfile:
    fieldnames = ['Date first seen', 'Duration', 'Proto', 'Src IP Addr', 'Src Pt', 
                  'Dst IP Addr', 'Dst Pt', 'Packets', 'Bytes', 'Flows', 'Flags', 
                  'Tos', 'class', 'attackType', 'attackID', 'attackDescription']
    
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
    writer.writeheader()
    
    with open(input_file, 'r') as infile:
        reader = csv.DictReader(infile, delimiter=',')
        
        for row in reader:
            new_row = {
                'Date first seen': row['ts'],  # Timestamp
                'Duration': row['td'],         # Duración del flujo
                'Proto': row['pr'],            # Protocolo
                'Src IP Addr': row['sa'],      # Dirección IP de origen
                'Src Pt': row['sp'],           # Puerto de origen
                'Dst IP Addr': row['da'],      # Dirección IP de destino
                'Dst Pt': row['dp'],           # Puerto de destino
                'Packets': row['ipkt'],        # Número de paquetes
                'Bytes': row['ibyt'],          # Número de bytes
                'Flows': '1',                  # Número de flujos
                'Flags': row['flg'],           # Flag
                'Tos': '0',                    # Tipo de servicio
                'class': 'normal',             # Clase
                'attackType': '---',           # Tipo de ataque
                'attackID': '---',             # ID de ataque
                'attackDescription': '---'     # Descripción de ataque
            }
            
            writer.writerow(new_row)