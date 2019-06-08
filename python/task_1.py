##########################################
#	TASK 1
#
# By: Antonio Scapellato & Massimo Valle
##########################################



from scapy.all import *


print("___________________TASK1___________________")

print("Loading the file...")

#______________________LOADING THE DATA______#

pkts = rdpcap("network_traffic.pcap")

print("General information")
print(pkts[0].summary())

pkts[0].payload.show()

print("Done...")


print("Loading and preparing the structure...")
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP, UDP
print(pkts[IP]) # a overview of all IP packets

# Store the pre-defined fields name in IP, TCP layers
f_ip = [field.name for field in IP().fields_desc]
f_tcp = [field.name for field in TCP().fields_desc]
f_all = f_ip + ['time'] + f_tcp + ['payload']


#______________________DATA FRAME____________#

# Data structures and data analysis
import pandas as pd
# Blank DataFrame
df = pd.DataFrame(columns=f_all)
i = 0
clear = lambda: os.system('clear')

for packet in pkts[IP]:

    clear()
    i=i+1
    print('upload: ' + str(i) + ' / Network_traffic')

    # store data for each row of DataFrame
    field_values = []
    # Read values of IP fields
    for field in f_ip:
        if field == 'options':
            # we only store the number of options defined in IP Header
            field_values.append(len(packet[IP].fields[field]))
        else:
            field_values.append(packet[IP].fields[field])

    # Read values of Time
    field_values.append(packet.time)
    # Read values of TCP fields
    layer_type = type(packet[IP].payload)
    for field in f_tcp:
        try:
            if field == 'options':
                field_values.append(len(packet[layer_type].fields[field]))
            else:
                field_values.append(packet[layer_type].fields[field])
        except:
            # the field value may not exist
            field_values.append(None)

    # Read values of Payload
    field_values.append(len(packet[layer_type].payload))

    # Fill the data of one row
    df_append = pd.DataFrame([field_values], columns=f_all)
    # Append row in df
    df = pd.concat([df, df_append], axis=0)



# Reset index
df = df.reset_index()
df = df.drop(columns="index")


print("Done...")

#______________________MANAGE THE DATA - TASK1______#

print("----------------RESULTs TASK1------------------")
print(df.groupby('dport').count())

df_port = df.groupby('dport').count()
df_port.rename(index='port', columns={'version':'traffic(pks)'})
df_port[['traffic(pks)']].to_csv(r'task_1.csv', index = True, header=True)




