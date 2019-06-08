##########################################
#	TASK 3
#
# By: Antonio Scapellato & Massimo Valle
##########################################




from scapy.all import *

print("___________________TASK3___________________")

print("Loading the file...")

#______________________LOADING THE DATA______#

pkts = rdpcap("smallFlows.pcap")

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP

f_ip = [field.name for field in IP().fields_desc]
f_tcp = [field.name for field in TCP().fields_desc]
f_all = f_ip + ['time'] + f_tcp + ['payload']

# Data structures and data analysis
import pandas as pd

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

#print('PRINT df:')
#print(df)

series_sorted = df['src'].value_counts()

series_topTen = series_sorted.head(10)

df_topTen = series_topTen.rename_axis('ip_addr').to_frame('amount_of_traffic')

#print(df_topTen)
#print(df_topTen.index)


df1 = df.set_index(['src'])
#print('############DF1:')
#print(df1)


df2 = pd.DataFrame(df1.loc[df_topTen.index])
#print('############DF2:')
#print(df2)


#print(df2.loc[[df_topTen.index[0]]])
#for row in df2:
    #print(row)

col_field = ['ip_addr', 'amount_of_total_traffic', 'protocol', 'amount_of_traffic_for_specific_protocol', 'source_port', 'amount_for_spec_source_port', 'destination_port', 'amount_for_spec_destination_port']
df_end = pd.DataFrame(columns=col_field)

for index in df_topTen.index:
    item = df2.loc[[index]]
    #print(item)

    #print(item['proto'].value_counts())

    series_proto = item['proto'].value_counts()
    top_proto = series_proto.head(1)
    df_top_proto = top_proto.rename_axis('protocol').to_frame('amount_of_traffic_for_specific_protocol')
    df_top_proto = df_top_proto.reset_index()
    #print(df_top_proto.loc[0]['protocol'])

    series_sport = item['sport'].value_counts()
    top_sport = series_sport.head(1)
    df_top_sport = top_sport.rename_axis('source_port').to_frame('amount_for_spec_source_port')
    df_top_sport = df_top_sport.reset_index()
    #print(df_top_sport)

    series_dport = item['dport'].value_counts()
    top_dport = series_dport.head(1)
    df_top_dport = top_dport.rename_axis('destination_port').to_frame('amount_for_spec_destination_port')
    df_top_dport = df_top_dport.reset_index()
    #print(df_top_dport)

    field_values = []
    field_values.append(index)
    field_values.append(df_topTen.loc[index]["amount_of_traffic"])
    #print(df_top_proto.loc[0]['protocol'])
    field_values.append(df_top_proto.loc[0]['protocol'])
    field_values.append(df_top_proto.loc[0]['amount_of_traffic_for_specific_protocol'])
    field_values.append(df_top_sport.loc[0]['source_port'])
    field_values.append(df_top_sport.loc[0]['amount_for_spec_source_port'])
    field_values.append(df_top_dport.loc[0]['destination_port'])
    field_values.append(df_top_dport.loc[0]['amount_for_spec_destination_port'])

    print('ciclo: ' + str(index))
    print(field_values)

    df_append = pd.DataFrame([field_values], columns=col_field)
    df_end = pd.concat([df_end, df_append], axis=0)


df_end = df_end.reset_index()

df_end.set_index('ip_addr')

df_end = df_end.drop(columns="index")


print(df_end)
df_end.to_csv(r'task_3.csv', index = False, header=True)
