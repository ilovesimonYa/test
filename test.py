import pyshark
import csv
#import nest_asyncio


#nest_asyncio.apply()

def pcap_to_csv(pcap_file, csv_file):
    # Open the pcap file
    cap = pyshark.FileCapture(pcap_file)

    # Open the CSV file
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write the CSV header
        writer.writerow(['Time', 'Source IP', 'Destination IP', 'Protocol', 'Length'])

        # Process each packet
        # Get packet information
        for i, pkt in enumerate(cap):
            if i == 0:
                init_time = pkt.sniff_time
            # Get packet information
            time = (pkt.sniff_time - init_time).seconds + (pkt.sniff_time - init_time).microseconds / 1000000
            protocol = pkt.layers[2].layer_name

            # Get packet data
            if pkt.layers[2].layer_name != 'udp' or pkt.layers[3].layer_name != 'DATA':
                continue
            src_ip = pkt.layers[1].src
            dst_ip = pkt.layers[1].dst
            length = pkt.length
            data = pkt.layers[3].data
            # Write to the CSV file
            writer.writerow([time, src_ip, dst_ip, protocol, length, data], )
            print(i, pkt.layers[2].layer_name)
            if pkt.layers[2].layer_name == 'udp' and pkt.layers[3].layer_name == 'DATA':
                #print(pkt.layers[3].layer_name)
                print(pkt.layers[3].data)


    print("Pcap file converted to CSV file")

# Execute the function
pcap_to_csv('./input.pcap', 'output.csv')
