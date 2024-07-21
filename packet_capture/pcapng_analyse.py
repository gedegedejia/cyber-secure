import pyshark
import pandas as pd
import os
import pandas as pd
from scapy.all import *
from datetime import datetime
# 指定 TShark 的路径


def pcapng_to_excel(pcapng_file, excel_file):
    
    try:
        # 读取 .pcapng 文件
        cap = pyshark.FileCapture(pcapng_file, tshark_path=os.getenv('tshark_path'))
        
        # 创建一个列表来存储数据包信息
        packets_data = []

        # 遍历所有数据包
        for packet in cap:
            packet_info = {
                'No.': packet.number,
                'Time': packet.sniff_time,
                'Length': packet.length,
                'Protocol': getattr(packet, 'transport_layer', 'N/A'),
                'Source': getattr(packet.ip, 'src', 'N/A') if hasattr(packet, 'ip') else 'N/A',
                'Destination': getattr(packet.ip, 'dst', 'N/A') if hasattr(packet, 'ip') else 'N/A',
                'Info': getattr(packet, 'info', '详见pcapng文件')
            }
            packets_data.append(packet_info)

        # 将数据包信息转化为 DataFrame
        df = pd.DataFrame(packets_data)

        # 将 DataFrame 写入 Excel 文件
        df.to_excel(excel_file, index=False)

        print(f"Data has been successfully saved to {excel_file}")
    except Exception as e:
        print(f"An error occurred: {e}")
def pcapng_to_xlsx(pcap_file, excel_file):
    pkts = rdpcap(pcap_file)
    data = []  # 用于存储每条数据包的信息

    for pkt in pkts:
        try:
            timestamp_float = float(pkt.time)
            dt_object = datetime.fromtimestamp(timestamp_float)
            formatted_time = dt_object.strftime('%Y-%m-%d %H:%M:%S')
            # 假设我们只保存时间戳和数据包的简化描述，你可以根据需要添加更多字段
            data.append({"Time": formatted_time, "Packet Summary": pkt.summary()})
        except (TypeError, ValueError) as e:
            print(f"Error converting timestamp: {e}")

    # 使用pandas DataFrame来整理数据，并保存到Excel文件
    df = pd.DataFrame(data)
    df.to_excel(excel_file, index=False)  # index=False避免写入索引列

pcapng_file = 'packet_capture\\my.pcapng'
excel_file = 'packet_capture\\output.xlsx'
pcapng_to_excel(pcapng_file, excel_file)