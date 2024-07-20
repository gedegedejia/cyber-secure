import pyshark
import pandas as pd
import os
# 指定 TShark 的路径


def pcapng_to_excel(pcapng_file, excel_file):
    print('1222222222222ssssssss')
    try:
        # 读取 .pcapng 文件
        cap = pyshark.FileCapture(pcapng_file, tshark_path=os.getenv('tshark_path'))
        print('111111111111111111111111111111111111111111sadadssssssssssss')
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

'''pcapng_file = 'packet_capture\\my.pcapng'
excel_file = 'packet_capture\\output.xlsx'
pcapng_to_excel(pcapng_file, excel_file)'''