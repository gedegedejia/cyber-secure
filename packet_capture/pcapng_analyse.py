import pyshark
import pandas as pd

def pcapng_to_excel(pcapng_file, excel_file):
    try:
        # 指定 tshark 的路径
        tshark_path = r'D:\\Wireshark\\wireshark\\Wireshark\\Wireshark.exe'
        cap = pyshark.FileCapture(pcapng_file, tshark_path=tshark_path)

        packets_data = []
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

        df = pd.DataFrame(packets_data)
        df.to_excel(excel_file, index=False)
        print(f"Data has been successfully saved to {excel_file}")
    except Exception as e:
        print(f"An error occurred: {e}")
# 示例用法
pcapng_file = 'packet_capture\\my.pcapng'
excel_file = 'packet_capture\\output.xlsx'
pcapng_to_excel(pcapng_file, excel_file)
