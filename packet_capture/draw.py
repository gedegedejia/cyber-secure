import pandas as pd
import matplotlib
matplotlib.use('Agg')  # 在导入plt之前设置
import matplotlib.pyplot as plt
import os

def plot_from_excel(excel_file, output_filepath):
    try:
        # 创建保存图表的目录
        output_dir = os.path.dirname(output_filepath)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # 读取 Excel 文件
        df = pd.read_excel(excel_file)

        # 确保 'Protocol' 列存在
        if 'Protocol' not in df.columns:
            raise ValueError("Excel file does not contain 'Protocol' column.")

        # 统计每种协议的数量
        protocol_counts = df['Protocol'].value_counts()

        # 确保 protocol_counts 不为空
        if protocol_counts.empty:
            raise ValueError("No data found in 'Protocol' column.")

        # 自定义颜色
        colors = [
            '#a4a5ef', '#5c7ada', '#312d50', '#63599d', '#86547a',
            '#df9cc0', '#0e0b14', '#685c7f', '#b8606c', '#b4446c'
        ]
        colors = colors * (len(protocol_counts) // len(colors) + 1)  # 扩展颜色列表以适应所有扇区

        # 突出显示最大值
        explode = [0.1 if protocol == protocol_counts.idxmax() else 0 for protocol in protocol_counts.index]

        # 绘制每种协议的数量饼图
        plt.figure(figsize=(6, 6))
        pie_chart = protocol_counts.plot.pie(
            autopct='%1.1f%%', 
            startangle=90, 
            colors=colors[:len(protocol_counts)], 
            explode=explode,
            shadow=True,
            wedgeprops={'edgecolor': '#382f51', 'linewidth': 1}  # 增加边缘宽度
        )

        wedges = pie_chart.patches  # 获取所有扇区

        plt.legend(wedges, protocol_counts.index, title="Protocols", loc="best")
        
        # 设置每个扇区的阴影
        for wedge in wedges:
            wedge.set_linewidth(1.5)  # 调整边缘宽度

        plt.title('Packet Count by Protocol')
        plt.ylabel('')  # 去掉默认的 y 轴标签
        plt.savefig(output_filepath)
        plt.close()

        print(f"Chart has been successfully saved to '{output_filepath}'.")
    
    except FileNotFoundError:
        print(f"File '{excel_file}' not found.")
    except ValueError as ve:
        print(ve)
    except Exception as e:
        print(f"An error occurred: {e}")