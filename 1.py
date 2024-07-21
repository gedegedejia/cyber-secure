import os

def get_filename_from_path(file_path):
    return os.path.basename(file_path)

# 示例使用
file_path = 'E:\\C4 A-ST\\pythonProject1\\uploads\\123.txt'
file_name = get_filename_from_path(file_path)
print(file_name)  # 输出: file.txt
