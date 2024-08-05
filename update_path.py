def update_tshark_path(new_path):
    # 读取 .env 文件
    with open('.env', 'r') as file:
        lines = file.readlines()

    # 更新 tshark_path 的行
    with open('.env', 'w') as file:
        for line in lines:
            if line.startswith('tshark_path'):
                line = f'tshark_path = "{new_path}"\n'
            file.write(line)

    print("TShark path updated successfully.")
