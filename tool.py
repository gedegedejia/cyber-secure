import requests
import os
from datetime import datetime
import json
import packet_capture.pcapng_analyse
import v2_uploadFile
from dotenv import load_dotenv
import packet_capture
import subprocess
import time


load_dotenv()

# 定义工具列表，模型在选择使用哪个工具时会参考工具的name和description
tools = [
    {
        "type": "function",
        "function": {
            "name": "get_current_time",
            "description": "当你想知道现在的时间时非常有用。",
            "parameters": {}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_secure_report",
            "description": "当你想检验文件网络安全性时非常有用。",
            "parameters": {
                "type": "object",
                "properties": {
                }
            },
            "required": [
                "file_name",
                "file_path"
            ]
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_wireshark",
            "description": "当你想抓包分析网络安全性时非常有用。",
            "parameters": {
                "type": "object",
                "properties": {
                }
            }
        }
    }
]

# 查询当前时间的工具。返回结果示例：“当前时间：2024-04-15 17:15:18。“
def get_current_time():
    # 获取当前日期和时间
    current_datetime = datetime.now()
    # 格式化当前日期和时间
    formatted_time = current_datetime.strftime('%Y-%m-%d %H:%M:%S')
    # 返回格式化后的当前时间
    return f"当前时间：{formatted_time}。"

def get_secure_report(file_name,file_path):
    #print(file_name,file_path)
    
    #v2_uploadFile_copy
    url1 = 'https://www.virustotal.com/vtapi/v2/file/scan'
    url2 = "https://www.virustotal.com/vtapi/v2/file/report"
    
    load_dotenv()
    apikey = os.getenv('API_KEY1')
    #获得文件scan_id
    scan_id = v2_uploadFile.getFileScanId(url1,apikey,file_name,file_path)
    md5 = v2_uploadFile.getFile_md5(url1,apikey,file_name,file_path)
    #获得返回的json结果并写入result文件
    #getFieReportResult(url2, apikey, scan_id)
    json = v2_uploadFile.getFieReportResult(url2,apikey,scan_id)
    
    json1 = v2_uploadFile.getFieReportResult_behaviour(apikey,md5)
    
    file_info=str('这是一份名为'+str(json['submission_names'])+'的'+str(json['type']+'文件'))
    txt=v2_uploadFile.getResult(json)
    behaviour=''
    signature_description=''
    mat_description=''
    if 'tags' in json1['data']:
        behaviour = str('文件行为标签为'+str(json1['data']['tags']))

    
    if 'signature_matches' in json1['data']:
        signature_description ='signature描述为：'
        for match in json1['data']['signature_matches']: 
            if 'description' in match:
                signature_description+=match['description']+','
        else:
            signature_description=''
        signature_description = signature_description.rstrip(',')


    if 'mitre_attack_techniques' in json1['data']:
        mat_description = 'mitre_attack_techniques描述为：'
        for match in json1['data']['mitre_attack_techniques']: 
            if 'signature_description' in match:
                mat_description+=match['signature_description']+','
            else:
                mat_description=''
        mat_description = mat_description.rstrip(',')

    
    answer=file_info+ "\n" +str(v2_uploadFile.culuateDate(txt))+ "\n" +behaviour+ "\n" +signature_description+ "\n" +mat_description
    '''''
    print("************************************************")
    print(f"answer:{answer}")
    print("************************************************")
    '''''
    return answer

def get_wireshark():
    try:
        wireshark_path = os.getenv('wireshark_path')
        if not wireshark_path:
            raise ValueError("Wireshark path is not set in environment variables.")

        # 启动Wireshark进行流量捕获
        process = subprocess.Popen([wireshark_path, "-i", "WLAN", "-w", "packet_capture\\my.pcapng"])
        time.sleep(10)  # 根据需要调整等待时间

        # 停止Wireshark流量捕获
        process.terminate()
        process.wait()

    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    
def get_response(messages):
    api_key = os.getenv("DASHSCOPE_API_KEY")
    url = 'https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation'
    headers = {'Content-Type': 'application/json',
            'Authorization':f'Bearer {api_key}'}
    body = {
        'model': 'qwen-max',
        "input": {
            "messages": messages
        },
        "parameters": {
            "result_format": "message",
            "tools": tools
        }
    }

    response = requests.post(url, headers=headers, json=body)
    #print(response.json())
    return response.json()

messages = [
    {
        "role": "user",
        "content": "今天天气怎么样？"
    }
]

def call_with_messages(content):
    messages = [
            {
                "content": content,  # 提问示例："现在几点了？" "一个小时后几点" "北京天气如何？"
                "role": "user"
            }
    ]
    
    # 模型的第一轮调用
    first_response = get_response(messages)
    #print(f"\n第一轮调用结果：{first_response}")
    assistant_output = first_response['output']['choices'][0]['message']
    messages.append(assistant_output)
    if 'tool_calls' not in assistant_output:  # 如果模型判断无需调用工具，则将assistant的回复直接打印出来，无需进行模型的第二轮调用
        #print(f"最终答案：{assistant_output['content']}")
        return assistant_output['content']
   
    # 如果模型选择的工具是get_current_time
    elif assistant_output['tool_calls'][0]['function']['name'] == 'get_current_time':
        tool_info = {"name": "get_current_time", "role":"tool"}
        tool_info['content'] = get_current_time()
    elif assistant_output['tool_calls'][0]['function']['name'] == 'get_secure_report':
        tool_info = {"name": "get_secure_report", "role":"tool"}
        arguments=json.loads(assistant_output['tool_calls'][0]['function']['arguments'])
        file_name=arguments['file_name']
        file_path=arguments['file_path']
        #print(file_name,file_path)
        tool_info['content'] = get_secure_report(file_name,file_path)
        #print(tool_info['content'])
        #print(tool_info)
    
    return tool_info["content"]
    
     
if __name__ == '__main__':
    content=input('请输入：')
    call_with_messages(content)