#www.virustotal.com/vtapi/v2/

import requests
import json
import pandas as pd
import os
from dotenv import load_dotenv
from datetime import datetime
import base64

def getFile_md5(url,apikey,a,b):
    params = {'apikey': apikey}
    files = {'file': (a, open(b, 'rb'))}
    response = requests.post(url, files=files, params=params)
    my_md5 = str(response.json()['md5'])
    return my_md5

def getFieReportResult(url,apikey,my_scan_id):
    #/file/report
    # /文件/报告
    # 检索文件扫描报告
    #该resource参数可以是要获取最新的病毒报告文件的MD5，SHA-1或SHA-256。
    #还可以指定/ file / scan端点scan_id返回的值。
    #如果allinfo参数设置为true除了返回防病毒结果之外的其他信息。
    get_params = {'apikey': apikey, 'resource': my_scan_id,'allinfo': '1'}
    #print(url)
    response2 = requests.get(url, params=get_params)
    jsondata = json.loads(response2.text)
    #print(jsondata)
    return jsondata

def getFieReportResult_behaviour(apikey,md5):
    url = f"https://www.virustotal.com/api/v3/files/{md5}/behaviour_summary"
    headers = {"accept": "application/json","X-Apikey": apikey}
    response = requests.get(url, headers=headers)
    jsondata = json.loads(response.text)
    return jsondata

def getUrlReportResult(apikey,url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json","X-Apikey": apikey}
    response = requests.get(url, headers=headers)
    jsondata = json.loads(response.text)

    return jsondata

def getIPReportResult(apikey,ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json","X-Apikey": apikey}
    response = requests.get(url, headers=headers)
    jsondata = json.loads(response.text)
    return jsondata

def getUrlResult(json):
    result = {}
    print("网页：",'https://www.virustotal.com/gui/url/'+json['data']['id'])
    for k,v in json['data']['attributes']['last_analysis_results'].items():
        result[k] = v['result']

    print("一共有{0}条杀毒数据。".format(len(result)))
    return result

def getIPResult(json):
    result = {}
    print("网页：",'https://www.virustotal.com/gui/ip-address/'+json['data']['id'])
    for k,v in json['data']['attributes']['last_analysis_results'].items():
        result[k] = v['result']

    print("一共有{0}条杀毒数据。".format(len(result)))
    return result

def getResult(json):
    result = {}
    #print(json)
    print("网页：",json["permalink"])
    for k,v in json["scans"].items():
        result[k] = v['result']
    #print(result)
    print("一共有{0}条杀毒数据。".format(len(result)))


    return result
def culuateDate(txt):
    #print(txt)
    a=[]
    virus_number=0
    fine_number=0
    prompt = ""
    for i in txt:
        if txt[i] != None:
            virus_number+=1
            a.append(i)
            prompt=f'{str(i)}引擎认为该文件具有{txt[i]}的问题，'+prompt
        elif txt[i] == None:
            fine_number+=1
    #print(prompt)
    
    if virus_number > 0:
        answer=f"经过virus total(专业病毒检测软件)的检测，有{str(virus_number)}个不同的著名引擎检测出病毒{str(fine_number)}个不同的著名引擎没有检测出病毒。分别是{prompt}"
    else:
        answer = '经过virus total(专业病毒检测软件)的检测,此文件未发现病毒'

    return answer,virus_number,fine_number

def culuateDate_url(txt):
    #print(txt)
    a=[]
    virus_number=0
    fine_number=0
    prompt = ""
    for i in txt:
        if txt[i] == 'malicious':
            virus_number+=1
            a.append(i)
            prompt=f'{str(i)}引擎认为该文件具有{txt[i]}的问题，'+prompt
        else:
            fine_number+=1
    #print(prompt)
    
    if virus_number > 0:
        answer=f"经过virus total(专业病毒检测软件)的检测，有{str(virus_number)}个不同的著名引擎认为是恶意的，{str(fine_number)}个不同的著名引擎认为安全。分别是{prompt}"
    else:
        answer = '经过virus total(专业病毒检测软件)的检测,安全'

    return answer,virus_number,fine_number

def save_virus_detection_results(file_name, virus_type, virus_number, fine_number):
    # 创建DataFrame
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    df = pd.DataFrame({
        '文件名称': [file_name],
        '文件类型': [virus_type],
        '提交时间': [timestamp],
        '反病毒引擎检出': [f'{virus_number}/{virus_number + fine_number}'],
        '判定': ['高危' if float(virus_number) / (virus_number + fine_number) > 0.3 else '安全']
    })

    # 设置Excel文件的路径
    file_path = 'virus_detection_results.xlsx'
    
    try:
        # 如果文件存在，加载文件并追加数据
        with pd.ExcelWriter(file_path, engine='openpyxl', mode='a', if_sheet_exists='overlay') as writer:
            # Find the last row in the existing sheet
            startrow = writer.sheets['Sheet1'].max_row
            
            # Append the new data without the header
            df.to_excel(writer, index=False, header=False, startrow=startrow)
    except FileNotFoundError:
        # 如果文件不存在，创建新的文件
        with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False)

def url_detection_results(url,url_type,virus_number, fine_number):
    # 创建DataFrame
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    df = pd.DataFrame({
        '网站': [url],
        '网站类型': [url_type],
        '提交时间': [timestamp],
        '反病毒引擎检出': [f'{virus_number}/{virus_number + fine_number}'],
        '判定': ['高危' if float(virus_number) / (virus_number + fine_number) > 0.3 else '安全']
    })

    # 设置Excel文件的路径
    file_path = 'url_detection_results.xlsx'
    
    try:
        # 如果文件存在，加载文件并追加数据
        with pd.ExcelWriter(file_path, engine='openpyxl', mode='a', if_sheet_exists='overlay') as writer:
            # Find the last row in the existing sheet
            startrow = writer.sheets['Sheet1'].max_row
            
            # Append the new data without the header
            df.to_excel(writer, index=False, header=False, startrow=startrow)
    except FileNotFoundError:
        # 如果文件不存在，创建新的文件
        with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False)

def ip_detection_results(ip,url_type,virus_number, fine_number,as_owner,country):
    # 创建DataFrame
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    df = pd.DataFrame({
        'ip地址': [ip],
        '类型': [url_type],
        '国家':[country],
        '所属':[as_owner],
        '提交时间': [timestamp],
        '反病毒引擎检出': [f'{virus_number}/{virus_number + fine_number}'],
        '判定': ['高危' if float(virus_number) / (virus_number + fine_number) > 0.3 else '安全']
    })

    # 设置Excel文件的路径
    file_path = 'ip_detection_results.xlsx'
    
    try:
        # 如果文件存在，加载文件并追加数据
        with pd.ExcelWriter(file_path, engine='openpyxl', mode='a', if_sheet_exists='overlay') as writer:
            # Find the last row in the existing sheet
            startrow = writer.sheets['Sheet1'].max_row
            
            # Append the new data without the header
            df.to_excel(writer, index=False, header=False, startrow=startrow)
    except FileNotFoundError:
        # 如果文件不存在，创建新的文件
        with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False)


def main():

    '''    #file_name = input("请输入文件名:")
    a = 'test.txt'
    #file_src  = input("请输入文件路径:")
    b = 'D://test.txt'

    url1 = 'https://www.virustotal.com/vtapi/v2/file/scan'
    url2 = "https://www.virustotal.com/vtapi/v2/file/report"
    #需要提供密钥，否者会出现403错误
    load_dotenv()
    apikey = os.getenv('API_KEY1')
    
    #获得文件scan_id
    my_md5 = getFile_md5(url1,apikey,a,b)
    #获得返回的json结果并写入result文件
    #getFieReportResult(url2, apikey, scan_id)
    json = getFieReportResult(url2,apikey,my_md5)
    getFieReportResult_behaviour(apikey,my_md5)
    #getFieReportResult1(url2,apikey,scan_id)
    file_info=str('这是一份名为'+str(json['submission_names'])+'的'+str(json['type']+'文件'))
    #print(json)
    txt=getResult(json)
    print(txt)
    tool_answer,virus_number,fine_number = culuateDate(txt)
    answer=file_info+str(tool_answer)
    virus_type = json['type']
    save_virus_detection_results(a,virus_type,virus_number,fine_number)
    print(answer)'''
    '''a = "3721.com"
  
    json = getUrlReportResult(apikey,a)
    txt = getUrlResult(json)
    culuateDate_url(txt)'''
    load_dotenv()
    ip = '108.61.209.12'
    apikey = os.getenv('API_KEY1')  
    json = getIPReportResult(apikey,ip)
    txt = getIPResult(json)
    tool_answer,virus_number,fine_number = culuateDate_url(txt)
    virus_type = json['data']['type']    
    url_detection_results(ip,virus_type,virus_number,fine_number)
    print(txt)
if __name__ == '__main__':
   main()