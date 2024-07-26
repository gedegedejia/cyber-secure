#www.virustotal.com/vtapi/v2/

import requests
import json

import os
from dotenv import load_dotenv

def getFileScanId(url,apikey,a,b):
    # /file/scan
    # /文件/扫描
    # 上传并扫描文件
    # 限制为32MB
    params = {'apikey': apikey}
    files = {'file': (a, open(b, 'rb'))}
    response = requests.post(url, files=files, params=params)
    my_scan_id = str(response.json()['scan_id'])
    return my_scan_id

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
    '''
    with open("jsonResult.json","w") as f:
        json.dump(jsondata, f, indent=4)
    '''
    return jsondata

def getFieReportResult_behaviour(apikey,md5):
    url = f"https://www.virustotal.com/api/v3/files/{md5}/behaviour_summary"
    headers = {"accept": "application/json","X-Apikey": apikey}
    response = requests.get(url, headers=headers)
    jsondata = json.loads(response.text)
    '''
    with open("jsonResult1.json","w") as f:
        json.dump(jsondata, f, indent=4)
    '''
    return jsondata

def getResult(json):
    result = {}
    #print(json)
    print("网页：",json["permalink"])
    permalink=json['permalink']
    for k,v in json["scans"].items():
        result[k] = v['result']
    #print(result)
    print("一共有{0}条杀毒数据。".format(len(result)))
    ''''
    with open("result.txt","w") as g:
        g.write(str(result))
    '''
    return result,permalink

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
    return answer

def main():
    file_name = input("请输入文件名:")
    a = str(file_name)
    file_src  = input("请输入文件路径:")
    b = str(file_src)

    url1 = 'https://www.virustotal.com/vtapi/v2/file/scan'
    url2 = "https://www.virustotal.com/vtapi/v2/file/report"
    #需要提供密钥，否者会出现403错误
    load_dotenv()
    apikey = os.getenv('API_KEY1')
    
    #获得文件scan_id
    scan_id = getFileScanId(url1,apikey,a,b)
    my_md5 = getFile_md5(url1,apikey,a,b)
    #获得返回的json结果并写入result文件
    #getFieReportResult(url2, apikey, scan_id)
    json = getFieReportResult(url2,apikey,scan_id)
    getFieReportResult_behaviour(apikey,my_md5)
    #getFieReportResult1(url2,apikey,scan_id)
    file_info=str('这是一份名为'+str(json['submission_names'])+'的'+str(json['type']+'文件'))
    #print(json)
    txt=getResult(json)
    #print(txt)
    #answer=file_info+str(culuateDate(txt))
    #print(qwen_7b_chat.call_with_messages(str(answer)))


if __name__ == '__main__':
   main()