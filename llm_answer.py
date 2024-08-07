import os
import dashscope
from dashscope import Generation,TextEmbedding
from dotenv import load_dotenv
from pymilvus import connections, FieldSchema, CollectionSchema, DataType, Collection,utility
from embedding import getEmbedding
from http import HTTPStatus
from flask import Flask, request, jsonify, render_template,Response,stream_with_context,json
import packet_capture.draw
import packet_capture.pcapng_analyse
import tool 
import packet_capture
import asyncio
from datetime import datetime
import time
import embedding
import pandas as pd
from update_path import update_tshark_path

load_dotenv()
api_key = os.getenv("DASHSCOPE_API_KEY")
url = 'https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation'
headers = {'Content-Type': 'application/json',
           'Authorization': f'Bearer {api_key}'}

messages = [
    {
        "role": "system",
        "content": "你是一个网络安全分析小助手，你的任务是解决用户的网络安全问题。你的功能:1.分析用户上传的文件。2.抓取并分析pcapng数据包"
    }
]
uploaded_file_paths = []

app = Flask(
    __name__,
    static_folder='static/assets',
    template_folder='static',
    static_url_path='/assets'
)
app.config['UPLOAD_FOLDER'] = os.getenv('uploads_path')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    # 检查上传目录是否存在，如果不存在则创建
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # 保存文件到上传目录
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)
    uploaded_file_paths.append(file_path)
    print(f"Uploaded file paths: {uploaded_file_paths}")  # 添加日志
    suggestions = ['分析文件安全性','分析文件安全性','分析文件安全性']
    return jsonify({'fileName': file.filename, 'filePath': file_path,'suggestions':suggestions})
    
def getAnswer(query, context,tool_message,messages,tool_call):
    if tool_call == 'get_secure_report':
        prompt = f'''
            请基于以下提供的网络安全知识来回答：
            {context}
            我的问题是：{query}。
            我通过工具调用获取了以下信息：{tool_message}。
            请你总结工具调用的信息，以表格的形式，解释文件标签，分析该文件的意图和可能存在的可疑活动，并提出建议和解决方案。
            '''
    elif tool_call == 'get_current_time':
        prompt = f'''
            我的问题是：{query},我通过工具调用得知 {tool_message}。请根据我工具调用的内容给我回答。
            '''
    
    elif tool_call == 'get_wireshark':
        prompt = f'''
            请基于以下提供的网络安全知识来回答：
            {context}
            我使用Wireshark工具进行抓包分析，获得了以下信息：{tool_message}。
            请你帮助我描述数据包的内容，判断是否存在可疑数据包，并分析其中可能存在的安全问题。
            同时，请提供相应的建议和解决方案。
            '''
    elif tool_call == 'get_url_report':
        prompt = f'''
            请基于以下提供的网络安全知识来回答：
            {context}
            我使用virustotal平台进行网页链接安全性分析，获得了以下信息：{tool_message}。
            请你总结网页内容，并分析其中可能存在的安全问题.
            '''
    elif tool_call == 'get_ip_report':
        prompt = f'''
            请基于以下提供的网络安全知识来回答：
            {context}
            我使用virustotal平台进行ip地址安全性分析，获得了以下信息：{tool_message}。
            请你总结信息，并分析其中可能存在的安全问题.
            '''
    else:
        prompt = f'''
            请回答我的问题：{query}。
            {context}
            请结合网络安全的知识，尽量简洁明了地回答，但请保持礼貌。
            '''

    rsp = Generation.call(model='qwen-turbo',messages=messages, prompt=prompt,result_format='message',incremental_output=True,stream=True)
    
    res = ''
    for response in rsp:
        if response.status_code == HTTPStatus.OK:
            
            print(response.output.choices[0]['message']['content'], end='')
            res += response.output.choices[0]['message']['content']
        else:
            print('Request id: %s, Status code: %s, error code: %s, error message: %s' % (
                response.request_id, response.status_code,
                response.code, response.message
            ))
    return res

def search(text,DashVector_name):
    # Search parameters for the index
    search_params = {
        "metric_type": "L2"
    }
    COLLECTION_NAME = DashVector_name
    DIMENSION = 1536
    MILVUS_HOST = 'c-e920f955ee756dbc.milvus.aliyuncs.com'
    MILVUS_PORT = '19530'
    USER = 'root'
    PASSWORD = '200413Cwj@'

    connections.connect(host=MILVUS_HOST, port=MILVUS_PORT, user=USER, password=PASSWORD)
    fields = [
        FieldSchema(name='id', dtype=DataType.INT64, description='Ids', is_primary=True, auto_id=False),
        FieldSchema(name='question', dtype=DataType.VARCHAR, description='Question', max_length=4096),
        FieldSchema(name='answer', dtype=DataType.VARCHAR, description='Answer', max_length=4096),
        FieldSchema(name='embedding', dtype=DataType.FLOAT_VECTOR, description='Embedding vectors', dim=DIMENSION)
    ]
    schema = CollectionSchema(fields=fields, description='CEC Corpus Collection')
    collection = Collection(name=COLLECTION_NAME, schema=schema)
    collection.load()
    results = collection.search(
        data=[getEmbedding(text)],  # Embeded search value
        anns_field="embedding",  # Search across embeddings
        param=search_params,
        limit=1,  # Limit to five results per search
        output_fields=['answer']  # Include title field in result
    )

    ret = []
    for hit in results[0]:
        ret.append(hit.entity.get('answer'))
    return ret

@app.route('/api/update-chat', methods=['POST'])
def update_chat():
    data = request.get_json()
    messages = data.get('messages')
    if not messages:
        return jsonify({'error': 'No messages provided'}), 400
    global update_messages
    # 在这里处理 messages，例如保存到数据库或进行其他操作
    update_messages = convert_messages_format(messages)
    # 返回成功响应
    return jsonify({'success': True}), 200

def convert_messages_format(messages):
    converted_messages = []

    # 添加系统角色的消息
    system_message = {
        'role': 'system',
        'content': '你是一名网络安全分析助手，专注于帮助用户解决网络安全问题。你的主要职责包括：1. 分析用户上传的文件，识别潜在的安全风险。2. 分析用户上传的网址链接，识别潜在的安全风险。3. 抓取和分析pcapng数据包，检测异常流量和可疑活动。'
    }
    converted_messages.append(system_message)

    for message in messages:
        role = 'user' if message['user'] else 'assistant'
        content = message['content']

        # 构建新的消息字典
        new_message = {
            'role': role,
            'content': content
        }

        # 将新消息添加到转换后的消息列表中
        converted_messages.append(new_message)

    return converted_messages

@app.route('/api/sse')
def sse():
    question = request.args.get('message')
    request_type = request.args.get('type')
    if not question:
        return jsonify({'error': 'No message provided'}), 400

    def stream():
        if request_type == 'chat':
            messages = update_messages
            context = search(question, 'ccc')
            print(context)
            answer = getAnswer(question, context, '', messages, '')
            suggestions = get_suggestions(messages,request_type)

            Response={'content':answer,'suggestions':suggestions}

        elif request_type == 'get_secure_report':
            context = search(question, 'web_leak')
            tool_call = tool.tool_jude(question)
            messages = update_messages
            tool_message = ''
            if(tool_call == 'get_secure_report'):
                if uploaded_file_paths:
                    tool_message = str(tool.get_secure_report(str(uploaded_file_paths[-1])))
                else:
                    tool_message = ''
            answer = getAnswer(question, context, str(tool_message), messages, tool_call)        
            suggestions = get_suggestions(messages,request_type)
            Response={'content':answer,'suggestions':suggestions}
        
        elif request_type == 'get_wireshark':
            asyncio.set_event_loop(asyncio.new_event_loop())
            tool.get_wireshark()  # 执行Wireshark抓包操作
            answer = None  # 初始化 answer
            image_url = None  # 初始化 image_url
            file_url = None     # 初始化 file_url
            context = search(question, 'web_leak')
            tool_call = tool.tool_jude(question)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            pcap_dir = 'static/assets/packet_capture'
            if not os.path.exists(pcap_dir):
                os.makedirs(pcap_dir, exist_ok=True)  # 确保目录存在
            pcapng_file = f'{pcap_dir}/my.pcapng'
            excel_file = f'{pcap_dir}/output.xlsx'
            xlsx_file = f'{pcap_dir}/packet_data_{timestamp}.xlsx'
            packet_capture.pcapng_analyse.pcapng_to_excel(pcapng_file, excel_file)
            packet_capture.pcapng_analyse.pcapng_to_xlsx(pcapng_file, xlsx_file)
            unique_chart_filename = f'protocol_count_pie_{timestamp}.png'
            unique_chart_filepath = os.path.join('static', 'assets', 'pictures', unique_chart_filename)
            packet_capture.draw.plot_from_excel(excel_file, unique_chart_filepath)
            tool_message = packet_capture.pcapng_analyse.read_packet_info_from_excel(xlsx_file)
            image_url = f'/assets/pictures/{unique_chart_filename}'
            file_url = xlsx_file.strip('static')
            if file_url:
                answer = f'[点击下载文件]({file_url})'
            if image_url:
                answer = f'{answer}\n![图片]({image_url})'
            messages = update_messages
            llm_answer = getAnswer(question, context, str(tool_message), messages, tool_call)
            answer = f'{answer}\n'+llm_answer
            suggestions = get_suggestions(messages,'get_wireshark')
            Response={'content':answer,'suggestions':suggestions}
        
        elif request_type == 'get_url_report' or request_type == 'get_ip_report':
            context = search(question, 'web_leak')
            tool_call = tool.tool_jude(question)
            print(tool_call)
            tool_message = ''
            if tool_call == 'get_url_report':
                x_url=tool.get_url(question)
                tool_message = str(tool.get_url_report(x_url))
            elif tool_call == 'get_ip_report':
                ip=tool.get_ip(question)
                tool_message = str(tool.get_ip_report(ip))
            messages = update_messages
            answer = getAnswer(question, context, str(tool_message), messages, tool_call)        
            suggestions = ['你好','谢谢','是的']
            Response={'content':answer,'suggestions':suggestions}    
        else:
            response_data = {'message': 'Invalid type provided', 'done': True}
            yield f'data: {json.dumps(response_data)}\n\n'
            return

        for char in Response['content']:
            response_data = {'message': char,'done': False}
            yield f'data: {json.dumps(response_data)}\n\n'
            time.sleep(0.05)  # 控制发送速度

        response_data = {'message': '', 'suggestions' : suggestions, 'done': True}
        yield f'data: {json.dumps(response_data)}\n\n'

    return Response(stream(), content_type='text/event-stream')

def get_suggestions(messages,tool):
    suggestions = []
    if tool == 'get_secure_report':
        function = '文件漏洞分析功能,可以上传文件,给出对文件的安全性分析报告和建议'
    if tool == 'get_wireshark':
        function = '抓包流量分析功能,可以自动抓包,对流量进行分析'
    if tool == 'chat':
        function = '网安知识问答功能,可以进行网络安全知识的问答'
    
    for i in range(3):
        prompt = f'''
            用户正在使用{function}，请根据用户的历史记录，给用户第{i}个可能的提示词来引导用户进行操作。
            以下是我的历史记录
            ```{messages}```
            输出严格在10-12字
        '''
        rsp = Generation.call(model='qwen-turbo',messages=messages, prompt=prompt,result_format='message',incremental_output=True,stream=True)
        res=''
        for response in rsp:
            if response.status_code == HTTPStatus.OK:
                print(response.output.choices[0]['message']['content'], end='')
                res += response.output.choices[0]['message']['content']
            else:
                print('Request id: %s, Status code: %s, error code: %s, error message: %s' % (
                    response.request_id, response.status_code,
                    response.code, response.message
                ))
        suggestions.append(res.strip('"').rstrip('。'))
    print(suggestions)
    return suggestions

@app.route('/api/uploadKnowledge', methods=['POST'])
def uploadKnowledge():
    knowledge_name = request.form.get('KnowledgeName')
    data_path = app.config['UPLOAD_FOLDER']+'/knowledge/'+knowledge_name
    file = request.files['file']
    
    print("knowledge_name:", knowledge_name)

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})

    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    if not os.path.exists(data_path):
        os.makedirs(data_path)

    file_path = os.path.join(data_path, file.filename)
    file.save(file_path)
    uploaded_file_paths.append(file_path)
    print(f"Uploaded file paths: {uploaded_file_paths}")  # 添加日志
    
    # Assuming embedding.uploadKnowledge is a function you defined elsewhere
    try:
        embedding.uploadKnowledge(knowledge_name, data_path)
        
        return jsonify({'message': 'File uploaded successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/uploadFileHistory', methods=['POST'])
def excel_data():
    data = request.get_json()
    print(data['tool'])
    tool = data['tool']
    if (tool == "get_url_report"):
        file_path = 'table/url_detection_results.xlsx'
    
    elif (tool == 'get_secure_report'):
        file_path = 'table/virus_detection_results.xlsx'
    
    elif (tool == 'get_ip_report'):
        file_path = 'table/ip_detection_results.xlsx'

    # 使用 pandas 读取 Excel 文件
    df = pd.read_excel(file_path, engine='openpyxl')
    # 将 DataFrame 转换为字典
    data_dict = df.to_dict(orient='records')
    return jsonify(data_dict)

@app.route('/api/set_tshark_path', methods=['POST'])
def set_tshark_path():
    new_path = request.get_json()['newTsharkPath']
    print(new_path)
    update_tshark_path(new_path)
    return jsonify('TShark path updated.')
    

if __name__ == '__main__':
    # 配置Dashscope API KEY
    dashscope.api_key = api_key
    app.run(debug=True,host='0.0.0.0',port=1223)