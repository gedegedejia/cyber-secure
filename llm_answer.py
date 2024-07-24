import os
import dashscope
from dashscope import Generation
from dotenv import load_dotenv
from pymilvus import connections, FieldSchema, CollectionSchema, DataType, Collection
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

load_dotenv()
api_key = os.getenv("DASHSCOPE_API_KEY")
url = 'https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation'
headers = {'Content-Type': 'application/json',
           'Authorization': f'Bearer {api_key}'}

uploaded_file_paths = []

app = Flask(
    __name__,
    static_folder='static/assets',
    template_folder='static',
    static_url_path='/assets'
)
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/chat', methods=['POST'])
def chat():
    print(messages)
    asyncio.set_event_loop(asyncio.new_event_loop())
    question = request.json.get('message')
    answer = None  # 初始化 answer
    if not question:
        return jsonify({'error': 'No message provided'}), 400
    context = search(question,'ccc')
    answer = getAnswer(question, context, '', messages,'')
    suggestions = get_suggestions(messages)
    messages.append({
        'role': "user",
        'content': question
    })    
    messages.append({
        "role": "assistant",
        "content": answer
    })

    answer = f'{answer}\n\n可能的提示词：{suggestions}'
    response_data = {'response': answer}
    return jsonify(response_data)
@app.route('/api/get_secure_report', methods=['POST'])
def get_secure_report_api():
    question = request.json.get('message')
    answer = None  # 初始化 answer
    if not question:
        return jsonify({'error': 'No message provided'}), 400
    context = search(question,'web_leak')  # 假设search函数已定义
    
    tool_call=tool.tool_jude(question)
    if uploaded_file_paths!=[]:
        tool_message = str(tool.get_secure_report(str(uploaded_file_paths[-1])))  # 调用get_secure_report工具函数
    else:
        tool_message=''
    answer = getAnswer(question, context, str(tool_message), messages, tool_call)  # 获取答案
    #多轮对话
    messages.append({
        'role': "user",
        'content': question
    })    
    messages.append({
        'role': "assistant",
        'content': tool_message
    })
    messages.append({
        "role": "assistant",
        "content": answer
    })
    suggestions = get_suggestions(messages)
    answer = f'{answer}\n\n可能的提示词：{suggestions}'    
    return jsonify({'response': answer})

@app.route('/api/get_wireshark', methods=['POST'])
def get_wireshark_api():
    asyncio.set_event_loop(asyncio.new_event_loop())
    tool.get_wireshark()  # 执行Wireshark抓包操作
    answer = None  # 初始化 answer
    image_url = None  # 初始化 image_url
    file_url = None     # 初始化 file_url
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
    
    answer = "抓包分析已完成"
    image_url = f'/assets/pictures/{unique_chart_filename}'
    file_url = xlsx_file.strip('static')
    if image_url:
        answer = f'{answer}\n![图片]({image_url})'
    if file_url:
        answer = f'{answer}\n[点击下载文件]({file_url})'
    print(messages)
    suggestions = get_suggestions(messages)
    answer = f'{answer}\n\n可能的提示词：{suggestions}'
    print(answer)
    response_data = {'response': answer}
    return jsonify(response_data)

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
    return jsonify({'fileName': file.filename, 'filePath': file_path})
    
@app.route('/api/delete_chat', methods=['GET'])
def delete_chat():
    global messages
    messages = [
        {
            "role": "system",
            "content": "你是一个网络安全分析小助手，你的任务是解决用户的网络安全问题。你的功能:1.分析用户上传的文件。2.抓取数据包"
        }
    ]
    return jsonify({'response': 'Chat history deleted successfully'})

def getAnswer(query, context,tool_message,messages,tool_call):
    if tool_call == 'get_secure_report':
        prompt = f'''请基于```内的网络安全知识，回答我的问题。
            ```
            {context},
            ```
            我的问题是：{query},我通过工具调用得知 {tool_message}。请你列出文件标签并解释，给出该文件的意图和可疑活动，并给出建议和解决方案。
            '''
    
    elif tool_call == 'get_current_time':
        prompt = f'''
            我的问题是：{query},我通过工具调用得知 {tool_message}。请根据我工具调用的内容给我回答。
            '''
    
    elif tool_call == 'get_wireshark':
        prompt = f'''
            我的问题是：{query},我通过工具调用得知 {tool_message}。
            '''
    else:
        prompt = f'''回答我。
            ```
            {context},
            ```
            我的问题是：{query}。回答尽量精炼，但需要有礼貌。
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
    print(res)
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
        FieldSchema(name='text', dtype=DataType.VARCHAR, description='Text', max_length=4096),
        FieldSchema(name='embedding', dtype=DataType.FLOAT_VECTOR, description='Embedding vectors', dim=DIMENSION)
    ]
    schema = CollectionSchema(fields=fields, description='CEC Corpus Collection')
    collection = Collection(name=COLLECTION_NAME, schema=schema)
    results = collection.search(
        data=[getEmbedding(text)],  # Embeded search value
        anns_field="embedding",  # Search across embeddings
        param=search_params,
        limit=1,  # Limit to five results per search
        output_fields=['text']  # Include title field in result
    )

    ret = []
    for hit in results[0]:
        ret.append(hit.entity.get('text'))
    return ret



@app.route('/api/sse')
def sse():
    question = request.args.get('message')
    request_type = request.args.get('type')
    if not question:
        return jsonify({'error': 'No message provided'}), 400

    def stream():
        if request_type == 'chat':

            context = search(question, 'ccc')
            answer = getAnswer(question, context, '', messages, '')
            suggestions = get_suggestions(messages)
            messages.append({'role': "user", 'content': question})
            messages.append({"role": "assistant", "content": answer})
            answer = f'{answer}\n\n可能的提示词：{suggestions}'

        elif request_type == 'get_secure_report':

            context = search(question, 'web_leak')
            tool_call = tool.tool_jude(question)
            
            if uploaded_file_paths:
                tool_message = str(tool.get_secure_report(str(uploaded_file_paths[-1])))
            else:
                tool_message = ''

            answer = getAnswer(question, context, str(tool_message), messages, tool_call)
            messages.append({'role': "user", 'content': question})
            messages.append({'role': "assistant", 'content': tool_message})
            messages.append({"role": "assistant", "content": answer})
            suggestions = get_suggestions(messages)
            answer = f'{answer}\n\n可能的提示词：{suggestions}'

        else:
            response_data = {'message': 'Invalid type provided', 'done': True}
            yield f'data: {json.dumps(response_data)}\n\n'
            return

        for char in answer:
            response_data = {'message': char, 'done': False}
            yield f'data: {json.dumps(response_data)}\n\n'
            time.sleep(0.05)  # 控制发送速度

        response_data = {'message': '', 'done': True}
        yield f'data: {json.dumps(response_data)}\n\n'

    return Response(stream(), content_type='text/event-stream')


def get_suggestions(messages):
    prompt = f'''
            目前你的推荐的功能有：
            侧边栏点击文件漏洞分析功能，上传文件后，可以文件的安全性分析报告和建议。
            侧边栏点击抓包流量分析功能，自动抓包，对流量进行分析。
            侧边栏点击网安知识问答功能，可以进行网络安全知识的问答。
            
            请根据我的历史记录和我的功能，给用户3个可能的提示词来引导用户进行操作。
            以下是我的历史记录
            ```
            {messages},
            ```
            输出格式：
            1.（引导词1）
            2.（引导词2）
            3.（引导词3）
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

    return res


if __name__ == '__main__':
    # 配置Dashscope API KEY
    dashscope.api_key = api_key
    app.run(debug=True,host='0.0.0.0',port=1223)

