from datetime import datetime
import os
import dashscope
from dashscope import Generation
from dotenv import load_dotenv
from pymilvus import connections, FieldSchema, CollectionSchema, DataType, Collection
from embedding import getEmbedding
from http import HTTPStatus
from flask import Flask, request, jsonify, render_template
import packet_capture.draw
import packet_capture.pcapng_analyse
import tool 
import packet_capture
import asyncio
import suggestions 

load_dotenv()
api_key = os.getenv("DASHSCOPE_API_KEY")
url = 'https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation'
headers = {'Content-Type': 'application/json',
           'Authorization': f'Bearer {api_key}'}

uploaded_file_paths = []

messages = [
    {
        "role": "system",
        "content": "你是一个网络安全分析小助手，你的任务是对用户上传的网络安全文件进行分析并解决用户的问题。"
    }
]

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
    asyncio.set_event_loop(asyncio.new_event_loop())
    question = request.json.get('message')
    
    answer = None  # 初始化 answer
    image_url = None  # 初始化 image_url
    file_url = None     # 初始化 file_url
    if not question:
        return jsonify({'error': 'No message provided'}), 400
    else :
        tool_call = tool.tool_jude(question)
        if tool_call == '':
            print("没有调用工具")
        else:
            print("调用的工具是：",tool_call)

        if tool_call == 'get_secure_report':
            context = search(question)
            tool_message = str(tool.get_secure_report(str(uploaded_file_paths[-1])))
            answer = getAnswer(question, context, tool_message, messages,tool_call)
            #多轮对话
            messages.append({
                'role': "user",
                'content': '给出工具调通的结果'
            })    
            messages.append({
                'role': "assistant",
                'content': tool_message
            })
            messages.append({
                "role": "assistant",
                "content": answer
            })
        
        elif tool_call == 'get_wireshark':

            tool.get_wireshark()
            # 生成唯一文件名
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            pcap_dir = 'static/assets/packet_capture'
            if not os.path.exists(pcap_dir):
                os.makedirs(pcap_dir)
            pcapng_file = f'{pcap_dir}/my.pcapng'
            excel_file = f'{pcap_dir}/output.xlsx'
            xlsx_file = f'{pcap_dir}/packet_data_{timestamp}.xlsx'
            packet_capture.pcapng_analyse.pcapng_to_excel(pcapng_file, excel_file)
            packet_capture.pcapng_analyse.pcapng_to_xlsx(pcapng_file, xlsx_file)
            unique_chart_filename = f'协议计数饼图_{timestamp}.png'
            unique_chart_filepath = os.path.join('static', 'assets', 'pictures', unique_chart_filename)
            print("unique_chart_filepath：",unique_chart_filepath)
            
            packet_capture.draw.plot_from_excel(excel_file,unique_chart_filepath)

            # 设置回答和图像 URL
            answer = "抓包操作已执行"
            image_url = f'/assets/pictures/{unique_chart_filename}'
            file_url = xlsx_file.strip('static')

        elif tool_call == 'get_current_time':
            context=''
            tool_message=tool.get_current_time()
            answer=getAnswer(question,context,tool_message,messages,tool_call)
        
        else:
            context = search(question)
            answer = getAnswer(question, context, '', messages,tool_call)
        
        response_message = generate_response(answer)
        if image_url:
            response_message = f'{response_message}\n![图片]({image_url})'
        if file_url:
            response_message = f'{response_message}\n[点击下载文件]({file_url})'
        
        suggestions = suggestions.get_suggestions(question)
        response_message = f'{response_message}\n\n可能的提示词：{suggestions}'
        print(response_message)

        response_data = {'response': response_message}
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
            "content": "我叫cc."
        }
    ]
    return jsonify({'response': 'Chat history deleted successfully'})

def generate_response(message):
    # 在这里实现你的对话逻辑，可以简单地返回一个预设的响应
    # 或者调用更复杂的逻辑/模型来生成响应
    return message

def getAnswer(query, context,tool_message,messages,tool_call):
    if tool_call == 'get_secure_report':
        prompt = f'''请基于```内的网络安全知识，回答我的问题。
            ```
            {context},
            ```
            我的问题是：{query},我通过工具调用得知 {context,tool_message}。请你解释文件标签，给出该文件的意图和文件可疑活动，并根据工具提供的信息给出建议和解决方案
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
        prompt = f'''请基于```内的网络安全知识，回答我的问题。
            ```
            {context},
            ```
            我的问题是：{query},我通过查找库文件得知 {context},通过工具调用得知{tool_call}。
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

def search(text):
    # Search parameters for the index
    search_params = {
        "metric_type": "L2"
    }

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


if __name__ == '__main__':

    # 配置Dashscope API KEY
    dashscope.api_key = api_key

    # 配置Milvus参数
    COLLECTION_NAME = 'ccc'
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

    # Load the collection into memory for searching
    collection.load()
    app.run(debug=True,host='0.0.0.0',port=1223)

