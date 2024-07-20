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

app = Flask(__name__)
app.static_folder = 'static'
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/chat', methods=['POST'])
def chat():
    asyncio.set_event_loop(asyncio.new_event_loop())
    question = request.json.get('message')
    context = search(question)
    answer = None  # 初始化 answer
    image_url = None  # 初始化 image_url
    print(uploaded_file_paths)
    
    if '分析' in question:
        print('11111')
        tool_message = tool.call_with_messages(question + str(context) + str(uploaded_file_paths))
        answer = getAnswer(question, context, tool_message, messages)
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
    elif '抓包' in question:

        tool.get_wireshark()
        pcapng_file = 'packet_capture\\my.pcapng'
        excel_file = 'packet_capture\\output.xlsx'
        
        packet_capture.pcapng_analyse.pcapng_to_excel(pcapng_file, excel_file)
        # 生成唯一文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_chart_filename = f'协议计数饼图_{timestamp}.png'
        unique_chart_filepath = os.path.join('static', 'pictures', unique_chart_filename)
        print("unique_chart_filepath：",unique_chart_filepath)
        
        packet_capture.draw.plot_from_excel(excel_file,unique_chart_filepath)

         # 设置回答和图像 URL
        answer = "抓包操作已执行"
        image_url = f'/static/pictures/{unique_chart_filename}'

    else:
        print('3333')
        messages.append({
            "role": "user",
            "content": question
        })   
        answer = multi_round(question, context, messages)
        messages.append({
            "role": "assistant",
            "content": answer
        })
    
    response_message = generate_response(answer)
    response_data = {'response': response_message}
    if image_url:
        response_data['image_url'] = image_url

    return jsonify(response_data)

@app.route('/upload', methods=['POST'])
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
    return jsonify({'fileName': file.filename, 'filePath': file_path})

    
@app.route('/delete_chat', methods=['POST'])
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

def getAnswer(query, context,tool_message,messages):
    
    prompt = f'''请基于```内的网络安全知识，回答我的问题。
        ```
        {context},
        ```
        我的问题是：{query},我通过工具调用得知 {context,tool_message}。请你解释文件标签，给出该文件的意图和文件可疑活动，并根据工具提供的信息给出建议和解决方案
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

def multi_round(query, context,messages):
    prompt = f'''请基于```内的网络安全知识，回答我的问题。
        ```
        {context},
        ```
        我的问题是：{query}
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
        FieldSchema(name='id', dtype=DataType.INT64, descrition='Ids', is_primary=True, auto_id=False),
        FieldSchema(name='text', dtype=DataType.VARCHAR, description='Text', max_length=4096),
        FieldSchema(name='embedding', dtype=DataType.FLOAT_VECTOR, description='Embedding vectors', dim=DIMENSION)
    ]
    schema = CollectionSchema(fields=fields, description='CEC Corpus Collection')
    collection = Collection(name=COLLECTION_NAME, schema=schema)

    # Load the collection into memory for searching
    collection.load()
    app.run(debug=True,host='0.0.0.0',port=1223)

