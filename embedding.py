import os
import time
from tqdm import tqdm
import dashscope
from dashscope import TextEmbedding
from pymilvus import connections, FieldSchema, CollectionSchema, DataType, Collection, utility
import pandas as pd
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

def prepareData(path, batch_size=25):
    batch_docs = []
    for file in os.listdir(path):
        with open(os.path.join(path, file), 'r', encoding='utf-8') as f:
            batch_docs.append(f.read())
            if len(batch_docs) == batch_size:
                yield batch_docs
                batch_docs = []

    if batch_docs:
        yield batch_docs

def reorder_embeddings(embeddings):
    # Calculate the cosine similarity between all pairs of embeddings
    similarity_matrix = cosine_similarity(embeddings)
    
    # Sum the similarities for each embedding to get a "relevance score"
    relevance_scores = np.sum(similarity_matrix, axis=1)
    
    # Get the indices that would sort the embeddings by their relevance score (descending order)
    sorted_indices = np.argsort(-relevance_scores)
    
    # Reorder the embeddings and corresponding texts
    sorted_embeddings = [embeddings[i] for i in sorted_indices]
    
    return sorted_embeddings

def getEmbedding(texts):
    model = TextEmbedding.call(
        model=TextEmbedding.Models.text_embedding_v1,
        input=texts
    )
    embeddings = [record['embedding'] for record in model.output['embeddings']]
    return embeddings if isinstance(texts, list) else embeddings[0]

def uploadKnowledge(COLLECTION_NAME, data_path):
    dashscope.api_key = os.getenv('DASHSCOPE_API_KEY')

    # 配置Milvus参数
    DIMENSION = 1536
    MILVUS_HOST = 'c-e920f955ee756dbc.milvus.aliyuncs.com'
    MILVUS_PORT = '19530'
    USER = 'root'
    PASSWORD = '200413Cwj@'

    connections.connect(host=MILVUS_HOST, port=MILVUS_PORT, user=USER, password=PASSWORD)

    # 检查集合是否存在
    if not utility.has_collection(COLLECTION_NAME):
        # 创建集合
        fields = [
            FieldSchema(name='id', dtype=DataType.INT64, description='Ids', is_primary=True, auto_id=False),
            FieldSchema(name='question', dtype=DataType.VARCHAR, description='Question', max_length=4096),
            FieldSchema(name='answer', dtype=DataType.VARCHAR, description='Answer', max_length=4096),
            FieldSchema(name='embedding', dtype=DataType.FLOAT_VECTOR, description='Embedding vectors', dim=DIMENSION)
        ]
        schema = CollectionSchema(fields=fields, description='CEC Corpus Collection')
        collection = Collection(name=COLLECTION_NAME, schema=schema)
        
        # 创建索引
        index_params = {
            'index_type': 'IVF_FLAT',
            'metric_type': 'L2',
            'params': {'nlist': 1024}
        }
        collection.create_index(field_name="embedding", index_params=index_params)
    else:
        collection = Collection(name=COLLECTION_NAME)
    
    collection.load()

    # 获取当前集合中的最大ID
    max_id = 0
    results = collection.query(expr="id >= 0", output_fields=['id'])
    if len(results) > 0:
        max_id=len(results)
    
    id = max_id + 1

    # 列出指定目录中的所有文件
    for filename in os.listdir(data_path):
        if filename.endswith('.csv'):
            file_path = os.path.join(data_path, filename)
            data = pd.read_csv(file_path, encoding='utf-8')

            for i, row in data.iterrows():
                question = row['question']
                answer = row['answer']
                
                # 检查数据是否已经存在
                exists_query = f'question == "{question}" and answer == "{answer}"'
                exists = collection.query(expr=exists_query, output_fields=['id'])
                
                if not exists:
                    texts = [question, answer]
                    vectors = getEmbedding(texts)
                    
                    # 重排序嵌入向量
                    sorted_vectors = reorder_embeddings(vectors)
                    
                    # 使用第一个向量作为嵌入向量
                    ins = [[id], [question], [answer], [sorted_vectors[0]]]
                    collection.insert(ins)
                    collection.load()  # 刷新集合数据
                    id += 1
                    time.sleep(2)
                else:
                    print(exists_query, "重复")

if __name__ == '__main__':
    data_path = 'E:\\C4 A-ST\\uploads\\knowledge\\ccc'  # 数据下载git clone https://github.com/shijiebei2009/CEC-Corpus.git
    COLLECTION_NAME = 'ysx'
    uploadKnowledge(COLLECTION_NAME, data_path)
