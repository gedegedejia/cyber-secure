import os
import time
from tqdm import tqdm
import dashscope
from dashscope import TextEmbedding
from pymilvus import connections, FieldSchema, CollectionSchema, DataType, Collection, utility


def prepareData(path, batch_size=25):
    batch_docs = []
    for file in os.listdir(path):
        with open(path + '/' + file, 'r', encoding='utf-8') as f:
            batch_docs.append(f.read())
            if len(batch_docs) == batch_size:
                yield batch_docs
                batch_docs = []

    if batch_docs:
        yield batch_docs


def getEmbedding(news):
    model = TextEmbedding.call(
        model=TextEmbedding.Models.text_embedding_v1,
        input=news
    )
    embeddings = [record['embedding'] for record in model.output['embeddings']]
    return embeddings if isinstance(news, list) else embeddings[0]


if __name__ == '__main__':

    data_path = f'D:/CEC-Corpus/raw corpus/1'  # 数据下载git clone https://github.com/shijiebei2009/CEC-Corpus.git

    # 配置Dashscope API KEY
    dashscope.api_key = 'sk-182776810944437196a71cd5f6e55ea6'

    # 配置Milvus参数
    COLLECTION_NAME = 'ccc'
    DIMENSION = 1536
    MILVUS_HOST = 'c-e920f955ee756dbc.milvus.aliyuncs.com'
    MILVUS_PORT = '19530'
    USER = 'root'
    PASSWORD = '200413Cwj@'

    connections.connect(host=MILVUS_HOST, port=MILVUS_PORT, user=USER, password=PASSWORD)

    # Remove collection if it already exists
    if utility.has_collection(COLLECTION_NAME):
        utility.drop_collection(COLLECTION_NAME)

    # Create collection which includes the id, title, and embedding.
    fields = [
        FieldSchema(name='id', dtype=DataType.INT64, description='Ids', is_primary=True, auto_id=False),
        FieldSchema(name='text', dtype=DataType.VARCHAR, description='Text', max_length=4096),
        FieldSchema(name='embedding', dtype=DataType.FLOAT_VECTOR, description='Embedding vectors', dim=DIMENSION)
    ]
    schema = CollectionSchema(fields=fields, description='CEC Corpus Collection')
    collection = Collection(name=COLLECTION_NAME, schema=schema)

    # Create an index for the collection.
    index_params = {
        'index_type': 'IVF_FLAT',
        'metric_type': 'L2',
        'params': {'nlist': 1024}
    }
    collection.create_index(field_name="embedding", index_params=index_params)

    id = 1
    for news in tqdm(list(prepareData(data_path))):
        ids = [id + i for i, _ in enumerate(news)]
        id += len(news)

        vectors = getEmbedding(news)
        # insert Milvus Collection
        for id, vector, doc in zip(ids, vectors, news):
            insert_doc = (doc[:2000] + '..') if len(doc) > 2002 else doc
            ins = [[id], [insert_doc], [vector]]  # Insert the title id, the text, and the text embedding vector
            collection.insert(ins)
            time.sleep(2)
