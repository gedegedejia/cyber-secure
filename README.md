
# 2024年网络技术挑战赛A-ST :sunglasses:

:point_down:
1. 需要在.env中自行更改tshark.exe的路径   
2. 需要在.env中自行更改uploads_path的路径 

将IP地址加入白名单，运行llm_answer.py

## 功能：
- 侧边栏点击文件漏洞分析功能，可以实现文件上传，在聊天框输入'分析文件内容'，模型自动调用工具将文件上传至virtustotal平台，生成对文件的安全性分析报告，报告内容传回大语言模型，并通过检索增强生产（RAG）获得针对该文件的安全性建议<br>

- 侧边栏点击抓包流量分析功能，可以实现自动抓包，对流量进行分析<br>

- 侧边栏点击对话功能，可以实现一些正常对话和网络安全知识的问答<br>

- 侧边栏点击知识库管理，可以实现上传文件到外挂的milvus向量库<br>

# 敬请期待 

2024/7/20修复抓包异步<br>

2024/7/21工具选择正常<br>  

2024/7/23 增加侧边栏工具切换，数据库自动切换<br>

2024/7/24 小改网页UI，修改输出方式为流式输出<br>

2024/7/30 完善知识库管理功能<br>

2024/7/31 添加历史上传文件汇总<br>

2024/8/1 更改上传文件的位置<br>