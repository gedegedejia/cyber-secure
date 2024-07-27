<template>
  <div class="hero min-h-screen max-h-full" style="background-image: url(https://cover.sli.dev)">
    <div class="flex w-full h-full">
      <!-- 侧边栏 -->
      <div class="sidebar w-1/5 bg-gray-300 p-4 overflow-y-auto" style="opacity: 0.9">
        <h2 class="text-xl font-bold mb-4 text-gray-700">网络安全助手</h2>
        <ul>
          <li class="mb-2">
            <button
              :class="{ 'btn btn-primary w-full mb-4 ': this.selectedButtonNumber === 1, 'btn-primary-500': this.selectedButtonNumber === 1, 'text-black': this.selectedButtonNumber !== 1, 'text-white': this.selectedButtonNumber === 1 }"
              class="btn w-full" @click="this.selectButton(1)">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" :fill="this.selectedButton === 1 ? 'white' : 'black'"
                viewBox="0 0 1024 1024" stroke="currentColor" stroke-width="2">
                <path
                  d="M512 117.76c218.065455 0 395.636364 135.68 395.636364 302.545455s-177.570909 302.545455-395.636364 302.545454a144.058182 144.058182 0 0 0-50.501818 10.472727 791.272727 791.272727 0 0 0-162.909091 99.374546c-4.421818-128.232727-23.272727-168.96-56.087273-191.534546C162.909091 584.145455 116.363636 503.621818 116.363636 420.538182c0-167.098182 177.570909-302.545455 395.636364-302.545455m0-69.818182c-256 0-465.454545 166.632727-465.454545 372.363637 0 110.312727 59.810909 209.454545 155.22909 277.643636 23.272727 16.756364 27.694545 116.363636 27.694546 192.232727a41.192727 41.192727 0 0 0 40.494545 41.89091 40.029091 40.029091 0 0 0 23.272728-8.61091c58.414545-45.149091 141.730909-105.425455 192-124.50909a74.007273 74.007273 0 0 1 26.763636-6.05091c256 0 465.454545-166.865455 465.454545-372.363636s-209.454545-372.363636-465.454545-372.363636z"
                  :fill="this.selectedButtonNumber === 1 ? 'white' : 'black'"></path>
                <path
                  d="M663.272727 325.818182h-302.545454a34.909091 34.909091 0 0 0 0 69.818182h302.545454a34.909091 34.909091 0 0 0 0-69.818182zM616.727273 488.727273h-209.454546a34.909091 34.909091 0 0 0 0 69.818182h209.454546a34.909091 34.909091 0 0 0 0-69.818182z"
                  :fill="this.selectedButtonNumber === 1 ? 'white' : 'black'"></path>
              </svg>
              网安知识问答
            </button>
          </li>

          <li class="mb-2">
            <button
              :class="{ 'btn btn-primary w-full mb-4': this.selectedButtonNumber === 2, 'btn-primary-500': this.selectedButtonNumber === 2, 'text-black': this.selectedButtonNumber !== 2, 'text-white': this.selectedButtonNumber === 2 }"
              class="btn w-full" @click="this.selectButton(2)">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" :fill="this.selectedButtonNumber === 2 ? 'white' : 'black'"
                viewBox="0 0 1024 1024" stroke="currentColor" stroke-width="2">
                <path
                  d="M715.001756 430.579512h-413.596097c-22.078439 0-39.960976-17.882537-39.960976-39.960975s17.882537-39.960976 39.960976-39.960976h413.596097c22.078439 0 39.960976 17.882537 39.960976 39.960976s-17.882537 39.960976-39.960976 39.960975zM715.001756 580.433171h-413.596097c-22.078439 0-39.960976-17.882537-39.960976-39.960976s17.882537-39.960976 39.960976-39.960975h413.596097c22.078439 0 39.960976 17.882537 39.960976 39.960975s-17.882537 39.960976-39.960976 39.960976zM715.001756 730.286829h-413.596097c-22.078439 0-39.960976-17.882537-39.960976-39.960975s17.882537-39.960976 39.960976-39.960976h413.596097c22.078439 0 39.960976 17.882537 39.960976 39.960976s-17.882537 39.960976-39.960976 39.960975zM611.602732 237.767805h-206.798049c-22.078439 0-39.960976-17.882537-39.960976-39.960976s17.882537-39.960976 39.960976-39.960975h206.798049c22.078439 0 39.960976 17.882537 39.960975 39.960975s-17.882537 39.960976-39.960975 39.960976zM700.515902 870.150244h-80.920975c-22.078439 0-39.960976-17.882537-39.960976-39.960976s17.882537-39.960976 39.960976-39.960975h80.920975c22.078439 0 39.960976 17.882537 39.960976 39.960975s-17.882537 39.960976-39.960976 39.960976z"
                  :fill="this.selectedButtonNumber === 2 ? 'white' : 'black'" p-id="4301"></path>
                <path
                  d="M827.891512 79.921951v863.157073h-639.37561V292.214634L400.808585 79.921951h427.082927m19.980488-79.921951H392.516683c-15.884488 0-31.169561 6.293854-42.358634 17.582829L126.076878 241.564098c-11.288976 11.288976-17.582829 26.474146-17.582829 42.358634V963.059512c0 33.067707 26.873756 59.941463 59.941463 59.941464h679.336586c33.067707 0 59.941463-26.873756 59.941463-59.941464V59.941463c0.099902-33.067707-26.773854-59.941463-59.841561-59.941463z"
                  :fill="this.selectedButtonNumber === 2 ? 'white' : 'black'" p-id="4302"></path>
              </svg>
              文件漏洞分析
            </button>
          </li>

          <li class="mb-2">
            <button
              :class="{ 'btn btn-primary w-full mb-4': this.selectedButtonNumber === 3, 'btn-primary-500': this.selectedButtonNumber === 3, 'text-black': this.selectedButtonNumber !== 3, 'text-white': this.selectedButtonNumber === 3 }"
              class="btn w-full" @click="this.selectButton(3)">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24"
                stroke="currentColor" stroke-width="2">
                <polygon points="2 12 2 21 6 21 6 12" />
                <polygon points="18 7 18 21 22 21 22 7" />
                <polygon points="10 3 10 21 14 21 14 3" />
              </svg>
              抓包流量分析
            </button>
          </li>

          <li class="mb-4">
            <button
              :class="{ 'btn btn-primary w-full mb-4': this.selectedButtonNumber === 4, 'btn-primary-500': this.selectedButtonNumber === 4, 'text-black': this.selectedButtonNumber !== 4, 'text-white': this.selectedButtonNumber === 4 }"
              class="btn w-full" @click="this.selectButton(4)">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" :fill="this.selectedButtonNumber === 4 ? 'white' : 'black'"
                viewBox="0 0 1024 1024" stroke="currentColor" stroke-width="2">
                <path
                  d="M959.718832 123.963683C872.444401 50.185297 704.593576 0.299912 511.850044 0.299912S151.255687 50.185297 63.981255 123.963683C23.193205 158.453578 0 198.04198 0 240.22962v543.840672c0 132.461193 229.132871 239.929708 511.850044 239.929708s511.850044-107.468515 511.850044-239.929708v-543.840672c0-42.18764-23.193205-81.776042-63.981256-116.265937zM87.774285 189.64444c19.794201-21.893586 50.685151-43.087377 89.373816-61.182075 42.287611-19.794201 92.073025-35.489603 147.956653-46.586352C384.087474 70.17944 446.869081 64.281168 511.850044 64.281168s127.76257 5.898272 186.745289 17.594845c55.883628 11.096749 105.669042 26.792151 147.956654 46.586352 38.688665 18.094699 69.579615 39.28849 89.373816 61.182075 15.795372 17.494875 23.793029 34.489896 23.793029 50.48521 0 16.095285-7.997657 33.090306-23.793029 50.485209-19.794201 21.893586-50.685151 43.087377-89.373816 61.182075-42.287611 19.894172-92.073025 35.489603-147.956654 46.586352-58.98272 11.696573-121.864298 17.594845-186.745289 17.594845s-127.76257-5.898272-186.74529-17.594845c-55.883628-11.096749-105.669042-26.792151-147.956653-46.586352-38.688665-18.094699-69.579615-39.28849-89.373816-61.182075C71.978912 273.319926 63.981255 256.324905 63.981255 240.22962s7.997657-33.090306 23.79303-50.58518zM63.981255 356.495558c87.274431 73.778385 255.125256 123.66377 447.868789 123.66377s360.594357-49.885385 447.868788-123.66377v155.254515c0 16.095285-7.997657 33.090306-23.793029 50.48521-19.794201 21.893586-50.685151 43.087377-89.373816 61.182075-42.287611 19.794201-92.073025 35.489603-147.956654 46.586352-58.98272 11.696573-121.864298 17.594845-186.745289 17.594845s-127.76257-5.898272-186.74529-17.594845c-55.883628-11.096749-105.669042-26.792151-147.956653-46.586352-38.688665-18.094699-69.579615-39.28849-89.373816-61.182075C71.978912 544.740408 63.981255 527.745387 63.981255 511.750073V356.495558z m895.737577 427.574734c0 16.095285-7.997657 33.090306-23.793029 50.485209-19.794201 21.893586-50.685151 43.087377-89.373816 61.182076-42.287611 19.894172-92.073025 35.489603-147.956654 46.586352-58.98272 11.696573-121.864298 17.594845-186.745289 17.594845s-127.76257-5.898272-186.74529-17.594845c-55.883628-11.096749-105.669042-26.792151-147.956653-46.586352-38.688665-18.094699-69.579615-39.28849-89.373816-61.182076C71.978912 817.160597 63.981255 800.165576 63.981255 784.070292V627.91604c87.274431 73.778385 255.125256 123.66377 447.868789 123.663771s360.594357-49.885385 447.868788-123.663771v156.154252z"
                  p-id="5503" :fill="this.selectedButtonNumber === 4 ? 'white' : 'black'"></path>
                <path
                  d="M167.950796 519.847701m-39.988285 0a39.988285 39.988285 0 1 0 79.976569 0 39.988285 39.988285 0 1 0-79.976569 0Z"
                  p-id="5504" :fill="this.selectedButtonNumber === 4 ? 'white' : 'black'"></path>
                <path
                  d="M167.950796 791.768037m-39.988285 0a39.988285 39.988285 0 1 0 79.976569 0 39.988285 39.988285 0 1 0-79.976569 0Z"
                  p-id="5505" :fill="this.selectedButtonNumber === 4 ? 'white' : 'black'"></path>
              </svg>
              数据库的管理
            </button>
          </li>
        </ul>

        <Text class='mt-8 text-lg font-bold text-center text-gray-700 '>
          知识库配置
        </Text>
      </div>
      <div class="hero-content w-4/5">
        <div class="card w-auto shadow-2xl bg-base-100 md:w-4/5">
          <div class="card-body p-5">
            <div v-if="this.selectedButtonNumber !== 4">
              <h2 class="card-title">Cyber Secure</h2>
              <div id="chat-panel" class="h-[32rem] max-h-full py-3 overflow-auto">
                <div v-for="msg in messages" :key="msg.id">
                  <div :class="msg.user ? 'chat chat-end' : 'chat chat-start'">
                    <div class="chat-image avatar">
                      <div class="w-10 rounded-full">
                        <img :src="'https://api.multiavatar.com/' + msg.name + '.png'" />
                      </div>
                    </div>
                    <div class="chat-bubble" v-html="md2html(msg.content)">
                    </div>
                  </div>
                </div>
              </div>
              <div class="flex justify-between mr-2">
                <button class="btn btn-primary w-1/3 mb-4 " @click="setTextMessage(suggestions[0])">{{
                  suggestions[0]}}</button>
                <button class="btn btn-primary w-1/3 mb-4 ml-2" @click="setTextMessage(suggestions[1])">{{
                  suggestions[1]}}</button>
                <button class="btn btn-primary w-1/3 mb-4 ml-2" @click="setTextMessage(suggestions[2])">{{
                  suggestions[2]}}</button>
              </div>
              <div class="card-actions justify-end flex-nowrap">
                <button class="btn btn-primary btn-circle btn-md" @click="selectUpload" :disabled="!ready">
                  <input type="file" id="file-input" class="hidden" />
                  <svg viewBox="0 0 24 24" fill="none" class="w-5 h-5">
                    <path
                      d="M15 21H9C6.17157 21 4.75736 21 3.87868 20.1213C3 19.2426 3 17.8284 3 15M21 15C21 17.8284 21 19.2426 20.1213 20.1213C19.8215 20.4211 19.4594 20.6186 19 20.7487"
                      stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                    <path d="M12 16V3M12 3L16 7.375M12 3L8 7.375" stroke="currentColor" stroke-width="2"
                      stroke-linecap="round" stroke-linejoin="round" />
                  </svg>
                </button>
                <input type="text" placeholder="提出你的问题..." class="input input-bordered w-full mx-1"
                  v-model="textMessage" @keyup.enter="sendMessage" :disabled="!ready" />

                <button class="btn btn-primary" @click="sendMessage" :disabled="!textMessage || !ready">
                  <svg class="w-6 h-6" viewBox="0 0 24 24" fill="none">
                    <path
                      d="M11.5003 12H5.41872M5.24634 12.7972L4.24158 15.7986C3.69128 17.4424 3.41613 18.2643 3.61359 18.7704C3.78506 19.21 4.15335 19.5432 4.6078 19.6701C5.13111 19.8161 5.92151 19.4604 7.50231 18.7491L17.6367 14.1886C19.1797 13.4942 19.9512 13.1471 20.1896 12.6648C20.3968 12.2458 20.3968 11.7541 20.1896 11.3351C19.9512 10.8529 19.1797 10.5057 17.6367 9.81135L7.48483 5.24303C5.90879 4.53382 5.12078 4.17921 4.59799 4.32468C4.14397 4.45101 3.77572 4.78336 3.60365 5.22209C3.40551 5.72728 3.67772 6.54741 4.22215 8.18767L5.24829 11.2793C5.34179 11.561 5.38855 11.7019 5.407 11.8459C5.42338 11.9738 5.42321 12.1032 5.40651 12.231C5.38768 12.375 5.34057 12.5157 5.24634 12.7972Z"
                      stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
                  </svg>
                </button>
              </div>
            </div>
            
            <div v-if="this.selectedButtonNumber === 4">
              <h2 class="card-title">知识库配置</h2>
              <div class="h-[32rem] max-h-full py-3 overflow-auto">
                <div>
                  <label for="database-select">
                    <Text class='mt-8 text-lg font-bold text-center text-gray-700 '>
                      知识库选择:
                    </Text>
                  </label>
                  <select id="database-select" v-model="selectedDatabase" class="select-box">
                    <option v-for="db in databases" :key="db" :value="db">{{ db }}</option>
                  </select>  

                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <dialog id="modal" class="modal modal-bottom sm:modal-middle">
        <div class="modal-box">
          <h3 class="text-lg font-bold">{{ modal.title }}</h3>
          <p class="py-4">{{ modal.content }}</p>
          <div class="modal-action">
            <form method="dialog">
              <button class="btn">关闭</button>
            </form>
          </div>
        </div>
      </dialog>
    </div>
  </div>
</template>

<script>
import { marked } from "marked";
import { Text } from "vue";

export default {
  setup() {
  },
  data() {
    return {
      ready: true,
      userName: 'User',
      botName: 'CyberSecure',
      textMessage: '',
      modal: {
        title: '',
        content: ''
      },
      messages: [],
      selectedButtonNumber: 1,
      tool: 'chat',
      suggestions: ['向我提问网络安全知识', '侧边栏点击抓包流量分析', '侧边栏点击文件漏洞分析'],
      databases: ['ccc', 'web-leak','cve','cve1']
    }
  },
  mounted() {
    this.deleteChat();
  },
  methods: {
    scrollToBottom: function () {
      setTimeout(() => {
        const chatPanel = document.getElementById('chat-panel');
        chatPanel.scrollTop = chatPanel.scrollHeight;
      }, 0);
    },
    showErr: function (e) {
      this.modal.title = '出错了';
      this.modal.content = e;
      document.getElementById('modal').showModal();
    },
    deleteChat: function () {
      this.ready = false;
      this.messages = []
      fetch('/api/delete_chat', {
        method: 'GET'
      })
        .catch((err) => this.showErr(err))
        .finally(() => this.ready = true);
    },
    setTextMessage(suggestion) {
      this.textMessage = suggestion;
    },
    sendMessage: function () {
      this.ready = false;
      const msg = this.textMessage.trim();

      // 选择请求类型
      if (this.selectedButton === 1) {
        this.tool = 'chat';
      } else if (this.selectedButton === 2) {
        this.tool = 'get_secure_report';
      } else if (this.selectedButton === 3) {
        this.tool = 'get_wireshark';
      }
      if (msg) {
        this.textMessage = '';
        this.messages.push({
          user: true,
          name: this.userName,
          content: msg
        });

        this.initSSE(msg);
      } else {
        return;
      }
    },
    selectButton: function (buttonNumber) {
      this.selectedButtonNumber = buttonNumber;
      console.log(this.selectedButtonNumber)
      this.deleteChat();
    },
    selectUpload: function () {
      let fileInput = document.getElementById('file-input');
      fileInput.click();
      fileInput.onchange = () => {
        if (fileInput.files.length > 0) {
          let f = fileInput.files[0];
          let formData = new FormData();
          formData.append('file', f);
          this.messages.push({
            user: true,
            name: this.userName,
            content: "正在上传文件: " + f.name
          });
          this.ready = false;
          fetch('/api/upload', {
            method: 'POST',
            body: formData
          })
            .then(resp => resp.json())
            .then(data => {
              let n = data.fileName;
              if (n) {
                this.messages.push({
                  user: false,
                  name: this.botName,
                  content: "文件上传成功: " + n
                });
              }
            })
            .catch((err) => this.showErr(err))
            .finally(() => {
              this.ready = true;
              this.scrollToBottom();
            });
        }
      }
    },
    initSSE: function (msg) {
      // 初始化 SSE 连接
      try {
        const eventSource = new EventSource(`/api/sse?message=${encodeURIComponent(msg)}&type=${this.tool}`);
        let fullMessage = '';

        // 处理从服务器接收到的消息
        eventSource.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);

            if (data.done) {
              this.scrollToBottom();
              eventSource.close();
              this.ready = true;
              this.suggestions = data.suggestions
            } else {
              // 累积完整消息
              fullMessage += data.message;
              if (this.messages.length > 0 && !this.messages[this.messages.length - 1].user) {
                this.messages[this.messages.length - 1].content = fullMessage;
              } else {
                this.messages.push({
                  user: false,
                  name: this.botName,
                  content: fullMessage
                });
              }
            }
          } catch (e) {
            console.error('Error parsing JSON:', e);
            this.showErr('数据解析错误');
          }
        };

        // 处理连接错误
        eventSource.onerror = (error) => {
          console.error('SSE error:', error);
          this.showErr('SSE 连接出错');
          eventSource.close();
          this.ready = true;  // 恢复用户操作
        };
      } catch (e) {
        console.error('SSE 初始化错误:', e);
        this.showErr('SSE 初始化错误');
        this.ready = true;  // 恢复用户操作
      }
    },
    md2html: function (md) {
      return marked.parse(md);
    }
  }
}
</script>

<style scoped>
::-webkit-scrollbar {
  display: none;
}
.select-box {
  border: 2px solid #85b3de; /* 边框样式 */
  padding: 5px;
  border-radius: 5px;
  width: 100%;
  box-sizing: border-box;
}

#database-select {
  margin-bottom: 1rem;
}

#file-upload {
  margin-bottom: 1rem;
}

</style>
