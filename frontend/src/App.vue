<template>
  <div class="hero min-h-screen max-h-full" style="background-image: url(https://cover.sli.dev)">
    <div class="hero-content w-full">
      <div class="card w-auto shadow-2xl bg-base-100 md:w-2/3">
        <div class="card-body p-5">
          <h2 class="card-title">Cyber Secure</h2>
          <div id="chat-panel" class="h-[32rem] max-h-full py-3 overflow-auto">
            <div v-for="msg in messages" :key="msg.id">
              <div :class="msg.user ? 'chat chat-end' : 'chat chat-start'">
                <div class="chat-image avatar">
                  <div class="w-10 rounded-full">
                    <img :src="'https://api.multiavatar.com/' + msg.name + '.png'" />
                  </div>
                </div>
                <div class="chat-bubble">
                  {{ msg.content }}
                  <img v-if="msg.img" :src="msg.img" />
                </div>
              </div>
            </div>
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
            <input type="text" placeholder="提出你的问题..." class="input input-bordered w-full mx-1" v-model="textMessage"
              @keyup.enter="sendMessage" :disabled="!ready" />

            <button class="btn btn-primary" @click="sendMessage" :disabled="!textMessage || !ready">
              <svg class="w-6 h-6" viewBox="0 0 24 24" fill="none">
                <path
                  d="M11.5003 12H5.41872M5.24634 12.7972L4.24158 15.7986C3.69128 17.4424 3.41613 18.2643 3.61359 18.7704C3.78506 19.21 4.15335 19.5432 4.6078 19.6701C5.13111 19.8161 5.92151 19.4604 7.50231 18.7491L17.6367 14.1886C19.1797 13.4942 19.9512 13.1471 20.1896 12.6648C20.3968 12.2458 20.3968 11.7541 20.1896 11.3351C19.9512 10.8529 19.1797 10.5057 17.6367 9.81135L7.48483 5.24303C5.90879 4.53382 5.12078 4.17921 4.59799 4.32468C4.14397 4.45101 3.77572 4.78336 3.60365 5.22209C3.40551 5.72728 3.67772 6.54741 4.22215 8.18767L5.24829 11.2793C5.34179 11.561 5.38855 11.7019 5.407 11.8459C5.42338 11.9738 5.42321 12.1032 5.40651 12.231C5.38768 12.375 5.34057 12.5157 5.24634 12.7972Z"
                  stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </button>
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
</template>

<script>
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
      messages: []
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
      modal.showModal();
    },
    deleteChat: function () {
      this.ready = false;
      fetch('/api/delete_chat', {
        method: 'GET'
      })
        .catch((err) => this.showErr(err))
        .finally(() => this.ready = true);
    },
    sendMessage: function () {
      let msg = this.textMessage.trim();
      if (!msg) return;
      this.textMessage = '';
      this.messages.push({
        user: true,
        name: this.userName,
        content: msg
      });
      this.scrollToBottom();
      this.ready = false;
      fetch('/api/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          'message': msg
        })
      })
        .then(resp => resp.json())
        .then(data => {
          let r = data.response;
          let m = {
            user: false,
            name: this.botName,
            content: r
          }
          if (data.image_url)
            m.img = data.image_url;
          this.messages.push(m);
        })
        .catch((err) => this.showErr(err))
        .finally(() => {
          this.ready = true;
          this.scrollToBottom();
        });
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
    }
  }
}
</script>

<style scoped>
::-webkit-scrollbar {
  display: none;
}
</style>