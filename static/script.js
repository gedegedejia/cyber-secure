document.getElementById("send-btn").addEventListener("click", sendMessage);
document.getElementById("user-input").addEventListener("keypress", function(event) {
  if (event.key === "Enter") {
    sendMessage();
  }
});

document.getElementById("new-chat-btn").addEventListener("click", newChat);
document.getElementById("upload-btn").addEventListener("click", () => {
  document.getElementById("file-input").click();
});

document.getElementById("file-input").addEventListener("change", uploadFile);

let chatHistory = JSON.parse(localStorage.getItem('chatHistory')) || [];
let currentChatIndex = chatHistory.length > 0 ? chatHistory.length - 1 : -1;

function newChat() {
  chatHistory.push([]);
  currentChatIndex = chatHistory.length - 1;
  updateChatBox();
  updateHistoryList();
}

function sendMessage() {
  const userInput = document.getElementById("user-input").value;
  if (userInput.trim() !== "") {
    appendMessage("user", userInput);
    document.getElementById("user-input").value = "";

    fetch("/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message: userInput })
    })
    .then(response => response.json())
    .then(data => {
      let responseMessage = data.response || '无响应';
      if (data.image_url) {
        // 包含图片URL
        responseMessage += `<br><img src="${data.image_url}" alt="图像" style="max-width: 100%;">`;
      }
      appendMessage("bot", responseMessage);
      saveCurrentChat();
    })
    .catch(error => {
      console.error("Error:", error);
      appendMessage("bot", "失败，请重试");
      saveCurrentChat();
    });
  }
}

function appendMessage(sender, message) {
  if (currentChatIndex === -1) {
    newChat();
  }
  chatHistory[currentChatIndex].push({ sender, message });
  updateChatBox();
}

function updateChatBox() {
  const chatBox = document.getElementById("chat-box");
  chatBox.innerHTML = "";
  if (currentChatIndex !== -1) {
    chatHistory[currentChatIndex].forEach(msg => {
      const messageDiv = document.createElement("div");
      messageDiv.classList.add("message", msg.sender);
      messageDiv.innerHTML = msg.message; // 允许HTML内容
      chatBox.appendChild(messageDiv);
    });
    chatBox.scrollTop = chatBox.scrollHeight;
  }
}

function saveCurrentChat() {
  localStorage.setItem('chatHistory', JSON.stringify(chatHistory));
  updateHistoryList();
}

function updateHistoryList() {
  const historyList = document.getElementById("history-list");
  historyList.innerHTML = "";
  chatHistory.forEach((chat, index) => {
    const listItem = document.createElement('li');
    listItem.textContent = `Chat ${index + 1}`;

    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = '删除';
    deleteBtn.addEventListener('click', (event) => {
      event.stopPropagation(); // 阻止事件冒泡，以防加载聊天记录
      deleteChat(index);
    });
    
    listItem.addEventListener('click', () => loadChat(index));
    listItem.appendChild(deleteBtn);
    historyList.appendChild(listItem);
  });
}

function loadChat(index) {
  currentChatIndex = index;
  updateChatBox();
}

function deleteChat(index) {
  chatHistory.splice(index, 1);
  currentChatIndex = chatHistory.length > 0 ? 0 : -1; // 更新当前聊天索引
  saveCurrentChat();
  updateChatBox();
}

function uploadFile(event) {
  const file = event.target.files[0];
  if (file) {
    const formData = new FormData();
    formData.append('file', file);

    fetch("/upload", {
      method: "POST",
      body: formData
    })
    .then(response => response.json())
    .then(data => {
      appendMessage("bot", `成功上传: ${data.fileName}`);
      saveCurrentChat();
    })
    .catch(error => {
      console.error("Error:", error);
      appendMessage("bot", "上传文件时发生错误。");
      saveCurrentChat();
    });
  }
}
