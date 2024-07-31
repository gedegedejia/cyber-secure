<template>
  <div class="hero min-h-screen max-h-full" style="background-image: url(https://cover.sli.dev)">
    <div class="flex w-full h-full">
      <div class="sidebar fixed top-0 left-0 w-1/5 h-full bg-gray-300 p-4 overflow-y-auto " style="opacity: 0.9; z-index: 10">
        <h2 class="text-xl font-bold mb-4 text-gray-700">网络安全助手</h2>
        <ul>
          <li class="mb-2">
            <button
              :class="{ 'btn btn-primary w-full mb-4 ': this.selectedButtonNumber === 1, 'btn-primary-500': this.selectedButtonNumber === 1, 'text-black': this.selectedButtonNumber !== 1, 'text-white': this.selectedButtonNumber === 1 }"
              class="btn w-full" @click="this.selectButton(1)">
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5"
                :fill="this.selectedButton === 1 ? 'white' : 'black'" viewBox="0 0 1024 1024" stroke="currentColor"
                stroke-width="2">
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
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5"
                :fill="this.selectedButtonNumber === 2 ? 'white' : 'black'" viewBox="0 0 1024 1024"
                stroke="currentColor" stroke-width="2">
                <path
                  d="M715.001756 430.579512h-413.596097c-22.078439 0-39.960976-17.882537-39.960976-39.960975s17.882537-39.960976 39.960976-39.960976h413.596097c22.078439 0 39.960976 17.882537 39.960976 39.960976s-17.882537 39.960976-39.960976 39.960975zM715.001756 580.433171h-413.596097c-22.078439 0-39.960976-17.882537-39.960976-39.960976s17.882537-39.960976 39.960976-39.960975h413.596097c22.078439 0 39.960976 17.882537 39.960976 39.960975s-17.882537 39.960976-39.960976 39.960976zM715.001756 730.286829h-413.596097c-22.078439 0-39.960976-17.882537-39.960976-39.960975s17.882537-39.960976 39.960976-39.960976h413.596097c22.078439 0 39.960976 17.882537 39.960976 39.960976s-17.882537 39.960976-39.960976 39.960975zM611.602732 237.767805h-206.798049c-22.078439 0-39.960976-17.882537-39.960976-39.960976s17.882537-39.960976 39.960976-39.960975h206.798049c22.078439 0 39.960976 17.882537 39.960975 39.960975s-17.882537 39.960976-39.960975 39.960976zM700.515902 870.150244h-80.920975c-22.078439 0-39.960976-17.882537-39.960976-39.960976s17.882537-39.960976 39.960976-39.960975h80.920975c22.078439 0 39.960976 17.882537 39.960976 39.960975s-17.882537 39.960976-39.960976 39.960976z"
                  :fill="this.selectedButtonNumber === 2 ? 'white' : 'black'" p-id="4301"></path>
                <path
                  d="M827.891512 79.921951v863.157073h-639.37561V292.214634L400.808585 79.921951h427.082927m19.980488-79.921951H392.516683c-15.884488 0-31.169561 6.293854-42.358634 17.582829L126.076878 241.564098c-11.288976 11.288976-17.582829 26.474146-17.582829 42.358634V963.059512c0 33.067707 26.873756 59.941463 59.941463 59.941464h679.336586c33.067707 0 59.941463-26.873756 59.941463-59.941464V59.941463c0.099902-33.067707-26.773854-59.941463-59.841561-59.941463z"
                  :fill="this.selectedButtonNumber === 2 ? 'white' : 'black'" p-id="4302"></path>
              </svg>
              文件漏洞分析
            </button>
            <div v-if="this.selectedButtonNumber === 2 ||  this.selectedButtonNumber === 5" class="flex items-center mt-2">
              <svg t="1722429322042" class="icon" viewBox="0 0 1024 1024" version="1.1"
                xmlns="http://www.w3.org/2000/svg" p-id="6932" width="24" height="24">
                <path
                  d="M377.018182 802.909091c-6.981818 0-11.636364-2.327273-16.290909-6.981818-9.309091-9.309091-9.309091-23.272727 0-32.581818L612.072727 512 360.727273 260.654545c-9.309091-9.309091-9.309091-23.272727 0-32.581818s23.272727-9.309091 32.581818 0l267.636364 267.636364c9.309091 9.309091 9.309091 23.272727 0 32.581818L395.636364 795.927273c-4.654545 4.654545-11.636364 6.981818-18.618182 6.981818z"
                  p-id="6933" fill="#707070"></path>
              </svg>
              <div class="flex items-center">
                <button 
                :class="{ 'btn btn-primary w-full mb-4': this.selectedButtonNumber === 5, 'btn-primary-500': this.selectedButtonNumber === 5, 'text-black': this.selectedButtonNumber !== 5, 'text-white': this.selectedButtonNumber === 5 }"
                class="btn " @click="this.selectButton(5);getFileHistory()">
                历史文件漏洞分析
                </button>
              </div>
            </div>
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
              <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5"
                :fill="this.selectedButtonNumber === 4 ? 'white' : 'black'" viewBox="0 0 1024 1024"
                stroke="currentColor" stroke-width="2">
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

        <div class="flex items-center justify-between mr-2">
          <text class='text-lg font-bold text-gray-700 '>历史对话</text>
          <div class="card-actions tooltip lg:tooltip tooltip-left" data-tip="新聊天">
            <button @click="createNewConversation">
              <svg t="1722247665926" class="icon " viewBox="0 0 1024 1024" version="1.1"
                xmlns="http://www.w3.org/2000/svg" p-id="4349" width="20" height="20">
                <path
                  d="M696.1152 0C908.6976 0 1024 115.3024 1024 327.8848v368.2304C1024 908.6976 908.6976 1024 696.1152 1024H97.792A98.048 98.048 0 0 1 0 926.208V327.8848C0 115.3024 115.3024 0 327.8848 0h368.2304z m0 103.5264H327.8848c-155.4432 0-224.3584 68.9152-224.3584 224.3584v592.4864h592.5888c150.272 0 219.648-64.256 224.0512-208.9984l0.3072-15.2576V327.8848c0-155.4432-68.9152-224.3584-224.3584-224.3584zM512 299.1616c28.5696 0 51.7632 23.1936 51.7632 51.8144v109.1584l109.2608 0.1024a51.7632 51.7632 0 1 1 0 103.5264h-109.2608l0.1024 109.2608a51.7632 51.7632 0 1 1-103.5776 0v-109.2608l-109.2608 0.1024a51.7632 51.7632 0 1 1 0-103.5776h109.2096l0.0512-109.2608c0-28.6208 23.1936-51.7632 51.7632-51.7632L512 299.1616z"
                  p-id="4350" fill="#374151"></path>
              </svg>
            </button>
          </div>
        </div>

        <div class="mt-2">
          <ul id="history-list" 
              :class="{'bg-white': chatHistory.length >= 1, 'bg-transparent': chatHistory.length === 0}" 
              class="menu rounded-box w-full">
            <li v-for="(chat, index) in chatHistory" :key="index" @click="loadChat(index)">
              <div class="flex items-center justify-between mr-2">
                <a class="text-base font-bold text-gray-700">Chat {{ index + 1 }}</a>
                <button @click="deleteChat(index)">
                  <svg t="1722251570726" class="icon" viewBox="0 0 1024 1024" version="1.1" xmlns="http://www.w3.org/2000/svg" p-id="5947" width="20" height="20">
                    <path 
                      d="M799.2 874.4c0 34.4-28.001 62.4-62.4 62.4H287.2c-34.4 0-62.4-28-62.4-62.4V212h574.4v662.4zM349.6 100c0-7.2 5.6-12.8 12.8-12.8h300c7.2 0 12.8 5.6 12.8 12.8v37.6H349.6V100z m636.8 37.6H749.6V100c0-48.001-39.2-87.2-87.2-87.2h-300c-48 0-87.2 39.199-87.2 87.2v37.6H37.6C16.8 137.6 0 154.4 0 175.2s16.8 37.6 37.6 37.6h112v661.6c0 76 61.6 137.6 137.6 137.6h449.6c76 0 137.6-61.6 137.6-137.6V212h112c20.8 0 37.6-16.8 37.6-37.6s-16.8-36.8-37.6-36.8zM512 824c20.8 0 37.6-16.8 37.6-37.6v-400c0-20.8-16.8-37.6-37.6-37.6s-37.6 16.8-37.6 37.6v400c0 20.8 16.8 37.6 37.6 37.6m-175.2 0c20.8 0 37.6-16.8 37.6-37.6v-400c0-20.8-16.8-37.6-37.6-37.6s-37.6 16.8-37.6 37.6v400c0.8 20.8 17.6 37.6 37.6 37.6m350.4 0c20.8 0 37.6-16.8 37.6-37.6v-400c0-20.8-16.8-37.6-37.6-37.6s-37.6 16.8-37.6 37.6v400c0 20.8 16.8 37.6 37.6 37.6"
                      fill="#374151" p-id="5948">
                    </path>
                  </svg>

                </button>
              </div>
              <div class="divider -my-1 w-full" style="pointer-events: none;"></div>
            </li>
          </ul>
        </div>
        
      </div>
      <div class="hero-content w-4/5 overflow-hidden" style="margin-left: 20%;">
        <div class="card w-auto shadow-2xl bg-base-100 md:w-4/5">
          <div class="card-body p-5">
            <div v-if="selectedButtonNumber !== 4 && selectedButtonNumber !== 5">
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
                  suggestions[0] }}</button>
                <button class="btn btn-primary w-1/3 mb-4 ml-2" @click="setTextMessage(suggestions[1])">{{
                  suggestions[1] }}</button>
                <button class="btn btn-primary w-1/3 mb-4 ml-2" @click="setTextMessage(suggestions[2])">{{
                  suggestions[2] }}</button>
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
                <div class="drawer drawer-end justify-end w-1/5">
                  <input id="my-drawer-4" type="checkbox" class="drawer-toggle" />
                  <div class="drawer-content">
                    <!-- Page content here -->
                    <label for="my-drawer-4" class="drawer-button btn btn-primary">提示词模板</label>
                  </div>
                  <div class="drawer-side">
                    <label for="my-drawer-4" aria-label="close sidebar" class="drawer-overlay"></label>
                    <ul class="menu bg-base-200 text-base-content min-h-full w-80 p-4">
                      <!-- Sidebar content here -->
                      <h2 class="card-title justify-center my-2 text-primary">提示词模板中心</h2>
                      <li v-for="db in instructions" :key="db">
                        <a @click="setTextMessage(db)" class="my-1 primary-content text-base ">
                          {{ truncateText(db, 15) }}
                        </a>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>

            <div v-if="this.selectedButtonNumber === 4">
              <h2 class="card-title">知识库配置</h2>

              <div class="h-[32rem] max-h-full py-3 overflow-auto">
                <div class="mx-2 my-2 align">
                  <a aria-hidden="true" tabindex="-1" href="#heading-1">
                    <span
                      class="opacity-20 hover:opacity-60 text-base font-bold inline-block align-middle relative -mt-1">
                      #
                    </span>
                    <text class="font-bold ml-1">知识库选择</text>
                  </a>


                  <div class="dropdown ml-7 my-2">
                    <div tabindex="0" role="button" class="btn m-1" @click="toggleDropdown">
                      {{ selectedDatabase || '点击选择知识库' }}
                    </div>
                    <ul v-show="dropdownVisible" tabindex="0"
                      class="dropdown-content menu bg-base-100 rounded-box z-[1] w-52 p-2 shadow">
                      <li v-for="db in databases" :key="db">
                        <a @click="selectDatabase(db)">{{ db }}</a>
                      </li>
                    </ul>
                  </div>
                </div>

                <div class="mx-2 flex align ">
                  <div class="flex justify-start items-center">
                    <a aria-hidden="true" tabindex="-1" href="#heading-1" class="flex items-center">
                      <span
                        class="opacity-20 hover:opacity-60 text-base font-bold inline-block align-middle relative -mt-1">
                        #
                      </span>
                      <span class="font-bold ml-1 w-auto whitespace-nowrap">文件选择</span>
                    </a>
                  </div>

                  <div class="justify-between ml-12">
                    <input type="file" class="file-input file-input-bordered file-input-primary" id="fileInput"/>
                  </div>
                  <div class="flex items-center justify-end w-full">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"
                      class="h-5 w-5 shrink-0 text-gray-500 stroke-current">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <span class="mr-2 text-med text-gray-500 font-bold">文件上传仅支持格式为txt的文件</span>
                  </div>
                </div>


                <div class="mx-2 my-4">
                  <h2 class="card-title my-4">知识库简介</h2>
                  <textarea class="textarea textarea-primary w-full my-2" placeholder="请输入知识库简介"></textarea>
                </div>

                <div class="mx-2">
                  <h2 class="card-title my-4">用户对知识库{{ selectedDatabase }}上传的文件</h2>
                  <div class="overflow-x-auto">
                    <table class="table table-zebra">
                      <thead>
                        <tr>
                          <th>序号</th>
                          <th>文件名称</th>
                          <th>分词器</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr v-for="(file, index) in files[selectedDatabase]" :key="index">
                          <th>{{ index + 1 }}</th>
                          <td>{{ file }}</td>
                          <td>text_embedding_v1</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
                <div>
                  <div class="flex flex-col items-center justify-center h-full mx-8">
                    <progress v-if="isUploading" class="progress w-full"></progress>
                  </div>
                  <div class="card-actions card-body items-center text-center">
                    <button class="btn btn-outline btn-primary w-full" @click="handleUpload(selectedDatabase)">确认上传</button>
                  </div>
                </div>
              </div>
            </div>

            <div v-if="this.selectedButtonNumber === 5">
              <h2 class="card-title">历史上传文件</h2>
              
              <div class="overflow-x-auto">
                <table class="table table-zebra">
                  <!-- 表头 -->
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>文件名称</th>
                      <th>文件类型</th>
                      <th>提交时间</th>
                      <th>反病毒引擎检出</th>
                      <th>判定</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="(item, index) in fileHistory" :key="index">
                      <th>{{ index + 1 }}</th>
                      <td>{{ item.文件名称 }}</td>
                      <td>{{ item.文件类型 }}</td>
                      <td>{{ item.提交时间 }}</td>
                      <td>{{ item.反病毒引擎检出 }}</td>
                      <td :style="{ color: item.判定 === '安全' ? 'green' : 'red',fontWeight: 'bold' }">{{ item.判定 }}</td>
                    </tr>
                  </tbody>
                </table>
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
      chatHistory: [], // 存储所有聊天记录
      currentChatIndex: 0, // 当前加载的聊天记录索引
      messages: [],
      selectedButtonNumber: 1,
      tool: 'chat',
      suggestions: ['向我提问网络安全知识', '侧边栏点击抓包流量分析', '侧边栏点击文件漏洞分析'],
      databases: ['ccc', 'web_leak', 'cve'],
      selectedDatabase: null,
      dropdownVisible: false,
      files: {
        'ccc':[],
        'web_leak':[],
        'cve':[]
      },
      instructions: [
        '作为网络安全专家，在公司最近经历了一次数据泄露事件的背景下，为了增强公司整体的网络安全防护能力，你如何制定一套全面的网络安全策略？',
        '你作为企业的网络安全顾问，面对公司网络基础设施近期频繁遭受DDoS攻击的情况，为了增强网络的抗攻击能力，你会推荐并实施哪些具体的防御措施？',
        '作为信息技术主管，在公司最近发生了一次严重的恶意软件感染事件之后，为了提高系统的防御和响应能力，你会如何改进现有的端点检测与响应（EDR）系统？',
        '你作为公司网络安全团队的领导，鉴于最近发现多个员工账户被未授权访问的事件，为了加强账户和权限管理，你会如何优化和实施多因素认证（MFA）系统？',
        '作为企业的IT安全经理，在公司最近的安全审计中发现了一些高风险的安全漏洞之后，为了确保这些漏洞得到及时修复并避免未来的风险，你会如何制定和实施漏洞管理流程？'
        // 根据需要添加更多指令
      ],
      isUploading: false,
      fileHistory: [],
      isUploading: false
    }
  },
  mounted() {
    this.loadChatHistoryFromLocalStorage();

    // 如果 chatHistory 为空，则创建一个默认的聊天记录
    if (this.chatHistory.length === 0) {
      this.createNewConversation();
      this.loadChat(0);
    }
  },
  methods: {
    async getFileHistory() {
      console.log('getFileHistory called');
      try {
        const response = await fetch('/api/uploadFileHistory', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          }
        });
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        const data = await response.json();
        this.fileHistory = data;
        console.log('File history fetched:', this.fileHistory);
      } catch (error) {
        console.error('Error fetching file history:', error);
      }
    },
    handleUpload(selectedDatabase) {
      this.isUploading = true; // 显示进度条
      this.addKnowledge(selectedDatabase)
      .finally(() => {
        this.isUploading = false; // 隐藏进度条
      });
    },
    handleUpload(selectedDatabase) {
      this.isUploading = true; // 显示进度条
      this.addKnowledge(selectedDatabase)
      .finally(() => {
        this.isUploading = false; // 隐藏进度条
      });
    },
    truncateText(text, length) {
      if (text.length > length) {
        return text.substring(0, length) + '...';
      }
      return text;
    },
    toggleDropdown() {
      this.dropdownVisible = !this.dropdownVisible;
    },
    selectDatabase(db) {
      this.selectedDatabase = db;
      this.dropdownVisible = false;
      console.log(db)
    },
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
    deleteChat: function (index) {
      this.ready = false;

      // 从 chatHistory 数组中删除指定索引的聊天记录
      this.chatHistory.splice(index, 1);

      // 如果当前显示的聊天记录索引大于或等于被删除的聊天记录索引，则递减当前显示的聊天记录索引
      if (this.currentChatIndex >= index) {
        this.currentChatIndex--;
      }

      // 如果当前显示的聊天记录索引超出了剩余聊天记录的范围，则设置为最后一个聊天记录的索引
      if (this.currentChatIndex >= this.chatHistory.length) {
        this.currentChatIndex = this.chatHistory.length - 1;
      }

      // 清空当前显示的聊天记录
      this.messages = [];
      this.saveChatHistoryToLocalStorage();
      this.ready = true;  // 设置 ready 为 true 表示操作完成
    },
    setTextMessage(suggestion) {
      this.textMessage = suggestion;
    },
    saveChatHistoryToLocalStorage: function () {
      localStorage.setItem('chatHistory', JSON.stringify(this.chatHistory));
    },
    loadChatHistoryFromLocalStorage: function () {
      const storedChatHistory = localStorage.getItem('chatHistory');
      if (storedChatHistory) {
        this.chatHistory = JSON.parse(storedChatHistory);
        if (this.chatHistory.length > 0) {
          this.loadChat(0); // 加载第一个聊天记录
        }
      }
    },
    sendMessage: function () {
      this.ready = false;
      const msg = this.textMessage.trim();

      // 选择请求类型
      if (this.selectedButtonNumber === 1) {
        this.tool = 'chat';
      } else if (this.selectedButtonNumber === 2) {
        this.tool = 'get_secure_report';
      } else if (this.selectedButtonNumber === 3) {
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
      this.sendMessagesToBackend();
    },
    selectButton: function (buttonNumber) {
      this.selectedButtonNumber = buttonNumber;
      console.log(this.selectedButtonNumber)
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
    },
    loadChat(index) {
      console.log(index)
      this.currentChatIndex = index;
      this.messages = this.chatHistory[index];
      console.log(this.chatHistory[index][0])
      this.sendMessagesToBackend();
    },
    async sendMessagesToBackend() {
      try {
        const response = await fetch('/api/update-chat', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ messages: this.messages }),
        });

        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const result = await response.json();
        console.log(result);
      } catch (error) {
        console.error('Error sending messages:', error);
      }
    },
    createNewConversation: function () {
      this.saveChatHistoryToLocalStorage();
      // 清空当前聊天记录
      this.messages = [];

      // 如果 chatHistory 为空，创建第一个聊天记录
      if (this.chatHistory.length === 0) {
        this.chatHistory.push(this.messages.slice());
        this.currentChatIndex = 0;
      } else {
        // 如果 chatHistory 不为空，则在列表末尾添加新聊天记录
        this.currentChatIndex = this.chatHistory.length;
        this.chatHistory.push(this.messages.slice());
      }

      // 保存当前聊天记录到 localStorage
      this.saveChatHistoryToLocalStorage();

      this.loadChat(this.currentChatIndex); // 加载新创建的聊天记录
    },
    // 保存当前聊天记录到 localStorage
    saveCurrentChat: function () {
      this.chatHistory.push(this.messages.slice());
      this.loadChat(this.chatHistory.length - 1); // 加载最新保存的聊天记录
    },
    // 设置预设消息
    setTextMessage(message) {
      this.textMessage = message;
    },
    addKnowledge(KnowledgeName) {
      const fileInput = document.getElementById('fileInput');
      if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const formData = new FormData();
        
        formData.append('file', file);
        formData.append('KnowledgeName', KnowledgeName);
        
        return fetch('/api/uploadKnowledge', {
          method: 'POST',
          body: formData
        })
        .then(response => {
          if (!response.ok) {
            throw new Error('Network response was not ok');
          }
          return response.json(); // 假设服务器返回 JSON
        })
        .then(data => {
          // 处理服务器返回的数据
          this.files[KnowledgeName].push(file.name);
          console.log(this.files[KnowledgeName]);
        });
      } else {
        return Promise.reject(new Error('No file selected'));
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