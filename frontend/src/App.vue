<template>
  <div class="hero min-h-screen max-h-full" style="background-image: url(https://cover.sli.dev)">
    <div class="flex w-full h-full">
      <div class="sidebar fixed top-0 left-0 w-1/5 h-full glass p-4 overflow-y-auto " style="opacity: 0.9; z-index: 10">

        <div class="flex justify-between items-center mb-4">
          <div>
            <h2 class="text-xl font-bold text-gray-900">网络安全助手</h2>
          </div>
          <div>
            <button class="btn glass text-gray-800" onclick="my_modal_2.showModal()">
              <svg t="1722842797261" class="icon" viewBox="0 0 1024 1024" version="1.1"
                xmlns="http://www.w3.org/2000/svg" p-id="4321" width="24" height="24">
                <path
                  d="M510.37806 337.803609c-98.010221 0-177.748287 78.842673-177.748287 175.75284 0 96.91426 79.738066 175.763073 177.748287 175.763073 9.537214 0 19.620873-0.978281 31.797194-3.088338 18.196431-3.281743 30.290887-20.538779 26.963095-38.471197-2.924609-15.732309-16.693194-27.152407-32.747845-27.152407-2.071172 0-4.15974 0.196475-6.123464 0.563842-7.937786 1.402953-14.233166 2.056845-19.807115 2.056845-61.159942 0-110.915136-49.201585-110.915136-109.671819 0-60.467163 49.679469-109.661585 110.747313-109.661585 61.116963 0 110.832248 49.194422 110.832248 109.661585 0 5.892197-0.656963 12.0832-2.088568 19.531845-3.327792 17.928325 8.769734 35.189454 26.959002 38.464033 2.006703 0.360204 4.045129 0.546446 6.070252 0.546446 16.204054 0 30.019711-11.43033 32.832779-27.116591 2.13871-11.45182 3.13848-21.435195 3.13848-31.41857 0.042979-46.873564-18.435884-90.990341-52.033074-124.223233C602.407056 356.106464 557.790906 337.803609 510.37806 337.803609z"
                  fill="#000000" p-id="4322"></path>
                <path
                  d="M938.476161 432.79917c-2.185782-11.426237-11.037381-20.499893-22.563902-23.12058-41.909505-9.508561-76.781734-34.929534-98.185206-71.550593-21.334911-36.560684-26.191522-79.099523-13.68979-119.709429 3.52836-11.123338 0.007163-23.235191-8.951883-30.840402-41.860387-35.721573-89.536222-62.938448-141.695163-80.885192-3.152806-1.088798-6.437619-1.639337-9.776667-1.639337-8.256034 0-16.182564 3.431146-21.724791 9.376555-29.236881 31.04404-68.840878 48.140417-111.5107 48.140417-42.673915 0-82.305541-17.125029-111.607914-48.230468-7.877411-8.333806-20.510126-11.512195-31.580253-7.726985-52.483328 18.171871-100.131535 45.416376-141.640927 80.988546-8.815783 7.591909-12.322653 19.620873-8.934486 30.67258 12.586666 40.645722 7.759731 83.180468-13.597693 119.78106-21.306258 36.5965-56.149834 62.006216-98.17395 71.561849-11.540847 2.709715-20.396539 11.812023-22.559808 23.166629-5.228071 27.169803-7.877411 54.346769-7.877411 80.770582 0 26.426883 2.64934 53.603849 7.873318 80.763418 2.174526 11.411911 11.023054 20.488637 22.552645 23.12058 41.913599 9.512654 76.785827 34.922371 98.19237 71.547523 21.349237 36.59343 26.177196 79.128175 13.583366 119.795387-3.363607 10.969842 0.121773 23.013133 8.973372 30.758538 41.84913 35.707246 89.494267 62.920028 141.662417 80.902588 11.466146 3.885494 23.738657 0.549515 31.454386-7.680936 29.29828-31.091112 68.925812-48.216141 111.593588-48.216141s82.302471 17.125029 111.560842 48.183396c5.556553 5.955642 13.494339 9.380648 21.782096 9.380648 3.27765 0 6.537903-0.520863 9.829879-1.599428 52.126194-17.968234 99.774401-45.184085 141.652184-80.912821 8.791224-7.577582 12.308327-19.628036 8.94165-30.758538-12.597923-40.678468-7.745405-83.20605 13.672394-119.773897 21.324678-36.625152 56.192813-62.030775 98.19237-71.547523 11.390421-2.592035 20.23588-11.633968 22.549575-23.106254 5.223978-27.184129 7.870248-54.358025 7.870248-80.770582C946.342316 487.171522 943.697069 459.965903 938.476161 432.79917zM728.572524 789.878798c-26.02677 20.157085-54.736649 36.553521-85.487 48.818869-36.682457-32.144094-83.60207-49.779753-132.792399-49.779753-48.926316 0-95.838765 17.635659-132.767839 49.786916-30.744211-12.262278-59.45716-28.655643-85.491093-48.812729 9.894348-47.441499 1.889023-96.449679-22.763446-138.627291-24.448832-41.966811-63.427588-73.339332-110.186542-88.840374-2.381234-16.343223-3.584642-32.758078-3.584642-48.869011 0-16.043395 1.203408-32.451086 3.584642-48.851615 46.612621-15.389502 85.584214-46.758953 110.186542-88.850607 24.523533-42.024116 32.525788-91.033319 22.74912-138.620128 26.0237-20.149922 54.735625-36.543288 85.494163-48.815799 36.821627 32.201399 83.73817 49.861618 132.778072 49.861618 49.194422 0 96.109941-17.635659 132.792399-49.779753 30.751375 12.269441 59.45716 28.662807 85.48086 48.812729-9.809413 47.63388-1.835811 96.634898 22.667256 138.620128 24.445762 41.966811 63.416332 73.343425 110.182448 88.850607 2.381234 16.386202 3.584642 32.801057 3.584642 48.940642 0.143263 15.443737-1.031493 31.797194-3.499707 48.701189-46.763047 15.504112-85.73771 46.873564-110.186542 88.836281C726.84416 693.189665 718.845998 742.190683 728.572524 789.878798z"
                  fill="#000000" p-id="4323"></path>
              </svg>
              设置
            </button>
          </div>
          <dialog id="my_modal_2" class="modal">
            <div class="modal-box">
              <h3 class="text-lg font-bold">修改配置</h3>
              <p class="py-4 text-base font-bold">tshark路径：{{ tshark_path }}</p>
              <input type="text" v-model="newTsharkPath" placeholder="请输入您的tshark路径"
                class="input input-bordered input-primary w-full" />
              <div class="grid place-items-end">
                <button class="btn btn-primary mt-4" @click="setPath(newTsharkPath)">确定</button>
              </div>
            </div>
            <form method="dialog" class="modal-backdrop">
              <button>close</button>
            </form>
          </dialog>
        </div>

        <ul>
          <li class="mb-2">
            <button
              :class="{ 'btn btn-primary w-full': this.selectedButtonNumber === 1, 'btn-primary-500': this.selectedButtonNumber === 1, 'text-black': this.selectedButtonNumber !== 1, 'text-white': this.selectedButtonNumber === 1 }"
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
              :class="{ 'btn btn-primary w-full': this.selectedButtonNumber === 2, 'btn-primary-500': this.selectedButtonNumber === 2, 'text-black': this.selectedButtonNumber !== 2, 'text-white': this.selectedButtonNumber === 2 }"
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
            <div v-if="this.selectedButtonNumber === 2 || this.selectedButtonNumber === 5" class="flex items-center">
              <div class="flex items-center mt-2">
                <svg t="1722501183923" class="icon" viewBox="0 0 1024 1024" version="1.1"
                  xmlns="http://www.w3.org/2000/svg" p-id="2642" width="24" height="24">
                  <path
                    d="M477.8 816.4l304.1-304.6-303.8-303.2c-18.5-18.5-18.5-48.5 0-67.1 18.5-18.6 48.6-18.6 67.1-0.1l337.3 336.7c18.5 18.5 18.5 48.5 0 67.1L544.9 883.4c-18.5 18.6-48.6 18.6-67.1 0.1-18.5-18.5-18.5-48.5 0-67.1z"
                    fill="#515151" p-id="2643"></path>
                </svg>
              </div>
              <div class="flex items-center mt-2 ml-4">
                <button
                  :class="{ 'btn btn-primary w-full': this.selectedButtonNumber === 5, 'btn-primary-500': this.selectedButtonNumber === 5, 'text-black': this.selectedButtonNumber !== 5, 'text-white': this.selectedButtonNumber === 5 }"
                  class="btn" @click="this.selectButton(5); getFileHistory('get_secure_report')">
                  历史文件漏洞分析
                </button>
              </div>
            </div>
          </li>

          <li class="mb-2">
            <button
              :class="{ 'btn btn-primary w-full': this.selectedButtonNumber === 6, 'btn-primary-500': this.selectedButtonNumber === 6, 'text-black': this.selectedButtonNumber !== 6, 'text-white': this.selectedButtonNumber === 6 }"
              class="btn w-full" @click="this.selectButton(6)">
              <svg t="1722582707958" class="icon" viewBox="0 0 1024 1024" version="1.1"
                :fill="this.selectedButtonNumber === 6 ? 'white' : 'black'" xmlns="http://www.w3.org/2000/svg"
                p-id="4555" width="24" height="24">
                <path
                  d="M240.426667 512A192 192 0 1 1 512 240.426667l67.84 67.84A42.666667 42.666667 0 0 0 640 248.106667l-67.626667-68.053334a274.56 274.56 0 0 0-91.733333-60.8 280.533333 280.533333 0 0 0-208.853333 0 277.333333 277.333333 0 0 0-152.533334 152.533334 279.253333 279.253333 0 0 0 0 208.853333 274.56 274.56 0 0 0 60.8 91.733333L248.106667 640a42.666667 42.666667 0 0 0 60.16-60.373333zM904.746667 543.36a274.56 274.56 0 0 0-60.8-91.733333L775.893333 384a42.666667 42.666667 0 1 0-60.16 60.373333L783.573333 512A192 192 0 1 1 512 783.573333l-67.84-67.84A42.666667 42.666667 0 1 0 384 775.893333l67.84 68.053334a274.56 274.56 0 0 0 91.733333 60.8 279.253333 279.253333 0 0 0 208.853334 0 277.333333 277.333333 0 0 0 152.533333-152.533334 279.253333 279.253333 0 0 0 0-208.853333z"
                  :fill="this.selectedButtonNumber === 6 ? 'white' : 'black'" p-id="4556"></path>
                <path
                  d="M647.68 690.346667A42.666667 42.666667 0 0 0 677.973333 618.666667L406.4 346.026667a42.666667 42.666667 0 1 0-60.373333 60.373333L618.666667 677.973333a42.666667 42.666667 0 0 0 29.013333 12.373334z"
                  :fill="this.selectedButtonNumber === 6 ? 'white' : 'black'" p-id="4557"></path>
              </svg>
              URL / IP 分析
            </button>
            <div
              v-if="this.selectedButtonNumber === 7 || this.selectedButtonNumber === 6 || this.selectedButtonNumber === 8">
              <div class="flex items-center mt-2">
                <svg t="1722501183923" class="icon" viewBox="0 0 1024 1024" version="1.1"
                  xmlns="http://www.w3.org/2000/svg" p-id="2642" width="24" height="24">
                  <path
                    d="M477.8 816.4l304.1-304.6-303.8-303.2c-18.5-18.5-18.5-48.5 0-67.1 18.5-18.6 48.6-18.6 67.1-0.1l337.3 336.7c18.5 18.5 18.5 48.5 0 67.1L544.9 883.4c-18.5 18.6-48.6 18.6-67.1 0.1-18.5-18.5-18.5-48.5 0-67.1z"
                    fill="#515151" p-id="2643"></path>
                </svg>
                <div class="flex items-center mt-2 ml-4">
                  <button
                    :class="{ 'btn btn-primary w-full': this.selectedButtonNumber === 7, 'btn-primary-500': this.selectedButtonNumber === 7, 'text-black': this.selectedButtonNumber !== 7, 'text-white': this.selectedButtonNumber === 7 }"
                    class="btn" @click="this.selectButton(7); getFileHistory('get_url_report')">
                    历史网页链接分析
                  </button>
                </div>
              </div>
              <div class="flex items-center mt-2">
                <svg t="1722501183923" class="icon" viewBox="0 0 1024 1024" version="1.1"
                  xmlns="http://www.w3.org/2000/svg" p-id="2642" width="24" height="24">
                  <path
                    d="M477.8 816.4l304.1-304.6-303.8-303.2c-18.5-18.5-18.5-48.5 0-67.1 18.5-18.6 48.6-18.6 67.1-0.1l337.3 336.7c18.5 18.5 18.5 48.5 0 67.1L544.9 883.4c-18.5 18.6-48.6 18.6-67.1 0.1-18.5-18.5-18.5-48.5 0-67.1z"
                    fill="#515151" p-id="2643"></path>
                </svg>
                <div class="flex items-center mt-2 ml-4">
                  <button
                    :class="{ 'btn btn-primary w-full': this.selectedButtonNumber === 8, 'btn-primary-500': this.selectedButtonNumber === 8, 'text-black': this.selectedButtonNumber !== 8, 'text-white': this.selectedButtonNumber === 8 }"
                    class="btn" @click="this.selectButton(8); getFileHistory('get_ip_report')">
                    历史IP地址分析
                  </button>
                </div>
              </div>
            </div>
          </li>

          <li class="mb-2">
            <button
              :class="{ 'btn btn-primary w-full': this.selectedButtonNumber === 3, 'btn-primary-500': this.selectedButtonNumber === 3, 'text-black': this.selectedButtonNumber !== 3, 'text-white': this.selectedButtonNumber === 3 }"
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

          <li class="mb-2">
            <button
              :class="{ 'btn btn-primary w-full': this.selectedButtonNumber === 4, 'btn-primary-500': this.selectedButtonNumber === 4, 'text-black': this.selectedButtonNumber !== 4, 'text-white': this.selectedButtonNumber === 4 }"
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
          <text class='text-lg font-bold text-gray-900 '>历史对话</text>
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
            :class="{ 'bg-white': chatHistory.length >= 1, 'bg-transparent': chatHistory.length === 0 }"
            class="menu rounded-box w-full">
            <li v-for="(chat, index) in chatHistory" :key="index" @click="loadChat(index)">
              <div class="flex items-center justify-between mr-2">
                <a class="text-base font-bold text-gray-700">Chat {{ index + 1 }}</a>
                <button @click="deleteChat(index)">
                  <svg t="1722251570726" class="icon" viewBox="0 0 1024 1024" version="1.1"
                    xmlns="http://www.w3.org/2000/svg" p-id="5947" width="20" height="20">
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
            <div
              v-if="selectedButtonNumber !== 4 && selectedButtonNumber !== 5 && selectedButtonNumber !== 7 && selectedButtonNumber !== 8">
              <h2 class="card-title">Cyber Secure</h2>
              <div id="chat-panel" ref="chatPanel" class="h-[32rem] max-h-full py-3 overflow-auto">
                <div v-if="messages.length === 0 " class="grid justify-items-center">
                  <div class="card bg-base-100 w-2/3 shadow-xl">
                    <div class="card-body">
                      <h2 class="card-title">你好~我是一名网络安全专家能为你解答一切安全相关的问题</h2>
                      <div class="w-full">
                        <button v-for="(item, index) in suggestions" :key="index" class="btn w-full my-1 " @click="setTextMessage(item)">
                          {{ item }}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
                <div v-for="msg in messages" :key="msg.id">
                  <div :class="msg.user ? 'chat chat-end' : 'chat chat-start'">
                    <div class="chat-image avatar">
                      <div class="w-10 rounded-full">
                        <img :src="'https://api.multiavatar.com/' + msg.name + '.png'" />
                      </div>
                    </div>
                    <div class="chat-bubble leading-loose" v-html="md2html(msg.content)" style="font-size: 0.9rem;">
                    </div>
                  </div>
                </div>
                <!-- 加载动画 -->
                <div v-if="loading" class="flex items-center mt-2">
                  <div class="w-10 rounded-full">
                    <img :src="'https://api.multiavatar.com/CyberSecure.png'" />
                  </div>
                  <span class="loading loading-dots loading-md ml-4"></span>
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
                    <input type="file" class="file-input file-input-bordered file-input-primary" id="fileInput" />
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
                    <button class="btn btn-outline btn-primary w-full"
                      @click="handleUpload(selectedDatabase)">确认上传</button>
                  </div>
                </div>
              </div>
            </div>

            <div v-if="this.selectedButtonNumber === 5">
              <div class="h-[40rem] max-h-full py-3 overflow-auto">
                <h2 class="card-title">最近上传样本</h2>

                <div class="overflow-auto">
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
                        <th>报告链接</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="(item, index) in fileHistory" :key="index">
                        <th>{{ index + 1 }}</th>
                        <td>{{ item.文件名称 }}</td>
                        <td>{{ item.文件类型 }}</td>
                        <td>{{ item.提交时间 }}</td>
                        <td>{{ item.反病毒引擎检出 }}</td>
                        <td :style="{ color: item.判定 === '安全' ? 'green' : 'red', fontWeight: 'bold' }">{{ item.判定 }}
                        </td>
                        <td><a :href="item.报告链接" target="_blank" class="underline">点击查看报告</a></td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            <div v-if="this.selectedButtonNumber === 7">
              <div class="h-[40rem] max-h-full py-3 overflow-auto">
                <h2 class="card-title">最近上传样本</h2>

                <div class="overflow-auto">
                  <table class="table table-zebra">
                    <!-- 表头 -->
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>网站</th>
                        <th>网站类型</th>
                        <th>提交时间</th>
                        <th>反病毒引擎检出</th>
                        <th>判定</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="(item, index) in fileHistory" :key="index">
                        <th>{{ index + 1 }}</th>
                        <td>{{ item.网站 }}</td>
                        <td>{{ item.网站类型 }}</td>
                        <td>{{ item.提交时间 }}</td>
                        <td>{{ item.反病毒引擎检出 }}</td>
                        <td :style="{ color: item.判定 === '安全' ? 'green' : 'red', fontWeight: 'bold' }">{{ item.判定 }}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            <div v-if="this.selectedButtonNumber === 8">
              <div class="h-[40rem] max-h-full py-3 overflow-auto">
                <h2 class="card-title">最近上传样本</h2>

                <div class="overflow-auto">
                  <table class="table table-zebra">
                    <!-- 表头 -->
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>ip地址</th>
                        <th>类型</th>
                        <th>国家</th>
                        <th>所属</th>
                        <th>提交时间</th>
                        <th>反病毒引擎检出</th>
                        <th>判定</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="(item, index) in fileHistory" :key="index">
                        <th>{{ index + 1 }}</th>
                        <td>{{ item.ip地址 }}</td>
                        <td>{{ item.类型 }}</td>
                        <td>{{ item.国家 }}</td>
                        <td>{{ item.所属 }}</td>
                        <td>{{ item.提交时间 }}</td>
                        <td>{{ item.反病毒引擎检出 }}</td>
                        <td :style="{ color: item.判定 === '安全' ? 'green' : 'red', fontWeight: 'bold' }">{{ item.判定 }}
                        </td>
                      </tr>
                    </tbody>
                  </table>
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
      chatHistory: [], // 存储所有聊天记录
      currentChatIndex: 0, // 当前加载的聊天记录索引
      messages: [],
      selectedButtonNumber: 1,
      tool: 'chat',
      suggestions: ['云计算环境中的数据加密有哪些主要方法？', '如何检测和防止SQL注入攻击？', '防火墙在现代网络安全策略中扮演什么角色？'],
      databases: ['ccc', 'web_leak', 'cve'],
      selectedDatabase: null,
      dropdownVisible: false,
      files: {
        'ccc': [],
        'web_leak': [],
        'cve': []
      },
      tshark_path: 'D:\\Wireshark\\wireshark\\Wireshark\\tshark.exe',
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
      loading: false, // 加载状态
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
    async setPath(newTsharkPath) {
      if (!newTsharkPath) {
        alert('路径不能为空，请输入有效的tshark路径。');
        return;
      }
      try {
        const response = await fetch('/api/set_tshark_path', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ newTsharkPath })
        });
        console.log(response);

        if (response.ok) {
          this.tshark_path = newTsharkPath; // 更新显示的 tshark 路径
          this.newTsharkPath = ''; // 清空输入框
          alert('tshark 路径已成功更新。');
        }
      } catch (error) {
        console.error(error);
        alert('更新 tshark 路径失败，请稍后重试。');
      }
    },
    async getFileHistory(tool) {
      console.log('getFileHistory called');
      try {
        const response = await fetch('/api/uploadFileHistory', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ tool })
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
    scrollToBottom() {
      const chatPanel = this.$refs.chatPanel;
      if (chatPanel) {
        const scrollHeight = chatPanel.scrollHeight;
        console.log(scrollHeight)
        const scrollStep = (scrollHeight - chatPanel.scrollTop) / 30; // 滑动的步长

        function scrollDown() {
          // 检查是否已经在底部，如果是则停止滚动
          console.log(chatPanel.scrollTop + chatPanel.clientHeight)
          if (chatPanel.scrollTop + chatPanel.clientHeight < scrollHeight - 1) {
            chatPanel.scrollTop += scrollStep;
            window.requestAnimationFrame(scrollDown);
          }
        }

        // 启动滚动前的一个微小延迟，确保DOM更新
        setTimeout(scrollDown, 100);
      }
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
      } else if (this.selectedButtonNumber === 6) {
        this.tool = 'get_url_report'
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
      // 设置加载状态为 true
      this.loading = true;

      try {
        const eventSource = new EventSource(`/api/sse?message=${encodeURIComponent(msg)}&type=${this.tool}`);
        let fullMessage = '';

        // 处理从服务器接收到的消息
        eventSource.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this.loading = false;  // 加载完成，隐藏转圈
            if (data.done) {
              this.scrollToBottom();
              eventSource.close();
              this.ready = true;
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
            this.loading = false;  // 数据解析错误，隐藏转圈
          }
        };

        // 处理连接错误
        eventSource.onerror = (error) => {
          console.error('SSE error:', error);
          this.showErr('SSE 连接出错');
          eventSource.close();
          this.ready = true;
          this.loading = false;  // 连接出错，隐藏转圈
        };
      } catch (e) {
        console.error('SSE 初始化错误:', e);
        this.showErr('SSE 初始化错误');
        this.ready = true;
        this.loading = false;  // 初始化错误，隐藏转圈
      }
    },
    md2html: function (md) {
      return marked.parse(md);
    },
    loadChat(index) {
      console.log(index);
      this.currentChatIndex = index;
      this.messages = this.chatHistory[index];
      console.log(this.chatHistory[index][0]);

      this.$nextTick(() => {
        this.scrollToBottom();
      });
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