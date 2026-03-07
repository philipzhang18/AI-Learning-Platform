AI调用函数 

 def call_ai_solution(self, cve_data, dell_advisory_data):

   """调用AI分析CVE和Dell安全公告，获取解决方案"""

   import threading

   threading.Thread(target=self._call_ai_solution_thread, args=(cve_data, dell_advisory_data), daemon=True).start()

 

 def _call_ai_solution_thread(self, cve_data, dell_advisory_data):

   """在后台线程中调用AI分析"""

   try:

​     \# 配置SiliconFlow API

​     api_key = os.getenv("SILICONFLOW_API_KEY")

​     if not api_key:

​       raise ValueError("SiliconFlow API key not found. Please set SILICONFLOW_API_KEY environment variable.")

​     model = os.getenv("SILICONFLOW_MODEL", "deepseek-ai/DeepSeek-V3")

 

​     \# 构建AI请求的提示

​     prompt = self._build_ai_prompt(cve_data, dell_advisory_data)

 

​     \# 调用SiliconFlow API

​     from openai import OpenAI

​     base_url = os.getenv("SILICONFLOW_BASE_URL", "https://api.siliconflow.cn")

 

​     try:

​       \# 创建OpenAI客户端并调用API

​       client = OpenAI(

​         api_key=api_key,

​         base_url=base_url

​       )

 

​       response = client.chat.completions.create(

​         model=model,

​         messages=[

​           {"role": "system", "content": "你是一个企业级安全顾问..."},

​           {"role": "user", "content": prompt}

​         ]

​       )

 

​       solution_result = response.choices[0].message.content

 

​       \# 在主线程中显示结果

​       self.root.after(0, self._show_ai_solution_result, solution_result, cve_data, dell_advisory_data)

​     except Exception as e:

​       error_msg = f"AI解决方案分析失败: {str(e)}"

​       self.root.after(0, self.log, error_msg)

​       self.root.after(0, messagebox.showerror, "错误", error_msg)