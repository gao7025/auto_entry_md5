# auto_entry_md5

Using tkinter to construct a graphical interface creation function, it mainly implements functions such as file selection, MD5 encryption processing, result preview, and download.


=========================================================================

利用Python的tkinter函数构造一个图形界面，实现了文件选择、MD5加密处理、结果预览和下载等功能

=========================================================================

##### GitHub文档地址：
[https://github.com/gao7025/auto_entry_md5.git](https://github.com/gao7025/auto_entry_md5.git)

=========================================================================

##### 引言
利用tkinter构造一个图形界面的创建函数，主要实现了文件选择、MD5加密处理、结果预览和下载等功能。下面是主要涉及的功能模块：主框架、文件选择部分、MD5加密部分、结果预览部分、下载功能和状态栏等功能。


 1. 支持CSV、Excel和文本文件的上传
 2. 可以同时选择多个列进行MD5加密
 3. 加密过程在后台线程中进行，不会阻塞界面
 4. 显示加密结果的预览信息
 5. 将加密结果导出为Excel文件


--------------------------------------------------------------------------
##### 1.创建界面组件

##### 2.打开文件浏览器选择文件，加载并显示文件内容

##### 3.对选中的列进行MD5加密

##### 4.通过pyinstaller函数对文件进行exe打包



参数说明：

 -w 或 --windowed：不显示命令行窗口（适合 GUI 应用）
 -F 或 --onefile：打包成单个可执行的exe文件
 --onedir 打包成包含所有依赖的文件夹（而不是单个exe文件）
 --hidden-import：指定需要包含的隐藏依赖


-------------------------