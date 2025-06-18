import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pandas as pd
import os
import threading
import hashlib
from datetime import datetime
import traceback
import sys

# 创建日志文件
LOG_FILE = "app_errors.log"


def log_error(exc_type, exc_value, exc_traceback):
    """记录错误信息到日志文件"""
    with open(LOG_FILE, "a") as f:
        f.write(f"\n[{datetime.now()}] 错误信息:\n")
        traceback.print_exception(exc_type, exc_value, exc_traceback, file=f)


# 设置全局异常处理
sys.excepthook = log_error


class MD5EncryptionTool:
    def __init__(self, root):
        """初始化应用"""
        self.root = root
        self.root.title("MD5 加密工具")
        self.root.geometry("800x600")
        self.root.minsize(600, 500)

        # 存储文件路径和数据
        self.file_path = None
        self.data = None
        self.encrypted_data = None

        # 创建界面
        self.create_widgets()

    def create_widgets(self):
        """创建界面组件"""
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 文件选择部分
        file_frame = ttk.LabelFrame(main_frame, text="文件选择", padding="10")
        file_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(file_frame, text="选择文件:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=50).grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(file_frame, text="浏览...", command=self.browse_file).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(file_frame, text="上传文件", command=self.load_file).grid(row=0, column=3, padx=5, pady=5)

        # 进度条
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(file_frame, variable=self.progress_var, maximum=100, length=300)
        self.progress_bar.grid(row=1, column=0, columnspan=4, padx=5, pady=5, sticky=tk.W + tk.E)

        # MD5加密部分
        md5_frame = ttk.LabelFrame(main_frame, text="MD5加密处理", padding="10")
        md5_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(md5_frame, text="选择要加密的列:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        # 创建一个带滚动条的列表框用于多选列
        listbox_frame = ttk.Frame(md5_frame)
        listbox_frame.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W + tk.E)

        self.columns_listbox = tk.Listbox(listbox_frame, selectmode=tk.MULTIPLE, width=30, height=5)
        self.columns_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=self.columns_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.columns_listbox.config(yscrollcommand=scrollbar.set)

        self.encrypt_btn = ttk.Button(md5_frame, text="加密所选列", command=self.encrypt_columns, state=tk.DISABLED)
        self.encrypt_btn.grid(row=0, column=2, padx=5, pady=5)

        # 结果预览部分
        results_frame = ttk.LabelFrame(main_frame, text="结果预览", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # 创建一个带滚动条的文本区域
        text_frame = ttk.Frame(results_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)

        self.result_text = tk.Text(text_frame, wrap=tk.WORD, height=10)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(text_frame, command=self.result_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.config(yscrollcommand=scrollbar.set)

        # 下载按钮
        self.download_btn = ttk.Button(main_frame, text="下载加密结果", command=self.download_results, state=tk.DISABLED)
        self.download_btn.pack(pady=10)

        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def browse_file(self):
        """打开文件浏览器选择文件"""
        file_path = filedialog.askopenfilename(
            filetypes=[
                ("CSV文件", "*.csv"),
                ("Excel文件", "*.xlsx;*.xls"),
                ("文本文件", "*.txt"),
                ("所有文件", "*.*")
            ]
        )
        if file_path:
            self.file_path_var.set(file_path)
            self.file_path = file_path

    def load_file(self):
        """加载并显示文件内容"""
        if not self.file_path:
            messagebox.showerror("错误", "请先选择一个文件")
            return

        # 清空结果文本区域和列表框
        self.result_text.delete(1.0, tk.END)
        self.columns_listbox.delete(0, tk.END)
        self.encrypted_data = None

        # 更新状态栏和启用进度条
        self.status_var.set("正在加载文件...")
        self.progress_var.set(0)
        self.progress_bar.start()

        # 在单独的线程中执行加载，避免界面卡顿
        load_thread = threading.Thread(target=self._perform_load)
        load_thread.daemon = True
        load_thread.start()

    def _perform_load(self):
        """执行文件加载的实际工作"""
        try:
            # 读取文件
            file_ext = os.path.splitext(self.file_path)[1].lower()

            if file_ext == '.csv':
                self.data = pd.read_csv(self.file_path)
            elif file_ext in ['.xlsx', '.xls']:
                self.data = pd.read_excel(self.file_path)
            elif file_ext == '.txt':
                # 尝试检测分隔符
                with open(self.file_path, 'r') as f:
                    first_line = f.readline()
                    if '\t' in first_line:
                        self.data = pd.read_csv(self.file_path, sep='\t')
                    elif ',' in first_line:
                        self.data = pd.read_csv(self.file_path, sep=',')
                    else:
                        self.data = pd.read_csv(self.file_path, sep=None, engine='python')
            else:
                # 尝试用 pandas 读取其他格式
                try:
                    self.data = pd.read_csv(self.file_path)
                except Exception as e:
                    self.update_ui(lambda: messagebox.showerror("错误", f"不支持的文件格式: {e}"))
                    self.update_ui(lambda: self.status_var.set("就绪"))
                    self.update_ui(lambda: self.progress_bar.stop())
                    return

            # 更新进度
            self.update_ui(lambda: self.progress_var.set(50))
            self.update_ui(lambda: self.status_var.set("正在准备预览..."))

            # 更新列选择列表框
            self.update_ui(self.update_columns_listbox)

            # 显示数据预览
            self.update_ui(self.display_data_preview)

            # 启用加密按钮
            self.update_ui(lambda: self.encrypt_btn.config(state=tk.NORMAL))

            # 完成
            self.update_ui(lambda: self.progress_var.set(100))
            self.update_ui(lambda: self.progress_bar.stop())
            self.update_ui(lambda: self.status_var.set("文件加载完成"))

        except Exception as e:
            # 显示错误信息并记录日志
            error_msg = f"加载文件时出错: {str(e)}"
            self.update_ui(lambda: messagebox.showerror("错误", error_msg))
            self.update_ui(lambda: self.progress_bar.stop())
            self.update_ui(lambda: self.status_var.set("加载失败"))
            log_error(type(e), e, e.__traceback__)

    def update_ui(self, func):
        """安全地更新 UI"""
        self.root.after(0, func)

    def update_columns_listbox(self):
        """更新列选择列表框"""
        if self.data is not None and not self.data.empty:
            # 添加所有列
            for col in self.data.columns:
                # 为了便于用户区分，为非字符串类型的列添加标记
                dtype = self.data[col].dtype
                if pd.api.types.is_string_dtype(dtype):
                    self.columns_listbox.insert(tk.END, col)
                else:
                    self.columns_listbox.insert(tk.END, f"{col} ({dtype})")

    def display_data_preview(self):
        """显示数据预览"""
        if self.data is None or self.data.empty:
            self.result_text.insert(tk.END, "没有数据可预览")
            return

        # 显示基本信息
        preview = f"数据基本信息：\n"
        preview += f"  文件: {os.path.basename(self.file_path)}\n"
        preview += f"  行数: {self.data.shape[0]}\n"
        preview += f"  列数: {self.data.shape[1]}\n"

        # 统计不同类型的列
        string_cols = []
        numeric_cols = []
        other_cols = []

        for col in self.data.columns:
            dtype = self.data[col].dtype
            if pd.api.types.is_string_dtype(dtype):
                string_cols.append(col)
            elif pd.api.types.is_numeric_dtype(dtype):
                numeric_cols.append(col)
            else:
                other_cols.append(col)

        preview += f"  字符串列: {len(string_cols)}\n"
        preview += f"  数值列: {len(numeric_cols)}\n"
        preview += f"  其他列: {len(other_cols)}\n\n"

        # 显示数据前几行预览
        preview += "数据前几行预览：\n"
        preview += self.data.head().to_string()

        self.result_text.insert(tk.END, preview)

    def encrypt_columns(self):
        """对选中的列进行MD5加密"""
        if self.data is None or self.data.empty:
            messagebox.showerror("错误", "没有数据可加密")
            return

        # 获取所有选中的列
        selected_indices = self.columns_listbox.curselection()
        if not selected_indices:
            messagebox.showerror("错误", "请选择至少一个列进行加密")
            return

        # 提取选中的列名（去除类型标记）
        selected_columns = []
        for i in selected_indices:
            col_text = self.columns_listbox.get(i)
            # 如果列名包含类型标记，则提取原始列名
            if '(' in col_text and ')' in col_text:
                col_name = col_text.split('(')[0].strip()
            else:
                col_name = col_text
            selected_columns.append(col_name)

        # 检查选中的列是否存在于数据中
        invalid_cols = [col for col in selected_columns if col not in self.data.columns]
        if invalid_cols:
            messagebox.showerror("错误", f"选中的列不存在: {', '.join(invalid_cols)}")
            return

        # 更新状态栏
        self.status_var.set("正在加密数据...")
        self.progress_var.set(0)
        self.progress_bar.start()

        # 在单独的线程中执行加密，避免界面卡顿
        encryption_thread = threading.Thread(target=self._perform_encryption, args=(selected_columns,))
        encryption_thread.daemon = True
        encryption_thread.start()

    def _perform_encryption(self, selected_columns):
        """执行MD5加密的实际工作"""
        try:
            # 创建数据副本
            self.encrypted_data = self.data.copy()

            # 对每列进行加密
            total_cols = len(selected_columns)
            for i, col in enumerate(selected_columns):
                # 更新进度
                progress = (i / total_cols) * 100
                self.update_ui(lambda p=progress: self.progress_var.set(p))

                # 创建新列名
                new_col = f"{col}_md5"

                # 对每一行进行MD5加密
                # 先将列转换为字符串类型
                self.encrypted_data[new_col] = self.data[col].astype(str).apply(
                    lambda x: self._md5_encrypt(x) if pd.notna(x) else x)

                self.encrypted_data[col] = self.data[col].astype(str)
            # 显示加密结果预览
            self.update_ui(self.display_encrypted_preview)

            # 启用下载按钮
            self.update_ui(lambda: self.download_btn.config(state=tk.NORMAL))

            # 完成
            self.update_ui(lambda: self.progress_var.set(100))
            self.update_ui(lambda: self.progress_bar.stop())
            self.update_ui(lambda: self.status_var.set("加密完成"))

            messagebox.showinfo("成功", f"已对选中的 {total_cols} 列进行MD5加密")

        except Exception as e:
            error_msg = f"加密过程中出错: {str(e)}"
            self.update_ui(lambda: messagebox.showerror("错误", error_msg))
            self.update_ui(lambda: self.progress_bar.stop())
            self.update_ui(lambda: self.status_var.set("加密失败"))
            log_error(type(e), e, e.__traceback__)

    def _md5_encrypt(self, text):
        """对文本进行MD5加密"""
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    def display_encrypted_preview(self):
        """显示加密结果预览"""
        if self.encrypted_data is None or self.encrypted_data.empty:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "没有加密数据可预览")
            return

        # 清空并显示加密结果
        self.result_text.delete(1.0, tk.END)

        # 显示基本信息
        preview = f"MD5加密结果：\n"
        preview += f"  原始列数: {self.data.shape[1]}\n"
        preview += f"  加密后列数: {self.encrypted_data.shape[1]}\n\n"

        # 显示加密的列
        encrypted_cols = [col for col in self.encrypted_data.columns if col.endswith('_md5')]
        preview += "加密的列：\n"
        for col in encrypted_cols:
            original_col = col.replace('_md5', '')
            preview += f"  - {original_col} → {col}\n"

        preview += "\n加密结果前几行预览：\n"
        preview += self.encrypted_data[encrypted_cols].head().to_string()

        self.result_text.insert(tk.END, preview)

    def download_results(self):
        """将加密结果导出为 Excel 文件"""
        if self.encrypted_data is None or self.encrypted_data.empty:
            messagebox.showerror("错误", "没有加密数据可导出")
            return

        # 让用户选择保存位置
        default_filename = f"加密结果_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        save_path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel文件", "*.xlsx")],
            initialfile=default_filename
        )

        if not save_path:
            return

        try:
            # 更新状态栏
            self.status_var.set("正在导出结果...")

            # 导出加密结果
            self.encrypted_data.to_excel(save_path, index=False)

            messagebox.showinfo("成功", f"加密结果已成功导出到 {save_path}")
            self.status_var.set("就绪")

        except Exception as e:
            messagebox.showerror("错误", f"导出文件时出错: {e}")
            self.status_var.set("导出失败")


if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = MD5EncryptionTool(root)
        root.mainloop()
    except Exception as e:
        # 捕获主程序异常
        log_error(type(e), e, e.__traceback__)
        # 创建一个简单的错误对话框
        error_root = tk.Tk()
        error_root.title("程序错误")
        error_root.geometry("400x200")

        ttk.Label(error_root, text="程序运行时发生错误:", font=("Arial", 10, "bold")).pack(pady=10)
        ttk.Label(error_root, text=str(e), wraplength=380).pack(pady=10)
        ttk.Label(error_root, text=f"错误详情已保存到 {LOG_FILE}", font=("Arial", 9)).pack(pady=10)

        ttk.Button(error_root, text="确定", command=error_root.destroy).pack(pady=10)

        error_root.mainloop()

