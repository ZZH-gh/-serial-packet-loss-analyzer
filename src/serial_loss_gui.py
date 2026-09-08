#!/usr/bin/env python3
"""Windows GUI for serial_loss_analyzer.py.

Accepts a dropped TXT/CSV log or a file passed as the first command-line
argument (so dropping a file on the EXE also works).
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, Canvas, StringVar, Toplevel, filedialog, messagebox, ttk

from tkinterdnd2 import DND_FILES, TkinterDnD

from frame_parser import CrcKind, FrameConfig, FrameProtocol, OperationCancelled, parse_chunks
from serial_loss_analyzer import (
    CycleResult, Gap, analyze_cycles, analyze_log, analyze_time_windows, analyze_timestamp_gaps,
    analyze_timestamp_windows, detect_modbus_rtu, detect_protocol, detect_sequence_field,
    detect_timestamp_table, match_transactions, parse_hex, read_directional_chunks,
)


PARAMETER_HELP = {
    "帧格式": "选择帧切分规则。Modbus 自动验证 CRC；私有协议可选固定帧或长度字段帧。",
    "帧头（HEX）": "每帧开头的固定字节，例如 AA55。长度字段帧与固定帧均用它重新同步。",
    "固定总帧长（固定帧用）": "固定帧模式下，一整帧从帧头到 CRC 的总字节数。",
    "长度字段偏移": "长度字段相对于帧头的字节位置；帧头第一个字节偏移为 0。",
    "长度字段字节数": "长度字段占用 1、2 或 4 字节。",
    "长度字段字节序": "多字节长度字段的排列方式；常见 MCU 协议多为 little，网络协议常为 big。",
    "长度字段调整值": "总帧长 = 长度字段值 + 调整值。例如 2 字节帧头 + 1 字节长度 + N 数据，调整值填 3。",
    "序号偏移": "递增序号相对于帧头的字节位置。证据页会显示每帧提取出的值，便于核对。",
    "序号字节数": "序号字段占用 1、2 或 4 字节。",
    "字节序": "多字节序号的排列方式。",
    "帧内超时(ms,0关闭)": "一帧尚未收全时，下一次接收相隔超过该值，前面的残留会记为截断。",
    "CRC": "选择帧尾校验规则。CRC 不通过的内容不会作为有效帧参与丢包统计。",
    "循环纳入阈值(%)": "某轮收到的唯一序号少于理论帧数的该比例时，标为采集冗余，不纳入过滤后平均。全部循环结果仍会显示。",
    "收发超时(ms,0关闭)": "TX 后在该时间内没有 RX，记为未响应。只影响收发健康度，不影响 RX 丢包率。",
    "手动循环起始序号": "已知协议循环范围时填写起点；需与手动理论帧数同时填写。",
    "手动理论帧数": "已知一个循环中应有多少序号时填写；会覆盖自动循环范围推断。",
    "时间统计窗口(s)": "按多少秒汇总有效 RX 帧、缺号和帧间隔；默认 60 秒。",
}


class Tooltip:
    """Small, keyboard-free parameter explanation popup."""

    def __init__(self, widget, text: str) -> None:
        self.widget, self.text, self.popup = widget, text, None
        widget.bind("<Enter>", self.show, add="+")
        widget.bind("<Leave>", self.hide, add="+")

    def show(self, _event=None) -> None:
        if self.popup:
            return
        self.popup = Toplevel(self.widget)
        self.popup.wm_overrideredirect(True)
        self.popup.attributes("-topmost", True)
        label = ttk.Label(self.popup, text=self.text, justify="left", wraplength=330, style="Tooltip.TLabel", padding=8)
        label.pack()
        self.popup.geometry(f"+{self.widget.winfo_rootx() + 18}+{self.widget.winfo_rooty() + 20}")

    def hide(self, _event=None) -> None:
        if self.popup:
            self.popup.destroy()
            self.popup = None


class LossAnalyzerApp:
    def __init__(self, root) -> None:
        self.root = root
        self.root.title("串口日志丢包统计工具")
        self.root.minsize(1080, 720)
        self.root.geometry("1180x820")
        self.root.configure(background="#EAF1F5")
        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind("<<Drop>>", self.on_drop)
        self.file_path = StringVar()
        self.header = StringVar(value="AA55")
        self.frame_size = StringVar(value="18")
        self.profile = StringVar(value="自定义固定帧")
        self.length_offset = StringVar(value="2")
        self.length_size = StringVar(value="1")
        self.length_endian = StringVar(value="little")
        self.length_adjust = StringVar(value="0")
        self.seq_offset = StringVar(value="2")
        self.seq_size = StringVar(value="2")
        self.endian = StringVar(value="little")
        self.max_gap = StringVar(value="1000")
        self.cycle_coverage = StringVar(value="50")
        self.transaction_timeout = StringVar(value="1500")
        self.manual_cycle_start = StringVar(value="")
        self.manual_cycle_count = StringVar(value="")
        self.time_window_seconds = StringVar(value="60")
        self.crc = StringVar(value=CrcKind.NONE.value)
        self.result = StringVar(value="拖入 SSCOM 导出的 TXT/CSV/DAT 文件，或点击“选择日志文件”。")
        self.primary_loss = StringVar(value="—")
        self.primary_loss_label = StringVar(value="等待统计")
        self.primary_loss_detail = StringVar(value="完成统计后显示当前日志的核心丢包率与统计口径。")
        self.parameter_source = StringVar(value="默认参数（尚未自检）")
        self.rule_summary = StringVar(value="导入日志后，这里会显示当前文件实际识别到的格式与统计口径。")
        self.preview_note = StringVar(value="点击“参数自检”后，这里会显示当前参数切出的前 10 帧。")
        self.progress_message = StringVar(value="")
        self.gaps: list[Gap] = []
        self.cycle_results: list[CycleResult] = []
        self.cyclic_mode = False
        self.input_stream = b""
        self.input_chunks = []
        self.direction_note = ""
        self.direction_read = None
        self.transaction_note = ""
        self.timestamp_table = None
        self.timestamp_gap_analysis = None
        self.evidence_rows: list[dict[str, str]] = []
        self.last_report: dict | None = None
        self.compare_paths: list[Path] = []
        self.comparison_rows: list[dict[str, str]] = []
        self.preview_confirmed = False
        self.preview_count = 0
        self.cancel_requested = False
        self._setting_parameters = False
        self._auto_display_mode: str | None = None
        self._build()
        self._watch_parameters()

    def _build(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", font=("Microsoft YaHei UI", 9), background="#EAF1F5", foreground="#18324A")
        style.configure("App.TFrame", background="#EAF1F5")
        style.configure("Header.TFrame", background="#102A43")
        style.configure("HeaderTitle.TLabel", background="#102A43", foreground="#FFFFFF", font=("Microsoft YaHei UI", 19, "bold"))
        style.configure("HeaderMeta.TLabel", background="#102A43", foreground="#A9C3D7", font=("Microsoft YaHei UI", 9))
        style.configure("Section.TLabel", background="#EAF1F5", foreground="#0B7189", font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("Hint.TLabel", background="#EAF1F5", foreground="#62778A", font=("Microsoft YaHei UI", 8))
        style.configure("Help.TLabel", background="#EAF1F5", foreground="#007C91", font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("Tooltip.TLabel", background="#102A43", foreground="#FFFFFF", relief="solid", borderwidth=1, font=("Microsoft YaHei UI", 9))
        style.configure("Drop.TLabel", background="#F9FCFD", foreground="#26526B", font=("Microsoft YaHei UI", 11, "bold"), relief="solid", borderwidth=1)
        style.configure("TLabelframe", background="#EAF1F5", bordercolor="#C4D5DF", relief="solid")
        style.configure("TLabelframe.Label", background="#EAF1F5", foreground="#1D536C", font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("TEntry", fieldbackground="#FFFFFF", bordercolor="#B9CEDA", padding=6)
        style.configure("TCombobox", fieldbackground="#FFFFFF", bordercolor="#B9CEDA", padding=5)
        style.configure("Primary.TButton", background="#007C91", foreground="#FFFFFF", borderwidth=0, padding=(14, 8), font=("Microsoft YaHei UI", 9, "bold"))
        style.map("Primary.TButton", background=[("active", "#006A7C"), ("disabled", "#B2C3CC")])
        style.configure("Secondary.TButton", background="#DDEAF0", foreground="#164A62", borderwidth=0, padding=(12, 8))
        style.map("Secondary.TButton", background=[("active", "#C8DDE7")])
        style.configure("Export.TButton", background="#FFF0D3", foreground="#8A5400", borderwidth=0, padding=(11, 8))
        style.map("Export.TButton", background=[("active", "#FFE0A8"), ("disabled", "#E7EDEF")])
        style.configure("Status.TLabel", background="#F9FCFD", foreground="#27485C", relief="solid", borderwidth=1, padding=10, font=("Microsoft YaHei UI", 9))
        style.configure("Metric.TFrame", background="#102A43")
        style.configure("MetricStripe.TFrame", background="#00A6A6")
        style.configure("MetricEyebrow.TLabel", background="#102A43", foreground="#A9C3D7", font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("MetricContext.TLabel", background="#102A43", foreground="#D6E4EC", font=("Microsoft YaHei UI", 9))
        style.configure("MetricGood.TLabel", background="#102A43", foreground="#5EEAD4", font=("Consolas", 28, "bold"))
        style.configure("MetricWatch.TLabel", background="#102A43", foreground="#FCD34D", font=("Consolas", 28, "bold"))
        style.configure("MetricAlert.TLabel", background="#102A43", foreground="#FDA4AF", font=("Consolas", 28, "bold"))
        style.configure("Verify.TLabel", background="#E1F1EF", foreground="#075D67", relief="solid", borderwidth=1, padding=9, font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("Progress.TLabel", background="#EAF1F5", foreground="#426176", font=("Microsoft YaHei UI", 8))
        style.configure("Treeview", background="#FFFFFF", fieldbackground="#FFFFFF", foreground="#18324A", rowheight=30, bordercolor="#C4D5DF", font=("Consolas", 9))
        style.configure("Treeview.Heading", background="#DCEAF0", foreground="#164A62", relief="flat", font=("Microsoft YaHei UI", 9, "bold"), padding=(7, 7))
        style.map("Treeview", background=[("selected", "#BDEAE5")], foreground=[("selected", "#102A43")])
        style.configure("TNotebook", background="#EAF1F5", borderwidth=0)
        style.configure("TNotebook.Tab", background="#D9E6EC", foreground="#426176", padding=(16, 8), font=("Microsoft YaHei UI", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#FFFFFF")], foreground=[("selected", "#007C91")])

        scroll_host = ttk.Frame(self.root, style="App.TFrame")
        scroll_host.pack(fill=BOTH, expand=True)
        canvas = Canvas(scroll_host, background="#EAF1F5", highlightthickness=0, borderwidth=0)
        page_scroll = ttk.Scrollbar(scroll_host, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=page_scroll.set)
        canvas.pack(side=LEFT, fill=BOTH, expand=True)
        page_scroll.pack(side=RIGHT, fill="y")
        outer = ttk.Frame(canvas, padding=18, style="App.TFrame")
        page_window = canvas.create_window((0, 0), window=outer, anchor="nw")

        def sync_scroll_region(_event=None) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def fit_page_width(event) -> None:
            canvas.itemconfigure(page_window, width=event.width)

        def scroll_page(event) -> str | None:
            # Let result tables keep their own wheel behavior; use the page
            # scrollbar for every other control and blank area.
            if isinstance(event.widget, ttk.Treeview):
                return None
            if canvas.bbox("all") and canvas.bbox("all")[3] > canvas.winfo_height():
                canvas.yview_scroll(-int(event.delta / 120), "units")
                return "break"
            return None

        outer.bind("<Configure>", sync_scroll_region)
        canvas.bind("<Configure>", fit_page_width)
        self.root.bind_all("<MouseWheel>", scroll_page, add="+")

        header = ttk.Frame(outer, style="Header.TFrame", padding=(22, 16))
        header.pack(fill="x", pady=(0, 14))
        ttk.Label(header, text="串口日志丢包统计", style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(header, text="RX 证据链  /  完整帧校验  /  序号缺失统计", style="HeaderMeta.TLabel").pack(anchor="w", pady=(4, 0))

        ttk.Label(outer, text="01  导入日志", style="Section.TLabel").pack(anchor="w", pady=(0, 6))

        drop = ttk.Label(
            outer,
            text="拖入 SSCOM 导出的日志文件\nTXT / CSV / DAT  ·  可连续拖入新文件，无需重启",
            anchor="center",
            style="Drop.TLabel",
            padding=16,
        )
        drop.pack(fill="x")
        drop.drop_target_register(DND_FILES)
        drop.dnd_bind("<<Drop>>", self.on_drop)

        file_row = ttk.Frame(outer, style="App.TFrame")
        file_row.pack(fill="x", pady=(10, 16))
        ttk.Entry(file_row, textvariable=self.file_path, state="readonly").pack(side=LEFT, fill="x", expand=True)
        ttk.Button(file_row, text="选择多份对比", command=self.choose_compare_files, style="Secondary.TButton").pack(side=RIGHT, padx=(6, 0))
        ttk.Button(file_row, text="选择日志文件", command=self.choose_file, style="Secondary.TButton").pack(side=RIGHT, padx=(10, 0))

        ttk.Label(outer, text="02  校验规则", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        config = ttk.LabelFrame(outer, text="协议与统计参数（导入后显示当前识别规则）", padding=12)
        config.pack(fill="x")
        fields = [
            ("帧格式", self.profile, 16),
            ("帧头（HEX）", self.header, 12),
            ("固定总帧长（固定帧用）", self.frame_size, 16),
            ("长度字段偏移", self.length_offset, 12),
            ("长度字段字节数", self.length_size, 12),
            ("长度字段字节序", self.length_endian, 12),
            ("长度字段调整值", self.length_adjust, 12),
            ("序号偏移", self.seq_offset, 10),
            ("序号字节数", self.seq_size, 8),
            ("字节序", self.endian, 9),
            ("帧内超时(ms,0关闭)", self.max_gap, 14),
            ("CRC", self.crc, 14),
            ("循环纳入阈值(%)", self.cycle_coverage, 14),
            ("收发超时(ms,0关闭)", self.transaction_timeout, 14),
            ("手动循环起始序号", self.manual_cycle_start, 14),
            ("手动理论帧数", self.manual_cycle_count, 14),
            ("时间统计窗口(s)", self.time_window_seconds, 14),
        ]
        for column, (label, variable, width) in enumerate(fields):
            row = (column // 4) * 2
            grid_column = column % 4
            label_row = ttk.Frame(config, style="App.TFrame")
            label_row.grid(row=row, column=grid_column, padx=4, sticky="w")
            ttk.Label(label_row, text=label).pack(side=LEFT)
            if label in PARAMETER_HELP:
                help_mark = ttk.Label(label_row, text="  ?", style="Help.TLabel", cursor="question_arrow")
                help_mark.pack(side=LEFT)
                Tooltip(help_mark, PARAMETER_HELP[label])
            if label == "帧格式":
                widget = ttk.Combobox(config, textvariable=variable, values=("自定义固定帧", "自定义长度字段帧", "Modbus RTU（CRC自动帧长）", "时间戳表格（自动）"), width=width, state="readonly")
            elif label in {"序号字节数", "长度字段字节数"}:
                widget = ttk.Combobox(config, textvariable=variable, values=("1", "2", "4", "不适用"), width=width, state="readonly")
            elif label in {"字节序", "长度字段字节序"}:
                widget = ttk.Combobox(config, textvariable=variable, values=("little", "big", "不适用"), width=width, state="readonly")
            elif label == "CRC":
                widget = ttk.Combobox(config, textvariable=variable, values=tuple(kind.value for kind in CrcKind) + ("不适用",), width=width, state="readonly")
            else:
                widget = ttk.Entry(config, textvariable=variable, width=width)
            widget.grid(row=row + 1, column=grid_column, padx=4, pady=(2, 8), sticky="ew")
        for column in range(4):
            config.columnconfigure(column, weight=1)
        ttk.Label(
            config,
            text="长度字段帧规则：总帧长 = 指定偏移处的长度字段值 + 调整值；固定总帧长在该模式下不使用。",
            style="Hint.TLabel",
        ).grid(row=((len(fields) + 3) // 4) * 2, column=0, columnspan=4, padx=4, sticky="w")
        ttk.Label(
            config, textvariable=self.rule_summary, justify="left", wraplength=1000, style="Verify.TLabel",
        ).grid(row=((len(fields) + 3) // 4) * 2 + 1, column=0, columnspan=4, padx=4, pady=(8, 0), sticky="ew")

        buttons = ttk.Frame(outer, style="App.TFrame")
        buttons.pack(fill="x", pady=(14, 10))
        self.auto_button = ttk.Button(buttons, text="自动识别", command=self.auto_detect, style="Secondary.TButton")
        self.auto_button.pack(side=LEFT)
        self.preview_button = ttk.Button(buttons, text="参数自检", command=self.preview_parameters, style="Secondary.TButton")
        self.preview_button.pack(side=LEFT, padx=(8, 0))
        self.analyze_button = ttk.Button(buttons, text="开始统计", command=self.analyze, style="Primary.TButton")
        self.analyze_button.pack(side=LEFT, padx=(8, 18))
        ttk.Button(buttons, text="保存方案", command=self.save_profile, style="Secondary.TButton").pack(side=LEFT)
        ttk.Button(buttons, text="加载方案", command=self.load_profile, style="Secondary.TButton").pack(side=LEFT, padx=(4, 14))
        self.export_button = ttk.Button(buttons, text="导出缺失 CSV", command=self.export, state="disabled", style="Export.TButton")
        self.export_button.pack(side=LEFT)
        self.evidence_export_button = ttk.Button(buttons, text="导出证据 CSV", command=self.export_evidence, state="disabled", style="Export.TButton")
        self.evidence_export_button.pack(side=LEFT, padx=(4, 0))
        self.report_export_button = ttk.Button(buttons, text="导出报告 JSON", command=self.export_report, state="disabled", style="Export.TButton")
        self.report_export_button.pack(side=LEFT, padx=(4, 0))
        self.comparison_export_button = ttk.Button(buttons, text="导出对比 CSV", command=self.export_comparison, state="disabled", style="Export.TButton")
        self.comparison_export_button.pack(side=LEFT, padx=(4, 0))
        progress_row = ttk.Frame(outer, style="App.TFrame")
        progress_row.pack(fill="x", pady=(0, 10))
        self.operation_progress = ttk.Progressbar(progress_row, orient="horizontal", mode="determinate", maximum=100)
        self.operation_progress.pack(side=LEFT, fill="x", expand=True)
        ttk.Label(progress_row, textvariable=self.progress_message, style="Progress.TLabel").pack(side=LEFT, padx=(8, 4))
        self.cancel_button = ttk.Button(progress_row, text="取消", command=self.request_cancel, state="disabled", style="Secondary.TButton")
        self.cancel_button.pack(side=RIGHT)

        ttk.Label(outer, text="03  分析结果", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        metric_panel = ttk.Frame(outer, style="Metric.TFrame")
        metric_panel.pack(fill="x", pady=(0, 8))
        ttk.Frame(metric_panel, style="MetricStripe.TFrame", width=7).pack(side=LEFT, fill="y")
        metric_copy = ttk.Frame(metric_panel, style="Metric.TFrame", padding=(18, 12))
        metric_copy.pack(side=LEFT, fill="both", expand=True)
        ttk.Label(metric_copy, text="核心读数 · 丢包率", style="MetricEyebrow.TLabel").pack(anchor="w")
        ttk.Label(metric_copy, textvariable=self.primary_loss_label, style="MetricContext.TLabel").pack(anchor="w", pady=(3, 0))
        ttk.Label(metric_copy, textvariable=self.primary_loss_detail, style="MetricContext.TLabel", wraplength=680, justify="left").pack(anchor="w", pady=(5, 0))
        self.primary_loss_value = ttk.Label(metric_panel, textvariable=self.primary_loss, style="MetricGood.TLabel", padding=(18, 18))
        self.primary_loss_value.pack(side=RIGHT)
        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill=BOTH, expand=True)
        table_frame = ttk.Frame(self.notebook)
        detail_frame = ttk.Frame(self.notebook)
        preview_frame = ttk.Frame(self.notebook)
        evidence_frame = ttk.Frame(self.notebook)
        time_frame = ttk.Frame(self.notebook)
        comparison_frame = ttk.Frame(self.notebook)
        self.notebook.add(table_frame, text="统计明细")
        self.notebook.add(detail_frame, text="分析说明")
        self.notebook.add(preview_frame, text="参数自检")
        self.notebook.add(evidence_frame, text="解析证据")
        self.notebook.add(time_frame, text="时间定位")
        self.notebook.add(comparison_frame, text="多文件对比")
        self.result_label = ttk.Label(detail_frame, textvariable=self.result, justify="left", wraplength=1000, style="Status.TLabel")
        self.result_label.pack(fill=BOTH, expand=True, padx=2, pady=2)
        self.table = ttk.Treeview(
            table_frame,
            columns=("after", "first", "last", "count"),
            show="headings",
            height=10,
        )
        self.set_table_headings((("after", "前一序号"), ("first", "首个缺失"), ("last", "最后缺失"), ("count", "缺失帧数")))
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side=LEFT, fill=BOTH, expand=True)
        scroll.pack(side=RIGHT, fill="y")

        ttk.Label(preview_frame, textvariable=self.preview_note, justify="left", wraplength=1000, style="Verify.TLabel").pack(fill="x", padx=1, pady=(0, 8))
        self.preview_table = ttk.Treeview(
            preview_frame, columns=("frame", "lines", "time", "bytes", "sequence", "check"),
            show="headings", height=10,
        )
        for key, text, width in (
            ("frame", "预览帧", 75), ("lines", "日志行", 85), ("time", "接收时间", 110),
            ("bytes", "按当前参数切出的完整帧", 360), ("sequence", "当前序号字段", 120), ("check", "核对结果", 220),
        ):
            self.preview_table.heading(key, text=text)
            self.preview_table.column(key, width=width, anchor="w", stretch=key in {"bytes", "check"})
        preview_scroll = ttk.Scrollbar(preview_frame, orient="vertical", command=self.preview_table.yview)
        self.preview_table.configure(yscrollcommand=preview_scroll.set)
        self.preview_table.pack(side=LEFT, fill=BOTH, expand=True)
        preview_scroll.pack(side=RIGHT, fill="y")

        self.evidence = ttk.Treeview(
            evidence_frame,
            columns=("frame", "lines", "time", "bytes", "sequence", "status"),
            show="headings", height=10,
        )
        for key, text, width in (
            ("frame", "帧 / 事件", 90), ("lines", "日志行", 80), ("time", "接收时间", 105),
            ("bytes", "帧内容（HEX，前48字节）", 310), ("sequence", "提取序号", 90), ("status", "判定依据", 230),
        ):
            self.evidence.heading(key, text=text)
            self.evidence.column(key, width=width, anchor="w", stretch=key in {"bytes", "status"})
        evidence_scroll = ttk.Scrollbar(evidence_frame, orient="vertical", command=self.evidence.yview)
        self.evidence.configure(yscrollcommand=evidence_scroll.set)
        self.evidence.pack(side=LEFT, fill=BOTH, expand=True)
        evidence_scroll.pack(side=RIGHT, fill="y")

        self.time_table = ttk.Treeview(time_frame, columns=("time", "frames", "missing", "loss", "avg", "max", "long"), show="headings", height=10)
        for key, text, width in (
            ("time", "时间段", 150), ("frames", "有效记录", 95), ("missing", "缺失/漏采", 95),
            ("loss", "丢包/断档率", 105), ("avg", "平均间隔", 110), ("max", "最大间隔", 110), ("long", "异常长间隔", 110),
        ):
            self.time_table.heading(key, text=text)
            self.time_table.column(key, width=width, anchor="center", stretch=True)
        time_scroll = ttk.Scrollbar(time_frame, orient="vertical", command=self.time_table.yview)
        self.time_table.configure(yscrollcommand=time_scroll.set)
        self.time_table.pack(side=LEFT, fill=BOTH, expand=True)
        time_scroll.pack(side=RIGHT, fill="y")

        self.comparison_table = ttk.Treeview(comparison_frame, columns=("file", "mode", "frames", "loss", "missing", "worst", "crc", "truncated", "direction", "result"), show="headings", height=10)
        for key, text, width in (
            ("file", "日志文件", 240), ("mode", "统计模式", 90), ("frames", "完整帧", 80),
            ("loss", "丢包/断档率", 105), ("missing", "缺失/漏采", 85), ("worst", "最差循环/阈值", 115), ("crc", "CRC错误", 85),
            ("truncated", "截断", 70), ("direction", "RX/TX", 100), ("result", "结果", 190),
        ):
            self.comparison_table.heading(key, text=text)
            self.comparison_table.column(key, width=width, anchor="center", stretch=key in {"file", "result"})
        comparison_scroll = ttk.Scrollbar(comparison_frame, orient="vertical", command=self.comparison_table.yview)
        self.comparison_table.configure(yscrollcommand=comparison_scroll.set)
        self.comparison_table.pack(side=LEFT, fill=BOTH, expand=True)
        comparison_scroll.pack(side=RIGHT, fill="y")

    def _watch_parameters(self) -> None:
        for variable in (
            self.profile, self.header, self.frame_size, self.length_offset, self.length_size,
            self.length_endian, self.length_adjust, self.seq_offset, self.seq_size, self.endian,
            self.max_gap, self.crc, self.cycle_coverage, self.transaction_timeout,
            self.manual_cycle_start, self.manual_cycle_count, self.time_window_seconds,
        ):
            variable.trace_add("write", self._on_parameter_change)

    def restore_protocol_parameter_inputs(self) -> None:
        """Restore editable protocol defaults after leaving an auto-display mode."""
        self._setting_parameters = True
        try:
            self.header.set("AA55")
            self.frame_size.set("18")
            self.length_offset.set("2")
            self.length_size.set("1")
            self.length_endian.set("little")
            self.length_adjust.set("0")
            self.seq_offset.set("2")
            self.seq_size.set("2")
            self.endian.set("little")
            self.max_gap.set("1000")
            self.crc.set(CrcKind.NONE.value)
            self.cycle_coverage.set("50")
            self.transaction_timeout.set("1500")
            self.manual_cycle_start.set("")
            self.manual_cycle_count.set("")
        finally:
            self._setting_parameters = False
        self._auto_display_mode = None

    def show_timestamp_table_parameters(self) -> None:
        """Replace irrelevant frame controls with the actual table structure."""
        if self.timestamp_table is None:
            return
        self._setting_parameters = True
        try:
            self.profile.set("时间戳表格（自动）")
            self.header.set("每行 = 1 条记录")
            self.frame_size.set(f"{self.timestamp_table.field_count} 列 + 行尾时间戳")
            self.length_offset.set("不适用")
            self.length_size.set("不适用")
            self.length_endian.set("不适用")
            self.length_adjust.set("不适用")
            self.seq_offset.set("无递增序号")
            self.seq_size.set("不适用")
            self.endian.set("不适用")
            self.max_gap.set("不适用")
            self.crc.set("不适用")
            self.cycle_coverage.set("不适用")
            self.transaction_timeout.set("不适用")
            self.manual_cycle_start.set("不适用")
            self.manual_cycle_count.set("不适用")
        finally:
            self._setting_parameters = False
        self._auto_display_mode = "timestamp_table"

    def show_modbus_parameters(self, frames: list[bytes]) -> str:
        """Expose observed Modbus address/function pairs instead of a fake fixed header."""
        pairs = sorted({(frame[0], frame[1] & 0x7F) for frame in frames if len(frame) >= 2})
        display_pairs = "、".join(f"{address:02X}/{function:02X}" for address, function in pairs[:3])
        if len(pairs) > 3:
            display_pairs += f" 等 {len(pairs)} 种"
        if not display_pairs:
            display_pairs = "未提取"
        minimum = min(map(len, frames)) if frames else 0
        maximum = max(map(len, frames)) if frames else 0
        self._setting_parameters = True
        try:
            self.header.set(f"动态：{display_pairs}")
            self.frame_size.set(f"自动：{minimum}~{maximum} B")
        finally:
            self._setting_parameters = False
        self._auto_display_mode = "modbus"
        return display_pairs

    def _on_parameter_change(self, *_args) -> None:
        if self._setting_parameters:
            return
        if self._auto_display_mode == "modbus" and not self.profile.get().startswith("Modbus"):
            self.restore_protocol_parameter_inputs()
        elif self._auto_display_mode == "timestamp_table" and self.profile.get() != "时间戳表格（自动）":
            self.restore_protocol_parameter_inputs()
        if self.timestamp_table is not None:
            self.parameter_source.set("自动识别：时间戳表格日志（无需帧参数）")
            self.preview_note.set("此类日志按“每行一条记录 + 末尾时间戳”统计；修改时间窗口后重新点击“开始统计”即可。")
            return
        self.parameter_source.set("人工调整（请重新自检）")
        self.invalidate_preview()

    def invalidate_preview(self) -> None:
        self.preview_confirmed = False
        self.preview_count = 0
        self.preview_note.set("参数已变更；请点击“参数自检”，核对当前帧头、帧长和序号字段。")
        self.preview_table.delete(*self.preview_table.get_children())

    def set_preview_headings(self, headings) -> None:
        for key, text, width in headings:
            self.preview_table.heading(key, text=text)
            self.preview_table.column(key, width=width, anchor="w", stretch=key in {"bytes", "check"})

    def request_cancel(self) -> None:
        self.cancel_requested = True
        self.progress_message.set("正在取消…")
        self.cancel_button.configure(state="disabled")

    def begin_operation(self, message: str) -> None:
        self.cancel_requested = False
        self.operation_progress.configure(value=0)
        self.progress_message.set(message)
        self.cancel_button.configure(state="normal")
        self.auto_button.configure(state="disabled")
        self.analyze_button.configure(state="disabled")
        self.preview_button.configure(state="disabled")
        self.root.update_idletasks()

    def progress_callback(self, message: str):
        def update(current: int, total: int) -> bool:
            percent = 100 if total <= 0 else min(100, current * 100 / total)
            self.operation_progress.configure(value=percent)
            self.progress_message.set(f"{message} {percent:.0f}%（可取消）")
            # Process the Cancel click while parsing remains on this thread.
            self.root.update_idletasks()
            self.root.update()
            return not self.cancel_requested
        return update

    def finish_operation(self) -> None:
        self.operation_progress.configure(value=0)
        self.progress_message.set("")
        self.cancel_button.configure(state="disabled")
        self.auto_button.configure(state="normal")
        self.analyze_button.configure(state="normal")
        self.preview_button.configure(state="normal")

    def reset_primary_loss(self) -> None:
        self.primary_loss.set("—")
        self.primary_loss_label.set("等待统计")
        self.primary_loss_detail.set("完成统计后显示当前日志的核心丢包率与统计口径。")
        self.primary_loss_value.configure(style="MetricGood.TLabel")

    def set_primary_loss(self, rate: float, label: str, detail: str) -> None:
        self.primary_loss.set(f"{rate:.4f}%")
        self.primary_loss_label.set(label)
        self.primary_loss_detail.set(detail)
        style = "MetricGood.TLabel" if rate == 0 else "MetricWatch.TLabel" if rate <= 0.1 else "MetricAlert.TLabel"
        self.primary_loss_value.configure(style=style)

    def analysis_setup(self):
        path = Path(self.file_path.get())
        if not path.is_file():
            raise ValueError("请先拖入或选择日志文件。")
        is_modbus = self.profile.get().startswith("Modbus")
        is_length_field = self.profile.get() == "自定义长度字段帧"
        header = b"" if is_modbus else parse_hex(self.header.get())
        frame_size = None if (is_modbus or is_length_field) else int(self.frame_size.get())
        length_offset = int(self.length_offset.get()) if is_length_field else None
        length_size = int(self.length_size.get()) if is_length_field else 1
        length_adjust = int(self.length_adjust.get()) if is_length_field else 0
        seq_offset = int(self.seq_offset.get())
        seq_size = int(self.seq_size.get())
        max_gap = int(self.max_gap.get())
        time_window = int(self.time_window_seconds.get())
        coverage = float(self.cycle_coverage.get()) / 100
        self.transaction_timeout_value()
        manual_start, manual_count = self.manual_cycle_values()
        if not is_modbus and not is_length_field and frame_size <= len(header):
            raise ValueError("总帧长必须大于帧头长度。")
        if is_length_field and (length_offset is None or length_offset < 0 or length_size not in (1, 2, 4)):
            raise ValueError("请填写有效的长度字段偏移和字节数（1、2 或 4）。")
        if seq_offset < 0 or (frame_size is not None and seq_offset + seq_size > frame_size):
            raise ValueError("序号字段超出帧范围。")
        if max_gap < 0:
            raise ValueError("帧内超时不能小于 0。")
        if time_window < 1 or time_window > 3600:
            raise ValueError("时间统计窗口必须在 1 到 3600 秒之间。")
        if not 0 < coverage <= 1:
            raise ValueError("循环纳入阈值必须在 0 到 100 之间。")
        config = (
            FrameConfig(protocol=FrameProtocol.MODBUS_RTU, crc=CrcKind.MODBUS, max_frame_gap_ms=max_gap or None)
            if is_modbus
            else FrameConfig(
                header, fixed_length=frame_size, length_offset=length_offset, length_size=length_size,
                length_endian=self.length_endian.get(), length_adjust=length_adjust,
                crc=CrcKind(self.crc.get()), max_frame_gap_ms=max_gap or None,
            )
        )
        return path, config, seq_offset, seq_size, max_gap, time_window, coverage, manual_start, manual_count

    def ensure_input_chunks(self, path: Path) -> None:
        if self.input_chunks:
            return
        self.begin_operation("正在读取并识别收发方向")
        try:
            self.direction_read = read_directional_chunks(path, self.progress_callback("正在读取日志"))
        finally:
            self.finish_operation()
        has_markers = self.direction_read.direction_markers_found
        is_raw_receive = self.direction_read.raw_binary_receive
        rx_lines = len(self.direction_read.rx_chunks)
        self.input_chunks = self.direction_read.rx_chunks if (has_markers or is_raw_receive) else self.direction_read.unknown_chunks
        self.input_stream = b"".join(chunk.data for chunk in self.input_chunks)
        self.direction_note = (
            "检测到 SSCOM 原始二进制接收文件：已直接按 RX 字节流解析（文件本身不含 TX 记录）。"
            if is_raw_receive
            else f"仅使用接收数据（RX {rx_lines}，TX {len(self.direction_read.tx_chunks)}；方向置信度 {self.direction_read.direction_confidence:.0%}）。"
            if has_markers
            else "日志未发现 TX/RX 方向标记：数据被标记为“方向未知”，暂按全部 HEX 数据分析。"
        )

    def parse_with_progress(self, config: FrameConfig, message: str):
        self.begin_operation(message)
        try:
            return parse_chunks(self.input_chunks, config, self.progress_callback(message))
        finally:
            self.finish_operation()

    def preview_timestamp_rules(self, select_tab: bool = False) -> None:
        """Display file-derived table validation samples in the existing preview tab."""
        if self.timestamp_table is None or self.timestamp_gap_analysis is None:
            return
        analysis = self.timestamp_gap_analysis
        gap_at_line = {gap.end.line_no: gap for gap in analysis.gaps}
        self.preview_table.delete(*self.preview_table.get_children())
        self.set_preview_headings((
            ("frame", "记录样本", 80), ("lines", "日志行", 80), ("time", "记录时间", 125),
            ("bytes", "识别到的数据结构", 220), ("sequence", "相邻间隔", 120), ("check", "文件校验结果", 350),
        ))
        previous = None
        for index, row in enumerate(self.timestamp_table.rows[:10], start=1):
            interval = "起始记录"
            check = f"行尾时间戳有效；{self.timestamp_table.field_count} 列一致"
            if previous is not None:
                interval_ms = (row.timestamp - previous.timestamp).total_seconds() * 1000
                interval = f"{interval_ms:.1f} ms"
                if interval_ms < 0:
                    check += "；时间倒退（不计漏采）"
                elif row.line_no in gap_at_line:
                    gap = gap_at_line[row.line_no]
                    check += f"；时间断档，估计漏采 {gap.estimated_missing} 条"
                else:
                    check += "；处于自动学习的正常节拍内"
            self.preview_table.insert(
                "", END,
                values=(index, row.line_no, row.timestamp.strftime("%H:%M:%S.%f")[:-3], f"{row.field_count} 个数据字段", interval, check),
            )
            previous = row
        self.preview_confirmed = True
        self.preview_count = min(10, len(self.timestamp_table.rows))
        baseline = f"{analysis.baseline_interval_ms:.1f}" if analysis.baseline_interval_ms is not None else "不足"
        upper = f"{analysis.normal_upper_interval_ms:.1f}" if analysis.normal_upper_interval_ms is not None else "—"
        threshold = f"{analysis.threshold_ms:.1f}" if analysis.threshold_ms is not None else "—"
        self.preview_note.set(
            f"已随当前文件更新校验规则：{len(self.timestamp_table.rows)} 条有效记录，固定 {self.timestamp_table.field_count} 列，"
            f"中位节拍 {baseline} ms，正常上沿 {upper} ms，"
            f"断档阈值 {threshold} ms；断档 {len(analysis.gaps)} 处、疑似漏采 {analysis.suspected_missing} 条。"
        )
        if select_tab:
            self.notebook.select(self.preview_table.master)

    def preview_parameters(self) -> None:
        if self.timestamp_table is not None:
            self.preview_timestamp_rules(select_tab=True)
            return
        self.set_preview_headings((
            ("frame", "预览帧", 75), ("lines", "日志行", 85), ("time", "接收时间", 110),
            ("bytes", "按当前参数切出的完整帧", 360), ("sequence", "当前序号字段", 120), ("check", "核对结果", 220),
        ))
        try:
            path, config, seq_offset, seq_size, *_rest = self.analysis_setup()
            self.ensure_input_chunks(path)
            parsed = self.parse_with_progress(config, "正在按当前参数自检")
            if not parsed.frames:
                raise ValueError("当前规则没有切出完整帧；请检查帧头、帧长或长度字段。")
        except OperationCancelled:
            self.preview_note.set("参数自检已取消；当前结果未更新。")
            return
        except (OSError, ValueError) as error:
            messagebox.showerror("无法自检", str(error))
            return
        self.preview_table.delete(*self.preview_table.get_children())
        for index, (evidence, frame) in enumerate(zip(parsed.frame_evidence[:10], parsed.frames[:10]), start=1):
            sequence_bytes = frame[seq_offset : seq_offset + seq_size]
            sequence = int.from_bytes(sequence_bytes, self.endian.get()) if len(sequence_bytes) == seq_size else None
            lines = str(evidence.first_line_no) if evidence.last_line_no == evidence.first_line_no else f"{evidence.first_line_no}→{evidence.last_line_no}"
            timestamp = evidence.first_timestamp.strftime("%H:%M:%S.%f")[:-3] if evidence.first_timestamp else "—"
            check = "完整帧" + ("；CRC通过" if config.crc is not CrcKind.NONE else "；未启用CRC")
            self.preview_table.insert("", END, values=(index, lines, timestamp, frame.hex(" ").upper(), sequence if sequence is not None else "序号超出帧长", check))
        self.preview_confirmed = True
        self.preview_count = min(10, len(parsed.frames))
        self.preview_note.set(
            f"已按当前参数自检 {self.preview_count} 帧：完整帧 {len(parsed.frames)}，CRC错误 {parsed.crc_errors}，截断 {parsed.truncations}，噪声 {parsed.noise_bytes} 字节。请逐行确认帧内容与序号字段。"
        )
        self.notebook.select(self.preview_table.master)

    def credibility_summary(self, parsed, config: FrameConfig, cycle_model) -> dict:
        direction_clear = bool(self.direction_read and (self.direction_read.direction_markers_found or self.direction_read.raw_binary_receive))
        total_checked = len(parsed.frames) + parsed.crc_errors + parsed.truncations
        crc_rate = parsed.crc_errors / total_checked if total_checked else None
        checks = {
            "parameter_source": self.parameter_source.get(),
            "previewed_current_parameters": self.preview_confirmed,
            "previewed_frames": self.preview_count,
            "direction": "明确（原始二进制RX文件）" if self.direction_read and self.direction_read.raw_binary_receive else "明确（仅RX）" if direction_clear else "未知（按全部HEX分析）",
            "crc": "未启用" if config.crc is CrcKind.NONE else f"错误 {parsed.crc_errors}/{total_checked}",
            "cycle_evidence": (
                "不适用（连续序号）" if cycle_model is None
                else "使用者手动设定" if cycle_model.evidence_cycles == 0
                else f"{cycle_model.evidence_cycles} 个宽范围循环共同证实"
            ),
        }
        warnings = []
        score = 0
        if direction_clear:
            score += 1
        else:
            warnings.append("未识别TX/RX方向，统计包含方向未知数据")
        if self.preview_confirmed:
            score += 1
        else:
            warnings.append("尚未在当前参数下完成自检预览")
        if config.crc is CrcKind.NONE:
            warnings.append("未启用CRC，帧完整性只能按帧头和长度判断")
        elif parsed.crc_errors == 0:
            score += 1
        else:
            warnings.append(f"发现 {parsed.crc_errors} 条CRC错误帧")
        if parsed.truncations:
            warnings.append(f"发现 {parsed.truncations} 处截断")
        else:
            score += 1
        if cycle_model is not None and cycle_model.evidence_cycles >= 2:
            score += 1
        level = "较高" if score >= 4 and not warnings else "中等" if score >= 2 else "需复核"
        return {"level": level, "checks": checks, "warnings": warnings}

    def set_table_headings(self, headings) -> None:
        for key, text in headings:
            self.table.heading(key, text=text)
            self.table.column(key, width=130, anchor="center", stretch=True)

    def populate_evidence(self, parsed, sequences: list[int]) -> None:
        self.evidence.delete(*self.evidence.get_children())
        self.evidence_rows = []
        cycle_index = 0
        previous = None
        for index, (evidence, sequence) in enumerate(zip(parsed.frame_evidence, sequences), start=1):
            if previous is None or sequence < previous:
                cycle_index += 1
            status = "有效完整帧"
            if previous is None:
                status += "；分析起点"
            else:
                advance = sequence - previous
                if advance == 1:
                    status += "；与上一帧连续"
                elif advance == 0:
                    status += "；重复序号"
                elif advance > 1:
                    status += f"；上一帧后缺 {advance - 1}"
                else:
                    status += "；序号回绕/新循环"
            if self.cyclic_mode and cycle_index <= len(self.cycle_results):
                cycle = self.cycle_results[cycle_index - 1]
                status += f"；循环 {cycle_index} {'纳入' if cycle.included else '采集冗余'}"
            line_text = str(evidence.first_line_no)
            if evidence.last_line_no != evidence.first_line_no:
                line_text += f"→{evidence.last_line_no}"
            time_text = evidence.first_timestamp.strftime("%H:%M:%S.%f")[:-3] if evidence.first_timestamp else "—"
            full_hex = evidence.frame.hex(" ").upper()
            display_hex = full_hex if len(evidence.frame) <= 48 else full_hex[:143] + " …"
            row = {
                "frame": str(index), "lines": line_text, "time": time_text, "bytes": full_hex,
                "sequence": str(sequence), "status": status,
            }
            self.evidence_rows.append(row)
            self.evidence.insert("", END, values=(row["frame"], row["lines"], row["time"], display_hex, row["sequence"], row["status"]))
            previous = sequence
        for event in parsed.events:
            status = f"{event.kind}: {event.detail or '无额外说明'}"
            received = str(event.received) if event.received else ""
            expected = str(event.expected) if event.expected is not None else ""
            row = {"frame": "事件", "lines": "—", "time": "—", "bytes": f"已收 {received} / 期望 {expected}", "sequence": "—", "status": status}
            self.evidence_rows.append(row)
            self.evidence.insert("", END, values=(row["frame"], row["lines"], row["time"], row["bytes"], row["sequence"], row["status"]))

    def populate_time_windows(self, parsed, sequences: list[int], sequence_size: int, max_gap: int, window_seconds: int) -> tuple[float | None, list]:
        self.time_table.delete(*self.time_table.get_children())
        baseline, windows = analyze_time_windows(parsed.frame_evidence, sequences, sequence_size, max_gap, window_seconds)
        for window in windows:
            average = f"{window.average_interval_ms:.1f} ms" if window.average_interval_ms is not None else "—"
            maximum = f"{window.max_interval_ms:.1f} ms" if window.max_interval_ms is not None else "—"
            self.time_table.insert(
                "", END,
                values=(window.start.strftime("%H:%M:%S"), window.received, window.missing, f"{window.loss_percent:.2f}%", average, maximum, window.long_intervals),
            )
        return baseline, windows

    def populate_comparisons(self, config, seq_offset: int, seq_size: int, endian: str, max_gap: int, coverage: float, manual_start: int | None, manual_count: int | None) -> None:
        self.comparison_table.delete(*self.comparison_table.get_children())
        self.comparison_rows = []
        for path in self.compare_paths:
            try:
                analysis = analyze_log(path, config, seq_offset, seq_size, endian, max_gap, coverage, manual_start, manual_count)
                direction = analysis.direction_read
                direction_text = "原始RX" if direction.raw_binary_receive else f"{len(direction.rx_chunks)}/{len(direction.tx_chunks)}" if direction.direction_markers_found else "方向未知"
                included_cycles = [cycle for cycle in analysis.cycle_results if cycle.included]
                worst_cycle = max(included_cycles, key=lambda cycle: cycle.missing / cycle.expected) if included_cycles else None
                result = (
                    f"循环 {analysis.cycle_model.first_sequence}..{analysis.cycle_model.last_sequence}"
                    if analysis.cycle_model else f"重复 {analysis.duplicates}；异常跳变 {analysis.resets}"
                )
                row = {
                    "file": path.name, "mode": "循环" if analysis.cycle_model else "连续", "frames": str(len(analysis.sequences)),
                    "loss": f"{analysis.loss_percent:.4f}%", "missing": str(analysis.missing),
                    "worst": f"第 {worst_cycle.index} 轮 {worst_cycle.missing / worst_cycle.expected * 100:.2f}%" if worst_cycle else "—",
                    "crc": str(analysis.parsed.crc_errors), "truncated": str(analysis.parsed.truncations),
                    "direction": direction_text, "result": result,
                }
            except (OSError, ValueError) as error:
                row = {"file": path.name, "mode": "—", "frames": "—", "loss": "—", "missing": "—", "worst": "—", "crc": "—", "truncated": "—", "direction": "—", "result": f"无法分析：{error}"}
            self.comparison_rows.append(row)
            self.comparison_table.insert("", END, values=tuple(row[key] for key in ("file", "mode", "frames", "loss", "missing", "worst", "crc", "truncated", "direction", "result")))
        self.comparison_export_button.configure(state="normal" if self.comparison_rows else "disabled")

    def profile_values(self) -> dict[str, str]:
        return {
            "profile": self.profile.get(), "header": self.header.get(), "frame_size": self.frame_size.get(),
            "length_offset": self.length_offset.get(), "length_size": self.length_size.get(),
            "length_endian": self.length_endian.get(), "length_adjust": self.length_adjust.get(),
            "seq_offset": self.seq_offset.get(), "seq_size": self.seq_size.get(), "endian": self.endian.get(),
            "max_gap": self.max_gap.get(), "crc": self.crc.get(), "cycle_coverage": self.cycle_coverage.get(),
            "transaction_timeout": self.transaction_timeout.get(), "manual_cycle_start": self.manual_cycle_start.get(),
            "manual_cycle_count": self.manual_cycle_count.get(), "time_window_seconds": self.time_window_seconds.get(),
        }

    def save_profile(self) -> None:
        filename = filedialog.asksaveasfilename(
            title="保存协议方案", defaultextension=".json", initialfile="serial-protocol-profile.json",
            filetypes=(("协议方案", "*.json"),),
        )
        if not filename:
            return
        try:
            with Path(filename).open("w", encoding="utf-8") as output:
                json.dump({"format": "serial-loss-profile", "version": 1, "parameters": self.profile_values()}, output, ensure_ascii=False, indent=2)
            messagebox.showinfo("方案已保存", f"已保存：\n{filename}")
        except OSError as error:
            messagebox.showerror("无法保存方案", str(error))

    def load_profile(self) -> None:
        filename = filedialog.askopenfilename(title="加载协议方案", filetypes=(("协议方案", "*.json"), ("所有文件", "*.*")))
        if not filename:
            return
        try:
            with Path(filename).open(encoding="utf-8") as source:
                document = json.load(source)
            values = document.get("parameters") if isinstance(document, dict) else None
            if not isinstance(document, dict) or document.get("format") != "serial-loss-profile" or not isinstance(values, dict):
                raise ValueError("不是本工具导出的协议方案。")
            self._setting_parameters = True
            try:
                for key, variable in (
                    ("profile", self.profile), ("header", self.header), ("frame_size", self.frame_size),
                    ("length_offset", self.length_offset), ("length_size", self.length_size),
                    ("length_endian", self.length_endian), ("length_adjust", self.length_adjust),
                    ("seq_offset", self.seq_offset), ("seq_size", self.seq_size), ("endian", self.endian),
                    ("max_gap", self.max_gap), ("crc", self.crc), ("cycle_coverage", self.cycle_coverage),
                    ("transaction_timeout", self.transaction_timeout), ("manual_cycle_start", self.manual_cycle_start),
                    ("manual_cycle_count", self.manual_cycle_count), ("time_window_seconds", self.time_window_seconds),
                ):
                    if key in values:
                        variable.set(str(values[key]))
            finally:
                self._setting_parameters = False
            self.parameter_source.set("已加载方案（请重新自检）")
            self.invalidate_preview()
            messagebox.showinfo("方案已加载", "协议参数已加载；请先点“参数自检”核对，再开始统计。")
        except (OSError, ValueError, json.JSONDecodeError) as error:
            messagebox.showerror("无法加载方案", str(error))

    def transaction_timeout_value(self) -> int | None:
        value = int(self.transaction_timeout.get())
        if value < 0:
            raise ValueError("收发超时不能小于 0。")
        return value or None

    def manual_cycle_values(self) -> tuple[int | None, int | None]:
        start_text, count_text = self.manual_cycle_start.get().strip(), self.manual_cycle_count.get().strip()
        if not start_text and not count_text:
            return None, None
        if not start_text or not count_text:
            raise ValueError("手动循环需要同时填写起始序号和理论帧数，或两项都留空自动推断。")
        start, count = int(start_text), int(count_text)
        if count < 2:
            raise ValueError("手动理论帧数必须至少为 2。")
        return start, count

    def choose_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="选择 SSCOM 导出日志",
            filetypes=(("日志文件", "*.txt *.csv *.dat"), ("文本文件", "*.txt"), ("CSV 文件", "*.csv"), ("DAT 文件", "*.dat"), ("所有文件", "*.*")),
        )
        if filename:
            self.load_file(Path(filename))

    def choose_compare_files(self) -> None:
        filenames = filedialog.askopenfilenames(
            title="选择同一协议的多份日志",
            filetypes=(("日志文件", "*.txt *.csv *.dat"), ("所有文件", "*.*")),
        )
        if filenames:
            self.load_files([Path(filename) for filename in filenames])

    def on_drop(self, event) -> None:
        paths = self.root.tk.splitlist(event.data)
        if paths:
            self.load_files([Path(path) for path in paths])

    def load_files(self, paths: list[Path]) -> None:
        valid = [path for path in paths if path.suffix.lower() in {".txt", ".csv", ".dat"}]
        if not valid:
            messagebox.showerror("文件类型不支持", "请选择 TXT、CSV 或 DAT 日志文件。")
            return
        self.load_file(valid[0], comparison_paths=valid)
        if len(valid) > 1:
            self.result.set(self.result.get() + f"\n已加入 {len(valid)} 份同协议日志；点击“开始统计”后在“多文件对比”页查看横向结果。")

    def load_file(self, path: Path, comparison_paths: list[Path] | None = None) -> None:
        if path.suffix.lower() not in {".txt", ".csv", ".dat"}:
            messagebox.showerror("文件类型不支持", "请选择 TXT、CSV 或 DAT 日志文件。")
            return
        if self.profile.get() == "时间戳表格（自动）":
            self._setting_parameters = True
            try:
                self.profile.set("自定义固定帧")
            finally:
                self._setting_parameters = False
            self.restore_protocol_parameter_inputs()
        self.file_path.set(str(path))
        self.compare_paths = comparison_paths or [path]
        self.gaps = []
        self.cycle_results = []
        self.cyclic_mode = False
        self.input_stream = b""
        self.input_chunks = []
        self.direction_read = None
        self.timestamp_table = None
        self.timestamp_gap_analysis = None
        self.rule_summary.set("导入日志后，这里会显示当前文件实际识别到的格式与统计口径。")
        self.preview_button.configure(text="参数自检")
        self.table.delete(*self.table.get_children())
        self.evidence.delete(*self.evidence.get_children())
        self.time_table.delete(*self.time_table.get_children())
        self.comparison_table.delete(*self.comparison_table.get_children())
        self.invalidate_preview()
        self.reset_primary_loss()
        self.evidence_rows = []
        self.comparison_rows = []
        self.last_report = None
        self.export_button.configure(state="disabled")
        self.evidence_export_button.configure(state="disabled")
        self.report_export_button.configure(state="disabled")
        self.comparison_export_button.configure(state="disabled")
        self.auto_detect(silent=True)

    def auto_detect(self, silent: bool = False) -> None:
        self.begin_operation("正在读取并自动识别")
        try:
            path = Path(self.file_path.get())
            if not path.is_file():
                raise ValueError("请先拖入或选择日志文件。")
            self.timestamp_table = detect_timestamp_table(path, self.progress_callback("正在识别时间戳表格"))
            if self.timestamp_table is not None:
                self.show_timestamp_table_parameters()
                self.parameter_source.set("自动识别：时间戳表格日志（无需帧参数）")
                self.preview_note.set("此类日志按“每行一条记录 + 末尾时间戳”统计，不进行帧参数自检。")
                self.preview_button.configure(text="时间规则预览")
                self.direction_note = (
                    f"已识别为时间戳表格日志：每条记录 {self.timestamp_table.field_count} 个数据字段，"
                    f"共 {len(self.timestamp_table.rows)} 条有效记录。"
                )
                self.analyze_timestamp_table()
                self.preview_timestamp_rules()
                return
            self.direction_read = read_directional_chunks(path, self.progress_callback("正在读取日志"))
            has_markers = self.direction_read.direction_markers_found
            is_raw_receive = self.direction_read.raw_binary_receive
            rx_lines = len(self.direction_read.rx_chunks)
            self.input_chunks = self.direction_read.rx_chunks if (has_markers or is_raw_receive) else self.direction_read.unknown_chunks
            self.input_stream = b"".join(chunk.data for chunk in self.input_chunks)
            self.direction_note = (
                "检测到 SSCOM 原始二进制接收文件：已直接按 RX 字节流解析（文件本身不含 TX 记录）。"
                if is_raw_receive
                else f"仅使用接收数据（SSCOM方向标签 {self.direction_read.native_sscom_markers} 行；RX {rx_lines}，TX {len(self.direction_read.tx_chunks)}；方向置信度 {self.direction_read.direction_confidence:.0%}）。"
                if has_markers
                else "日志未发现 TX/RX 方向标记：数据被标记为“方向未知”，暂按全部 HEX 数据分析。"
            )
            timeout = self.transaction_timeout_value()
            transaction = match_transactions(self.direction_read, timeout)
            if has_markers and (transaction.sent or transaction.received):
                latency = f"，平均往返 {transaction.average_latency_ms:.1f} ms" if transaction.average_latency_ms is not None else ""
                self.transaction_note = (
                    f"收发核对（不参与丢包率）：TX {transaction.sent}，RX {transaction.received}，按时间配对 {transaction.paired}，"
                    f"未响应TX {transaction.unmatched_sent}（超时 {transaction.timed_out_sent}），孤立RX {transaction.orphan_received}，"
                    f"命令地址/功能码证实 {transaction.key_confirmed}{latency}。"
                )
            else:
                self.transaction_note = ""
            modbus = detect_modbus_rtu(self.input_chunks, self.progress_callback("正在验证 Modbus 帧"))
            if modbus is not None:
                captured, parsed = modbus
                suggested = detect_sequence_field(captured)
                self._setting_parameters = True
                try:
                    self.profile.set("Modbus RTU（CRC自动帧长）")
                    self.crc.set(CrcKind.MODBUS.value)
                    if suggested:
                        self.seq_offset.set(str(suggested[0]))
                        self.seq_size.set(str(suggested[1]))
                        self.endian.set(suggested[2])
                        sequence_text = f"候选序号偏移 {suggested[0]}、{suggested[1]} 字节、{suggested[2]}"
                    else:
                        sequence_text = "未发现可信的递增序号字段"
                finally:
                    self._setting_parameters = False
                observed_pairs = self.show_modbus_parameters(captured)
                self.parameter_source.set("自动识别候选（请自检）")
                self.invalidate_preview()
                self.result.set(
                    f"已验证为 Modbus RTU：{len(captured)} 条完整帧全部经 CRC16-Modbus 校验；{sequence_text}。\n"
                    f"{self.direction_note}\n{self.transaction_note}\n请核对序号字段后点击“开始统计”。"
                )
                self.rule_summary.set(
                    f"当前文件识别：Modbus RTU；完整 CRC 通过帧 {len(captured)} 条；实际站号/功能码 {observed_pairs}；{sequence_text}。"
                    "以下参数是候选值，点击“参数自检”可查看具体帧。"
                )
                return
            detected = detect_protocol(self.input_stream, self.progress_callback("正在推断固定帧"))
            if detected is None:
                raise ValueError("日志数据不足，或未找到间距稳定的固定长度帧。")
            self._setting_parameters = True
            try:
                self.header.set(detected.header.hex().upper())
                self.frame_size.set(str(detected.frame_size))
                if detected.seq_offset is not None:
                    self.seq_offset.set(str(detected.seq_offset))
                    self.seq_size.set(str(detected.seq_size))
                    self.endian.set(detected.endian or "little")
                    sequence_text = f"序号偏移 {detected.seq_offset}、{detected.seq_size} 字节、{detected.endian}"
                else:
                    sequence_text = "未能可靠识别序号字段，请手动填写"
            finally:
                self._setting_parameters = False
            self.parameter_source.set("自动识别候选（请自检）")
            self.invalidate_preview()
            self.result.set(
                f"已自动识别：帧头 {detected.header.hex(' ').upper()}，总帧长 {detected.frame_size} 字节；{sequence_text}。\n"
                f"{self.direction_note} 间距置信度 {detected.confidence:.0%}；请核对后点击“开始统计”。\n{self.transaction_note}"
            )
            self.rule_summary.set(
                f"当前文件识别：固定帧头 {detected.header.hex(' ').upper()}，总帧长 {detected.frame_size} 字节，"
                f"{sequence_text}，帧间距置信度 {detected.confidence:.0%}。"
            )
        except OperationCancelled:
            self.result.set("自动识别已取消；当前参数未改变。")
        except (OSError, ValueError) as error:
            if not silent:
                messagebox.showwarning("无法自动识别", str(error))
            elif self.file_path.get():
                self.result.set("已加载：%s\n未能自动识别协议，请手动填写参数后统计。" % path.name)
        finally:
            self.finish_operation()

    def populate_timestamp_evidence(self) -> None:
        """Show only discontinuity evidence; this format has no protocol frames."""
        self.evidence.delete(*self.evidence.get_children())
        self.evidence_rows = []
        analysis = self.timestamp_gap_analysis
        if analysis is None:
            return
        for index, gap in enumerate(analysis.gaps, start=1):
            row = {
                "frame": f"断档 {index}",
                "lines": f"{gap.start.line_no}→{gap.end.line_no}",
                "time": gap.end.timestamp.strftime("%H:%M:%S.%f")[:-3],
                "bytes": f"{gap.start.timestamp.strftime('%H:%M:%S.%f')[:-3]} → {gap.end.timestamp.strftime('%H:%M:%S.%f')[:-3]}（{gap.interval_ms:.1f} ms）",
                "sequence": str(gap.estimated_missing),
                "status": "疑似漏采；仅由时间断档推测，非序号确证",
            }
            self.evidence_rows.append(row)
            self.evidence.insert("", END, values=(row["frame"], row["lines"], row["time"], row["bytes"], row["sequence"], row["status"]))

    def populate_timestamp_windows(self, windows: list) -> None:
        self.time_table.delete(*self.time_table.get_children())
        for window in windows:
            average = f"{window.average_interval_ms:.1f} ms" if window.average_interval_ms is not None else "—"
            maximum = f"{window.max_interval_ms:.1f} ms" if window.max_interval_ms is not None else "—"
            self.time_table.insert(
                "", END,
                values=(window.start.strftime("%H:%M:%S"), window.received, window.missing, f"{window.loss_percent:.2f}%", average, maximum, window.long_intervals),
            )

    def populate_timestamp_comparisons(self) -> None:
        self.comparison_table.delete(*self.comparison_table.get_children())
        self.comparison_rows = []
        for path in self.compare_paths:
            try:
                table = detect_timestamp_table(path)
                if table is None:
                    raise ValueError("不是同类的时间戳表格日志")
                analysis = analyze_timestamp_gaps(table)
                baseline = f"{analysis.baseline_interval_ms:.1f} ms" if analysis.baseline_interval_ms else "—"
                threshold = f"{analysis.threshold_ms:.1f} ms" if analysis.threshold_ms else "—"
                row = {
                    "file": path.name, "mode": "时间断档", "frames": str(analysis.received),
                    "loss": f"{analysis.gap_rate_percent:.4f}%", "missing": str(analysis.suspected_missing),
                    "worst": f"阈值 {threshold}", "crc": "—", "truncated": str(table.invalid_rows),
                    "direction": "表格时间戳", "result": f"基准 {baseline}；断档 {len(analysis.gaps)} 次",
                }
            except (OSError, ValueError) as error:
                row = {"file": path.name, "mode": "—", "frames": "—", "loss": "—", "missing": "—", "worst": "—", "crc": "—", "truncated": "—", "direction": "—", "result": f"无法分析：{error}"}
            self.comparison_rows.append(row)
            self.comparison_table.insert("", END, values=tuple(row[key] for key in ("file", "mode", "frames", "loss", "missing", "worst", "crc", "truncated", "direction", "result")))
        self.comparison_export_button.configure(state="normal" if self.comparison_rows else "disabled")

    def analyze_timestamp_table(self) -> None:
        """Analyze an already-decoded table log without pretending it is UART HEX."""
        if self.timestamp_table is None:
            raise ValueError("尚未识别到时间戳表格日志。")
        try:
            time_window = int(self.time_window_seconds.get())
            if not 1 <= time_window <= 3600:
                raise ValueError("时间统计窗口必须在 1 到 3600 秒之间。")
        except ValueError as error:
            messagebox.showerror("无法统计", str(error))
            return
        path = Path(self.file_path.get())
        analysis = analyze_timestamp_gaps(self.timestamp_table)
        windows = analyze_timestamp_windows(self.timestamp_table, analysis, time_window)
        self.timestamp_gap_analysis = analysis
        baseline = f"{analysis.baseline_interval_ms:.1f} ms" if analysis.baseline_interval_ms is not None else "不足"
        upper = f"{analysis.normal_upper_interval_ms:.1f} ms" if analysis.normal_upper_interval_ms is not None else "—"
        threshold = f"{analysis.threshold_ms:.1f} ms" if analysis.threshold_ms is not None else "—"
        self.rule_summary.set(
            f"当前文件识别：时间戳表格；有效记录 {analysis.received} 条，固定 {self.timestamp_table.field_count} 列，"
            f"异常行 {self.timestamp_table.invalid_rows}，时间倒退 {analysis.time_reversals} 次。"
            f"自动节拍：中位 {baseline}，正常上沿 {upper}，"
            f"断档阈值 {threshold}；以下帧协议参数对此文件不参与统计。"
        )
        self.table.delete(*self.table.get_children())
        self.gaps = []
        self.cycle_results = []
        self.cyclic_mode = False
        self.set_table_headings((("after", "断档起点"), ("first", "断档终点"), ("last", "实际 / 基准间隔"), ("count", "疑似漏采")))
        for gap in analysis.gaps:
            self.table.insert(
                "", END,
                values=(
                    gap.start.timestamp.strftime("%H:%M:%S.%f")[:-3],
                    gap.end.timestamp.strftime("%H:%M:%S.%f")[:-3],
                    f"{gap.interval_ms:.1f} / {analysis.baseline_interval_ms:.1f} ms",
                    gap.estimated_missing,
                ),
            )
        primary_label = "时间断档率（疑似漏采）"
        primary_detail = (
            f"统计口径：有效记录 {analysis.received}，以自动学习的时间节拍识别 {len(analysis.gaps)} 处断档，"
            f"估计漏采 {analysis.suspected_missing} 条；无递增序号，不能称为精确丢包率。"
        )
        self.set_primary_loss(analysis.gap_rate_percent, primary_label, primary_detail)
        self.populate_timestamp_evidence()
        self.populate_timestamp_windows(windows)
        self.populate_timestamp_comparisons()
        self.result.set(
            f"{self.direction_note}\n"
            f"时间断档模式：有效记录 {analysis.received}，字段数 {self.timestamp_table.field_count}，格式异常行 {self.timestamp_table.invalid_rows}，时间倒退 {analysis.time_reversals} 次。\n"
            f"自动节拍：中位间隔 {baseline}，正常上沿 {upper}，断档阈值 {threshold}（取中位间隔 × 1.6 与正常上沿 × 1.25 的较大值）。\n"
            f"发现 {len(analysis.gaps)} 处时间断档，疑似漏采 {analysis.suspected_missing} 条，时间断档率 {analysis.gap_rate_percent:.4f}%。\n"
            "说明：该结论只反映日志记录时间的不连续；未携带递增序号时，不能区分设备未发送、链路漏收或日志程序未写入。"
        )
        credibility = {
            "level": "较高" if not self.timestamp_table.invalid_rows and not analysis.time_reversals else "中等",
            "checks": {
                "mode": "固定列数 + 行尾完整时间戳自动识别",
                "valid_records": analysis.received,
                "field_count": self.timestamp_table.field_count,
                "invalid_rows": self.timestamp_table.invalid_rows,
                "time_reversals": analysis.time_reversals,
            },
            "warnings": (["此格式没有递增序号，时间断档率不是精确丢包率"] +
                         ([f"发现 {self.timestamp_table.invalid_rows} 行格式异常"] if self.timestamp_table.invalid_rows else []) +
                         ([f"发现 {analysis.time_reversals} 次时间倒退"] if analysis.time_reversals else [])),
        }
        file_bytes = path.read_bytes()
        self.last_report = {
            "format": "serial-loss-analysis-report", "version": 2,
            "input": {"file_name": path.name, "bytes": len(file_bytes), "sha256": hashlib.sha256(file_bytes).hexdigest()},
            "parameters": {"mode": "timestamp_table", "time_window_seconds": time_window, "gap_rule": "max(median*1.6, p95*1.25)"},
            "statistics": {
                "mode": "timestamp_table", "valid_records": analysis.received,
                "field_count": self.timestamp_table.field_count, "invalid_rows": self.timestamp_table.invalid_rows,
                "baseline_interval_ms": analysis.baseline_interval_ms, "normal_upper_interval_ms": analysis.normal_upper_interval_ms,
                "gap_threshold_ms": analysis.threshold_ms, "time_reversals": analysis.time_reversals,
                "suspected_missing_records": analysis.suspected_missing, "time_gap_rate_percent": analysis.gap_rate_percent,
                "gaps": [{"start_line": gap.start.line_no, "end_line": gap.end.line_no, "start": gap.start.timestamp.isoformat(), "end": gap.end.timestamp.isoformat(), "interval_ms": gap.interval_ms, "estimated_missing": gap.estimated_missing} for gap in analysis.gaps],
            },
            "time_statistics": {"window_seconds": time_window, "windows": [{"start": item.start.isoformat(), "received": item.received, "suspected_missing": item.missing, "time_gap_rate_percent": item.loss_percent, "average_interval_ms": item.average_interval_ms, "max_interval_ms": item.max_interval_ms, "time_gaps": item.long_intervals} for item in windows]},
            "credibility": credibility,
            "evidence_csv_columns": ["frame", "lines", "time", "bytes", "sequence", "status"],
            "comparisons": self.comparison_rows,
        }
        self.export_button.configure(state="normal")
        self.evidence_export_button.configure(state="normal")
        self.report_export_button.configure(state="normal")

    def analyze(self) -> None:
        if self.timestamp_table is not None:
            self.analyze_timestamp_table()
            return
        try:
            path, config, seq_offset, seq_size, max_gap, time_window, coverage, manual_start, manual_count = self.analysis_setup()
            self.ensure_input_chunks(path)
            parsed = self.parse_with_progress(config, "正在验证完整帧")
            captured = parsed.frames
            sequences = [int.from_bytes(frame[seq_offset : seq_offset + seq_size], self.endian.get()) for frame in captured]
            if not sequences:
                raise ValueError("没有找到完整帧。请检查帧头和总帧长。")
            cyclic = analyze_cycles(sequences, coverage, manual_start, manual_count)
        except OperationCancelled:
            self.result.set("统计已取消；未覆盖上一份统计结果。")
            return
        except (OSError, ValueError) as error:
            messagebox.showerror("无法统计", str(error))
            return

        self.table.delete(*self.table.get_children())
        self.cycle_results = []
        self.gaps = []
        self.cyclic_mode = cyclic is not None
        cycle_model = cyclic[0] if cyclic is not None else None
        analysis_stats = {}
        if cyclic is not None:
            model, self.cycle_results = cyclic
            expected = model.expected
            included = [cycle for cycle in self.cycle_results if cycle.included]
            missing = sum(cycle.missing for cycle in included)
            received = sum(cycle.received for cycle in included)
            rate = 100 * missing / (received + missing) if received + missing else 0.0
            self.set_table_headings((("after", "循环 / 范围"), ("first", "接收帧数"), ("last", "理论帧数"), ("count", "结果 / 丢包率")))
            for cycle in self.cycle_results:
                if cycle.included:
                    result = f"纳入  {cycle.missing / cycle.expected * 100:.2f}%（缺 {cycle.missing}）"
                else:
                    result = f"忽略（少于 {coverage * 100:g}%）"
                self.table.insert("", END, values=(f"{cycle.index} ({cycle.first}..{cycle.last})", cycle.received, cycle.expected, result))
            ignored = len(self.cycle_results) - len(included)
            raw_missing = sum(cycle.missing for cycle in self.cycle_results)
            raw_received = sum(cycle.received for cycle in self.cycle_results)
            raw_rate = 100 * raw_missing / (raw_received + raw_missing) if raw_received + raw_missing else 0.0
            primary_label = "纳入循环的平均丢包率"
            primary_detail = (
                f"统计口径：仅纳入收到不少于 {coverage * 100:g}% 理论帧数的 {len(included)}/{len(self.cycle_results)} 轮；"
                f"全部循环丢包率 {raw_rate:.4f}%。"
            )
            analysis_stats = {
                "mode": "cycle", "sequence_range": [model.first_sequence, model.last_sequence],
                "expected_per_cycle": expected, "domain_evidence_cycles": model.evidence_cycles,
                "coverage_threshold_percent": coverage * 100, "all_cycles_loss_percent": raw_rate,
                "included_cycles_loss_percent": rate,
                "cycles": [{"index": cycle.index, "received": cycle.received, "missing": cycle.missing, "included": cycle.included, "missing_sequence_ids": list(cycle.missing_values)} for cycle in self.cycle_results],
            }
            self.result.set(
                f"{self.direction_note} 完整帧 {len(captured)}，截断 {parsed.truncations}，CRC错误 {parsed.crc_errors}，噪声 {parsed.noise_bytes} 字节。\n循环模式：自动识别每轮理论帧数为 {expected}。共 {len(self.cycle_results)} 轮，纳入 {len(included)} 轮，忽略 {ignored} 轮。\n"
                f"理论序号范围：{model.first_sequence}..{model.last_sequence}，"
                f"{'由使用者手动设定' if model.evidence_cycles == 0 else f'由 {model.evidence_cycles} 个完整范围循环共同证实'}。\n"
                f"全部循环丢包率：{raw_rate:.4f}%；纳入循环的平均丢包率：{rate:.4f}%（少于 {expected * coverage:g} 帧，即 {coverage * 100:g}% 的循环未计入）。\n"
                f"每轮的确切缺失序号可通过“导出缺失明细 CSV”复核。\n{self.transaction_note}"
            )
        else:
            modulus = 1 << (8 * seq_size)
            duplicates = resets = 0
            for previous, current in zip(sequences, sequences[1:]):
                advance = (current - previous) % modulus
                if advance == 0:
                    duplicates += 1
                elif advance == 1:
                    continue
                elif advance - 1 <= max_gap:
                    self.gaps.append(Gap(previous, (previous + 1) % modulus, (current - 1) % modulus, advance - 1))
                else:
                    resets += 1
            missing = sum(gap.count for gap in self.gaps)
            rate = 100 * missing / (len(sequences) + missing)
            primary_label = "连续序号丢包率"
            primary_detail = f"统计口径：有效完整帧 {len(sequences)}，缺失帧 {missing}；重复和异常跳变不计作丢包。"
            analysis_stats = {
                "mode": "continuous", "received_frames": len(sequences), "missing_frames": missing,
                "loss_percent": rate, "duplicates": duplicates, "restart_or_outlier": resets,
                "gaps": [{"after": gap.after, "first_missing": gap.first_missing, "last_missing": gap.last_missing, "count": gap.count} for gap in self.gaps],
            }
            self.set_table_headings((("after", "前一序号"), ("first", "首个缺失"), ("last", "最后缺失"), ("count", "缺失帧数")))
            for gap in self.gaps:
                self.table.insert("", END, values=(gap.after, gap.first_missing, gap.last_missing, gap.count))
            self.result.set(
                f"{self.direction_note} 完整帧 {len(captured)}，截断 {parsed.truncations}，CRC错误 {parsed.crc_errors}，噪声 {parsed.noise_bytes} 字节。\n连续序号模式：接收帧数 {len(sequences)}，丢失帧数 {missing}，丢包率 {rate:.4f}%。\n"
                f"重复序号：{duplicates}    疑似复位/异常跳变：{resets}    缺失区段：{len(self.gaps)}\n{self.transaction_note}"
            )
        self.set_primary_loss(rate, primary_label, primary_detail)
        self.populate_evidence(parsed, sequences)
        interval_baseline, time_windows = self.populate_time_windows(parsed, sequences, seq_size, max_gap, time_window)
        self.populate_comparisons(config, seq_offset, seq_size, self.endian.get(), max_gap, coverage, manual_start, manual_count)
        if time_windows:
            worst = max(time_windows, key=lambda item: (item.loss_percent, item.long_intervals, item.max_interval_ms or 0))
            baseline_text = f"基准帧间隔 {interval_baseline:.1f} ms" if interval_baseline is not None else "基准帧间隔不足"
            self.result.set(self.result.get() + f"\n时间定位：{baseline_text}；最需关注 {worst.start.strftime('%H:%M:%S')}，丢包 {worst.loss_percent:.2f}%，异常长间隔 {worst.long_intervals} 次。")
        else:
            self.result.set(self.result.get() + "\n时间定位：日志缺少可用时间戳，无法按时间段统计。")
        credibility = self.credibility_summary(parsed, config, cycle_model)
        warning_text = "；".join(credibility["warnings"]) if credibility["warnings"] else "未发现方向、完整性或自检告警"
        self.result.set(
            self.result.get()
            + f"\n可信度摘要：{credibility['level']}。方向：{credibility['checks']['direction']}；参数：{credibility['checks']['parameter_source']}；"
            + f"自检：{'已核对前 ' + str(credibility['checks']['previewed_frames']) + ' 帧' if credibility['checks']['previewed_current_parameters'] else '未完成'}；"
            + f"循环：{credibility['checks']['cycle_evidence']}。提示：{warning_text}。"
        )
        transaction = match_transactions(self.direction_read, self.transaction_timeout_value()) if self.direction_read and self.direction_read.direction_markers_found else None
        file_bytes = path.read_bytes()
        self.last_report = {
            "format": "serial-loss-analysis-report", "version": 1,
            "input": {"file_name": path.name, "bytes": len(file_bytes), "sha256": hashlib.sha256(file_bytes).hexdigest()},
            "parameters": self.profile_values(),
            "direction": {
                "markers_found": bool(self.direction_read and self.direction_read.direction_markers_found),
                "raw_binary_capture": bool(self.direction_read and self.direction_read.raw_binary_capture),
                "raw_binary_receive": bool(self.direction_read and self.direction_read.raw_binary_receive),
                "rx_records": len(self.direction_read.rx_chunks) if self.direction_read else 0,
                "tx_records": len(self.direction_read.tx_chunks) if self.direction_read else 0,
                "unknown_records": len(self.direction_read.unknown_chunks) if self.direction_read else 0,
                "confidence": self.direction_read.direction_confidence if self.direction_read else 0,
            },
            "frame_parsing": {
                "complete_frames": len(captured), "truncations": parsed.truncations,
                "crc_errors": parsed.crc_errors, "noise_bytes": parsed.noise_bytes,
                "events": [{"kind": event.kind, "received": event.received, "expected": event.expected, "detail": event.detail} for event in parsed.events],
            },
            "statistics": analysis_stats,
            "credibility": credibility,
            "time_statistics": {
                "window_seconds": time_window, "baseline_interval_ms": interval_baseline,
                "windows": [{
                    "start": item.start.isoformat(), "received": item.received, "missing": item.missing,
                    "loss_percent": item.loss_percent, "average_interval_ms": item.average_interval_ms,
                    "max_interval_ms": item.max_interval_ms, "long_intervals": item.long_intervals,
                } for item in time_windows],
            },
            "transactions": None if transaction is None else {
                "sent": transaction.sent, "received": transaction.received, "paired": transaction.paired,
                "unmatched_sent": transaction.unmatched_sent, "timed_out_sent": transaction.timed_out_sent,
                "orphan_received": transaction.orphan_received, "key_confirmed": transaction.key_confirmed,
                "average_latency_ms": transaction.average_latency_ms,
            },
            "evidence_csv_columns": ["frame", "lines", "time", "bytes", "sequence", "status"],
            "comparisons": self.comparison_rows,
        }
        self.export_button.configure(state="normal")
        self.evidence_export_button.configure(state="normal")
        self.report_export_button.configure(state="normal")

    def export(self) -> None:
        filename = filedialog.asksaveasfilename(
            title="保存缺失明细",
            defaultextension=".csv",
            initialfile="serial-loss-report.csv",
            filetypes=(("CSV 文件", "*.csv"),),
        )
        if not filename:
            return
        with Path(filename).open("w", newline="", encoding="utf-8-sig") as output:
            writer = csv.writer(output)
            if self.timestamp_gap_analysis is not None:
                writer.writerow(("start_line", "end_line", "start_time", "end_time", "interval_ms", "baseline_interval_ms", "estimated_missing", "note"))
                for gap in self.timestamp_gap_analysis.gaps:
                    writer.writerow((
                        gap.start.line_no, gap.end.line_no, gap.start.timestamp.isoformat(), gap.end.timestamp.isoformat(),
                        f"{gap.interval_ms:.3f}", f"{self.timestamp_gap_analysis.baseline_interval_ms:.3f}",
                        gap.estimated_missing, "suspected_missing_from_time_gap_not_sequence_confirmed",
                    ))
            elif self.cyclic_mode:
                writer.writerow(("cycle", "observed_first", "observed_last", "received_frames", "expected_frames", "missing_frames", "duplicate_frames", "included", "missing_sequence_ids"))
                for cycle in self.cycle_results:
                    writer.writerow((
                        cycle.index, cycle.first, cycle.last, cycle.received, cycle.expected,
                        cycle.missing, cycle.duplicates,
                        "yes" if cycle.included else "ignored_under_50_percent",
                        " ".join(map(str, cycle.missing_values)),
                    ))
            else:
                writer.writerow(("previous_sequence", "first_missing", "last_missing", "missing_count"))
                for gap in self.gaps:
                    writer.writerow((gap.after, gap.first_missing, gap.last_missing, gap.count))
        messagebox.showinfo("导出完成", f"已保存：\n{filename}")

    def export_evidence(self) -> None:
        filename = filedialog.asksaveasfilename(
            title="保存解析证据", defaultextension=".csv", initialfile="serial-parse-evidence.csv",
            filetypes=(("CSV 文件", "*.csv"),),
        )
        if not filename:
            return
        with Path(filename).open("w", newline="", encoding="utf-8-sig") as output:
            writer = csv.DictWriter(output, fieldnames=("frame", "lines", "time", "bytes", "sequence", "status"))
            writer.writeheader()
            writer.writerows(self.evidence_rows)
        messagebox.showinfo("导出完成", f"已保存：\n{filename}")

    def export_comparison(self) -> None:
        if not self.comparison_rows:
            messagebox.showwarning("暂无对比", "请先拖入一份或多份日志并完成统计。")
            return
        filename = filedialog.asksaveasfilename(
            title="保存多文件对比", defaultextension=".csv", initialfile="serial-log-comparison.csv",
            filetypes=(("CSV 文件", "*.csv"),),
        )
        if not filename:
            return
        fields = ("file", "mode", "frames", "loss", "missing", "worst", "crc", "truncated", "direction", "result")
        with Path(filename).open("w", newline="", encoding="utf-8-sig") as output:
            writer = csv.DictWriter(output, fieldnames=fields)
            writer.writeheader()
            writer.writerows(self.comparison_rows)
        messagebox.showinfo("导出完成", f"已保存：\n{filename}")

    def export_report(self) -> None:
        if not self.last_report:
            messagebox.showwarning("暂无报告", "请先完成一次统计。")
            return
        filename = filedialog.asksaveasfilename(
            title="保存可复现报告", defaultextension=".json", initialfile="serial-loss-analysis-report.json",
            filetypes=(("JSON 文件", "*.json"),),
        )
        if not filename:
            return
        with Path(filename).open("w", encoding="utf-8") as output:
            json.dump(self.last_report, output, ensure_ascii=False, indent=2)
        messagebox.showinfo("导出完成", f"已保存：\n{filename}")


def main() -> None:
    root = TkinterDnD.Tk()
    app = LossAnalyzerApp(root)
    if len(sys.argv) > 1:
        app.load_file(Path(sys.argv[1]))
    root.mainloop()


if __name__ == "__main__":
    main()
