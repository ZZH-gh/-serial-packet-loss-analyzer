#!/usr/bin/env python3
"""Windows GUI for serial_loss_analyzer.py.

Accepts a dropped TXT/CSV log or a file passed as the first command-line
argument (so dropping a file on the EXE also works).
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, StringVar, filedialog, messagebox, ttk

from tkinterdnd2 import DND_FILES, TkinterDnD

from frame_parser import CrcKind, FrameConfig, FrameProtocol, parse_chunks
from serial_loss_analyzer import (
    CycleResult, Gap, analyze_cycles, detect_modbus_rtu, detect_protocol,
    detect_sequence_field, match_transactions, parse_hex, read_directional_chunks,
)


class LossAnalyzerApp:
    def __init__(self, root) -> None:
        self.root = root
        self.root.title("串口日志丢包统计工具")
        self.root.minsize(760, 560)
        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind("<<Drop>>", self.on_drop)
        self.file_path = StringVar()
        self.header = StringVar(value="AA55")
        self.frame_size = StringVar(value="18")
        self.profile = StringVar(value="自定义固定帧")
        self.seq_offset = StringVar(value="2")
        self.seq_size = StringVar(value="2")
        self.endian = StringVar(value="little")
        self.max_gap = StringVar(value="1000")
        self.cycle_coverage = StringVar(value="50")
        self.transaction_timeout = StringVar(value="1500")
        self.crc = StringVar(value=CrcKind.NONE.value)
        self.result = StringVar(value="拖入 SSCOM 导出的 TXT/CSV 文件，或点击“选择日志文件”。")
        self.gaps: list[Gap] = []
        self.cycle_results: list[CycleResult] = []
        self.cyclic_mode = False
        self.input_stream = b""
        self.input_chunks = []
        self.direction_note = ""
        self.direction_read = None
        self.transaction_note = ""
        self.evidence_rows: list[dict[str, str]] = []
        self._build()

    def _build(self) -> None:
        style = ttk.Style()
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 14, "bold"))
        style.configure("Hint.TLabel", foreground="#5b6573")
        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill=BOTH, expand=True)

        ttk.Label(outer, text="串口日志丢包统计", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="只用接收数据统计帧与序号丢失；收发配对仅作通信健康度核对。支持 SSCOM TXT/CSV。",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(2, 12))

        drop = ttk.Label(
            outer,
            text="将日志文件拖到这里\n支持 .txt / .csv，也可点击右侧按钮选择",
            anchor="center",
            relief="groove",
            padding=18,
        )
        drop.pack(fill="x")
        drop.drop_target_register(DND_FILES)
        drop.dnd_bind("<<Drop>>", self.on_drop)

        file_row = ttk.Frame(outer)
        file_row.pack(fill="x", pady=10)
        ttk.Entry(file_row, textvariable=self.file_path, state="readonly").pack(side=LEFT, fill="x", expand=True)
        ttk.Button(file_row, text="选择日志文件", command=self.choose_file).pack(side=RIGHT, padx=(8, 0))

        config = ttk.LabelFrame(outer, text="协议参数", padding=10)
        config.pack(fill="x")
        fields = [
            ("帧格式", self.profile, 16),
            ("帧头（HEX）", self.header, 12),
            ("总帧长（字节）", self.frame_size, 10),
            ("序号偏移", self.seq_offset, 10),
            ("序号字节数", self.seq_size, 8),
            ("字节序", self.endian, 9),
            ("帧内超时(ms,0关闭)", self.max_gap, 14),
            ("CRC", self.crc, 14),
            ("循环纳入阈值(%)", self.cycle_coverage, 14),
            ("收发超时(ms,0关闭)", self.transaction_timeout, 14),
        ]
        for column, (label, variable, width) in enumerate(fields):
            row = (column // 4) * 2
            grid_column = column % 4
            ttk.Label(config, text=label).grid(row=row, column=grid_column, padx=4, sticky="w")
            if label == "帧格式":
                widget = ttk.Combobox(config, textvariable=variable, values=("自定义固定帧", "Modbus RTU（CRC自动帧长）"), width=width, state="readonly")
            elif label == "序号字节数":
                widget = ttk.Combobox(config, textvariable=variable, values=("1", "2", "4"), width=width, state="readonly")
            elif label == "字节序":
                widget = ttk.Combobox(config, textvariable=variable, values=("little", "big"), width=width, state="readonly")
            elif label == "CRC":
                widget = ttk.Combobox(config, textvariable=variable, values=tuple(kind.value for kind in CrcKind), width=width, state="readonly")
            else:
                widget = ttk.Entry(config, textvariable=variable, width=width)
            widget.grid(row=row + 1, column=grid_column, padx=4, pady=(2, 8), sticky="ew")
        for column in range(4):
            config.columnconfigure(column, weight=1)

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=12)
        ttk.Button(buttons, text="自动识别协议", command=self.auto_detect).pack(side=LEFT)
        ttk.Button(buttons, text="开始统计", command=self.analyze).pack(side=LEFT)
        ttk.Button(buttons, text="保存方案", command=self.save_profile).pack(side=LEFT, padx=(8, 0))
        ttk.Button(buttons, text="加载方案", command=self.load_profile).pack(side=LEFT, padx=(4, 0))
        self.export_button = ttk.Button(buttons, text="导出缺失明细 CSV", command=self.export, state="disabled")
        self.export_button.pack(side=LEFT, padx=8)
        self.evidence_export_button = ttk.Button(buttons, text="导出解析证据 CSV", command=self.export_evidence, state="disabled")
        self.evidence_export_button.pack(side=LEFT)

        ttk.Label(outer, textvariable=self.result, justify="left", font=("Consolas", 10)).pack(anchor="w", pady=(0, 8))
        notebook = ttk.Notebook(outer)
        notebook.pack(fill=BOTH, expand=True)
        table_frame = ttk.Frame(notebook)
        evidence_frame = ttk.Frame(notebook)
        notebook.add(table_frame, text="统计明细")
        notebook.add(evidence_frame, text="解析证据")
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

    def profile_values(self) -> dict[str, str]:
        return {
            "profile": self.profile.get(), "header": self.header.get(), "frame_size": self.frame_size.get(),
            "seq_offset": self.seq_offset.get(), "seq_size": self.seq_size.get(), "endian": self.endian.get(),
            "max_gap": self.max_gap.get(), "crc": self.crc.get(), "cycle_coverage": self.cycle_coverage.get(),
            "transaction_timeout": self.transaction_timeout.get(),
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
            for key, variable in (
                ("profile", self.profile), ("header", self.header), ("frame_size", self.frame_size),
                ("seq_offset", self.seq_offset), ("seq_size", self.seq_size), ("endian", self.endian),
                ("max_gap", self.max_gap), ("crc", self.crc), ("cycle_coverage", self.cycle_coverage),
                ("transaction_timeout", self.transaction_timeout),
            ):
                if key in values:
                    variable.set(str(values[key]))
            messagebox.showinfo("方案已加载", "协议参数已加载；请拖入日志后点击“开始统计”。")
        except (OSError, ValueError, json.JSONDecodeError) as error:
            messagebox.showerror("无法加载方案", str(error))

    def transaction_timeout_value(self) -> int | None:
        value = int(self.transaction_timeout.get())
        if value < 0:
            raise ValueError("收发超时不能小于 0。")
        return value or None

    def choose_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="选择 SSCOM 导出日志",
            filetypes=(("日志文件", "*.txt *.csv"), ("文本文件", "*.txt"), ("CSV 文件", "*.csv"), ("所有文件", "*.*")),
        )
        if filename:
            self.load_file(Path(filename))

    def on_drop(self, event) -> None:
        paths = self.root.tk.splitlist(event.data)
        if paths:
            self.load_file(Path(paths[0]))

    def load_file(self, path: Path) -> None:
        if path.suffix.lower() not in {".txt", ".csv"}:
            messagebox.showerror("文件类型不支持", "请选择 TXT 或 CSV 日志文件。")
            return
        self.file_path.set(str(path))
        self.gaps = []
        self.cycle_results = []
        self.cyclic_mode = False
        self.input_stream = b""
        self.input_chunks = []
        self.direction_read = None
        self.table.delete(*self.table.get_children())
        self.evidence.delete(*self.evidence.get_children())
        self.evidence_rows = []
        self.export_button.configure(state="disabled")
        self.evidence_export_button.configure(state="disabled")
        self.auto_detect(silent=True)

    def auto_detect(self, silent: bool = False) -> None:
        try:
            path = Path(self.file_path.get())
            if not path.is_file():
                raise ValueError("请先拖入或选择日志文件。")
            self.direction_read = read_directional_chunks(path)
            has_markers = self.direction_read.direction_markers_found
            rx_lines = len(self.direction_read.rx_chunks)
            self.input_chunks = self.direction_read.rx_chunks if has_markers else self.direction_read.unknown_chunks
            self.input_stream = b"".join(chunk.data for chunk in self.input_chunks)
            self.direction_note = (
                f"仅使用接收数据（SSCOM方向标签 {self.direction_read.native_sscom_markers} 行；RX {rx_lines}，TX {len(self.direction_read.tx_chunks)}；方向置信度 {self.direction_read.direction_confidence:.0%}）。"
                if has_markers
                else "日志未发现 TX/RX 方向标记：数据被标记为“方向未知”，暂按全部 HEX 数据分析。"
            )
            timeout = self.transaction_timeout_value()
            transaction = match_transactions(self.direction_read, timeout)
            if transaction.sent or transaction.received:
                latency = f"，平均往返 {transaction.average_latency_ms:.1f} ms" if transaction.average_latency_ms is not None else ""
                self.transaction_note = (
                    f"收发核对（不参与丢包率）：TX {transaction.sent}，RX {transaction.received}，按时间配对 {transaction.paired}，"
                    f"未响应TX {transaction.unmatched_sent}（超时 {transaction.timed_out_sent}），孤立RX {transaction.orphan_received}，"
                    f"命令地址/功能码证实 {transaction.key_confirmed}{latency}。"
                )
            else:
                self.transaction_note = ""
            modbus = detect_modbus_rtu(self.input_chunks)
            if modbus is not None:
                captured, parsed = modbus
                suggested = detect_sequence_field(captured)
                self.profile.set("Modbus RTU（CRC自动帧长）")
                self.header.set("任意站号 + 功能码")
                self.frame_size.set("自动")
                self.crc.set(CrcKind.MODBUS.value)
                if suggested:
                    self.seq_offset.set(str(suggested[0]))
                    self.seq_size.set(str(suggested[1]))
                    self.endian.set(suggested[2])
                    sequence_text = f"候选序号偏移 {suggested[0]}、{suggested[1]} 字节、{suggested[2]}"
                else:
                    sequence_text = "未发现可信的递增序号字段"
                self.result.set(
                    f"已验证为 Modbus RTU：{len(captured)} 条完整帧全部经 CRC16-Modbus 校验；{sequence_text}。\n"
                    f"{self.direction_note}\n{self.transaction_note}\n请核对序号字段后点击“开始统计”。"
                )
                return
            detected = detect_protocol(self.input_stream)
            if detected is None:
                raise ValueError("日志数据不足，或未找到间距稳定的固定长度帧。")
            self.header.set(detected.header.hex().upper())
            self.frame_size.set(str(detected.frame_size))
            if detected.seq_offset is not None:
                self.seq_offset.set(str(detected.seq_offset))
                self.seq_size.set(str(detected.seq_size))
                self.endian.set(detected.endian or "little")
                sequence_text = f"序号偏移 {detected.seq_offset}、{detected.seq_size} 字节、{detected.endian}"
            else:
                sequence_text = "未能可靠识别序号字段，请手动填写"
            self.result.set(
                f"已自动识别：帧头 {detected.header.hex(' ').upper()}，总帧长 {detected.frame_size} 字节；{sequence_text}。\n"
                f"{self.direction_note} 间距置信度 {detected.confidence:.0%}；请核对后点击“开始统计”。\n{self.transaction_note}"
            )
        except (OSError, ValueError) as error:
            if not silent:
                messagebox.showwarning("无法自动识别", str(error))
            elif self.file_path.get():
                self.result.set("已加载：%s\n未能自动识别协议，请手动填写参数后统计。" % path.name)

    def analyze(self) -> None:
        try:
            path = Path(self.file_path.get())
            if not path.is_file():
                raise ValueError("请先拖入或选择日志文件。")
            is_modbus = self.profile.get().startswith("Modbus")
            header = b"" if is_modbus else parse_hex(self.header.get())
            frame_size = None if is_modbus else int(self.frame_size.get())
            seq_offset = int(self.seq_offset.get())
            seq_size = int(self.seq_size.get())
            max_gap = int(self.max_gap.get())
            coverage = float(self.cycle_coverage.get()) / 100
            self.transaction_timeout_value()
            if not is_modbus and frame_size <= len(header):
                raise ValueError("总帧长必须大于帧头长度。")
            if seq_offset < 0 or (frame_size is not None and seq_offset + seq_size > frame_size):
                raise ValueError("序号字段超出帧范围。")
            if max_gap < 0:
                raise ValueError("帧内超时不能小于 0。")
            if not 0 < coverage <= 1:
                raise ValueError("循环纳入阈值必须在 0 到 100 之间。")
            if not self.input_chunks:
                self.direction_read = read_directional_chunks(path)
                has_markers = self.direction_read.direction_markers_found
                rx_lines = len(self.direction_read.rx_chunks)
                self.input_chunks = self.direction_read.rx_chunks if has_markers else self.direction_read.unknown_chunks
                self.input_stream = b"".join(chunk.data for chunk in self.input_chunks)
                self.direction_note = (
                    f"仅使用接收数据（RX {rx_lines}，TX {len(self.direction_read.tx_chunks)}；方向置信度 {self.direction_read.direction_confidence:.0%}）。"
                    if has_markers
                    else "日志未发现 TX/RX 方向标记：数据被标记为“方向未知”，暂按全部 HEX 数据分析。"
                )
            config = (
                FrameConfig(protocol=FrameProtocol.MODBUS_RTU, crc=CrcKind.MODBUS, max_frame_gap_ms=max_gap or None)
                if is_modbus
                else FrameConfig(header, fixed_length=frame_size, crc=CrcKind(self.crc.get()), max_frame_gap_ms=max_gap or None)
            )
            parsed = parse_chunks(self.input_chunks, config)
            captured = parsed.frames
            sequences = [int.from_bytes(frame[seq_offset : seq_offset + seq_size], self.endian.get()) for frame in captured]
            if not sequences:
                raise ValueError("没有找到完整帧。请检查帧头和总帧长。")
            cyclic = analyze_cycles(sequences, coverage)
        except (OSError, ValueError) as error:
            messagebox.showerror("无法统计", str(error))
            return

        self.table.delete(*self.table.get_children())
        self.cycle_results = []
        self.gaps = []
        self.cyclic_mode = cyclic is not None
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
            self.result.set(
                f"{self.direction_note} 完整帧 {len(captured)}，截断 {parsed.truncations}，CRC错误 {parsed.crc_errors}，噪声 {parsed.noise_bytes} 字节。\n循环模式：自动识别每轮理论帧数为 {expected}。共 {len(self.cycle_results)} 轮，纳入 {len(included)} 轮，忽略 {ignored} 轮。\n"
                f"理论序号范围：{model.first_sequence}..{model.last_sequence}，由 {model.evidence_cycles} 个完整范围循环共同证实。\n"
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
            self.set_table_headings((("after", "前一序号"), ("first", "首个缺失"), ("last", "最后缺失"), ("count", "缺失帧数")))
            for gap in self.gaps:
                self.table.insert("", END, values=(gap.after, gap.first_missing, gap.last_missing, gap.count))
            self.result.set(
                f"{self.direction_note} 完整帧 {len(captured)}，截断 {parsed.truncations}，CRC错误 {parsed.crc_errors}，噪声 {parsed.noise_bytes} 字节。\n连续序号模式：接收帧数 {len(sequences)}，丢失帧数 {missing}，丢包率 {rate:.4f}%。\n"
                f"重复序号：{duplicates}    疑似复位/异常跳变：{resets}    缺失区段：{len(self.gaps)}\n{self.transaction_note}"
            )
        self.populate_evidence(parsed, sequences)
        self.export_button.configure(state="normal")
        self.evidence_export_button.configure(state="normal")

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
            if self.cyclic_mode:
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


def main() -> None:
    root = TkinterDnD.Tk()
    app = LossAnalyzerApp(root)
    if len(sys.argv) > 1:
        app.load_file(Path(sys.argv[1]))
    root.mainloop()


if __name__ == "__main__":
    main()
