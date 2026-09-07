# 串口丢包统计工具

面向 SSCOM 等串口助手导出日志的 Windows 桌面工具。拖入 `.txt` 或 `.csv` 日志后，工具会自动推测固定帧协议并统计接收方向的循环丢包情况。

## 功能

- 支持重复拖入多个 TXT/CSV 日志，无需重启窗口。
- 自动推测候选帧头、固定帧长、序号位置和字节序；参数始终可以手工校正。
- 识别常见 TX/RX 标记，只分析 `RX` / `Recv` / `Receive` / `接收` / `收到` / `<<` / `←` 等接收方向数据。
- 若序号每轮回到较小值，自动按循环统计；接收量不足理论帧数 50% 的循环标记为忽略，不计入平均丢包率。
- 导出每个缺失序号范围，或循环模式下每轮的接收数、缺失数和是否纳入统计。

## 运行源码

```powershell
py -m pip install -r requirements.txt
py .\src\serial_loss_gui.py
```

## 打包 Windows EXE

```powershell
py -m pip install -r requirements.txt pyinstaller
py -m PyInstaller --noconfirm --onefile --windowed --name SerialLossAnalyzer --paths .\src --collect-all tkinterdnd2 .\src\serial_loss_gui.py
```

生成文件为 `dist\SerialLossAnalyzer.exe`。

## 限制

自动识别依赖重复且固定间距的帧头，以及递增的序号字段。变长帧、无序号协议或日志没有 TX/RX 标记时，界面会保留手动校正空间并提示限制。
