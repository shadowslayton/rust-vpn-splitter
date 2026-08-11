# VPN 分流管理器

一個 Windows 桌面應用程式，用來把指定的 IPv4 網段、IP、網域或網址導向 FortiClient、F5 或 Ivanti VPN。

程式會自動偵測已連線的 VPN 網卡、解析網域並建立 Windows 分流路由。停用分流或關閉程式時，會移除由本程式建立的路由。

## 使用方式

需要 Windows 11 與 Rust stable。在專案目錄執行：

```powershell
cargo run
```

啟動時請同意 UAC 權限要求，讓程式能修改 Windows 路由。

1. 在 FortiClient、F5 或 Ivanti 區域輸入目的地，每行一筆。
2. 連線 VPN；如果沒有顯示正確網卡，按「重新偵測 VPN」。
3. 有多張候選網卡時，選擇實際連線使用的網卡。
4. 按「啟用分流」建立路由。
5. 需要修改內容時，先按「停用分流」。

輸入範例：

```text
192.0.2.0/24
203.0.113.8
gitlab.example.test
http://gitlab.example.test:1500/
```

網址會依主機名稱解析成 IP；通訊協定、路徑與連接埠不影響 Windows 路由結果。
