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

## 安裝

完成開發與測試後，以固定位置安裝 release 版本：

```powershell
& .\scripts\install.ps1
```

腳本會執行 locked release build、要求系統管理員權限、將程式安裝到
`C:\Program Files\Rust VPN Splitter`，並建立開始功能表捷徑。工作列應釘選這個
已安裝版本，不要釘選 `target` 內的建置產物。

再次執行同一腳本即可更新已安裝版本。安裝完成後執行 `cargo clean` 不會移除
已安裝的程式。

## 解除安裝

```powershell
& "C:\Program Files\Rust VPN Splitter\uninstall.ps1"
```

解除安裝會移除程式與開始功能表捷徑，但保留 `%APPDATA%` 中的使用者設定。
