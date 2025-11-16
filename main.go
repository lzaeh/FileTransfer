package main

import (
	"archive/zip"
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func getDesktop() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Desktop")
}

var (
	authPassword string
	serverToken  string
)

const authCookieName = "mac2win_auth"

// 生成本次进程唯一的随机 token，用来和 cookie 绑定
func generateServerToken() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("tok_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// 选择端口：提示默认端口，问是否修改
func choosePort(reader *bufio.Reader) string {
	defaultPort := "8080"
	fmt.Printf("默认端口为: %s\n", defaultPort)
	fmt.Print("是否要修改端口? (y/N): ")
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if strings.EqualFold(line, "y") || strings.EqualFold(line, "yes") {
		for {
			fmt.Print("请输入新端口(例如 8080): ")
			p, _ := reader.ReadString('\n')
			p = strings.TrimSpace(p)
			if p != "" {
				return p
			}
			fmt.Println("端口不能为空。")
		}
	}
	return defaultPort
}

// 选择密码：提示默认密码 0000，问是否修改
func choosePassword(reader *bufio.Reader) string {
	defaultPwd := "0000"
	fmt.Printf("默认密码为: %s\n", defaultPwd)
	fmt.Print("是否要修改密码? (y/N): ")
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if strings.EqualFold(line, "y") || strings.EqualFold(line, "yes") {
		for {
			fmt.Print("请输入新密码(不能是空): ")
			p, _ := reader.ReadString('\n')
			p = strings.TrimSpace(p)
			if p != "" {
				return p
			}
			fmt.Println("密码不能为空。")
		}
	}
	return defaultPwd
}

func isAuthed(r *http.Request) bool {
	if serverToken == "" {
		return false
	}
	c, err := r.Cookie(authCookieName)
	return err == nil && c.Value == serverToken
}

func setAuthCookie(w http.ResponseWriter) {
	if serverToken == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    serverToken,
		Path:     "/",
		HttpOnly: true,
	})
}

// 登录页
const loginPageTemplate = "" +
	"<!DOCTYPE html>\n" +
	"<html>\n" +
	"<head>\n" +
	"  <meta charset=\"utf-8\" />\n" +
	"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n" +
	"  <title>Login - File Transfer</title>\n" +
	"  <style>\n" +
	"  body {\n" +
	"    font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;\n" +
	"    max-width: 420px;\n" +
	"    margin: 40px auto;\n" +
	"    padding: 0 16px;\n" +
	"    box-sizing: border-box;\n" +
	"    background: linear-gradient(135deg, #f9fafb, #e5e7eb);\n" +
	"  }\n" +
	"  .card {\n" +
	"    padding: 20px 20px 16px 20px;\n" +
	"    border-radius: 16px;\n" +
	"    background: rgba(255,255,255,0.9);\n" +
	"    box-shadow: 0 16px 40px rgba(15,23,42,0.12);\n" +
	"    backdrop-filter: blur(12px);\n" +
	"  }\n" +
	"  .title {\n" +
	"    margin-top: 0;\n" +
	"    margin-bottom: 4px;\n" +
	"    font-size: 20px;\n" +
	"  }\n" +
	"  .subtitle {\n" +
	"    margin-top: 0;\n" +
	"    margin-bottom: 16px;\n" +
	"    font-size: 13px;\n" +
	"    color: #6b7280;\n" +
	"  }\n" +
	"  .input {\n" +
	"    width: 100%;\n" +
	"    padding: 8px 10px;\n" +
	"    border-radius: 8px;\n" +
	"    border: 1px solid #d1d5db;\n" +
	"    font-size: 14px;\n" +
	"    box-sizing: border-box;\n" +
	"  }\n" +
	"  .btn {\n" +
	"    width: 100%;\n" +
	"    margin-top: 12px;\n" +
	"    padding: 9px 10px;\n" +
	"    border-radius: 999px;\n" +
	"    border: none;\n" +
	"    background: linear-gradient(135deg, #4f46e5, #6366f1);\n" +
	"    color: white;\n" +
	"    font-weight: 600;\n" +
	"    cursor: pointer;\n" +
	"    font-size: 14px;\n" +
	"  }\n" +
	"  .error {\n" +
	"    color: #dc2626;\n" +
	"    margin-bottom: 8px;\n" +
	"    font-size: 13px;\n" +
	"  }\n" +
	"  .hint {\n" +
	"    margin-top: 8px;\n" +
	"    font-size: 12px;\n" +
	"    color: #6b7280;\n" +
	"  }\n" +
	"  @media (max-width: 600px) {\n" +
	"    body { margin: 24px auto; }\n" +
	"  }\n" +
	"  </style>\n" +
	"</head>\n" +
	"<body>\n" +
	"  <div class=\"card\">\n" +
	"    <h1 class=\"title\">Unlock transfer console</h1>\n" +
	"    <p class=\"subtitle\">输入在服务端启动程序时设置的密码。</p>\n" +
	"    __ERROR__\n" +
	"    <form method=\"post\" action=\"/login\">\n" +
	"      <input class=\"input\" type=\"password\" name=\"password\" placeholder=\"Password\" autocomplete=\"current-password\" />\n" +
	"      <button class=\"btn\" type=\"submit\">Enter</button>\n" +
	"    </form>\n" +
	"    <div class=\"hint\">建议仅在可信局域网使用，并定期更换密码。</div>\n" +
	"  </div>\n" +
	"</body>\n" +
	"</html>\n"

// 上传页模板，含 __ROOT__ 和 __ROWS__
const pageTemplate = "" +
	"<!DOCTYPE html>\n" +
	"<html>\n" +
	"<head>\n" +
	"    <meta charset=\"utf-8\" />\n" +
	"    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n" +
	"    <title>File Transfer</title>\n" +
	"    <style>\n" +
	"    body {\n" +
	"        font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;\n" +
	"        max-width: 960px;\n" +
	"        margin: 0 auto;\n" +
	"        padding: 16px;\n" +
	"        box-sizing: border-box;\n" +
	"        background: linear-gradient(135deg, #f9fafb, #e5e7eb);\n" +
	"    }\n" +
	"    .shell-card {\n" +
	"        margin-top: 16px;\n" +
	"        padding: 16px;\n" +
	"        border-radius: 18px;\n" +
	"        background: rgba(255,255,255,0.9);\n" +
	"        box-shadow: 0 18px 45px rgba(15,23,42,0.14);\n" +
	"        backdrop-filter: blur(14px);\n" +
	"    }\n" +
	"    .top-bar {\n" +
	"        display: flex;\n" +
	"        justify-content: space-between;\n" +
	"        align-items: center;\n" +
	"        gap: 12px;\n" +
	"        flex-wrap: wrap;\n" +
	"        margin-bottom: 16px;\n" +
	"    }\n" +
	"    .title-wrap {\n" +
	"        display: flex;\n" +
	"        align-items: center;\n" +
	"        gap: 10px;\n" +
	"    }\n" +
	"    .title-badge {\n" +
	"        width: 32px;\n" +
	"        height: 32px;\n" +
	"        border-radius: 999px;\n" +
	"        background: radial-gradient(circle at 30% 30%, #fef3c7, #f97316);\n" +
	"        display: flex;\n" +
	"        align-items: center;\n" +
	"        justify-content: center;\n" +
	"        font-size: 16px;\n" +
	"        color: #111827;\n" +
	"        font-weight: 700;\n" +
	"    }\n" +
	"    .title-text-main {\n" +
	"        font-size: 18px;\n" +
	"        font-weight: 600;\n" +
	"        color: #111827;\n" +
	"    }\n" +
	"    .title-text-sub {\n" +
	"        font-size: 12px;\n" +
	"        color: #6b7280;\n" +
	"    }\n" +
	"    .chip-row {\n" +
	"        display: flex;\n" +
	"        flex-wrap: wrap;\n" +
	"        gap: 8px;\n" +
	"        margin-top: 4px;\n" +
	"        font-size: 11px;\n" +
	"        color: #6b7280;\n" +
	"    }\n" +
	"    .chip {\n" +
	"        padding: 2px 8px;\n" +
	"        border-radius: 999px;\n" +
	"        background: #f3f4ff;\n" +
	"        border: 1px solid #e5e7eb;\n" +
	"    }\n" +
	"    .btn-pill {\n" +
	"        padding: 0 16px;\n" +
	"        border-radius: 999px;\n" +
	"        border: none;\n" +
	"        cursor: pointer;\n" +
	"        font-weight: 600;\n" +
	"        height: 40px;\n" +
	"        font-size: 14px;\n" +
	"        display: inline-flex;\n" +
	"        align-items: center;\n" +
	"        gap: 6px;\n" +
	"        white-space: nowrap;\n" +
	"    }\n" +
	"    #browseRootBtn {\n" +
	"        background: linear-gradient(135deg, #0ea5e9, #38bdf8);\n" +
	"        color: white;\n" +
	"    }\n" +
	"    #addFolderBtn {\n" +
	"        font-size: 18px;\n" +
	"        width: 40px;\n" +
	"        height: 40px;\n" +
	"        border-radius: 50%;\n" +
	"        border: none;\n" +
	"        background: #4f46e5;\n" +
	"        color: white;\n" +
	"        cursor: pointer;\n" +
	"    }\n" +
	"    #uploadAllBtn {\n" +
	"        background: linear-gradient(135deg, #16a34a, #22c55e);\n" +
	"        color: white;\n" +
	"    }\n" +
	"    .root-card {\n" +
	"        margin-bottom: 16px;\n" +
	"        padding: 10px 12px;\n" +
	"        background: #f3f4f6;\n" +
	"        border-radius: 12px;\n" +
	"        font-size: 12px;\n" +
	"        border: 1px solid #e5e7eb;\n" +
	"    }\n" +
	"    .root-label {\n" +
	"        color: #6b7280;\n" +
	"        margin-bottom: 2px;\n" +
	"    }\n" +
	"    .root-path {\n" +
	"        font-family: SFMono-Regular, ui-monospace, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace;\n" +
	"        font-size: 11px;\n" +
	"        color: #374151;\n" +
	"    }\n" +
	"    .section-title {\n" +
	"        margin-top: 0;\n" +
	"        margin-bottom: 8px;\n" +
	"        font-size: 13px;\n" +
	"        text-transform: uppercase;\n" +
	"        letter-spacing: 0.06em;\n" +
	"        color: #6b7280;\n" +
	"    }\n" +
	"    .folder-wrapper {\n" +
	"        background: #eef1ff;\n" +
	"        border-radius: 12px;\n" +
	"        padding: 0;\n" +
	"        max-height: 60vh;\n" +
	"        min-height: 40vh;\n" +
	"        display: flex;\n" +
	"        flex-direction: column;\n" +
	"        overflow: hidden;\n" +
	"        border: 1px solid #e5e7eb;\n" +
	"    }\n" +
	"    #folderContainer {\n" +
	"        padding: 12px;\n" +
	"        overflow-y: auto;\n" +
	"        flex: 1 1 auto;\n" +
	"    }\n" +
	"    .folder-row {\n" +
	"        border-radius: 8px;\n" +
	"    }\n" +
	"    @media (max-width: 600px) {\n" +
	"        .shell-card { margin-top: 12px; padding: 12px; border-radius: 14px; }\n" +
	"        .title-text-main { font-size: 16px; }\n" +
	"        .title-text-sub { font-size: 11px; }\n" +
	"        body { padding: 12px; }\n" +
	"    }\n" +
	"    </style>\n" +
	"</head>\n" +
	"<body>\n" +
	"  <div class=\"shell-card\">\n" +
	"    <div class=\"top-bar\">\n" +
	"        <div class=\"title-wrap\">\n" +
	"            <div class=\"title-badge\">⇄</div>\n" +
	"            <div>\n" +
	"              <div class=\"title-text-main\">File Transfer</div>\n" +
	"              <div class=\"title-text-sub\">用chatGPT弄出来的简单局域网传输工具。</div>\n" +
	"              <div class=\"chip-row\">\n" +
	"                <div class=\"chip\">Root: Myfiles</div>\n" +
	"                <div class=\"chip\">Multi-folder upload</div>\n" +
	"                <div class=\"chip\">ZIP download</div>\n" +
	"              </div>\n" +
	"            </div>\n" +
	"        </div>\n" +
	"        <div style=\"display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end;\">\n" +
	"            <button id=\"browseRootBtn\" class=\"btn-pill\">\n" +
	"              <span>Browse Root</span>\n" +
	"            </button>\n" +
	"            <button id=\"uploadAllBtn\" class=\"btn-pill\">\n" +
	"              <span>Upload All</span>\n" +
	"            </button>\n" +
	"            <button id=\"addFolderBtn\">+</button>\n" +
	"        </div>\n" +
	"    </div>\n" +
	"\n" +
	"    <div class=\"root-card\">\n" +
	"        <div class=\"root-label\">Root directory on your PC:</div>\n" +
	"        <div class=\"root-path\">__ROOT__</div>\n" +
	"    </div>\n" +
	"\n" +
	"    <h3 class=\"section-title\">Folder list (inside fromMacBookProM3)</h3>\n" +
	"    <div class=\"folder-wrapper\">\n" +
	"      <div id=\"folderContainer\" data-root=\"__ROOT__\">\n" +
	"        __ROWS__\n" +
	"      </div>\n" +
	"    </div>\n" +
	"  </div>\n" +
	"\n" +
	"    <div id=\"fsModal\" style=\"display:none; position:fixed; inset:0; background:rgba(0,0,0,0.4); z-index:9999;\">\n" +
	"      <div style=\"background:#ffffff; max-width:800px; margin:40px auto; padding:16px; border-radius:12px; max-height:80vh; overflow:auto; box-shadow:0 18px 45px rgba(15,23,42,0.3);\">\n" +
	"        <div style=\"display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; gap:8px; flex-wrap:wrap;\">\n" +
	"          <div>\n" +
	"            <div style=\"font-weight:600;\">File Browser</div>\n" +
	"            <div id=\"fsPath\" style=\"font-size:12px; color:#6b7280; word-break:break-all;\"></div>\n" +
	"          </div>\n" +
	"          <div style=\"display:flex; gap:8px; flex-wrap:wrap;\">\n" +
	"            <button id=\"fsUpBtn\" style=\"padding:6px 10px; border-radius:999px; border:none; background:#e5e7eb; color:#111827; font-size:12px; cursor:pointer;\">Up</button>\n" +
	"            <a id=\"fsZipLink\" href=\"#\" style=\"padding:6px 10px; border-radius:999px; background:#16a34a; color:white; font-size:12px; text-decoration:none;\">Download this folder</a>\n" +
	"            <button id=\"fsCloseBtn\" style=\"padding:6px 10px; border-radius:999px; border:none; background:#9ca3af; color:white; font-size:12px; cursor:pointer;\">Close</button>\n" +
	"          </div>\n" +
	"        </div>\n" +
	"        <div id=\"fsSelection\" style=\"margin-bottom:6px; font-size:12px; color:#6b7280;\">No item selected. Click a file or folder to select.</div>\n" +
	"        <ul id=\"fsList\" style=\"list-style:none; padding-left:0; margin:0;\"></ul>\n" +
	"      </div>\n" +
	"    </div>\n" +
	"\n" +
	"<script>\n" +
	"var folderContainer = document.getElementById('folderContainer');\n" +
	"var rootPath = folderContainer.getAttribute('data-root');\n" +
	"\n" +
	"var fsModal = document.getElementById('fsModal');\n" +
	"var fsList = document.getElementById('fsList');\n" +
	"var fsPath = document.getElementById('fsPath');\n" +
	"var fsZipLink = document.getElementById('fsZipLink');\n" +
	"var fsUpBtn = document.getElementById('fsUpBtn');\n" +
	"var fsSelection = document.getElementById('fsSelection');\n" +
	"var currentFsDir = '';\n" +
	"var selectedItemPath = '';\n" +
	"var selectedItemType = '';\n" +
	"var selectedLi = null;\n" +
	"\n" +
	"function uploadRow(row) {\n" +
	"    var folder = row.getAttribute('data-folder');\n" +
	"    var fileInput = row.querySelector('.file-input');\n" +
	"    var progressBar = row.querySelector('.progress-bar');\n" +
	"    var percentEl = row.querySelector('.percent');\n" +
	"    var speedEl = row.querySelector('.speed');\n" +
	"    var resultEl = row.querySelector('.result');\n" +
	"\n" +
	"    var files = fileInput.files;\n" +
	"    if (!files || files.length === 0) {\n" +
	"        return;\n" +
	"    }\n" +
	"\n" +
	"    var formData = new FormData();\n" +
	"    for (var i = 0; i < files.length; i++) {\n" +
	"        formData.append('files', files[i]);\n" +
	"    }\n" +
	"    formData.append('target', folder);\n" +
	"\n" +
	"    var xhr = new XMLHttpRequest();\n" +
	"    xhr.open('POST', '/upload', true);\n" +
	"\n" +
	"    var startTime = Date.now();\n" +
	"\n" +
	"    xhr.upload.onprogress = function(e) {\n" +
	"        if (e.lengthComputable) {\n" +
	"            var percent = e.loaded / e.total * 100;\n" +
	"            progressBar.value = percent;\n" +
	"            percentEl.textContent = percent.toFixed(1);\n" +
	"\n" +
	"            var elapsedSec = (Date.now() - startTime) / 1000;\n" +
	"            if (elapsedSec > 0) {\n" +
	"                var bytesPerSec = e.loaded / elapsedSec;\n" +
	"                var mbPerSec = bytesPerSec / (1024 * 1024);\n" +
	"                speedEl.textContent = mbPerSec.toFixed(2) + ' MB/s';\n" +
	"            }\n" +
	"        }\n" +
	"    };\n" +
	"\n" +
	"    xhr.onload = function() {\n" +
	"        if (xhr.status === 200) {\n" +
	"            resultEl.textContent = xhr.responseText;\n" +
	"        } else {\n" +
	"            resultEl.textContent = 'Upload failed: ' + xhr.status + ' ' + xhr.statusText;\n" +
	"        }\n" +
	"    };\n" +
	"\n" +
	"    xhr.onerror = function() {\n" +
	"        resultEl.textContent = 'Upload error (network or server issue)';\n" +
	"    };\n" +
	"\n" +
	"    progressBar.value = 0;\n" +
	"    percentEl.textContent = '0';\n" +
	"    speedEl.textContent = '0 MB/s';\n" +
	"    resultEl.textContent = 'Uploading...';\n" +
	"\n" +
	"    xhr.send(formData);\n" +
	"}\n" +
	"\n" +
	"function createFolderRow(name) {\n" +
	"    var row = document.createElement('div');\n" +
	"    row.className = 'folder-row';\n" +
	"    row.setAttribute('data-folder', name);\n" +
	"\n" +
	"    var bg = '#f0f4ff';\n" +
	"    var displayPath = rootPath + '/' + name;\n" +
	"\n" +
	"    row.style.display = 'flex';\n" +
	"    row.style.flexDirection = 'column';\n" +
	"    row.style.gap = '6px';\n" +
	"    row.style.padding = '10px';\n" +
	"    row.style.marginBottom = '10px';\n" +
	"    row.style.borderRadius = '8px';\n" +
	"    row.style.background = bg;\n" +
	"\n" +
	"    row.innerHTML = '' +\n" +
	"        '<div style=\"display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap;\">' +\n" +
	"            '<div style=\"font-weight: 600;\">[Folder] ' + name + '</div>' +\n" +
	"            '<div>' +\n" +
	"                '<input type=\"file\" class=\"file-input\" multiple style=\"max-width: 100%;\" />' +\n" +
	"            '</div>' +\n" +
	"        '</div>' +\n" +
	"        '<div style=\"font-size: 12px; color: #555; word-break: break-all;\">' +\n" +
	"            'Target path: ' + displayPath +\n" +
	"        '</div>' +\n" +
	"        '<div style=\"display: flex; align-items: center; gap: 10px; font-size: 12px; flex-wrap: wrap;\">' +\n" +
	"            '<span>Progress: <span class=\"percent\">0</span></span>' +\n" +
	"            '<span>Speed: <span class=\"speed\">0 MB/s</span></span>' +\n" +
	"        '</div>' +\n" +
	"        '<progress class=\"progress-bar\" value=\"0\" max=\"100\" style=\"width: 100%;\"></progress>' +\n" +
	"        '<pre class=\"result\" style=\"margin: 0; background: transparent; padding: 0; font-size: 12px; white-space: pre-wrap;\"></pre>';\n" +
	"\n" +
	"    folderContainer.appendChild(row);\n" +
	"}\n" +
	"\n" +
	"document.getElementById('uploadAllBtn').addEventListener('click', function() {\n" +
	"    var rows = document.querySelectorAll('.folder-row');\n" +
	"    var hasAny = false;\n" +
	"    for (var i = 0; i < rows.length; i++) {\n" +
	"        var fileInput = rows[i].querySelector('.file-input');\n" +
	"        if (fileInput && fileInput.files && fileInput.files.length > 0) {\n" +
	"            hasAny = true;\n" +
	"            uploadRow(rows[i]);\n" +
	"        }\n" +
	"    }\n" +
	"    if (!hasAny) {\n" +
	"        alert('No files selected in any folder');\n" +
	"    }\n" +
	"});\n" +
	"\n" +
	"document.getElementById('addFolderBtn').addEventListener('click', function() {\n" +
	"    var name = window.prompt(\"New folder relative path (e.g. 'foo' or 'foo/bar'):\");\n" +
	"    if (!name) return;\n" +
	"    var trimmed = name.trim();\n" +
	"    if (!trimmed) return;\n" +
	"    if (trimmed.indexOf('..') !== -1) {\n" +
	"        alert('Path cannot contain ..');\n" +
	"        return;\n" +
	"    }\n" +
	"    createFolderRow(trimmed);\n" +
	"});\n" +
	"\n" +
	"function openBrowserForFolder(rel) {\n" +
	"  currentFsDir = rel || '';\n" +
	"  fsModal.style.display = 'block';\n" +
	"  loadFsDir(currentFsDir);\n" +
	"}\n" +
	"\n" +
	"function closeFsModal() {\n" +
	"  fsModal.style.display = 'none';\n" +
	"}\n" +
	"\n" +
	"function updateUpButtonState() {\n" +
	"  if (!fsUpBtn) return;\n" +
	"  if (!currentFsDir || currentFsDir === '') {\n" +
	"    fsUpBtn.disabled = true;\n" +
	"    fsUpBtn.style.opacity = '0.5';\n" +
	"    fsUpBtn.style.cursor = 'default';\n" +
	"  } else {\n" +
	"    fsUpBtn.disabled = false;\n" +
	"    fsUpBtn.style.opacity = '1';\n" +
	"    fsUpBtn.style.cursor = 'pointer';\n" +
	"  }\n" +
	"}\n" +
	"\n" +
	"function clearSelection() {\n" +
	"  selectedItemPath = '';\n" +
	"  selectedItemType = '';\n" +
	"  if (selectedLi) {\n" +
	"    selectedLi.style.boxShadow = '';\n" +
	"    selectedLi.style.backgroundColor = '';\n" +
	"    selectedLi = null;\n" +
	"  }\n" +
	"  if (fsSelection) {\n" +
	"    fsSelection.textContent = 'No item selected. Click a file or folder to select.';\n" +
	"  }\n" +
	"}\n" +
	"\n" +
	"function updateSelectionText() {\n" +
	"  if (!fsSelection) return;\n" +
	"  if (!selectedItemPath) {\n" +
	"    fsSelection.textContent = 'No item selected. Click a file or folder to select.';\n" +
	"    return;\n" +
	"  }\n" +
	"  if (selectedItemType === 'dir') {\n" +
	"    fsSelection.textContent = 'Selected folder: ' + selectedItemPath + ' (click again to enter this folder)';\n" +
	"  } else if (selectedItemType === 'file') {\n" +
	"    fsSelection.textContent = 'Selected file: ' + selectedItemPath + ' (click again to download)';\n" +
	"  }\n" +
	"}\n" +
	"\n" +
	"function onItemClick(li, entry) {\n" +
	"  // 第二次点击同一个条目\n" +
	"  if (selectedItemPath && selectedItemPath === entry.relPath) {\n" +
	"    if (entry.isDir) {\n" +
	"      openBrowserForFolder(entry.relPath);\n" +
	"    } else {\n" +
	"      window.location = '/download?file=' + encodeURIComponent(entry.relPath);\n" +
	"    }\n" +
	"    return;\n" +
	"  }\n" +
	"\n" +
	"  // 第一次点击：选中高亮\n" +
	"  if (selectedLi) {\n" +
	"    selectedLi.style.boxShadow = '';\n" +
	"    selectedLi.style.backgroundColor = '';\n" +
	"  }\n" +
	"  selectedLi = li;\n" +
	"  li.style.boxShadow = '0 0 0 1px #6366f1 inset';\n" +
	"  li.style.backgroundColor = '#eef2ff';\n" +
	"\n" +
	"  selectedItemPath = entry.relPath;\n" +
	"  selectedItemType = entry.isDir ? 'dir' : 'file';\n" +
	"  updateSelectionText();\n" +
	"}\n" +
	"\n" +
	"function loadFsDir(rel) {\n" +
	"  var url = '/api/list';\n" +
	"  if (rel && rel.length > 0) {\n" +
	"    url += '?dir=' + encodeURIComponent(rel);\n" +
	"  }\n" +
	"  fetch(url).then(function(resp) {\n" +
	"    if (!resp.ok) { throw new Error('HTTP ' + resp.status); }\n" +
	"    return resp.json();\n" +
	"  }).then(function(data) {\n" +
	"    fsPath.textContent = data.displayPath;\n" +
	"    if (data.dir !== undefined) {\n" +
	"      currentFsDir = data.dir || '';\n" +
	"    }\n" +
	"    var zipHref = '/download-zip';\n" +
	"    if (currentFsDir && currentFsDir.length > 0) {\n" +
	"      zipHref += '?dir=' + encodeURIComponent(currentFsDir);\n" +
	"    }\n" +
	"    fsZipLink.href = zipHref;\n" +
	"    updateUpButtonState();\n" +
	"    clearSelection();\n" +
	"\n" +
	"    fsList.innerHTML = '';\n" +
	"    if (!data.entries || data.entries.length === 0) {\n" +
	"      var li = document.createElement('li');\n" +
	"      li.textContent = 'Empty folder.';\n" +
	"      fsList.appendChild(li);\n" +
	"      return;\n" +
	"    }\n" +
	"    data.entries.forEach(function(e) {\n" +
	"      var li = document.createElement('li');\n" +
	"      li.style.margin = '4px 0';\n" +
	"      li.style.fontSize = '14px';\n" +
	"      li.style.cursor = 'pointer';\n" +
	"      li.style.padding = '4px 6px';\n" +
	"      li.style.borderRadius = '6px';\n" +
	"\n" +
	"      var label = document.createElement('span');\n" +
	"      label.style.marginRight = '6px';\n" +
	"      label.textContent = e.isDir ? '[Dir]' : '[File]';\n" +
	"      li.appendChild(label);\n" +
	"\n" +
	"      var nameSpan = document.createElement('span');\n" +
	"      nameSpan.textContent = e.name;\n" +
	"      li.appendChild(nameSpan);\n" +
	"\n" +
	"      if (!e.isDir) {\n" +
	"        var info = document.createElement('span');\n" +
	"        info.style.marginLeft = '8px';\n" +
	"        info.style.fontSize = '12px';\n" +
	"        info.style.color = '#6b7280';\n" +
	"        info.textContent = ' (' + e.size + ' bytes)';\n" +
	"        li.appendChild(info);\n" +
	"      }\n" +
	"\n" +
	"      li.onclick = function(ev) {\n" +
	"        ev.preventDefault();\n" +
	"        onItemClick(li, e);\n" +
	"      };\n" +
	"\n" +
	"      fsList.appendChild(li);\n" +
	"    });\n" +
	"  }).catch(function(err) {\n" +
	"    fsList.innerHTML = '';\n" +
	"    var li = document.createElement('li');\n" +
	"    li.textContent = 'Failed to load: ' + err;\n" +
	"    fsList.appendChild(li);\n" +
	"  });\n" +
	"}\n" +
	"\n" +
	"document.getElementById('fsCloseBtn').addEventListener('click', function() {\n" +
	"  closeFsModal();\n" +
	"});\n" +
	"\n" +
	"fsModal.addEventListener('click', function(e) {\n" +
	"  if (e.target === fsModal) { closeFsModal(); }\n" +
	"});\n" +
	"\n" +
	"if (fsUpBtn) {\n" +
	"  fsUpBtn.addEventListener('click', function() {\n" +
	"    if (!currentFsDir || currentFsDir === '') return;\n" +
	"    var parts = currentFsDir.split('/');\n" +
	"    parts.pop();\n" +
	"    var parent = parts.join('/');\n" +
	"    openBrowserForFolder(parent);\n" +
	"  });\n" +
	"}\n" +
	"\n" +
	"var browseRootBtn = document.getElementById('browseRootBtn');\n" +
	"if (browseRootBtn) {\n" +
	"  browseRootBtn.addEventListener('click', function() {\n" +
	"    openBrowserForFolder('');\n" +
	"  });\n" +
	"}\n" +
	"</script>\n" +
	"</body>\n" +
	"</html>\n"

func renderLogin(w http.ResponseWriter, showError bool) {
	errHTML := ""
	if showError {
		errHTML = "<div class=\"error\">密码错误，请重试。</div>"
	}
	page := strings.Replace(loginPageTemplate, "__ERROR__", errHTML, 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}

// 安全拼路径 + 检查不能逃出 root
func joinSafe(root, rel string) (string, error) {
	rel = strings.ReplaceAll(rel, "\\", "/")
	rel = strings.TrimSpace(rel)
	if rel == "" || rel == "." {
		return root, nil
	}
	if strings.Contains(rel, "..") {
		return "", fmt.Errorf("invalid path")
	}
	full := filepath.Join(root, rel)
	rootAbs, _ := filepath.Abs(root)
	fullAbs, _ := filepath.Abs(full)
	if !strings.HasPrefix(fullAbs, rootAbs) {
		return "", fmt.Errorf("out of root")
	}
	return fullAbs, nil
}

type listEntry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"isDir"`
	RelPath string `json:"relPath"`
	Size    int64  `json:"size"`
	ModTime string `json:"modTime"`
}

type listResponse struct {
	Dir         string      `json:"dir"`
	DisplayPath string      `json:"displayPath"`
	Entries     []listEntry `json:"entries"`
}

func main() {
	desktop := getDesktop()
	root := filepath.Join(desktop, "Myfiles")
	_ = os.MkdirAll(root, 0755)

	reader := bufio.NewReader(os.Stdin)
	port := choosePort(reader)
	authPassword = choosePassword(reader)
	serverToken = generateServerToken() // 每次启动生成新的 token，旧 cookie 全失效

	// 根路径：未登录 -> 登录页；已登录 -> 上传页
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthed(r) {
			renderLogin(w, false)
			return
		}

		var folders []string
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return nil
			}
			if rel == "." {
				return nil
			}
			rel = filepath.ToSlash(rel)
			folders = append(folders, rel)
			return nil
		})

		rowsHTML := ""
		if len(folders) == 0 {
			rowsHTML = "" +
				"<div style=\"padding: 20px; color: #777; font-size: 13px;\">" +
				"No folders yet. Click \"+\" to add a row (e.g. 'foo' or 'foo/bar'), then upload to create it." +
				"</div>"
		} else {
			for i, rel := range folders {
				escName := html.EscapeString(rel)
				bg := "#f0f4ff"
				if i%2 == 1 {
					bg = "#f7f7ff"
				}
				row := fmt.Sprintf(
					"<div class=\"folder-row\" data-folder=\"%s\" style=\"display: flex; flex-direction: column; gap: 6px; padding: 10px; margin-bottom: 10px; border-radius: 8px; background: %s;\">"+
						"<div style=\"display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap;\">"+
						"<div style=\"font-weight: 600;\">[Folder] %s</div>"+
						"<div>"+
						"<input type=\"file\" class=\"file-input\" multiple style=\"max-width: 100%%;\" />"+
						"</div>"+
						"</div>"+
						"<div style=\"font-size: 12px; color: #555; word-break: break-all;\">"+
						"Target path: %s"+
						"</div>"+
						"<div style=\"display: flex; align-items: center; gap: 10px; font-size: 12px; flex-wrap: wrap;\">"+
						"<span>Progress: <span class=\"percent\">0</span></span>"+
						"<span>Speed: <span class=\"speed\">0 MB/s</span></span>"+
						"</div>"+
						"<progress class=\"progress-bar\" value=\"0\" max=\"100\" style=\"width: 100%%;\"></progress>"+
						"<pre class=\"result\" style=\"margin: 0; background: transparent; padding: 0; font-size: 12px; white-space: pre-wrap;\"></pre>"+
						"</div>",
					escName,
					bg,
					escName,
					html.EscapeString(filepath.Join(root, rel)),
				)
				rowsHTML += row
			}
		}

		page := strings.ReplaceAll(pageTemplate, "__ROOT__", html.EscapeString(root))
		page = strings.Replace(page, "__ROWS__", rowsHTML, 1)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	// 登录
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			renderLogin(w, false)
			return
		}
		if err := r.ParseForm(); err != nil {
			renderLogin(w, true)
			return
		}
		pwd := strings.TrimSpace(r.FormValue("password"))
		if pwd == authPassword {
			setAuthCookie(w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		renderLogin(w, true)
	})

	// 上传：需要已登录
	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := r.ParseMultipartForm(32 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		targetRel := strings.TrimSpace(r.FormValue("target"))
		fullDir, err := joinSafe(root, targetRel)
		if err != nil {
			http.Error(w, "invalid target dir", http.StatusBadRequest)
			return
		}

		if err := os.MkdirAll(fullDir, 0755); err != nil {
			http.Error(w, "failed to ensure target dir: "+err.Error(), http.StatusInternalServerError)
			return
		}

		files := r.MultipartForm.File["files"]
		if len(files) == 0 {
			http.Error(w, "no files uploaded", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Target directory:\n%s\n\n", fullDir)
		fmt.Fprintf(w, "Received %d file(s):\n\n", len(files))

		for _, header := range files {
			src, err := header.Open()
			if err != nil {
				fmt.Fprintf(w, "FAILED: %s (%v)\n", header.Filename, err)
				continue
			}

			dstPath := filepath.Join(fullDir, header.Filename)
			dst, err := os.Create(dstPath)
			if err != nil {
				fmt.Fprintf(w, "FAILED: %s (%v)\n", header.Filename, err)
				_ = src.Close()
				continue
			}

			_, err = io.Copy(dst, src)
			_ = src.Close()
			_ = dst.Close()

			if err != nil {
				fmt.Fprintf(w, "FAILED: %s (%v)\n", header.Filename, err)
				continue
			}

			fmt.Fprintf(w, "OK: %s -> %s\n", header.Filename, dstPath)
		}
	})

	// JSON 列目录（给前端文件系统窗口用）
	http.HandleFunc("/api/list", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		rel := strings.TrimSpace(r.URL.Query().Get("dir"))
		full, err := joinSafe(root, rel)
		if err != nil {
			http.Error(w, "invalid dir", http.StatusBadRequest)
			return
		}

		st, err := os.Stat(full)
		if err != nil || !st.IsDir() {
			http.Error(w, "not a directory", http.StatusBadRequest)
			return
		}

		entries, err := os.ReadDir(full)
		if err != nil {
			http.Error(w, "failed to read dir: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := listResponse{
			Dir:         filepath.ToSlash(rel),
			DisplayPath: full,
		}

		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			name := e.Name()
			relPath := name
			if rel != "" {
				relPath = filepath.Join(rel, name)
			}
			relPath = filepath.ToSlash(relPath)

			resp.Entries = append(resp.Entries, listEntry{
				Name:    name,
				IsDir:   e.IsDir(),
				RelPath: relPath,
				Size:    info.Size(),
				ModTime: info.ModTime().Format(time.RFC3339),
			})
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 下载单个文件
	http.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		rel := strings.TrimSpace(r.URL.Query().Get("file"))
		full, err := joinSafe(root, rel)
		if err != nil {
			http.Error(w, "invalid file", http.StatusBadRequest)
			return
		}

		st, err := os.Stat(full)
		if err != nil {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}
		if st.IsDir() {
			http.Error(w, "cannot download directory here (use /download-zip)", http.StatusBadRequest)
			return
		}

		fileName := filepath.Base(full)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fileName))
		http.ServeFile(w, r, full)
	})

	// 下载整个文件夹为 zip
	http.HandleFunc("/download-zip", func(w http.ResponseWriter, r *http.Request) {
		if !isAuthed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		rel := strings.TrimSpace(r.URL.Query().Get("dir"))
		full, err := joinSafe(root, rel)
		if err != nil {
			http.Error(w, "invalid dir", http.StatusBadRequest)
			return
		}

		st, err := os.Stat(full)
		if err != nil || !st.IsDir() {
			http.Error(w, "not a directory", http.StatusBadRequest)
			return
		}

		baseName := filepath.Base(full)
		if baseName == "" || baseName == "." {
			baseName = "root"
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zip"`, baseName))

		zw := zip.NewWriter(w)
		defer zw.Close()

		_ = filepath.WalkDir(full, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			relInside, err := filepath.Rel(full, path)
			if err != nil {
				return nil
			}
			zipPath := filepath.ToSlash(relInside)

			fw, err := zw.Create(zipPath)
			if err != nil {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			_, _ = io.Copy(fw, f)
			return nil
		})
	})

	fmt.Println("Root folder:", root)
	fmt.Println("密码已设置，打开浏览器访问: http://<本机的IP>:" + port)
	_ = http.ListenAndServe(":"+port, nil)
}
