import sys
import os
import requests

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QLabel,
    QMessageBox,
)

from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineDownloadRequest

# -------------------------------------------------
# Configurações gerais
# -------------------------------------------------
HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SteamGameLookup/1.0)"
}

TARGET_URL = "https://manifestor.cc"
DOWNLOAD_SUBFOLDER = "lua_files"   # pasta onde os .lua serão salvos


# -------------------------------------------------
# FUNÇÕES DE BUSCA NA STEAM
# -------------------------------------------------
def fetch_app_by_appid(appid: int):
    url = "https://store.steampowered.com/api/appdetails"
    params = {"appids": appid, "l": "english", "cc": "US"}

    try:
        resp = requests.get(url, params=params, headers=HTTP_HEADERS, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        print(f"Erro HTTP em appdetails: {e}")
        return None

    try:
        data = resp.json()
    except Exception as e:
        print(f"Erro parse JSON appdetails: {e}")
        return None

    block = data.get(str(appid))
    if not block or not block.get("success"):
        return None

    appdata = block.get("data", {})
    name = appdata.get("name")
    header_image = appdata.get("header_image")

    if not name or not header_image:
        return None

    return {
        "appid": appid,
        "name": name,
        "header_image": header_image,
    }


def search_app_by_name(query: str):
    url = "https://store.steampowered.com/api/storesearch/"
    params = {"term": query, "l": "english", "cc": "US"}

    try:
        resp = requests.get(url, params=params, headers=HTTP_HEADERS, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        print(f"Erro HTTP em storesearch: {e}")
        return None

    try:
        data = resp.json()
    except Exception as e:
        print(f"Erro parse JSON storesearch: {e}")
        return None

    items = data.get("items") or []
    if not items:
        return None

    first = items[0]
    appid = first.get("id")
    if not appid:
        return None

    return fetch_app_by_appid(appid)


# -------------------------------------------------
# JANELA PRINCIPAL
# -------------------------------------------------
class SteamSearchWindow(QMainWindow):
    """
    - Busca Steam (nome ou AppID)
    - Mostra nome + header do jogo
    - Botão "Get Lua" que usa um QWebEngineView oculto
      para baixar o arquivo no Manifestor.cc
    """

    def __init__(self):
        super().__init__()

        self.setWindowTitle("The Last Option")
        self.resize(900, 500)

        self.last_result = None          # dict com appid/name/header
        self.manifestor_loaded = False   # se página já carregou
        self.pending_appid = None        # appid que está esperando carregar
        self.manifestor_started = False  # se já iniciamos o WebEngine

        self._downloads = []             # manter referências de download

        # --------- ESTILO ESCURO ----------
        self.setStyleSheet(
            """
            QWidget {
                background-color: #020617;
                color: #e5e7eb;
                font-family: Segoe UI, sans-serif;
                font-size: 10pt;
            }
            QLineEdit {
                background-color: #020617;
                border: 1px solid #1f2937;
                border-radius: 6px;
                padding: 6px 8px;
                color: #e5e7eb;
            }
            QPushButton {
                background-color: #111827;
                border: 1px solid #1f2937;
                padding: 6px 16px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #020617;
            }
            QPushButton:pressed {
                background-color: #0b1120;
            }
            """
        )

        # --------- LAYOUT PRINCIPAL ----------
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(10)

        # Linha de busca
        search_row = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(
            "Digite o nome do jogo ou AppID | Type game name or AppID "
        )
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.on_search_clicked)

        search_row.addWidget(self.search_edit, stretch=1)
        search_row.addWidget(self.search_button)

        root_layout.addLayout(search_row)

        # Linha com info do jogo + botão Get Lua
        info_row = QHBoxLayout()
        self.info_label = QLabel("Sem jogo | No game.")
        self.info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.info_label.setWordWrap(True)

        self.get_lua_button = QPushButton("Get Lua")
        self.get_lua_button.setEnabled(False)
        self.get_lua_button.clicked.connect(self.on_get_lua_clicked)

        info_row.addWidget(self.info_label, stretch=1)
        info_row.addWidget(self.get_lua_button)

        root_layout.addLayout(info_row)

        # Logo/header
        self.logo_label = QLabel()
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo_label.setMinimumHeight(220)
        root_layout.addWidget(self.logo_label, stretch=1)

        # ---- Inicializa WebEngine oculto (Manifestor) ----
        self.init_hidden_webengine()

    # -------------------------------------------------
    # WEBENGINE OCULTO (MANIFESTOR.CC)
    # -------------------------------------------------
    def init_hidden_webengine(self):
        """
        Cria um QWebEngineView oculto e começa a carregar o Manifestor.cc.
        """
        if self.manifestor_started:
            return

        self.manifestor_started = True

        # WebEngine totalmente escondido
        self.hidden_browser = QWebEngineView(self)
        self.hidden_browser.hide()  # não aparece nunca
        self.hidden_browser.setFixedSize(1, 1)
        self.hidden_browser.move(-10000, -10000)
        self.hidden_browser.setAttribute(
            Qt.WidgetAttribute.WA_DontShowOnScreen, True
        )

        self.web_profile = self.hidden_browser.page().profile()

        # Limpa cache e depois carrega a página
        self.web_profile.clearHttpCacheCompleted.connect(self.on_cache_cleared)
        self.web_profile.clearHttpCache()


    def on_cache_cleared(self):
        print("Cache do Manifestor limpo. Carregando página...")
        self.web_profile.downloadRequested.connect(self.handle_download_request)
        self.hidden_browser.loadFinished.connect(self.on_manifestor_load_finished)
        self.hidden_browser.setUrl(QUrl(TARGET_URL))

    def on_manifestor_load_finished(self, success: bool):
        if not success:
            print("Falha ao carregar Manifestor.cc")
            return

        print("Manifestor.cc carregado.")
        self.manifestor_loaded = True

        # Tenta fechar modal de boas-vindas (bem parecido com seu script)
        js_close_modal = """
            setTimeout(function() {
                var closeButton = document.getElementById('welcome-close');
                if (closeButton) {
                    closeButton.click();
                    console.log('Cliquei em #welcome-close');
                }
                document.body.classList.remove('modal-open');
            }, 800);
        """
        self.hidden_browser.page().runJavaScript(js_close_modal)

        # Se já tinha um appid esperando, dispara a automação agora
        if self.pending_appid is not None:
            appid = self.pending_appid
            self.pending_appid = None
            self.inject_and_download(appid)

    def handle_download_request(self, download: QWebEngineDownloadRequest):
        """
        Intercepta o download, salva em lua_files
        e EXIBE MENSAGEM QUANDO TERMINAR, depois fecha a janela.
        """
        self._downloads.append(download)

        base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        download_dir = os.path.join(base_dir, DOWNLOAD_SUBFOLDER)

        if not os.path.isdir(download_dir):
            os.makedirs(download_dir, exist_ok=True)

        suggested_filename = download.suggestedFileName()
        final_path_display = os.path.join(download_dir, suggested_filename)

        download_dir_qt = download_dir.replace("\\", "/")
        download.setDownloadDirectory(download_dir_qt)
        download.setDownloadFileName(suggested_filename)

        print("\n--- DOWNLOAD INTERCEPTADO ---")
        print(f"Destino: {download_dir_qt}/{suggested_filename}")
        print("-----------------------------")

        def download_state_changed(state):
            from PyQt6.QtWebEngineCore import QWebEngineDownloadRequest

            if state in (
                QWebEngineDownloadRequest.DownloadState.DownloadCompleted,
                QWebEngineDownloadRequest.DownloadState.DownloadInterrupted,
            ):
                ok = (
                    state == QWebEngineDownloadRequest.DownloadState.DownloadCompleted
                    and os.path.exists(final_path_display)
                )

                if ok:
                    print(f"SUCESSO: Arquivo {suggested_filename} salvo com sucesso.")

                    QMessageBox.information(
                        self,
                        "Lua salvo",
                        f"{suggested_filename}\nfoi salvo em |saved in:\n\n{download_dir}\n\nClique OK para fechar |Click ok to close."
                    )

                    # FECHAR A JANELA AO CONFIRMAR
                    self.close()

                else:
                    print(f"FALHA no download de {suggested_filename}.")
                    QMessageBox.warning(
                        self,
                        "Falha",
                        "O download foi interrompido ou falhou."
                    )

                if download in self._downloads:
                    self._downloads.remove(download)

        download.stateChanged.connect(download_state_changed)
        download.accept()

    # -------------------------------------------------
    # LÓGICA DE BUSCA (STEAM)
    # -------------------------------------------------
    def on_search_clicked(self):
        text = self.search_edit.text().strip()
        if not text:
            self.show_message("Aviso", "Digite um nome de jogo ou um AppID.")
            return

        self.info_label.setText("Buscando | Searching...")
        self.logo_label.clear()
        QApplication.processEvents()

        if text.isdigit():
            appid = int(text)
            result = fetch_app_by_appid(appid)
        else:
            result = search_app_by_name(text)

        if not result:
            self.last_result = None
            self.get_lua_button.setEnabled(False)
            self.info_label.setText("Nenhum resultado encontrado.")
            self.show_message("Erro", "Não encontrei nenhum jogo com esse termo / AppID.")
            return

        self.last_result = result
        name = result["name"]
        appid = result["appid"]
        header_url = result["header_image"]

        self.info_label.setText(f"{name} (AppID: {appid})")
        self.get_lua_button.setEnabled(True)

        # Baixa e mostra a imagem do header
        try:
            img_resp = requests.get(header_url, headers=HTTP_HEADERS, timeout=10)
            img_resp.raise_for_status()
            pixmap = QPixmap()
            pixmap.loadFromData(img_resp.content)

            if not pixmap.isNull():
                scaled = pixmap.scaled(
                    600,
                    260,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
                self.logo_label.setPixmap(scaled)
            else:
                self.logo_label.setText(
                    "Não foi possível carregar a imagem do jogo."
                )
        except Exception as e:
            print(f"Erro ao baixar imagem: {e}")
            self.logo_label.setText("Erro ao baixar imagem do jogo.")

    # -------------------------------------------------
    # BOTÃO GET LUA
    # -------------------------------------------------
    def on_get_lua_clicked(self):
        """
        Pega o AppID do último resultado e manda o Manifestor baixar.
        """
        if not self.last_result:
            self.show_message(
                "Aviso", "Nenhum jogo carregado. Faça uma busca primeiro."
            )
            return

        appid = self.last_result["appid"]
        print(f"Get Lua solicitado para AppID {appid}")

        # Se a página ainda não carregou, marca como pendente
        self.pending_appid = appid

        # Garante que o WebEngine foi iniciado
        if not self.manifestor_started:
            self.init_hidden_webengine()
            return

        # Se já está carregado, dispara direto
        if self.manifestor_loaded:
            self.pending_appid = None
            self.inject_and_download(appid)
        else:
            print("Manifestor ainda carregando, AppID aguardando load...")

    def inject_and_download(self, appid: int):
        """
        Executa JavaScript dentro do Manifestor:
        - Preenche o campo de busca com o AppID
        - Simula busca/enter
        - Clica no botão 'Download'
        """
        print(f"Injetando JS no Manifestor para AppID {appid}")

        js_code = f"""
            (function() {{
                try {{
                    // Encontra o campo de busca principal
                    var input = document.querySelector('input[placeholder*="Search for a game"]')
                               || document.querySelector('input[placeholder*="Search for a game or enter AppID"]')
                               || document.querySelector('input');

                    if (!input) {{
                        console.log('Campo de busca não encontrado.');
                        return 'no-input';
                    }}

                    input.focus();
                    input.value = '{appid}';

                    // dispara eventos pra simular digitação
                    input.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    input.dispatchEvent(new Event('change', {{ bubbles: true }}));

                    // tenta simular Enter
                    var evDown = new KeyboardEvent('keydown', {{ key: 'Enter', keyCode: 13, which: 13, bubbles: true }});
                    var evUp   = new KeyboardEvent('keyup',   {{ key: 'Enter', keyCode: 13, which: 13, bubbles: true }});
                    input.dispatchEvent(evDown);
                    input.dispatchEvent(evUp);

                    // Após um pequeno atraso, tenta achar o botão Download
                    setTimeout(function() {{
                        var btn = null;
                        var candidates = document.querySelectorAll('button, a');

                        candidates.forEach(function(el) {{
                            if (!btn && /download/i.test(el.textContent || '')) {{
                                btn = el;
                            }}
                        }});

                        if (btn) {{
                            btn.click();
                            console.log('Botão Download clicado.');
                        }} else {{
                            console.log('Botão Download não encontrado.');
                        }}
                    }}, 1200);

                    return 'ok';
                }} catch (e) {{
                    console.log('Erro no script de automação:', e);
                    return 'error';
                }}
            }})();
        """

        self.hidden_browser.page().runJavaScript(js_code)

    # -------------------------------------------------
    def show_message(self, title: str, text: str):
        msg = QMessageBox(self)
        msg.setWindowTitle(title)
        msg.setText(text)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.exec()


# -------------------------------------------------
def main():
    app = QApplication(sys.argv)
    win = SteamSearchWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
