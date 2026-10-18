"""ProxyScout - finds working free proxies and exports them to Telegram / v2rayNG / any app.

It does NOT create a system-wide VPN: it hands the working proxies to apps that can use them.
"""
import os
import threading

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import BooleanProperty, ListProperty, NumericProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.utils import platform

import proxycore as pc

MAX_TEST = 400          # proxies tested per scan (keeps phone and battery happy)
MAX_SHOWN = 60

KV = r"""
#:import dp kivy.metrics.dp
#:import sp kivy.metrics.sp

<LeftLabel@Label>:
    text_size: self.width, None
    halign: 'left'
    valign: 'middle'

<Card>:
    canvas.before:
        Color:
            rgba: self.bg
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: self.radius

<PillButton>:
    background_normal: ''
    background_down: ''
    background_color: 0, 0, 0, 0
    bold: True
    color: 1, 1, 1, 1
    font_size: sp(14)
    canvas.before:
        Color:
            rgba: self.bg if self.state == 'normal' else self.bg_down
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]

<Chip@ToggleButton>:
    background_normal: ''
    background_down: ''
    background_color: 0, 0, 0, 0
    bold: True
    font_size: sp(14)
    color: (1, 1, 1, 1) if self.state == 'down' else (0.62, 0.68, 0.80, 1)
    canvas.before:
        Color:
            rgba: (0.22, 0.52, 1, 1) if self.state == 'down' else (0.12, 0.15, 0.25, 1)
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(12)]

<StatCard>:
    orientation: 'vertical'
    padding: dp(8), dp(8)
    Label:
        text: root.value
        font_size: sp(26)
        bold: True
        color: root.accent
    Label:
        text: root.caption
        font_size: sp(12)
        color: 0.62, 0.68, 0.80, 1

<ProxyRow>:
    size_hint_y: None
    height: dp(70)
    padding: dp(14), dp(8), dp(10), dp(8)
    spacing: dp(8)
    BoxLayout:
        orientation: 'vertical'
        LeftLabel:
            text: root.title
            font_size: sp(16)
            bold: True
            color: 1, 1, 1, 1
        LeftLabel:
            text: root.subtitle
            font_size: sp(12)
            color: root.sub_color
    PillButton:
        size_hint: None, None
        size: dp(86), dp(42)
        pos_hint: {'center_y': .5}
        text: 'Telegram'
        disabled: not root.can_tg
        opacity: 1 if root.can_tg else 0.3
        bg: 0.22, 0.52, 1, 1
        bg_down: 0.16, 0.40, 0.85, 1
        on_release: root.on_tg()
    PillButton:
        size_hint: None, None
        size: dp(64), dp(42)
        pos_hint: {'center_y': .5}
        text: 'Copy'
        bg: 0.18, 0.22, 0.34, 1
        bg_down: 0.24, 0.29, 0.44, 1
        on_release: root.on_copy()

BoxLayout:
    orientation: 'vertical'
    padding: dp(16), dp(10), dp(16), dp(10)
    spacing: dp(10)

    BoxLayout:
        orientation: 'vertical'
        size_hint_y: None
        height: dp(58)
        LeftLabel:
            text: 'ProxyScout'
            font_size: sp(28)
            bold: True
            color: 1, 1, 1, 1
        LeftLabel:
            text: 'Find working proxies, send them to Telegram or v2rayNG'
            font_size: sp(12)
            color: 0.62, 0.68, 0.80, 1

    BoxLayout:
        size_hint_y: None
        height: dp(80)
        spacing: dp(10)
        StatCard:
            value: str(app.n_found)
            caption: 'candidates'
            accent: 0.62, 0.68, 0.80, 1
        StatCard:
            value: str(app.n_tested)
            caption: 'tested'
            accent: 0.98, 0.78, 0.30, 1
        StatCard:
            value: str(app.n_working)
            caption: 'working'
            accent: 0.25, 0.85, 0.55, 1

    BoxLayout:
        size_hint_y: None
        height: dp(42)
        spacing: dp(8)
        Chip:
            id: chip_socks
            text: 'SOCKS5'
            state: 'down'
        Chip:
            id: chip_http
            text: 'HTTP'
            state: 'down'
        PillButton:
            text: 'Paste list & test'
            bg: 0.18, 0.22, 0.34, 1
            bg_down: 0.24, 0.29, 0.44, 1
            on_release: app.scan(True)

    PillButton:
        size_hint_y: None
        height: dp(54)
        font_size: sp(17)
        text: 'STOP' if app.scanning else 'SCAN FOR PROXIES'
        bg: (0.92, 0.30, 0.36, 1) if app.scanning else (0.22, 0.52, 1, 1)
        bg_down: (0.75, 0.22, 0.28, 1) if app.scanning else (0.16, 0.40, 0.85, 1)
        on_release: app.toggle_scan()

    Widget:
        size_hint_y: None
        height: dp(6)
        canvas:
            Color:
                rgba: 0.12, 0.15, 0.25, 1
            RoundedRectangle:
                pos: self.pos
                size: self.size
                radius: [dp(3)]
            Color:
                rgba: 0.25, 0.78, 0.95, 1
            RoundedRectangle:
                pos: self.pos
                size: max(self.height, self.width * app.progress), self.height
                radius: [dp(3)]

    LeftLabel:
        size_hint_y: None
        height: dp(34)
        text: app.status_text
        font_size: sp(12)
        color: 0.62, 0.68, 0.80, 1

    ScrollView:
        bar_width: dp(3)
        do_scroll_x: False
        BoxLayout:
            id: rows
            orientation: 'vertical'
            size_hint_y: None
            height: self.minimum_height
            spacing: dp(8)

    BoxLayout:
        size_hint_y: None
        height: dp(48)
        spacing: dp(8)
        PillButton:
            text: 'Telegram links'
            bg: 0.18, 0.22, 0.34, 1
            bg_down: 0.24, 0.29, 0.44, 1
            on_release: app.copy_all('tg')
        PillButton:
            text: 'v2rayNG list'
            bg: 0.18, 0.22, 0.34, 1
            bg_down: 0.24, 0.29, 0.44, 1
            on_release: app.copy_all('v2ray')
        PillButton:
            text: 'Share all'
            bg: 0.18, 0.22, 0.34, 1
            bg_down: 0.24, 0.29, 0.44, 1
            on_release: app.share_all()

    LeftLabel:
        size_hint_y: None
        height: dp(30)
        text: 'Free public proxies are slow, short-lived and can read unencrypted traffic. Do not use them for banking or logins.'
        font_size: sp(10)
        color: 0.45, 0.50, 0.62, 1
"""


class Card(BoxLayout):
    bg = ListProperty([0.10, 0.13, 0.21, 1])
    radius = ListProperty([dp(16)])


class StatCard(Card):
    value = StringProperty("0")
    caption = StringProperty("")
    accent = ListProperty([1, 1, 1, 1])


class PillButton(Button):
    bg = ListProperty([0.22, 0.52, 1, 1])
    bg_down = ListProperty([0.16, 0.40, 0.85, 1])


class ProxyRow(Card):
    title = StringProperty("")
    subtitle = StringProperty("")
    sub_color = ListProperty([0.6, 0.65, 0.75, 1])
    can_tg = BooleanProperty(False)

    def __init__(self, proxy, **kw):
        super().__init__(**kw)
        self.proxy = proxy
        self.title = proxy.addr
        ms = proxy.ms or 0
        self.subtitle = "%s  ·  %d ms" % ("SOCKS5" if proxy.kind == "socks5" else "HTTP", ms)
        self.sub_color = ([0.25, 0.85, 0.55, 1] if ms < 800 else
                          [0.98, 0.78, 0.30, 1] if ms < 2000 else [0.98, 0.55, 0.30, 1])
        self.can_tg = proxy.kind == "socks5"

    def on_tg(self):
        App.get_running_app().open_telegram(self.proxy)

    def on_copy(self):
        App.get_running_app().copy_text(pc.plain_link(self.proxy), "Copied " + self.proxy.addr)


def _android_activity():
    from jnius import autoclass
    return autoclass("org.kivy.android.PythonActivity").mActivity


def android_view(url):
    from jnius import autoclass
    Intent = autoclass("android.content.Intent")
    Uri = autoclass("android.net.Uri")
    _android_activity().startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))


def android_share(text):
    from jnius import autoclass, cast
    Intent = autoclass("android.content.Intent")
    String = autoclass("java.lang.String")
    it = Intent()
    it.setAction(Intent.ACTION_SEND)
    it.putExtra(Intent.EXTRA_TEXT, String(text))
    it.setType("text/plain")
    chooser = Intent.createChooser(it, cast("java.lang.CharSequence", String("Share proxies")))
    _android_activity().startActivity(chooser)


class ProxyScoutApp(App):
    title = "ProxyScout"
    n_found = NumericProperty(0)
    n_tested = NumericProperty(0)
    n_working = NumericProperty(0)
    progress = NumericProperty(0)
    scanning = BooleanProperty(False)
    status_text = StringProperty("Press SCAN to look for working proxies.")

    def build(self):
        Window.clearcolor = (0.04, 0.06, 0.11, 1)
        self.working = []
        self.total = 0
        self.stop_evt = threading.Event()
        self._refresh = Clock.create_trigger(self._refresh_list, 0.4)
        return Builder.load_string(KV)

    def on_start(self):
        self.cache_path = os.path.join(self.user_data_dir, "last_scan.json")
        self.working = pc.load_results(self.cache_path)
        self.n_working = len(self.working)
        if self.working:
            self.status_text = "Showing the last scan (%d proxies, not re-tested). Press SCAN to refresh." % len(self.working)
        self._refresh_list()

    def on_pause(self):
        return True

    # ---------------------------------------------------------------- scanning
    def toggle_scan(self):
        if self.scanning:
            self.stop_evt.set()
            self.status_text = "Stopping..."
        else:
            self.scan(False)

    def scan(self, from_clipboard):
        if self.scanning:
            return
        ids = self.root.ids
        kinds = [k for k, chip in (("socks5", ids.chip_socks), ("http", ids.chip_http)) if chip.state == "down"]
        if not kinds:
            self.status_text = "Select SOCKS5 and/or HTTP first."
            return
        clip = ""
        if from_clipboard:
            try:
                clip = Clipboard.paste() or ""
            except Exception:
                clip = ""
            if not clip.strip():
                self.status_text = "Clipboard is empty. Copy a list of ip:port lines first."
                return
        self.scanning = True
        self.stop_evt = threading.Event()
        self.working = []
        self.n_found = self.n_tested = self.n_working = 0
        self.progress = 0
        self._refresh_list()
        threading.Thread(target=self._worker, args=(kinds, from_clipboard, clip, self.stop_evt),
                         daemon=True).start()

    def _ui(self, fn, *args):
        Clock.schedule_once(lambda dt: fn(*args), 0)

    def _worker(self, kinds, from_clipboard, clip, stop):
        try:
            if from_clipboard:
                cands = pc.parse_proxies(clip, tuple(kinds))
                cands = [p for p in cands if p.kind in kinds]
            else:
                self._ui(self._say, "Downloading proxy lists...")
                cands = pc.fetch_candidates(kinds, log=lambda m: self._ui(self._say, m), stop=stop)
            if stop.is_set():
                return
            if not cands:
                self._ui(self._say, "No proxies found. The list sources may be blocked - try 'Paste list & test'.")
                return
            sample = pc.pick_sample(cands, MAX_TEST)
            self._ui(self._begin, len(cands), len(sample))
            pc.test_many(sample, lambda p, ok: self._ui(self._result, p, ok), stop)
        except Exception as e:
            self._ui(self._say, "Error: %s: %s" % (type(e).__name__, e))
        finally:
            self._ui(self._finish, stop)

    def _say(self, text):
        self.status_text = text

    def _begin(self, found, total):
        self.n_found = found
        self.total = total
        self.status_text = "Testing %d proxies..." % total

    def _result(self, p, ok):
        self.n_tested += 1
        if self.total:
            self.progress = self.n_tested / float(self.total)
        if ok:
            self.working.append(p)
            self.working.sort(key=lambda x: x.ms or 10 ** 9)
            self.n_working = len(self.working)
            self._refresh()
        self.status_text = "Testing... %d / %d tested, %d working" % (self.n_tested, self.total, self.n_working)

    def _finish(self, stop):
        if stop is not self.stop_evt:
            return
        self.scanning = False
        stopped = stop.is_set()
        self.progress = 1 if (self.total and not stopped) else self.progress
        self._refresh_list()
        if self.working:
            pc.save_results(self.cache_path, self.working)
        if stopped:
            self.status_text = "Stopped. %d working proxies found." % self.n_working
        elif self.n_tested:
            self.status_text = ("Done: %d working out of %d tested." % (self.n_working, self.n_tested)
                                if self.n_working else
                                "Done: none of %d proxies worked. Scan again - free lists change fast." % self.n_tested)

    def _refresh_list(self, *_):
        rows = self.root.ids.rows
        rows.clear_widgets()
        for p in self.working[:MAX_SHOWN]:
            rows.add_widget(ProxyRow(p))

    # ---------------------------------------------------------------- export
    def copy_text(self, text, msg):
        try:
            Clipboard.copy(text)
            self.status_text = msg
        except Exception as e:
            self.status_text = "Copy failed: %s" % e

    def copy_all(self, fmt):
        items = self.working[:100]
        text = pc.export_text(items, fmt)
        if not text:
            self.status_text = ("Nothing to export yet - scan first." if not items else
                                "Telegram links need SOCKS5 proxies; none found yet.")
            return
        n = len(text.splitlines())
        self.copy_text(text, "Copied %d %s links. Paste them into a chat or the app's import." % (
            n, "Telegram" if fmt == "tg" else "v2rayNG"))

    def share_all(self):
        text = pc.export_text(self.working[:100], "plain")
        if not text:
            self.status_text = "Nothing to share yet - scan first."
            return
        if platform == "android":
            try:
                android_share(text)
                return
            except Exception as e:
                self.status_text = "Share failed (%s) - copied instead." % type(e).__name__
        self.copy_text(text, "Copied %d proxies to the clipboard." % len(text.splitlines()))

    def open_telegram(self, p):
        link = pc.tg_link(p)
        if not link:
            return
        if platform == "android":
            try:
                android_view(link)
                return
            except Exception:
                pass
        self.copy_text(pc.tg_web_link(p), "Telegram link copied - open it in Telegram.")


if __name__ == "__main__":
    ProxyScoutApp().run()
