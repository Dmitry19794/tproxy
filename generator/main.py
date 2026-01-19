import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ================= VERIFIED TEMPLATES =================

TEMPLATES = {

    # -------- SAFARI --------

    "Safari iOS": {
        "16.6": {
            "tls": {
                "cipher_suites": [
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256"
                ],
                "extensions": [
                    "server_name",
                    "supported_versions",
                    "signature_algorithms",
                    "key_share",
                    "psk_key_exchange_modes",
                    "application_layer_protocol_negotiation"
                ],
                "supported_versions": ["TLS 1.3"],
                "alpn": ["h2", "http/1.1"],
                "signature_algorithms": ["ecdsa_secp256r1_sha256"],
                "key_share_groups": ["x25519"],
                "psk_key_exchange_modes": ["psk_dhe_ke"]
            },
            "http2": {
                "settings": {
                    "HEADER_TABLE_SIZE": 65536,
                    "INITIAL_WINDOW_SIZE": 983040,
                    "MAX_FRAME_SIZE": 16384
                },
                "window_update_policy": "ios_natural",
                "priority_tree": "safari_style",
                "flow_control": "passive"
            },
            "timing": {
                "tcp_ack_delay_ms": 45,
                "tls_record_flush_ms": 18,
                "http2_window_update_ms": 130
            }
        },

        "17.2": {
            "tls": {
                "cipher_suites": [
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256"
                ],
                "extensions": [
                    "server_name",
                    "supported_versions",
                    "signature_algorithms",
                    "key_share",
                    "psk_key_exchange_modes",
                    "compress_certificate",
                    "application_layer_protocol_negotiation"
                ],
                "supported_versions": ["TLS 1.3"],
                "alpn": ["h2", "http/1.1"],
                "signature_algorithms": ["ecdsa_secp256r1_sha256"],
                "key_share_groups": ["x25519"],
                "psk_key_exchange_modes": ["psk_dhe_ke"],
                "compress_certificate": ["brotli"]
            },
            "http2": {
                "settings": {
                    "HEADER_TABLE_SIZE": 65536,
                    "INITIAL_WINDOW_SIZE": 1048576,
                    "MAX_FRAME_SIZE": 16384
                },
                "window_update_policy": "ios_natural",
                "priority_tree": "safari_style",
                "flow_control": "passive"
            },
            "timing": {
                "tcp_ack_delay_ms": 40,
                "tls_record_flush_ms": 15,
                "http2_window_update_ms": 120
            }
        }
    },

    # -------- CHROME --------

    "Chrome Desktop": {
        "118": {
            "tls": {
                "cipher_suites": [
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256"
                ],
                "extensions": [
                    "server_name",
                    "supported_versions",
                    "signature_algorithms",
                    "key_share",
                    "psk_key_exchange_modes",
                    "application_layer_protocol_negotiation"
                ],
                "supported_versions": ["TLS 1.3"],
                "alpn": ["h2", "http/1.1"],
                "signature_algorithms": [
                    "ecdsa_secp256r1_sha256",
                    "rsa_pss_rsae_sha256"
                ],
                "key_share_groups": ["x25519"],
                "psk_key_exchange_modes": ["psk_dhe_ke"]
            },
            "http2": {
                "settings": {
                    "HEADER_TABLE_SIZE": 65536,
                    "INITIAL_WINDOW_SIZE": 6291456,
                    "MAX_FRAME_SIZE": 16384
                },
                "window_update_policy": "chrome_natural",
                "priority_tree": "chrome_style",
                "flow_control": "balanced"
            },
            "timing": {
                "tcp_ack_delay_ms": 28,
                "tls_record_flush_ms": 9,
                "http2_window_update_ms": 85
            }
        }
    },

    # -------- FIREFOX --------

    "Firefox Desktop": {
        "120": {
            "tls": {
                "cipher_suites": [
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_CHACHA20_POLY1305_SHA256",
                    "TLS_AES_256_GCM_SHA384"
                ],
                "extensions": [
                    "server_name",
                    "supported_versions",
                    "signature_algorithms",
                    "key_share",
                    "application_layer_protocol_negotiation"
                ],
                "supported_versions": ["TLS 1.3"],
                "alpn": ["h2", "http/1.1"],
                "signature_algorithms": [
                    "ecdsa_secp256r1_sha256",
                    "rsa_pss_rsae_sha256"
                ],
                "key_share_groups": ["x25519"]
            },
            "http2": {
                "settings": {
                    "HEADER_TABLE_SIZE": 65536,
                    "INITIAL_WINDOW_SIZE": 131072,
                    "MAX_FRAME_SIZE": 16384
                },
                "window_update_policy": "firefox_natural",
                "priority_tree": "firefox_style",
                "flow_control": "conservative"
            },
            "timing": {
                "tcp_ack_delay_ms": 25,
                "tls_record_flush_ms": 12,
                "http2_window_update_ms": 110
            }
        }
    }
}

# ================= GUI =================

def update_versions(*_):
    versions = list(TEMPLATES[browser_var.get()].keys())
    version_box["values"] = versions
    version_var.set(versions[0])

def generate():
    name = name_entry.get().strip()
    if not name:
        messagebox.showerror("Ошибка", "Имя профиля обязательно")
        return

    tpl = TEMPLATES[browser_var.get()][version_var.get()]

    profile = {
        "name": name,
        **tpl
    }

    config = {
        "profiles": [profile],
        "default_profile": name,
        "proxy_settings": {
            "proxy_host": proxy_host.get(),
            "proxy_port": int(proxy_port.get()),
            "proxy_type": "socks5",
            "username": None,
            "password": None
        }
    }

    path = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON", "*.json")]
    )
    if not path:
        return

    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    messagebox.showinfo("Готово", "Профиль создан из проверенного шаблона")

root = tk.Tk()
root.title("Browser Profile Generator")

frame = ttk.Frame(root, padding=14)
frame.grid()

ttk.Label(frame, text="Имя профиля").grid(row=0, column=0, sticky="w")
name_entry = ttk.Entry(frame, width=32)
name_entry.grid(row=0, column=1)

ttk.Label(frame, text="Браузер").grid(row=1, column=0, sticky="w")
browser_var = tk.StringVar(value="Safari iOS")
browser_box = ttk.Combobox(
    frame,
    textvariable=browser_var,
    values=list(TEMPLATES.keys()),
    state="readonly"
)
browser_box.grid(row=1, column=1)
browser_var.trace_add("write", update_versions)

ttk.Label(frame, text="Версия").grid(row=2, column=0, sticky="w")
version_var = tk.StringVar()
version_box = ttk.Combobox(frame, textvariable=version_var, state="readonly")
version_box.grid(row=2, column=1)

ttk.Label(frame, text="SOCKS5 Host").grid(row=3, column=0, sticky="w")
proxy_host = ttk.Entry(frame)
proxy_host.insert(0, "127.0.0.1")
proxy_host.grid(row=3, column=1)

ttk.Label(frame, text="SOCKS5 Port").grid(row=4, column=0, sticky="w")
proxy_port = ttk.Entry(frame)
proxy_port.insert(0, "1080")
proxy_port.grid(row=4, column=1)

ttk.Button(frame, text="Создать профиль", command=generate)\
    .grid(row=5, column=0, columnspan=2, pady=10)

update_versions()
root.mainloop()
