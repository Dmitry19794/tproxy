import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ================= REAL CLIENT MODELS =================

CLIENTS = {
    "Safari iOS": {
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
    },

    "Chrome Android": {
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
            "tcp_ack_delay_ms": 30,
            "tls_record_flush_ms": 10,
            "http2_window_update_ms": 90
        }
    },

    "Firefox Desktop": {
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

# ================= GENERATOR =================

def generate():
    name = profile_name.get().strip()
    client = client_var.get()

    if not name:
        messagebox.showerror("Ошибка", "Имя профиля обязательно")
        return

    model = CLIENTS[client]

    profile = {
        "name": name,
        "tls": model["tls"],
        "http2": model["http2"],
        "timing": model["timing"]
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

    messagebox.showinfo("Готово", "Профиль создан. Поведение согласовано.")

# ================= GUI =================

root = tk.Tk()
root.title("TPROXY Profile Generator")

ui = ttk.Frame(root, padding=14)
ui.grid()

ttk.Label(ui, text="Имя профиля").grid(row=0, column=0, sticky="w")
profile_name = ttk.Entry(ui, width=32)
profile_name.grid(row=0, column=1)

ttk.Label(ui, text="Клиент").grid(row=1, column=0, sticky="w")
client_var = tk.StringVar(value="Safari iOS")
ttk.Combobox(
    ui,
    textvariable=client_var,
    values=list(CLIENTS.keys()),
    state="readonly"
).grid(row=1, column=1)

ttk.Label(ui, text="SOCKS5 Host").grid(row=2, column=0, sticky="w")
proxy_host = ttk.Entry(ui)
proxy_host.insert(0, "127.0.0.1")
proxy_host.grid(row=2, column=1)

ttk.Label(ui, text="SOCKS5 Port").grid(row=3, column=0, sticky="w")
proxy_port = ttk.Entry(ui)
proxy_port.insert(0, "1080")
proxy_port.grid(row=3, column=1)

ttk.Button(ui, text="Создать профиль", command=generate)\
    .grid(row=4, column=0, columnspan=2, pady=10)

root.mainloop()
