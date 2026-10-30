# NACo v3.0.0 — Tasarım Dokümanı

- **Tarih:** 2026-10-30
- **Durum:** Onaylandı (beyin fırtınası oturumu), uygulama planı bekleniyor
- **Dal:** `v3`
- **Kapsam:** v2.3.0'ın denetimi sonrası yeniden yapılanma — daha güvenli, daha hafif, daha sade, çalıştığı kanıtlanmış bir ürün.

> Bu bir çalışma dokümanıdır; v3.0.0 yayınlanırken `docs/superpowers/` dizini ürün dokümantasyonundan çıkarılabilir.

---

## 1. Hedef ve kararlar

| Karar | Seçim |
|---|---|
| Hedef kitle | Tek sunucu, küçük-orta kurum (≈5.000 cihaza kadar), Docker Compose kurulumu |
| RADIUS mimarisi | Tek kapı FreeRADIUS 3.2 (1812/1813); NACo yalnızca karar veren beyin |
| Veritabanı | Yalnızca SQLite (WAL); PostgreSQL ve Redis kaldırılır |
| Mevcut kurulumlar | Yok — temiz başlangıç, v2'den veri taşıma yok, migration zinciri tek baseline'a indirilir |
| Panel | Mevcut tasarım korunur, eksikler tamamlanır, görsel olarak yükseltilir (animasyon, akıcılık, canlı veri) |
| Arayüz dili | İngilizce |

### Kalan özellikler
802.1X + MAB + VLAN politikaları · CoA · LDAP/AD · TACACS+ (yeniden tasarım) · Misafir portalı (CWA, yeniden tasarım) · Yönetici TOTP (zorunlu) · Syslog iletimi · CSV içe/dışa aktarım · API token'ları · `/metrics` (iç ağ) · `nacoctl` · Denetim kaydı

### Kaldırılanlar
Helm chart + Kubernetes dokümanları ve CI işi · rol bazlı süreç ayrımı (`server.roles`) · Redis + `core/cache.py` + politika pub/sub · PostgreSQL, asyncpg, PgBouncer, havuz ayarları · OpenTelemetry · log partisyonlama · Grafana/Prometheus/Loki/Promtail profili · mkdocs sitesi + docs iş akışı · `deploy/Dockerfile.dev`, `deploy/docker-compose.dev.yml` · `install.sh` · RadSec · NACo'nun kendi RADIUS sunucusu (`radius/server.py`), `probe.py`, `pyrad`, `radius/dictionary` · scapy profilleyici + `psutil` · OIDC · Graylog, log-webhook, olay webhook'ları (`core/webhooks.py`) · JWT (PyJWT) ve `session/api/csrf` sırları · misafir QR kodu + `pillow` · systemd/journalctl "System" sayfası ve servis yeniden başlatma · VLAN eşleme modeli/sayfası · Ayarları panelden YAML'a yazma · `docs/ROADMAP.md`, `docs/BENCHMARKS.md`, `bench/`

---

## 2. Mimari ve dağıtım

```
 Switch / AP ──UDP 1812/1813──► [freeradius] ──REST :8081 (iç ağ)──┐
 Switch CLI ───TCP 49─────────────────────────────────────────────► [naco] ──► SQLite (/var/lib/naco)
 Yönetici / Misafir ──80/443──► [caddy] ──HTTP :8080 (iç ağ)──────┘   │
                                                                      └─UDP 3799──► NAS (CoA)
```

### Konteynerler (tek `docker-compose.yml`)

| Servis | Dışarı açık | Not |
|---|---|---|
| `caddy` | TCP 80, 443 | Yalnızca `/`, `/api/v1/*`, `/portal/*`, `/static/*` yollarını NACo:8080'e iletir. Yetki: yalnızca `NET_BIND_SERVICE`. |
| `freeradius` | UDP 1812, 1813 | `freeradius/freeradius-server:3.2.x`. Dinamik istemciler (aşağıda). Root olmayan kullanıcı, yetkiler düşürülmüş. |
| `naco` | TCP 49 (konteyner içi 4949) | Root olmayan kullanıcı (uid 10001), salt-okunur kök dosya sistemi, `cap_drop: [ALL]`, `no-new-privileges`. Yazılabilir: `/var/lib/naco` (veri), `/tmp` (tmpfs). |

- Ağ: köprü ağı `naco`, alt ağ `.env` ile ayarlanabilir (`NACO_SUBNET`, varsayılan `172.30.0.0/24`), sabit IP'ler: caddy `.10`, freeradius `.11`, naco `.12`. Host ağı kullanılmaz; NAS kaynak IP'leri Docker'ın DNAT yönlendirmesiyle korunur.
- Görüntü etiketleri ve taban imajlar digest ile sabitlenir.

### NACo dinleyicileri (tek süreç, tek event loop)

| Port | Uygulama | Erişim |
|---|---|---|
| 8080 | Panel, `/api/v1`, `/portal` | Yalnızca Caddy üzerinden. `X-Forwarded-*` başlıklarına yalnızca Caddy'nin sabit IP'sinden gelince güvenilir (uvicorn `forwarded_allow_ips` + uygulama `client_ip()` aynı kaynaktan). |
| 8081 | İç AAA API (`/aaa/*`) + `/metrics` | Yayınlanmaz, Caddy iletmez. `/aaa/*` için `Authorization: Bearer $NACO_INTERNAL_TOKEN` zorunlu (bayt düzeyinde sabit-zamanlı karşılaştırma). `/metrics` iç ağda kimlik doğrulamasız. |
| 4949 | TACACS+ | Host 49'a yayınlanır. |

İki HTTP sunucusu aynı süreçte iki `uvicorn.Server` örneği olarak çalışır. Uzun süren CPU işleri (bcrypt hash/verify, LDAP bind) `asyncio.to_thread` ile iş parçacığına itilir; AAA trafiği asla bloklanmaz. Arka plan döngüleri: misafir süre sonu, log saklama/temizlik, bayat oturum temizliği.

### Yapılandırma ve sırlar

- `config.yaml` (salt-okunur bağlanır) **sır içermez**; yalnızca davranış: sunucu adı, saat dilimi, CoA ayarları, TACACS limitleri, portal metinleri ve erişim kodu politikası, LDAP sunucu/eşleme ayarları, syslog hedefi, güvenlik ayarları (TOTP zorunluluğu, oturum süreleri, giriş limitleri), log saklama süreleri.
- Pydantic modelleri `extra="forbid"` ile — bilinmeyen anahtar açılışı durdurur (dokümandaki iddia gerçek olur).
- `.env` (quickstart üretir, `chmod 600`) yalnızca:
  - `NACO_MASTER_KEY` — veritabanındaki sırları şifreler (AES-256-GCM).
  - `NACO_INTERNAL_TOKEN` — FreeRADIUS ↔ NACo.
  - Opsiyonel: `NACO_LDAP_BIND_PASSWORD`.
- Her sır `NAME_FILE` biçimiyle dosyadan (Docker secret) okunabilir.
- Veritabanındaki şifreli değerler (NAS sırları, TACACS anahtarları, TOTP tohumları) AAD olarak `tablo.sütun` ile şifrelenir → bir değer başka bir sütuna taşınırsa çözülemez. (Satır kimliği INSERT anında henüz bilinmediği için satır düzeyinde bağlama yapılmaz; aynı sütunda satır takası yalnızca DB yazma yetkisi olan birine açıktır.) Düz metin değer okunduğunda kabul edilmez.
- Açılışta: `NACO_MASTER_KEY` (tam 32 bayt, base64/hex) veya `NACO_INTERNAL_TOKEN` (en az 32 karakter) eksik, kısa veya yer tutucu (`REPLACE_ME…`, `CHANGE_ME…`) ise süreç açılmaz. NAS/TACACS sırları panelde en az 16 karakter olmalıdır. "Debug bypass" yok; geliştirme kolaylığı yalnızca `NACO_DEV=1` ortam değişkeni ile ve büyük bir uyarıyla.

### Kurulum (`./quickstart.sh`)

1. Önkoşullar: Docker 24+, Compose v2, openssl. Port kontrolü: 80, 443, 1812/udp, 1813/udp, 49.
2. `.env` üretir (yoksa). Var olanı asla ezmez.
3. EAP PKI: `secrets/ca/` altında CA (anahtar FreeRADIUS'a **bağlanmaz**), `deploy/freeradius/certs/` altında sunucu sertifikası; anahtar izinleri FreeRADIUS kullanıcısına göre (chgrp başarısız olursa dünya-okunur'a düşmek yerine hata).
4. Alan adı sorar: verilirse Let's Encrypt; boşsa sunucunun IP'si için Caddy yerel CA (`tls internal`) ve tarayıcıda güvenilmesi gereken kök sertifikanın yolu yazdırılır.
5. `docker compose up -d`, sağlık bekler, **erişilebilir** panel adresini ve tek kullanımlık admin şifresini yazdırır.
- Yardımcı: `./scripts/issue-client-cert.sh <ad>` — EAP-TLS istemci sertifikası (PKCS#12) üretir.

### Bağımlılıklar (çalışma zamanı)
`fastapi`, `uvicorn`, `jinja2`, `python-multipart`, `sqlalchemy[asyncio]`, `aiosqlite`, `alembic`, `bcrypt`, `cryptography`, `pyotp`, `ldap3`, `qrcode` (yalnızca SVG çıktı, pillow yok), `pydantic`, `pyyaml`, `click`.
- `pyproject.toml` `dependencies` alanında tanımlı (bugün boş — kurulum kırık).
- Docker imajı, hash'li kilit dosyasından (`requirements.lock`, `uv pip compile --generate-hashes`) kurulur.

---

## 3. AAA akışları

### 3.1 FreeRADIUS yapılandırması (NACo ile birlikte gelir)

- **Dinamik istemciler:** `client dynamic { ipaddr = <NACO_NAS_NETWORKS> ... dynamic_clients = dynamic_clients; lifetime = 60 }`. Bilinmeyen IP'den paket → `dynamic_clients` sanal sunucusu → `rest` ile `GET /aaa/clients/{ip}` → NACo etkin NAS için `{"control:FreeRADIUS-Client-IP-Address", "control:FreeRADIUS-Client-Secret", "control:FreeRADIUS-Client-Shortname", (destekleniyorsa) Message-Authenticator zorunluluğu}` döner; bilinmeyen/kapalı NAS → 404 → paket düşer. NAS silme/kapatma ≤ 60 sn'de etkili. `NACO_NAS_NETWORKS` (varsayılan `0.0.0.0/0, ::/0`) ile yalnızca belirli ağlardan gelen IP'ler için sorgu yapılır.
- **BlastRADIUS:** Message-Authenticator zorunluluğu NAS başına (varsayılan açık).
- **REST çağrıları:** `body = json`, `data` şablonu **yok** → rlm_rest istek özniteliklerini kendi JSON kodlayıcısıyla gönderir (`{"Attr":{"type":..,"value":[..]}}`), kaçış sorunu yok. Ek bağlam yerel sözlükte tanımlı özniteliklerle aktarılır: `NACo-Auth-Method`, `NACo-Inner-Identity`, (EAP-TLS) `TLS-Client-Cert-Common-Name`.
- **Yanıt sözleşmesi:**

| Uç nokta | Başarı | Ret | Hata/zaman aşımı |
|---|---|---|---|
| `POST /aaa/authenticate` | `204` (→ `ok`) | `401` (→ `reject`) | `5xx`/timeout → `fail` → ret |
| `POST /aaa/authorize` | `200` + öznitelikler (→ `updated`) veya `204` (öznitelik yoksa) | `401` + opsiyonel `Reply-Message` | → ret |
| `POST /aaa/accounting` | `204` | — | `5xx` → `fail` → **Accounting-Response gönderilmez**, NAS tekrar dener |

- Yanıt öznitelikleri `{"value": "...", "do_xlat": false}` biçiminde döner → panelde girilen değerler FreeRADIUS'ta şablon olarak yorumlanmaz.
- unlang'da her `rest` çağrısının ardından açık kontrol: `if (!(ok || updated)) { reject }`.

### 3.2 İstek türlerine göre akış

1. **NAS kontrolü** — dinamik istemci; bilinmeyen NAS → sessizce düşer.
2. **Kimlik doğrulama**
   - **PAP (dış), EAP-TTLS/PAP ve PEAP/GTC (iç tünel):** `Auth-Type rest` → `/aaa/authenticate {username, password}`. NACo: devre dışı kullanıcı → 401 (LDAP'a gidilmez); yerel kullanıcı → bcrypt; `source=ldap` kullanıcı veya bilinmeyen kullanıcı + LDAP etkin → LDAP bind; aksi → sahte bcrypt + 401.
   - **EAP-TLS:** sertifika zincirini FreeRADIUS doğrular (opsiyonel CRL). Kimlik = sertifika CN'i (istemcinin dış User-Name'i değil).
   - **MAB:** yalnızca `Service-Type == Call-Check` **veya** (User-Name MAC biçiminde **ve** normalleştirilmiş User-Password == User-Name == Calling-Station-Id). Bu koşulda `NACo-Auth-Method := MAB`, `Auth-Type := Accept`; asıl karar post-auth'ta.
3. **Karar** — dış `post-auth`'ta **her** yöntem için `/aaa/authorize` (tüm istek öznitelikleri + yöntem + iç kimlik + sertifika CN). NACo sırası:
   1. Kimliği çöz: kullanıcı (PAP/TTLS/PEAP: iç kimlik; EAP-TLS: CN) veya cihaz (MAB: MAC).
   2. Sabit kurallar: devre dışı kullanıcı → ret; EAP-TLS'te CN'e karşılık etkin kullanıcı yoksa → ret; engellenmiş cihaz (MAC) → ret.
   3. Cihaz kaydı: görülen her MAC (MAB veya Calling-Station-Id) yoksa `pending` olarak eklenir; `last_seen`, `last_nas` güncellenir. Üretici OUI listesinden.
   4. Politikalar öncelik sırasıyla; ilk tam eşleşen kazanır; eşleşme yok → ret (`DEFAULT_DENY`).
   5. Kabul: `Tunnel-Type=VLAN(13)`, `Tunnel-Medium-Type=IEEE-802(6)`, `Tunnel-Private-Group-Id=<vlan>` (VLAN varsa) + politikanın satıcı öznitelikleri.
   6. Her karar `auth_logs`'a yazılır (kullanıcı, MAC, NAS, SSID, yöntem, sonuç, gerekçe, politika, VLAN).
4. **Muhasebe** — `/aaa/accounting`: Start/Interim/Stop → `sessions` tablosu (anahtar: `nas_ip + acct_session_id`), Gigawords destekli 64-bit sayaçlar; Accounting-On/Off → o NAS'ın tüm oturumları kapatılır. Start'ta oturum bağlamı (yöntem, SSID, politika, VLAN, karar özeti) aynı NAS+MAC için son başarılı `auth_logs` kaydından alınır. Yinelenen Start idempotenttir (upsert). DB yazımı başarılı olmadan 204 dönülmez.
- Desteklenmeyen: PEAP-MSCHAPv2 (bcrypt ile imkânsız) — dokümanda açıkça; Windows için EAP-TLS veya EAP-TTLS önerilir.

### 3.3 Politika modeli

Politika: `name, description, priority (1–9999, küçük önce), enabled, conditions[] (AND), action (PERMIT|DENY), vlan (1–4094, opsiyonel), reply_attributes{}`.

| Koşul `type` | Operatörler | Değer |
|---|---|---|
| `always` | — | — |
| `username` | `equals`, `not_equals`, `in`, `matches` (glob) | metin / liste |
| `group` | `in`, `not_in` | grup adları |
| `auth_method` | `in` | `EAP-TLS`, `EAP-TTLS`, `PEAP`, `PAP`, `MAB` |
| `device_status` | `in` | `approved`, `pending`, `guest` |
| `device_type` | `in` | türler |
| `mac` | `equals`, `in`, `matches` (glob, örn. `00:11:22:*`) | MAC |
| `vendor` | `in`, `matches` | OUI üretici adı |
| `nas` | `in` | NAS adları |
| `ssid` | `in`, `matches` | SSID (Called-Station-Id'den ayrıştırılır) |
| `time` | `between` | `start`, `end` (HH:MM), `days` (mon..sun); `server.timezone` ile |

- Şema her `type` için operatörü ve değeri doğrular; hatalı politika kaydedilemez (çalışma anında istisna atılmaz).
- Regex yok; glob (`fnmatch`, büyük/küçük harf duyarsız, uzunluk sınırlı).
- `reply_attributes`: öznitelik adı `^[A-Za-z0-9-]+(:[A-Za-z0-9-]+)?$`, değer düz metin; `%{` içeren değer reddedilir (çift güvence).
- Önbellek: süreç içi, sürüm sayacıyla; her yazımda geçersiz kılınır (yarış yok).
- **Politika simülatörü:** `POST /api/v1/policies/simulate {username?, mac?, auth_method, ssid?, nas?, time?}` → eşleşen politika, her politikanın neden eşleşip eşleşmediği, sonuç.
- `device_status = guest`, MAC için etkin (süresi dolmamış, iptal edilmemiş) misafir kaydı varsa türetilir; `blocked` durumu sabit kural olarak her şeyden önce gelir.

### 3.4 CoA

- Tetikleyiciler: politika, cihaz (durum/tür), kullanıcı (etkinlik/grup), grup değişikliği. Yalnızca karara etki eden alanlar değiştiğinde (açıklama/ad değişikliği tetiklemez).
- Yeniden değerlendirme: etkilenebilecek her aktif oturum için bağlam (güncel kullanıcı/grup/cihaz durumu + oturumun yöntem/SSID/NAS'ı) ile yeni karar hesaplanır; `(action, vlan, reply_attributes)` özeti oturumdakinden farklıysa Disconnect-Request (RFC 5176).
- NAS başına `coa_port` (varsayılan 3799), zaman aşımı + 3 deneme, Event-Timestamp, Message-Authenticator, IPv4/IPv6, yanıt kaynağı ve authenticator doğrulaması.
- Elle: oturum sayfasından tekil veya toplu kesme (OPERATOR).

### 3.5 Cihazlar

- Durumlar: `pending` (varsayılan), `approved`, `blocked`. Tür ve notları yalnızca yönetici belirler (DHCP'den otomatik sınıflandırma yok).
- Panelde "Onay bekleyenler" sekmesi, toplu onay/engelleme.
- OUI listesi pakete dahil (IEEE MA-L'den üretilmiş sıkıştırılmış dosya + güncelleme betiği).

### 3.6 Misafir portalı (CWA)

1. Tanınmayan cihaz misafir SSID'sinde MAB ile gelir → `pending`. Operatörün politikası örn. `device_status in [pending] AND ssid in [Guest] → PERMIT VLAN 21` (portal VLAN'ı; HTTP yönlendirmesi ağ tarafında).
2. Misafir `http://<naco>/portal` açar. NACo istemci IP'sini (Caddy'den gelen güvenilir `X-Forwarded-For`) son 15 dk içinde güncellenmiş aktif oturumun `framed_ip` değeriyle eşleştirir → MAC + NAS. **MAC asla formdan alınmaz.** Eşleşme yoksa "cihazınız tanınıyor…" ekranı otomatik yeniden dener; süre sonunda açıklayıcı hata.
3. Misafir koşulları kabul eder (+ yapılandırılmışsa erişim kodu; ad/e-posta opsiyonel) → `guest_registrations` (MAC, süre: `portal.session_hours`) → o NAS'a Disconnect → cihaz yeniden bağlanır → `device_status = guest` → politika örn. `device_status in [guest] → PERMIT VLAN 20`.
4. Süre dolunca veya yönetici iptal edince → Disconnect → cihaz `pending`'e döner.
- Engellenmiş cihaz kayıt olamaz. Aktif RADIUS oturumu olmayan IP kayıt olamaz.
- IP başına gerçekten sayan hız sınırı; çerez tabanlı CSRF; Caddy'de portal yolu HTTP üzerinden de servis edilir (HTTPS'e zorla yönlendirme yok).
- Şart: misafir VLAN'ı ile NACo arasında NAT olmamalı; NAS muhasebede `Framed-IP-Address` göndermeli — satıcı örnekleri dokümanda.

### 3.7 TACACS+ (RFC 8907)

- İstemciler yalnızca veritabanından (panel); her biri kendi anahtarıyla; global anahtar yok. Bilinmeyen kaynak IP → bağlantı hemen kapatılır. İstemci ekleme/silme/kapatma anında etkili (yazımda önbellek yenilenir).
- Şifrelenmemiş bayrak taşıyan paketler reddedilir; sürüm baytı ve `seq_no` doğrulanır (255 taşmasında oturum kapanır); CONTINUE paketleri oturum kimliğine bağlıdır.
- **Cihaz yönetimi ağ erişiminden ayrıdır:** grupta `device_admin_privilege` (1–15) ve opsiyonel `command_set_id`. Bu alana sahip bir grupta olmayan kullanıcı TACACS+ ile giremez.
- Authentication: PAP ve ASCII login; kullanıcı yerel veya LDAP. `enable` (authen_service ENABLE veya istenen `priv_lvl`) yalnızca grubun privilege seviyesine kadar.
- Authorization: `service=shell` başlangıcında `priv-lvl=<grup>` döner. Komut yetkilendirme: `cmd` + tüm `cmd-arg` birleştirilmiş tam satır, komut setinin kurallarına sırayla glob ile; ilk eşleşen kazanır; eşleşme yok → komut setinin `default_action`'ı (varsayılan DENY). Komut seti atanmamışsa privilege seviyesindeki tüm komutlar serbest. RADIUS politikalarına asla düşülmez.
- Accounting: `tacacs_logs`'a yazılır.
- Dayanıklılık: okuma zaman aşımı (varsayılan 30 sn boşta), toplam ve eş başına bağlantı limiti, paket boyutu sınırı.

### 3.8 LDAP / Active Directory

- `ldaps://` veya StartTLS'te sertifika **doğrulanır** (`ldap.ca_file` ile özel CA); düz `ldap://` ancak açık bir `allow_insecure: true` ile ve uyarıyla.
- LDAP ile ilk kez doğrulanan kullanıcı `source=ldap`, `password_hash=NULL` olarak eklenir; sonraki her giriş LDAP'tan doğrulanır.
- Grup eşlemesi (`group_map`, yapılandırma sırasıyla ilk eşleşen) her girişte yenilenir; eşleşme yoksa kullanıcının grubu boşaltılır.
- Filtre değerleri RFC 4515'e göre kaçışlanır; birden fazla sunucu (failover) ve iç içe grup desteği korunur.
- NACo'da devre dışı LDAP kullanıcısı LDAP'a hiç gidilmeden reddedilir.

---

## 4. Panel ve API

### 4.1 Yönetici kimlik doğrulama

- Yerel `admin_users` (OIDC yok). İlk açılışta `admin` hesabı tek kullanımlık rastgele şifreyle oluşturulur (`must_change_password = true`).
- **Sunucu tarafı oturumlar** (`admin_sessions`): 256-bit rastgele kimlik, veritabanında SHA-256 özeti; çerez `naco_session` — `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`. Boşta 30 dk, mutlak 12 saat (ayarlanabilir). Çıkış, şifre değişikliği, rol değişikliği, hesabın kapatılması/silinmesi → ilgili oturumlar anında silinir.
- **CSRF:** oturuma bağlı rastgele token (sunucuda saklı); değişiklik yapan her istekte `X-CSRF-Token` başlığı **ve** `Origin`/`Sec-Fetch-Site` kontrolü. Giriş formu da oturum-öncesi token ile korunur.
- **Kaba kuvvet:** IP başına sınır (örn. 10 deneme / 5 dk) + hesap başına artan gecikme (1 → 30 sn tavan); hesabı kalıcı kilitleyen mekanizma yok. Hata mesajı tektir ("geçersiz kimlik bilgisi") — şifrenin doğru olduğu TOTP adımında sızdırılmaz.
- **TOTP:** varsayılan zorunlu (`security.require_totp: true`). Akış: giriş → zorunlu şifre değişikliği → TOTP kaydı (SVG QR + manuel anahtar + 10 tek kullanımlık kurtarma kodu, bcrypt ile saklanır). Son kullanılan zaman adımı saklanır (tekrar kullanım yok). TOTP sıfırlama: şifre + geçerli kod; başka bir SUPERUSER tarafından sıfırlama (denetlenir); acil durum: `nacoctl reset-totp <kullanıcı>`.

### 4.2 API

- `/api/v1` tek yazma yolu; panel de yalnızca bunu kullanır (oturum çerezi + CSRF başlığı). Otomasyon: `Authorization: Bearer naco_…` API token'ları (SHA-256 özet, rol tavanı, son kullanma, son kullanım zamanı, iptal). Token'lar token üretemez/iptal edemez.
- Uç nokta grupları: auth (login/logout/me/password/totp), users, groups, devices, policies (+simulate), nas-clients, tacacs-clients, command-sets, sessions (+disconnect), guests, logs (auth/tacacs), audit, admins, tokens, csv, system (sürüm, durum, yapılandırma özeti — sırlar gizli), events (SSE).
- Sayfalama, tutarlı hata biçimi (`{"error": {"code", "message", "request_id"}}`).
- Swagger (`/api/v1/docs`) yalnızca oturum açmış yöneticilere.
- CSV: dışa aktarımda `=`, `+`, `-`, `@`, tab, CR ile başlayan hücreler `'` ile kaçışlanır; içe aktarımda akış halinde boyut sınırı (örn. 5 MB / 10.000 satır), hash'leme iş parçacığında; yalnızca oluşturma (var olanı ezmez).

### 4.3 Roller (tek bağımlılık fonksiyonu ile uygulanır)

| Yetki | VIEWER | OPERATOR | SUPERUSER |
|---|---|---|---|
| Tüm sayfaları/logları görme (sırlar hariç) | ✓ | ✓ | ✓ |
| Kullanıcı CRUD, CSV | | ✓ | ✓ |
| Kullanıcıyı cihaz yöneticisi profili olan gruba atama | | | ✓ |
| Cihaz onay/engelleme/tür | | ✓ | ✓ |
| Misafir kaydı oluşturma/iptal | | ✓ | ✓ |
| Oturum kesme (tekil/toplu) | | ✓ | ✓ |
| Politikalar, gruplar, komut setleri | | | ✓ |
| NAS/TACACS istemcileri ve sırlarını görme (denetlenir) | | | ✓ |
| Yöneticiler, API token'ları | | | ✓ |

Son etkin SUPERUSER silinemez/düşürülemez.

### 4.4 Denetim kaydı

- Tek mekanizma (API katmanında): değişiklik yapan her istek → `audit_logs` (zaman, aktör, aktör türü, IP, eylem, hedef türü/kimliği, değişen alanlar — sırlar `***`). Ek olaylar: başarılı/başarısız giriş, çıkış, TOTP değişiklikleri, sır görüntüleme, CoA.
- Panelde filtrelenebilir sayfa; syslog'a da iletilir. Saklama 365 gün (ayarlanabilir).

### 4.5 Sayfalar

- **Overview:** canlı KPI'lar (kullanıcı, cihaz, onay bekleyen, aktif oturum, misafir), son 24 saat kimlik doğrulama grafiği, canlı olay akışı, ilk kurulum kontrol listesi.
- **Identity:** Users · Groups (cihaz yöneticisi profili ile).
- **Devices:** envanter, "Pending" sekmesi, toplu işlemler.
- **Access:** Policies (görsel koşul oluşturucu, düzenleme, öncelik değiştirme) · Simulator.
- **Network devices:** NAS clients · TACACS+ clients · Command sets.
- **Monitoring:** Sessions (canlı) · Guests · Auth logs · TACACS logs.
- **Administration:** Admins · API tokens · Audit log · System.
- **Account:** şifre, TOTP, aktif oturumlarım.
- Saatler tek yerde, `server.timezone`'a göre biçimlendirilir.

### 4.6 Görsel tasarım ve etkileşim

- Mevcut koyu yan menülü düzen korunur; renk, boşluk, yarıçap, gölge, tipografi CSS değişkenleri (design tokens) ile tutarlı hale getirilir. Yerel font (Inter, lisansıyla). Koyu + açık tema; varsayılan sistem tercihi, elle değiştirilebilir.
- Sayfa geçişleri: tarayıcılar arası View Transitions (`@view-transition { navigation: auto; }`), menü sabit, içerik akarak değişir; desteklemeyen tarayıcıda normal geçiş.
- Canlı veri: `GET /api/v1/events` (Server-Sent Events) → KPI'lar sayarak güncellenir, yeni olaylar tablo başına kayarak girer ve kısa vurgu alır; oturum sayfası canlı.
- Grafikler: Chart.js yerine elde yazılmış hafif SVG grafikler (çizilerek açılan animasyon).
- Mikro etkileşimler: kayan toast bildirimleri, ölçeklenerek açılan modallar, iskelet yükleyiciler, satır ekleme/silme animasyonları, "canlı" rozetinde hafif nabız.
- ⌘K / Ctrl+K komut paleti: sayfalar + kullanıcı/MAC hızlı arama.
- Erişilebilirlik: klavye ile tam gezinme, görünür odak halkaları, WCAG AA kontrast, mobilde daralan menü. `prefers-reduced-motion: reduce` → tüm animasyonlar kapalı.
- Misafir portalı: mobil öncelikli, kurum adı ve kullanım koşulları özelleştirilebilir.
- Teknik: Bootstrap 5.3 + Bootstrap Icons yerel (vendored, lisanslarıyla), üstüne kendi CSS katmanı ve tek ES modülü `app.js`. Derleme adımı yok, satır içi script/olay işleyici yok. CSP: `default-src 'self'; script-src 'self' 'nonce-…'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`.
- 403/404/500 için dostça hata sayfaları; API hataları toast'ta istek kimliğiyle.

---

## 5. Operasyon

- **Migration:** Alembic, `render_as_batch=True`, tek baseline `0001_v3_baseline`. NACo açılışta `alembic upgrade head` çalıştırır (`create_all` yok).
- **Saklama:** auth/tacacs logları 90 gün, denetim 365 gün, bayat oturumlar (24 saat güncellenmeyen) — ayarlanabilir; saatlik temizlik.
- **Yedekleme:** `nacoctl backup --output /backups/…` → SQLite online backup API ile tutarlı kopya (WAL dahil), dosya izni `0600`, opsiyonel `--age-recipient` şifreleme. `nacoctl restore` yalnızca NACo durdurulmuşken (`docker compose run --rm naco nacoctl restore …`), WAL/SHM dosyalarını doğru yönetir, bütünlük kontrolü yapar. `./backups` dizini compose'ta bağlıdır.
- **`nacoctl`:** `backup`, `restore`, `reset-password`, `reset-totp`, `rotate-master-key` (çalışan süreç yokken), `check-config`. Sırlar komut satırı argümanı olarak alınmaz (stdin/dosya).
- **Loglar:** stdout'a (Docker logları), insan okunur veya `log_format: json`. Gizli bilgi temizleme filtresi tüm handler'lara bağlanır (bugünkü etkisiz filtre düzeltilir).
- **Syslog:** auth kararları, TACACS olayları, denetim kayıtları → UDP veya TCP, RFC 5424.
- **Metrikler (`:8081/metrics`):** sonuç ve yönteme göre auth kararları, TACACS istekleri, aktif oturum (DB'den), CoA gönderilen/başarısız, `/aaa` gecikme histogramı, build bilgisi. Prometheus'u bağlamak için NACo ağına eklemek dokümante edilir.
- **Sağlık:** `/api/v1/health/live` (süreç), `/api/v1/health/ready` (DB) — herkese açık yanıtlarda sürüm/servis detayı yok. FreeRADIUS sağlık kontrolü kendi `status` sunucusuna `radclient`.

---

## 6. Test ve doğrulama

1. **Birim (pytest):** politika motoru (her koşul × operatör, öncelik, varsayılan ret, sabit kurallar, glob, saat dilimi); `/aaa/*` sözleşmesi (kodlar ve gövde biçimleri, rlm_rest JSON girdisi); TACACS+ paket ve yetkilendirme (cmd+args, privilege, enable, istemci iptali, zaman aşımı); LDAP (mock: devre dışı, grup yenileme, TLS doğrulama ayarı, filtre kaçışı); oturumlar/CSRF/TOTP (tekrar kullanım, kurtarma kodu); kripto (AAD bağlama); yapılandırma (`extra=forbid`, sır kontrolleri); CSV kaçışlama; CoA karar karşılaştırması.
   - **Rol matrisi testi:** route tablosundan otomatik — her uç nokta × her rol; beklenen sonuç tablodan; rolü tanımsız uç nokta testi kırar.
   - **Denetim/CSRF kapsama testi:** değişiklik yapan her uç noktanın denetim kaydı yazdığı ve CSRF'siz isteği reddettiği otomatik doğrulanır.
2. **Entegrasyon (Docker, `tests/e2e/`):** gerçek FreeRADIUS 3.2 + NACo + Debian test istemcisi (`freeradius-utils` → `radclient`, `eapoltest` → `eapol_test`):
   - PAP kabul/ret; MAB onaylı/pending/engelli; EAP-TLS geçerli/politika reddi/devre dışı kullanıcı/bilinmeyen CN; EAP-TTLS/PAP ve PEAP/GTC doğru/yanlış şifre; şifrede `"`, `\`, Unicode.
   - Access-Accept içinde VLAN öznitelikleri; bilinmeyen NAS → yanıt yok; silinen NAS → ≤ lifetime sonra yanıt yok.
   - Güvenli kapanma: NACo durdurulmuş / 500 dönüyor / yavaş → kabul **yok**.
   - Muhasebe: Start/Interim/Stop → `sessions`; DB yazımı başarısızken Accounting-Response yok.
   - CoA: sahte NAS dinleyicisi yalnızca kararı değişen oturumlar için Disconnect alır.
   - TACACS+: gerçek istemci ile login, enable, komut yetkilendirme, yetkisiz kullanıcı reddi.
   - Misafir: muhasebede Framed-IP → portal kaydı o IP'den → Disconnect gönderildi → MAB misafir VLAN'ı alır; yabancı IP kayıt olamaz.
3. **Panel (Playwright):** ilk giriş → zorunlu şifre değişikliği → TOTP kaydı → NAS/kullanıcı/politika oluşturma → politika düzenleme → simülatör → denetim kaydında girişler; VIEWER hiçbir sır/düzenleme düğmesi görmez; koyu/açık tema ekran görüntüleri (görsel kontrol); reduced-motion.
4. **Kurulum:** `./quickstart.sh` temiz Linux ortamında (Docker-in-Docker) baştan sona; sonunda panel erişilebilir ve `radclient` ile PAP kabul.
5. **Güvenlik kapısı:** ruff (S kuralları dahil), mypy, pip-audit, trivy imaj taraması; son aşamada bağımsız kod incelemesi; **izlenebilirlik tablosu** (Ek A'daki her bulgu → nasıl kapandı → hangi test).

### CI / yayın
- GitHub Actions: lint + tip + birim (Python 3.12), entegrasyon (compose), imaj derleme + trivy + pip-audit. Action'lar commit SHA ile sabit; `permissions: contents: read` (yayın işinde gerekenler hariç).
- Yayın yalnızca `v*` etiketinde ve CI yeşilken: çok mimarili imaj → GHCR, cosign (keyless) imza, SBOM. `:latest` yalnızca sürüm etiketlerinde.

---

## 7. Teslim

- `v3` dalında küçük, her biri testleri yeşil commit'ler; kullanıcı istemeden push yok.
- Aşamalar: (1) temizlik + SQLite + paketleme, (2) çekirdek güvenlik (oturum, CSRF, RBAC, denetim, TOTP), (3) AAA iç API + politika motoru + cihaz/oturum/muhasebe + CoA, (4) FreeRADIUS yapılandırması + entegrasyon testleri, (5) TACACS+, (6) misafir portalı, (7) panel + tasarım + animasyon + canlı veri, (8) dağıtım (compose, Caddy, Dockerfile, quickstart) + CI, (9) dokümantasyon (README ≈200 satır, `docs/` sadeleştirme, `VENDORS.md` 1812'ye göre, CHANGELOG v3.0.0, SECURITY.md → GitHub özel güvenlik bildirimi), (10) son doğrulama.
- Bilinçli kapsam dışı: PEAP-MSCHAPv2 / `ntlm_auth`, yüksek erişilebilirlik, çok kiracılılık, posture, OIDC, yerleşik tam CA yönetimi (yalnızca istemci sertifikası betiği var).

---

## Ek A — v2.3.0 denetim bulguları ve v3'te kapanışı

| # | Bulgu (v2.3.0) | v3'te |
|---|---|---|
| A1 | `pyproject.toml`'da bağımlılık yok; SQLAlchemy 2.1 `greenlet` getirmiyor → temiz imaj çöker | `dependencies` + `sqlalchemy[asyncio]` + hash'li kilit; kurulum testi |
| A2 | EAP REST sözleşmesi kırık (ret de 200) → TTLS/PEAP herkesi reddediyor; naif düzeltme fail-open | 204/401/200 sözleşmesi; unlang açık kontrol; e2e testleri |
| A3 | EAP-TLS politikayı/devre dışı kullanıcıyı/logu atlıyor | Her yöntem post-auth'ta `/aaa/authorize`; CN → kullanıcı zorunlu |
| A4 | TACACS+: ağ kullanıcısı `enable` ile priv 15; `priv_lvl` yok sayılıyor | Cihaz yöneticisi profili; enable grup seviyesine kadar |
| A5 | TACACS+ komut kuralları argüman görmüyor → DENY çalışmıyor; politikaya geri düşme | Tam komut satırı eşleme; varsayılan DENY; politika fallback yok |
| A6 | Portal formdaki MAC'i yetkilendiriyor; engelli cihaz misafir olabiliyor | MAC oturumdan (Framed-IP); engelli kayıt olamaz |
| A7 | MAB yalnızca kullanıcı adı biçimine göre | Call-Check veya ad=şifre=Calling-Station-Id |
| A8 | VIEWER sırları görüyor; UI yazma uçlarında rol kontrolü yok | Tek yazma yolu (API) + tek rol bağımlılığı + rol matrisi testi |
| A9 | Silinen/kapatılan admin 8 saat erişimde; çıkış sunucuda geçersiz kılmıyor | Sunucu tarafı oturumlar, anında iptal |
| A10 | `X-Forwarded-For` herkesten kabul; CIDR karşılaştırma hatası; 8080 tüm ağa açık | Yalnızca Caddy IP'si güvenilir; 8080 yayınlanmaz |
| A11 | `/api/v1/eap/*`, `/metrics`, `/openapi.json` internete açık | İç API ayrı port (8081), yayınlanmaz; Swagger oturum ister |
| A12 | EAP token yer tutucusu kabul ediliyor | Tüm sırlar açılışta doğrulanır |
| A13 | Devre dışı kullanıcı LDAP üzerinden giriyor; LDAP kullanıcısı yalnızca ilk girişte | Devre dışı → LDAP'a gidilmez; `source=ldap` |
| A14 | LDAP TLS sertifikası doğrulanmıyor | Doğrulama zorunlu (`ca_file`) |
| A15 | AD grubundan çıkarılan kullanıcı NACo grubunu koruyor | Her girişte grup yenileme |
| A16 | Silinen TACACS istemcisi yeniden başlatmaya kadar çalışıyor | Yazımda anında yenileme |
| A17 | TACACS okuma zaman aşımı yok → bağlantı slotu sızıntısı | Boşta zaman aşımı + limitler |
| A18 | Migration'lar varsayılan kurulumda çalışamaz; model/şema sapması | Tek baseline, açılışta `upgrade head` |
| A19 | OIDC hesap ele geçirme, login CSRF | OIDC kaldırıldı |
| A20 | TOTP: kayıt ekranı yok, tekrar kullanım, kapatma için şifre istemiyor, şifre doğruluğunu sızdırıyor | 4.1'deki TOTP akışı |
| A21 | Denetim kaydı eksik | Tek mekanizma + kapsama testi |
| A22 | CSV formül enjeksiyonu; bcrypt event loop'u kilitliyor; tüm dosya belleğe | Kaçışlama, iş parçacığı, akış sınırı |
| A23 | Regex koşulları event loop'u kilitleyebiliyor (ReDoS) → DENY atlanabiliyor | Regex yok, glob |
| A24 | Politika CoA'sı her düzenlemede gereğinden fazla oturum kesiyor | Karar farkına göre yeniden değerlendirme |
| A25 | Muhasebe: DB'den önce ACK; oturum kimliği NAS'lar arası çakışıyor; Accounting-On/Off yok | 3.2 madde 4 |
| A26 | Yinelenen istek tespiti yok, DB bağlantısı bcrypt boyunca tutuluyor | FreeRADIUS yineleme tespiti; bcrypt iş parçacığında, bağlantı dışında |
| A27 | Profilleyici: DHCP ile toplu kayıt silme, sel, kendi türünü belirleme | Profilleyici kaldırıldı; tür yalnızca yönetici |
| A28 | Gizli bilgi temizleme filtresi etkisiz | Tüm handler'lara bağlanır + test |
| A29 | Yedek/geri yükleme: SQLite WAL hatası, `ON_ERROR_STOP` yok, 0644 izinler, sırlar argümanda | Bölüm 5 |
| A30 | Swagger 404; README/doküman iddiaları gerçekle uyuşmuyor | Dokümantasyon aşaması + kurulum testi |
| A31 | CDN'den SRI'sız betik, CSP tüm jsdelivr'e açık; internetsiz ağda panel bozuk | Yerel dosyalar, sıkı CSP |
| A32 | Settings sayfası salt-okunur config'e yazmaya çalışıyor; systemd sayfası ölü; VLAN eşleme kullanılmıyor | Kaldırıldı; System sayfası salt-okunur |
| A33 | Quickstart sonunda erişilebilir HTTPS yok; `NACO_DOMAIN` ayarlanmıyor; portal Caddy'de çalışmıyor | Quickstart alan adı/IP akışı; portal HTTP yolu |
| A34 | Sunucu anahtarı dünya-okunur olabiliyor; CA anahtarı FreeRADIUS'a bağlı | `secrets/ca/`, doğru izinler, hata durumunda dur |
| A35 | `NET_ADMIN`/`NET_RAW`, host ağı, docker.sock (promtail) | Hepsi kaldırıldı |
| A36 | CI: action'lar etiketle sabit, `:latest` CI beklemeden, imza yok | SHA sabitleme, CI kapısı, cosign + SBOM |
| A37 | FreeRADIUS `data` JSON kaçışlamıyor; yanıt değerleri xlat ediliyor | `data` şablonu yok; `do_xlat: false` |
| A38 | Güvenlik iletişim adresi yer tutucu | GitHub özel güvenlik bildirimi |
