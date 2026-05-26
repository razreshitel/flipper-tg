// Telegram Reader — Flipper Zero App
// Browse messages collected by @FlipperApp_bot via local Pi server
// Uses FlipperHTTP library for WiFi communication

#include "flipper_http/flipper_http.h"
#include <furi.h>
#include <furi_hal_random.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/text_input.h>
#include <storage/storage.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define TAG        "TgReader"
#define CREDS_PATH "/ext/apps_data/telegram_reader/creds.txt"
#define COMPOSE_SZ 65
#define CRED_SZ    64

#define SW 128
#define SH  64
#define HH  11
#define RH  10
#define VR  ((SH - HH) / RH)

#define MAX_CHATS 12
#define MAX_MSGS   5
#define ID_SZ     24
#define NAME_SZ   20
#define FROM_SZ   13
#define TEXT_SZ  257
#define TIME_SZ    6
#define RESP_SZ  4096

#define EV_RUN  (1u << 0)
#define EV_STOP (1u << 2)

#define CUSTOM_EV_DONE   1
#define CUSTOM_EV_REDRAW 2

typedef enum { VIEW_MAIN, VIEW_TEXT_INPUT } AppViewId;
typedef enum { ST_DEBUG, ST_LOADING, ST_CHATS, ST_MSGS, ST_ERROR } AppSt;
typedef enum { CMD_CHATS, CMD_MSGS, CMD_SEND } WorkerCmd;

typedef struct {
    int8_t  ping;
    int8_t  wifi;
    int8_t  http;
    int8_t  resp;
    int8_t  parse;
    int     resp_len;
    int     n_chats;
    char    state_s[5];
    char    preview[34];
    bool    done;
} DbgInfo;

typedef struct {
    char id[ID_SZ];
    char name[NAME_SZ];
    int  count;
} Chat;

typedef struct {
    char from[FROM_SZ];
    char text[TEXT_SZ];
    char time[TIME_SZ];
} Message;

typedef struct {
    Gui*            gui;
    ViewDispatcher* vd;
    View*           main_view;
    TextInput*      text_input;
    FuriThread*     wt;
    FuriEventFlag*  ev;
    FuriMutex*      mx;
    FlipperHTTP*    fhttp;

    AppSt  st;
    char   err[64];
    bool   in_compose;

    WorkerCmd wcmd;
    char      wurl[200];
    char      wresp[RESP_SZ];
    bool      wok;

    DbgInfo dbg;

    Chat ch[MAX_CHATS];
    int  ch_cnt, ch_sel, ch_top;

    Message mg[MAX_MSGS];
    int     mg_cnt, mg_sel, mg_page, mg_pages;

    char ac_id[ID_SZ];
    char ac_name[NAME_SZ];

    char compose_buf[COMPOSE_SZ];
    char send_payload[200];
    int  msg_char_off;

    char creds_ssid[CRED_SZ];
    char creds_pass[CRED_SZ];
    char creds_secret[CRED_SZ];
    char creds_ip[CRED_SZ];  /* e.g. 192.168.1.100 */
    char creds_port[8];      /* e.g. 8888 */
    char creds_host[72];     /* computed: ip:port, max 71 chars */
    char api_base[80];        /* https://<creds_host> */
    char get_headers[160];
    char post_headers[220];
    bool in_setup;

    uint8_t crypto_key[32];    /* SHA256(creds_secret) */
    char    secret_hash[65];   /* hex of crypto_key, sent as X-Secret */
    char    enc_payload_buf[401]; /* XOR+hex encoded POST body */
} TgApp;

// ─── Utilities ───────────────────────────────────────────────────────────────

static void json_escape(const char* src, char* dst, size_t dsz) {
    size_t j = 0;
    for(size_t i = 0; src[i] && j + 2 < dsz; i++) {
        if(src[i] == '"' || src[i] == '\\') {
            if(j + 3 >= dsz) break;
            dst[j++] = '\\';
        }
        dst[j++] = src[i];
    }
    dst[j] = '\0';
}

// ─── SHA-256 + XOR crypto ─────────────────────────────────────────────────────

static const uint32_t _SHA_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

static void _sha_block(uint32_t h[8], const uint8_t blk[64]) {
    uint32_t w[64];
    for(int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)|
               ((uint32_t)blk[i*4+2]<<8)|(uint32_t)blk[i*4+3];
    for(int i = 16; i < 64; i++) {
        uint32_t s0=(w[i-15]>>7|w[i-15]<<25)^(w[i-15]>>18|w[i-15]<<14)^(w[i-15]>>3);
        uint32_t s1=(w[i-2]>>17|w[i-2]<<15)^(w[i-2]>>19|w[i-2]<<13)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hv=h[7];
    for(int i = 0; i < 64; i++) {
        uint32_t S1=(e>>6|e<<26)^(e>>11|e<<21)^(e>>25|e<<7);
        uint32_t ch=(e&f)^(~e&g);
        uint32_t t1=hv+S1+ch+_SHA_K[i]+w[i];
        uint32_t S0=(a>>2|a<<30)^(a>>13|a<<19)^(a>>22|a<<10);
        uint32_t maj=(a&b)^(a&c)^(b&c);
        uint32_t t2=S0+maj;
        hv=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hv;
}

static void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t blk[64];
    size_t off=0;
    while(off+64<=len){_sha_block(h,data+off);off+=64;}
    size_t rem=len-off;
    memcpy(blk,data+off,rem);
    blk[rem]=0x80;
    if(rem<56){
        memset(blk+rem+1,0,55-rem);
        uint64_t bits=(uint64_t)len*8;
        for(int i=0;i<8;i++) blk[56+i]=(uint8_t)(bits>>(56-i*8));
        _sha_block(h,blk);
    } else {
        memset(blk+rem+1,0,63-rem);
        _sha_block(h,blk);
        memset(blk,0,56);
        uint64_t bits=(uint64_t)len*8;
        for(int i=0;i<8;i++) blk[56+i]=(uint8_t)(bits>>(56-i*8));
        _sha_block(h,blk);
    }
    for(int i=0;i<8;i++){
        out[i*4]=(uint8_t)(h[i]>>24); out[i*4+1]=(uint8_t)(h[i]>>16);
        out[i*4+2]=(uint8_t)(h[i]>>8); out[i*4+3]=(uint8_t)h[i];
    }
}

static void xor_encode_hex(const uint8_t* key, const char* plain, char* out, size_t outsz) {
    static const char HX[] = "0123456789abcdef";
    size_t n=strlen(plain), i;
    for(i=0; i<n && (i*2+2)<outsz; i++){
        uint8_t b=(uint8_t)plain[i]^key[i&31];
        out[i*2]=HX[b>>4]; out[i*2+1]=HX[b&15];
    }
    out[i*2<outsz ? i*2 : outsz-1]='\0';
}

static void xor_decode_hex(const uint8_t* key, char* buf) {
    size_t n=strlen(buf)/2;
    for(size_t i=0; i<n; i++){
        uint8_t hi=(uint8_t)buf[i*2], lo=(uint8_t)buf[i*2+1];
        hi=hi>='a'?hi-'a'+10:hi>='A'?hi-'A'+10:hi-'0';
        lo=lo>='a'?lo-'a'+10:lo>='A'?lo-'A'+10:lo-'0';
        buf[i]=(char)(((hi<<4)|lo)^key[i&31]);
    }
    buf[n]='\0';
}

/* Generate an 8-byte random nonce, hex-encode it, then derive a
   per-request 32-byte key as SHA256(base_key || nonce). */
static void derive_req_key(const uint8_t base_key[32],
                           uint8_t req_key[32], char nonce_hex[17]) {
    uint8_t nonce[8];
    furi_hal_random_fill_buf(nonce, sizeof(nonce));
    for(int i = 0; i < 8; i++)
        snprintf(nonce_hex + i*2, 3, "%02x", nonce[i]);
    nonce_hex[16] = '\0';
    uint8_t kn[40];
    memcpy(kn, base_key, 32);
    memcpy(kn + 32, nonce, 8);
    sha256(kn, 40, req_key);
}

// ─── Credentials file ────────────────────────────────────────────────────────

static void creds_apply(TgApp* app) {
    if(app->creds_ip[0] && app->creds_port[0])
        snprintf(app->creds_host, sizeof(app->creds_host),
                 "%s:%s", app->creds_ip, app->creds_port);
    snprintf(app->api_base, sizeof(app->api_base), "https://%s", app->creds_host);

    sha256((const uint8_t*)app->creds_secret, strlen(app->creds_secret), app->crypto_key);
    for(int i = 0; i < 32; i++)
        snprintf(app->secret_hash + i*2, 3, "%02x", app->crypto_key[i]);
    app->secret_hash[64] = '\0';
    /* get_headers / post_headers are no longer used; headers are built
       per-request inside do_http_get / do_http_post with a fresh nonce. */
}

static bool creds_load(TgApp* app) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    File*    f  = storage_file_alloc(st);
    bool     ok = false;

    if(storage_file_open(f, CREDS_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        char buf[350] = {0};
        storage_file_read(f, buf, sizeof(buf) - 1);
        storage_file_close(f);

        char* p;
        char* nl;
        #define PARSE_FIELD(key, dst) \
            p = strstr(buf, key "="); \
            if(p) { \
                snprintf(dst, sizeof(dst), "%s", p + strlen(key) + 1); \
                nl = strchr(dst, '\n'); if(nl) *nl = '\0'; \
                nl = strchr(dst, '\r'); if(nl) *nl = '\0'; \
            }
        PARSE_FIELD("ssid",   app->creds_ssid)
        PARSE_FIELD("pass",   app->creds_pass)
        PARSE_FIELD("secret", app->creds_secret)
        PARSE_FIELD("ip",     app->creds_ip)
        PARSE_FIELD("port",   app->creds_port)
        if(!app->creds_ip[0] || !app->creds_port[0]) {
            char legacy_host[CRED_SZ] = {0};
            PARSE_FIELD("host", legacy_host)
            char* col = strchr(legacy_host, ':');
            if(col) {
                *col = '\0';
                snprintf(app->creds_ip, CRED_SZ, "%s", legacy_host);
                snprintf(app->creds_port, sizeof(app->creds_port), "%s", col + 1);
            }
        }
        #undef PARSE_FIELD

        ok = app->creds_ssid[0] && app->creds_pass[0] &&
             app->creds_secret[0] && app->creds_ip[0] && app->creds_port[0];
    }

    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static void creds_save(TgApp* app) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(st, "/ext/apps_data/telegram_reader");
    File* f = storage_file_alloc(st);

    if(storage_file_open(f, CREDS_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        char buf[350];
        int  len = snprintf(buf, sizeof(buf), "ssid=%s\npass=%s\nsecret=%s\nip=%s\nport=%s\n",
                            app->creds_ssid, app->creds_pass,
                            app->creds_secret, app->creds_ip, app->creds_port);
        storage_file_write(f, buf, (uint16_t)len);
        storage_file_close(f);
    }

    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
}

// ─── JSON helpers ─────────────────────────────────────────────────────────────

static bool jstr(const char* j, const char* k, char* out, int n) {
    char pat[48];
    snprintf(pat, sizeof(pat), "\"%s\":\"", k);
    const char* p = strstr(j, pat);
    if(!p) return false;
    p += strlen(pat);
    const char* e = strchr(p, '"');
    if(!e) return false;
    int len = (int)(e - p);
    if(len >= n) len = n - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

static bool jint(const char* j, const char* k, int* out) {
    char pat[48];
    snprintf(pat, sizeof(pat), "\"%s\":", k);
    const char* p = strstr(j, pat);
    if(!p) return false;
    p += strlen(pat);
    while(*p == ' ') p++;
    *out = (int)strtol(p, NULL, 10);
    return true;
}

static bool jid(const char* j, const char* k, char* out, int n) {
    char pat[48];
    snprintf(pat, sizeof(pat), "\"%s\":", k);
    const char* p = strstr(j, pat);
    if(!p) return false;
    p += strlen(pat);
    while(*p == ' ') p++;
    if(*p == '"') {
        p++;
        const char* e = strchr(p, '"');
        if(!e) return false;
        int len = (int)(e - p);
        if(len >= n) len = n - 1;
        memcpy(out, p, len);
        out[len] = '\0';
    } else {
        const char* s = p;
        if(*p == '-') p++;
        while(*p >= '0' && *p <= '9') p++;
        int len = (int)(p - s);
        if(len >= n) len = n - 1;
        memcpy(out, s, len);
        out[len] = '\0';
    }
    return true;
}

// ─── Parsers ─────────────────────────────────────────────────────────────────

static int parse_chats(const char* j, Chat* ch, int max) {
    const char* p = strstr(j, "\"items\":[");
    if(!p) return 0;
    p += 9;
    int cnt = 0;
    while(cnt < max && *p && *p != ']') {
        if(*p == '{') {
            int d = 1;
            const char* q = p + 1;
            while(*q && d > 0) {
                if(*q == '{') d++;
                else if(*q == '}') d--;
                q++;
            }
            char obj[256] = {0};
            int len = (int)(q - p);
            if(len >= (int)sizeof(obj)) len = (int)sizeof(obj) - 1;
            memcpy(obj, p, len);
            jid(obj,  "id",   ch[cnt].id,   ID_SZ);
            jstr(obj, "name", ch[cnt].name, NAME_SZ);
            jint(obj, "n",   &ch[cnt].count);
            cnt++;
            p = q;
        } else {
            p++;
        }
    }
    return cnt;
}

static int parse_msgs(const char* j, Message* mg, int max, int* page, int* pages) {
    jint(j, "page",  page);
    jint(j, "pages", pages);
    const char* p = strstr(j, "\"msgs\":[");
    if(!p) return 0;
    p += 8;
    int cnt = 0;
    while(cnt < max && *p && *p != ']') {
        if(*p == '{') {
            int d = 1;
            const char* q = p + 1;
            while(*q && d > 0) {
                if(*q == '{') d++;
                else if(*q == '}') d--;
                q++;
            }
            char obj[512] = {0};
            int len = (int)(q - p);
            if(len >= (int)sizeof(obj)) len = (int)sizeof(obj) - 1;
            memcpy(obj, p, len);
            jstr(obj, "f", mg[cnt].from, FROM_SZ);
            jstr(obj, "t", mg[cnt].text, TEXT_SZ);
            jstr(obj, "d", mg[cnt].time, TIME_SZ);
            cnt++;
            p = q;
        } else {
            p++;
        }
    }
    return cnt;
}

// ─── Drawing ─────────────────────────────────────────────────────────────────

static void draw_header(Canvas* c, const char* title) {
    canvas_draw_box(c, 0, 0, SW, HH);
    canvas_invert_color(c);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str_aligned(c, SW / 2, 1, AlignCenter, AlignTop, title);
    canvas_invert_color(c);
}

static void draw_status(Canvas* c, int x, int y, int8_t s) {
    const char* t = (s < 0) ? "[..]" : (s == 1) ? "[OK]" : (s == 2) ? "[ER]" : "[NO]";
    canvas_draw_str(c, x, y, t);
}

static void render_debug(Canvas* c, TgApp* app) {
    canvas_clear(c);
    draw_header(c, "Debug");
    canvas_set_font(c, FontSecondary);

    canvas_draw_str(c, 0, 18, "PING:");
    draw_status(c, 32, 18, app->dbg.ping);

    canvas_draw_str(c, 0, 26, "WiFi:");
    if(app->dbg.wifi == 2)
        canvas_draw_str(c, 32, 26, "[con]");
    else
        draw_status(c, 32, 26, app->dbg.wifi);

    canvas_draw_str(c, 0, 34, "HTTP:");
    draw_status(c, 32, 34, app->dbg.http);

    canvas_draw_str(c, 0, 42, "Resp:");
    if(app->dbg.resp < 0) {
        canvas_draw_str(c, 32, 42, "[..]");
    } else {
        char rb[20];
        snprintf(rb, sizeof(rb), "[%db %s]", app->dbg.resp_len, app->dbg.state_s);
        canvas_draw_str(c, 32, 42, rb);
    }

    canvas_draw_str(c, 0, 50, "Chts:");
    if(app->dbg.parse < 0) {
        canvas_draw_str(c, 32, 50, "[..]");
    } else {
        char pb[14];
        snprintf(pb, sizeof(pb), "[%d chat]", app->dbg.n_chats);
        canvas_draw_str(c, 32, 50, pb);
    }

    if(app->dbg.done && app->dbg.resp_len > 0 && app->dbg.n_chats == 0) {
        char prev[22];
        snprintf(prev, sizeof(prev), "%.21s", app->dbg.preview);
        canvas_draw_str_aligned(c, SW/2, 63, AlignCenter, AlignBottom, prev);
    } else if(app->dbg.done) {
        const char* hint;
        if(app->dbg.n_chats > 0)      hint = "OK=view chats";
        else if(app->dbg.ping  <= 0)  hint = "No board-OK=retry";
        else if(app->dbg.wifi  == 0)  hint = "No WiFi-OK=retry";
        else if(app->dbg.http  <= 0)  hint = "Send fail-OK=retry";
        else if(app->dbg.resp  <= 0)  hint = "Timeout-OK=retry";
        else                          hint = "0 chats-OK=retry";
        canvas_draw_str_aligned(c, SW/2, 63, AlignCenter, AlignBottom, hint);
    }
}

static void render_loading(Canvas* c) {
    canvas_clear(c);
    draw_header(c, "Telegram");
    canvas_set_font(c, FontSecondary);
    canvas_draw_str_aligned(c, SW/2, SH/2 - 4, AlignCenter, AlignCenter, "Loading...");
}

static void render_error(Canvas* c, const char* e) {
    canvas_clear(c);
    draw_header(c, "Error");
    canvas_set_font(c, FontSecondary);
    canvas_draw_str_aligned(c, SW/2, 24, AlignCenter, AlignTop, e);
    canvas_draw_str_aligned(c, SW/2, SH - 2, AlignCenter, AlignBottom, "Back=exit");
}

static void render_chats(Canvas* c, TgApp* app) {
    canvas_clear(c);
    draw_header(c, "Telegram Chats");

    if(app->ch_cnt == 0) {
        canvas_set_font(c, FontSecondary);
        canvas_draw_str_aligned(c, SW/2, 30, AlignCenter, AlignTop, "No chats yet");
        canvas_draw_str_aligned(c, SW/2, 42, AlignCenter, AlignTop, "@FlipperApp_bot");
        return;
    }

    canvas_set_font(c, FontSecondary);
    for(int i = 0; i < VR && (app->ch_top + i) < app->ch_cnt; i++) {
        int idx = app->ch_top + i;
        int y   = HH + i * RH;
        bool sel = (idx == app->ch_sel);

        if(sel) { canvas_draw_box(c, 0, y, SW, RH); canvas_invert_color(c); }
        char nm[19];
        snprintf(nm, sizeof(nm), "%s", app->ch[idx].name);
        canvas_draw_str(c, 2, y + 8, nm);
        char cnt[8];
        snprintf(cnt, sizeof(cnt), "%d", app->ch[idx].count);
        canvas_draw_str_aligned(c, SW - 2, y + 8, AlignRight, AlignBottom, cnt);
        if(sel) canvas_invert_color(c);
    }

    if(app->ch_cnt > VR) {
        int area  = SH - HH;
        int bar_h = area * VR / app->ch_cnt;
        int bar_y = HH + area * app->ch_top / app->ch_cnt;
        if(bar_h < 3) bar_h = 3;
        canvas_draw_box(c, SW - 2, bar_y, 2, bar_h);
    }
}

static int text_measure(const char* text, int maxw, int maxl) {
    int len = (int)strlen(text), off = 0, lines = 0;
    while(off < len && lines < maxl) {
        int rem  = len - off;
        int take = rem < maxw ? rem : maxw;
        if(rem > maxw) {
            int sp = -1;
            for(int i = 0; i < take; i++) if(text[off + i] == ' ') sp = i;
            if(sp > 0) take = sp;
        }
        off += take;
        if(off < len && text[off] == ' ') off++;
        lines++;
    }
    return off;
}

static int draw_wrapped(Canvas* c, int x, int ytop, const char* text, int maxw, int maxl) {
    int len = (int)strlen(text), off = 0, lines = 0;
    while(off < len && lines < maxl) {
        int rem  = len - off;
        int take = rem < maxw ? rem : maxw;
        if(rem > maxw) {
            int sp = -1;
            for(int i = 0; i < take; i++) if(text[off + i] == ' ') sp = i;
            if(sp > 0) take = sp;
        }
        char buf[22] = {0};
        if(take >= (int)sizeof(buf)) take = (int)sizeof(buf) - 1;
        memcpy(buf, text + off, take);
        canvas_draw_str(c, x, ytop + (lines + 1) * 9, buf);
        off += take;
        if(off < len && text[off] == ' ') off++;
        lines++;
    }
    return lines;
}

static void render_msgs(Canvas* c, TgApp* app) {
    canvas_clear(c);

    char hdr[NAME_SZ + 1];
    snprintf(hdr, sizeof(hdr), "%s", app->ac_name);
    draw_header(c, hdr);

    canvas_set_font(c, FontSecondary);

    if(app->mg_cnt == 0) {
        canvas_draw_str_aligned(c, SW/2, 30, AlignCenter, AlignTop, "No messages");
        char pg[32];
        snprintf(pg, sizeof(pg), "pg %d/%d", app->mg_page + 1, app->mg_pages);
        canvas_draw_str_aligned(c, SW/2, SH - 2, AlignCenter, AlignBottom, pg);
        return;
    }

    Message* m = &app->mg[app->mg_sel];

    canvas_draw_str(c, 2, 19, m->from);
    canvas_draw_str_aligned(c, SW - 2, 19, AlignRight, AlignBottom, m->time);
    canvas_draw_line(c, 0, 20, SW, 20);

    int tlen = (int)strlen(m->text);
    int off  = app->msg_char_off < tlen ? app->msg_char_off : (tlen > 0 ? tlen - 1 : 0);
    draw_wrapped(c, 2, 21, m->text + off, 20, 3);

    int page_chars = text_measure(m->text + off, 20, 3);
    bool more = (off + page_chars < tlen);
    char nav[40];
    int used = snprintf(nav, sizeof(nav), "%d/%d p%d/%d",
                        app->mg_sel + 1, app->mg_cnt,
                        app->mg_page + 1, app->mg_pages);
    const char* suffix = more ? " >" : " hld:snd";
    if(used > 0 && used < (int)sizeof(nav) - 9)
        strcpy(nav + used, suffix);
    canvas_draw_str_aligned(c, SW/2, SH - 1, AlignCenter, AlignBottom, nav);
}

// ─── Main view draw callback ──────────────────────────────────────────────────

static void draw_cb(Canvas* c, void* model) {
    TgApp* app = *(TgApp**)model;
    furi_mutex_acquire(app->mx, FuriWaitForever);
    switch(app->st) {
    case ST_DEBUG:   render_debug(c, app);          break;
    case ST_LOADING: render_loading(c);              break;
    case ST_CHATS:   render_chats(c, app);           break;
    case ST_MSGS:    render_msgs(c, app);            break;
    case ST_ERROR:   render_error(c, app->err);      break;
    }
    furi_mutex_release(app->mx);
}

// ─── Worker thread ────────────────────────────────────────────────────────────

static const char* state_name(HTTPState s) {
    switch(s) {
    case IDLE:      return "IDL";
    case RECEIVING: return "RCV";
    case SENDING:   return "SND";
    case ISSUE:     return "ISS";
    case INACTIVE:  return "INA";
    default:        return "???";
    }
}

static bool do_http_get(TgApp* app) {
    furi_mutex_acquire(app->mx, FuriWaitForever);
    char url[200];
    snprintf(url, sizeof(url), "%s", app->wurl);
    app->dbg.http = -1;
    app->dbg.resp = -1;
    furi_mutex_release(app->mx);
    view_dispatcher_send_custom_event(app->vd, CUSTOM_EV_REDRAW);

    uint8_t req_key[32];
    char nonce_hex[17];
    derive_req_key(app->crypto_key, req_key, nonce_hex);
    char req_headers[180];
    snprintf(req_headers, sizeof(req_headers),
             "{\"X-Secret\":\"%s\",\"X-Nonce\":\"%s\"}", app->secret_hash, nonce_hex);

    bool sent = flipper_http_request(app->fhttp, GET, url, req_headers, NULL);
    FURI_LOG_I(TAG, "HTTP GET %s → sent=%d", url, (int)sent);

    furi_mutex_acquire(app->mx, FuriWaitForever);
    app->dbg.http = sent ? 1 : 0;
    furi_mutex_release(app->mx);
    view_dispatcher_send_custom_event(app->vd, CUSTOM_EV_REDRAW);

    if(!sent) return false;

    uint32_t t1 = 50;
    while(t1 > 0 && !app->fhttp->started_receiving && app->fhttp->state != ISSUE) {
        furi_delay_ms(100);
        t1--;
    }

    bool had_success = app->fhttp->started_receiving;
    bool fast_done = (!app->fhttp->started_receiving &&
                      app->fhttp->state == IDLE &&
                      app->fhttp->last_response &&
                      app->fhttp->last_response[0] != '\0');

    if(had_success && !fast_done) {
        uint32_t t2 = 100;
        while(t2 > 0 && app->fhttp->started_receiving && app->fhttp->state != ISSUE) {
            furi_delay_ms(100);
            t2--;
        }
    }

    HTTPState fs = app->fhttp->state;
    int rlen = app->fhttp->last_response ? (int)strlen(app->fhttp->last_response) : 0;

    furi_mutex_acquire(app->mx, FuriWaitForever);
    snprintf(app->dbg.state_s, sizeof(app->dbg.state_s), "%s", state_name(fs));
    app->dbg.resp_len = rlen;
    if(rlen > 0)
        snprintf(app->dbg.preview, sizeof(app->dbg.preview), "%.33s",
                 app->fhttp->last_response);
    furi_mutex_release(app->mx);

    bool timed_out = (t1 == 0 && !had_success && !fast_done);
    if(timed_out) {
        furi_mutex_acquire(app->mx, FuriWaitForever);
        app->dbg.resp = 0;
        furi_mutex_release(app->mx);
        return false;
    }

    if(fs == ISSUE || fs == INACTIVE) {
        furi_mutex_acquire(app->mx, FuriWaitForever);
        app->dbg.resp = 2;
        furi_mutex_release(app->mx);
        return false;
    }

    if(!app->fhttp->last_response || rlen == 0) {
        furi_mutex_acquire(app->mx, FuriWaitForever);
        app->dbg.resp = 0;
        furi_mutex_release(app->mx);
        return false;
    }

    furi_mutex_acquire(app->mx, FuriWaitForever);
    snprintf(app->wresp, RESP_SZ - 1, "%s", app->fhttp->last_response);
    app->wresp[RESP_SZ - 1] = '\0';
    xor_decode_hex(req_key, app->wresp);
    app->dbg.resp = 1;
    furi_mutex_release(app->mx);

    return true;
}

static bool do_http_post(TgApp* app) {
    furi_mutex_acquire(app->mx, FuriWaitForever);
    char url[200];
    char payload[200];
    snprintf(url, sizeof(url), "%s", app->wurl);
    snprintf(payload, sizeof(payload), "%s", app->send_payload);
    furi_mutex_release(app->mx);

    uint8_t req_key[32];
    char nonce_hex[17];
    derive_req_key(app->crypto_key, req_key, nonce_hex);
    char req_headers[240];
    snprintf(req_headers, sizeof(req_headers),
             "{\"Content-Type\":\"text/plain\",\"X-Secret\":\"%s\",\"X-Nonce\":\"%s\"}",
             app->secret_hash, nonce_hex);

    xor_encode_hex(req_key, payload, app->enc_payload_buf, sizeof(app->enc_payload_buf));
    bool sent = flipper_http_request(app->fhttp, POST, url, req_headers, app->enc_payload_buf);
    if(!sent) return false;

    uint32_t t1 = 50;
    while(t1 > 0 && !app->fhttp->started_receiving && app->fhttp->state != ISSUE) {
        furi_delay_ms(100);
        t1--;
    }
    bool had_success = app->fhttp->started_receiving;
    bool fast_done = (!app->fhttp->started_receiving &&
                      app->fhttp->state == IDLE &&
                      app->fhttp->last_response &&
                      app->fhttp->last_response[0] != '\0');
    if(had_success && !fast_done) {
        uint32_t t2 = 100;
        while(t2 > 0 && app->fhttp->started_receiving && app->fhttp->state != ISSUE) {
            furi_delay_ms(100);
            t2--;
        }
    }
    HTTPState fs = app->fhttp->state;
    if((fs == IDLE || fast_done) && app->fhttp->last_response) {
        furi_mutex_acquire(app->mx, FuriWaitForever);
        snprintf(app->wresp, RESP_SZ - 1, "%s", app->fhttp->last_response);
        xor_decode_hex(req_key, app->wresp);
        furi_mutex_release(app->mx);
        return true;
    }
    return false;
}

static int32_t worker_thread(void* ctx) {
    TgApp* app = ctx;
    FURI_LOG_I(TAG, "Worker started");

    furi_mutex_acquire(app->mx, FuriWaitForever);
    app->dbg.ping = -1;
    furi_mutex_release(app->mx);
    view_dispatcher_send_custom_event(app->vd, CUSTOM_EV_REDRAW);

    flipper_http_send_command(app->fhttp, HTTP_CMD_PING);
    uint32_t pt = 50;
    while(app->fhttp->state == INACTIVE && pt-- > 0) furi_delay_ms(100);

    bool ping_ok = (pt > 0);
    furi_mutex_acquire(app->mx, FuriWaitForever);
    app->dbg.ping = ping_ok ? 1 : 0;
    furi_mutex_release(app->mx);
    view_dispatcher_send_custom_event(app->vd, CUSTOM_EV_REDRAW);

    if(!ping_ok) {
        furi_mutex_acquire(app->mx, FuriWaitForever);
        snprintf(app->err, sizeof(app->err), "No WiFi board response");
        app->st = ST_ERROR;
        app->dbg.done = true;
        furi_mutex_release(app->mx);
        view_dispatcher_send_custom_event(app->vd, CUSTOM_EV_DONE);
        return 0;
    }

    app->fhttp->state = IDLE;
    furi_delay_ms(300);
    if(furi_event_flag_get(app->ev) & EV_STOP) return 0;

    furi_mutex_acquire(app->mx, FuriWaitForever);
    app->dbg.wifi = -1;
    furi_mutex_release(app->mx);
    view_dispatcher_send_custom_event(app->vd, CUSTOM_EV_REDRAW);

    flipper_http_send_command(app->fhttp, HTTP_CMD_STATUS);
    furi_delay_ms(2000);
    if(furi_event_flag_get(app->ev) & EV_STOP) return 0;

    bool wifi_ok = app->fhttp->last_response &&
                   strstr(app->fhttp->last_response, "[CONNECTED]") != NULL;

    if(!wifi_ok) {
        flipper_http_save_wifi(app->fhttp, app->creds_ssid, app->creds_pass);
        furi_delay_ms(3000);
        if(furi_event_flag_get(app->ev) & EV_STOP) return 0;

        furi_mutex_acquire(app->mx, FuriWaitForever);
        app->dbg.wifi = 2;
        furi_mutex_release(app->mx);
        view_dispatcher_send_custom_event(app->vd, CUSTOM_EV_REDRAW);

        flipper_http_send_command(app->fhttp, HTTP_CMD_WIFI_CONNECT);
        for(int wi = 0; wi < 60 && !wifi_ok; wi++) {
            furi_delay_ms(500);
            if(furi_event_flag_get(app->ev) & EV_STOP) return 0;
            const char* lr = app->fhttp->last_response;
            if(lr)
                wifi_ok = strstr(lr, "[CONNECTED]") != NULL ||
                          strstr(lr, "Already connected") != NULL;
        }
    }

    furi_mutex_acquire(app->mx, FuriWaitForever);
    if(app->fhttp->last_response && app->fhttp->last_response[0]) {
        snprintf(app->dbg.preview, sizeof(app->dbg.preview),
                 "%.33s", app->fhttp->last_response);
        app->dbg.resp_len = (int)strlen(app->fhttp->last_response);
    }
    app->dbg.wifi = wifi_ok ? 1 : 0;
    furi_mutex_release(app->mx);
    view_dispatcher_send_custom_event(app->vd, CUSTOM_EV_REDRAW);

    if(!wifi_ok) {
        furi_mutex_acquire(app->mx, FuriWaitForever);
        app->dbg.parse = 0;
        app->dbg.done  = true;
        app->st = ST_DEBUG;
        furi_mutex_release(app->mx);
        view_dispatcher_send_custom_event(app->vd, CUSTOM_EV_DONE);
        return 0;
    }

    furi_delay_ms(2000);
    if(furi_event_flag_get(app->ev) & EV_STOP) return 0;

    furi_mutex_acquire(app->mx, FuriWaitForever);
    app->wcmd = CMD_CHATS;
    snprintf(app->wurl, sizeof(app->wurl), "%s/flipper/chats", app->api_base);
    furi_mutex_release(app->mx);

    app->wok = false;
    for(int retry = 0; retry < 3; retry++) {
        if(retry > 0) {
            app->fhttp->state = IDLE;
            furi_delay_ms(2000);
        }
        app->wok = do_http_get(app);
        if(app->wok) break;
    }

    furi_mutex_acquire(app->mx, FuriWaitForever);
    app->dbg.parse = -1;
    furi_mutex_release(app->mx);

    if(!app->wok) {
        furi_mutex_acquire(app->mx, FuriWaitForever);
        app->dbg.parse = 0;
        app->dbg.done  = true;
        app->st = ST_DEBUG;
        furi_mutex_release(app->mx);
    }

    view_dispatcher_send_custom_event(app->vd, CUSTOM_EV_DONE);

    // ── Main request loop ─────────────────────────────────────────────────────
    while(true) {
        uint32_t f = furi_event_flag_wait(app->ev, EV_RUN | EV_STOP,
                                          FuriFlagWaitAny, FuriWaitForever);
        if(f & EV_STOP) break;
        if(!(f & EV_RUN)) continue;

        WorkerCmd wc = app->wcmd;
        if(wc == CMD_SEND) {
            app->wok = do_http_post(app);
        } else {
            app->wok = do_http_get(app);
        }

        if(!app->wok && wc != CMD_SEND) {
            furi_mutex_acquire(app->mx, FuriWaitForever);
            app->dbg.parse = 0;
            app->dbg.done  = true;
            app->st = ST_DEBUG;
            furi_mutex_release(app->mx);
        }
        view_dispatcher_send_custom_event(app->vd, CUSTOM_EV_DONE);
    }

    FURI_LOG_I(TAG, "Worker stopped");
    return 0;
}

// ─── Setup callbacks (credential collection) ──────────────────────────────────

static void setup_port_done(void* ctx) {
    TgApp* app = ctx;
    app->in_setup = false;
    creds_save(app);
    creds_apply(app);
    app->st = ST_DEBUG;
    view_dispatcher_switch_to_view(app->vd, VIEW_MAIN);
    app->wt = furi_thread_alloc_ex("TgWorker", 4 * 1024, worker_thread, app);
    furi_thread_start(app->wt);
}

static void setup_ip_done(void* ctx) {
    TgApp* app = ctx;
    memset(app->creds_port, 0, sizeof(app->creds_port));
    text_input_set_header_text(app->text_input, "Server Port");
    text_input_set_result_callback(app->text_input, setup_port_done, app,
                                   app->creds_port, sizeof(app->creds_port), false);
    view_dispatcher_switch_to_view(app->vd, VIEW_TEXT_INPUT);
}

static void setup_secret_done(void* ctx) {
    TgApp* app = ctx;
    memset(app->creds_ip, 0, sizeof(app->creds_ip));
    text_input_set_header_text(app->text_input, "Server IP");
    text_input_set_result_callback(app->text_input, setup_ip_done, app,
                                   app->creds_ip, sizeof(app->creds_ip), false);
    view_dispatcher_switch_to_view(app->vd, VIEW_TEXT_INPUT);
}

static void setup_pass_done(void* ctx) {
    TgApp* app = ctx;
    memset(app->creds_secret, 0, sizeof(app->creds_secret));
    text_input_set_header_text(app->text_input, "Secret Key");
    text_input_set_result_callback(app->text_input, setup_secret_done, app,
                                   app->creds_secret, sizeof(app->creds_secret), false);
    view_dispatcher_switch_to_view(app->vd, VIEW_TEXT_INPUT);
}

static void setup_ssid_done(void* ctx) {
    TgApp* app = ctx;
    memset(app->creds_pass, 0, sizeof(app->creds_pass));
    text_input_set_header_text(app->text_input, "WiFi Password");
    text_input_set_result_callback(app->text_input, setup_pass_done, app,
                                   app->creds_pass, sizeof(app->creds_pass), false);
    view_dispatcher_switch_to_view(app->vd, VIEW_TEXT_INPUT);
}

static void begin_setup(TgApp* app) {
    app->in_setup = true;
    memset(app->creds_ssid, 0, sizeof(app->creds_ssid));
    text_input_set_header_text(app->text_input, "WiFi SSID");
    text_input_set_result_callback(app->text_input, setup_ssid_done, app,
                                   app->creds_ssid, sizeof(app->creds_ssid), false);
    view_dispatcher_switch_to_view(app->vd, VIEW_TEXT_INPUT);
}

// ─── ViewDispatcher callbacks ─────────────────────────────────────────────────

static void redraw_main(TgApp* app) {
    with_view_model(app->main_view, TgApp** model, { (void)model; }, true);
}

static bool custom_event_cb(void* ctx, uint32_t event) {
    TgApp* app = ctx;

    if(event == CUSTOM_EV_REDRAW) {
        redraw_main(app);
        return true;
    }

    if(event != CUSTOM_EV_DONE) return false;

    furi_mutex_acquire(app->mx, FuriWaitForever);

    if(app->wok) {
        WorkerCmd cmd = app->wcmd;
        if(cmd == CMD_CHATS) {
            int cnt = parse_chats(app->wresp, app->ch, MAX_CHATS);
            app->ch_cnt      = cnt;
            app->ch_sel      = 0;
            app->ch_top      = 0;
            app->dbg.n_chats = cnt;
            app->dbg.parse   = (cnt > 0) ? 1 : 0;
            app->dbg.done    = true;
            app->st = ST_DEBUG;
        } else if(cmd == CMD_SEND) {
            app->compose_buf[0] = '\0';
            app->st = ST_MSGS;
        } else {
            app->mg_cnt = parse_msgs(app->wresp, app->mg, MAX_MSGS,
                                     &app->mg_page, &app->mg_pages);
            app->mg_sel = 0;
            app->msg_char_off = 0;
            app->st = ST_MSGS;
        }
    } else if(app->wcmd == CMD_SEND) {
        app->st = ST_MSGS;
    }

    furi_mutex_release(app->mx);
    redraw_main(app);
    return true;
}

static bool navigation_cb(void* ctx) {
    TgApp* app = ctx;
    if(app->in_compose) {
        app->in_compose = false;
        view_dispatcher_switch_to_view(app->vd, VIEW_MAIN);
        return true;
    }
    view_dispatcher_stop(app->vd);
    return true;
}

static void text_input_result_cb(void* ctx) {
    TgApp* app = ctx;
    app->in_compose = false;

    if(app->compose_buf[0] == '\0') {
        view_dispatcher_switch_to_view(app->vd, VIEW_MAIN);
        return;
    }

    furi_mutex_acquire(app->mx, FuriWaitForever);
    snprintf(app->wurl, sizeof(app->wurl), "%s/flipper/send/%s", app->api_base, app->ac_id);
    char esc_text[COMPOSE_SZ * 2];
    json_escape(app->compose_buf, esc_text, sizeof(esc_text));
    snprintf(app->send_payload, sizeof(app->send_payload),
             "{\"text\":\"%s\"}", esc_text);
    app->wcmd = CMD_SEND;
    app->st = ST_LOADING;
    furi_mutex_release(app->mx);

    view_dispatcher_switch_to_view(app->vd, VIEW_MAIN);
    redraw_main(app);
    furi_event_flag_set(app->ev, EV_RUN);
}

static bool input_cb(InputEvent* e, void* ctx) {
    TgApp* app = ctx;
    if(e->type != InputTypeShort && e->type != InputTypeLong) return false;

    furi_mutex_acquire(app->mx, FuriWaitForever);
    char url_buf[200];
    bool consumed = true;

    switch(app->st) {

    case ST_DEBUG:
        if(e->key == InputKeyBack) {
            furi_mutex_release(app->mx);
            view_dispatcher_stop(app->vd);
            return true;
        } else if(e->key == InputKeyOk && app->dbg.done) {
            if(app->dbg.n_chats > 0) {
                app->ch_sel = 0;
                app->ch_top = 0;
                app->st = ST_CHATS;
            } else {
                app->dbg.wifi  = -1;
                app->dbg.http  = -1;
                app->dbg.resp  = -1;
                app->dbg.parse = -1;
                app->dbg.done  = false;
                app->dbg.resp_len   = 0;
                app->dbg.preview[0] = '\0';
                app->dbg.state_s[0] = '\0';
                app->wcmd = CMD_CHATS;
                snprintf(app->wurl, sizeof(app->wurl), "%s/flipper/chats", app->api_base);
                furi_event_flag_set(app->ev, EV_RUN);
            }
        } else {
            consumed = false;
        }
        break;

    case ST_CHATS:
        switch(e->key) {
        case InputKeyUp:
            if(app->ch_sel > 0) {
                app->ch_sel--;
                if(app->ch_sel < app->ch_top) app->ch_top = app->ch_sel;
            }
            break;
        case InputKeyDown:
            if(app->ch_sel < app->ch_cnt - 1) {
                app->ch_sel++;
                if(app->ch_sel >= app->ch_top + VR)
                    app->ch_top = app->ch_sel - VR + 1;
            }
            break;
        case InputKeyOk:
        case InputKeyRight:
            if(app->ch_cnt > 0) {
                snprintf(app->ac_id,   sizeof(app->ac_id),   "%s", app->ch[app->ch_sel].id);
                snprintf(app->ac_name, sizeof(app->ac_name), "%s", app->ch[app->ch_sel].name);
                app->msg_char_off = 0;
                snprintf(url_buf, sizeof(url_buf),
                         "%s/flipper/messages/%s?page=0", app->api_base, app->ac_id);
                snprintf(app->wurl, sizeof(app->wurl), "%s", url_buf);
                app->wcmd = CMD_MSGS;
                app->st = ST_LOADING;
                furi_event_flag_set(app->ev, EV_RUN);
            }
            break;
        case InputKeyBack:
            app->st = ST_DEBUG;
            break;
        default:
            consumed = false;
            break;
        }
        break;

    case ST_MSGS:
        switch(e->key) {
        case InputKeyUp:
            if(app->mg_sel > 0) {
                app->mg_sel--;
                app->msg_char_off = 0;
            } else if(app->mg_page > 0) {
                snprintf(url_buf, sizeof(url_buf),
                         "%s/flipper/messages/%s?page=%d",
                         app->api_base, app->ac_id, app->mg_page - 1);
                snprintf(app->wurl, sizeof(app->wurl), "%s", url_buf);
                app->wcmd = CMD_MSGS;
                app->st = ST_LOADING;
                furi_event_flag_set(app->ev, EV_RUN);
            }
            break;
        case InputKeyDown:
            if(app->mg_sel < app->mg_cnt - 1) {
                app->mg_sel++;
                app->msg_char_off = 0;
            } else if(app->mg_page < app->mg_pages - 1) {
                snprintf(url_buf, sizeof(url_buf),
                         "%s/flipper/messages/%s?page=%d",
                         app->api_base, app->ac_id, app->mg_page + 1);
                snprintf(app->wurl, sizeof(app->wurl), "%s", url_buf);
                app->wcmd = CMD_MSGS;
                app->st = ST_LOADING;
                furi_event_flag_set(app->ev, EV_RUN);
            }
            break;
        case InputKeyLeft: {
            if(app->msg_char_off > 0) {
                Message* ml = &app->mg[app->mg_sel];
                int off = 0, prev = 0;
                while(off < app->msg_char_off) {
                    int adv = text_measure(ml->text + off, 20, 3);
                    if(adv == 0) break;
                    int nxt = off + adv;
                    if(nxt >= app->msg_char_off) {
                        prev = (off == app->msg_char_off) ? prev : off;
                        break;
                    }
                    prev = off;
                    off = nxt;
                }
                app->msg_char_off = prev;
            }
            break;
        }
        case InputKeyRight: {
            Message* mr = &app->mg[app->mg_sel];
            int tlen = (int)strlen(mr->text);
            int adv  = text_measure(mr->text + app->msg_char_off, 20, 3);
            int nxt  = app->msg_char_off + adv;
            if(nxt < tlen) app->msg_char_off = nxt;
            break;
        }
        case InputKeyOk:
            if(e->type == InputTypeLong) {
                app->compose_buf[0] = '\0';
                app->in_compose = true;
                furi_mutex_release(app->mx);
                text_input_set_header_text(app->text_input, "Message");
                text_input_set_result_callback(app->text_input, text_input_result_cb, app,
                                               app->compose_buf, COMPOSE_SZ, false);
                view_dispatcher_switch_to_view(app->vd, VIEW_TEXT_INPUT);
                return true;
            }
            consumed = false;
            break;
        case InputKeyBack:
            snprintf(url_buf, sizeof(url_buf), "%s/flipper/chats", app->api_base);
            snprintf(app->wurl, sizeof(app->wurl), "%s", url_buf);
            app->wcmd = CMD_CHATS;
            app->st = ST_LOADING;
            furi_event_flag_set(app->ev, EV_RUN);
            break;
        default:
            consumed = false;
            break;
        }
        break;

    case ST_ERROR:
        if(e->key == InputKeyBack) {
            furi_mutex_release(app->mx);
            view_dispatcher_stop(app->vd);
            return true;
        }
        consumed = false;
        break;

    default:
        consumed = false;
        break;
    }

    furi_mutex_release(app->mx);
    if(consumed) redraw_main(app);
    return consumed;
}

// ─── Entry point ─────────────────────────────────────────────────────────────

int32_t telegram_reader_app(void* p) {
    UNUSED(p);

    TgApp* app = malloc(sizeof(TgApp));
    furi_check(app);
    memset(app, 0, sizeof(TgApp));
    app->st = ST_DEBUG;

    app->dbg.ping  = -1;
    app->dbg.wifi  = -1;
    app->dbg.http  = -1;
    app->dbg.resp  = -1;
    app->dbg.parse = -1;

    app->mx  = furi_mutex_alloc(FuriMutexTypeNormal);
    app->ev  = furi_event_flag_alloc();
    app->gui = furi_record_open(RECORD_GUI);

    app->vd = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->vd, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->vd, app);
    view_dispatcher_set_custom_event_callback(app->vd, custom_event_cb);
    view_dispatcher_set_navigation_event_callback(app->vd, navigation_cb);

    app->main_view = view_alloc();
    view_allocate_model(app->main_view, ViewModelTypeLockFree, sizeof(TgApp*));
    with_view_model(app->main_view, TgApp** model, { *model = app; }, false);
    view_set_draw_callback(app->main_view, draw_cb);
    view_set_input_callback(app->main_view, input_cb);
    view_set_context(app->main_view, app);
    view_dispatcher_add_view(app->vd, VIEW_MAIN, app->main_view);

    app->text_input = text_input_alloc();
    view_dispatcher_add_view(app->vd, VIEW_TEXT_INPUT, text_input_get_view(app->text_input));

    view_dispatcher_switch_to_view(app->vd, VIEW_MAIN);

    app->fhttp = flipper_http_alloc();
    if(!app->fhttp) {
        furi_mutex_acquire(app->mx, FuriWaitForever);
        snprintf(app->err, sizeof(app->err), "FlipperHTTP init failed");
        app->st = ST_ERROR;
        app->dbg.done = true;
        furi_mutex_release(app->mx);
        redraw_main(app);
    } else if(creds_load(app)) {
        creds_apply(app);
        app->wt = furi_thread_alloc_ex("TgWorker", 4 * 1024, worker_thread, app);
        furi_thread_start(app->wt);
    } else {
        begin_setup(app);
    }

    view_dispatcher_run(app->vd);

    // ─── Cleanup ─────────────────────────────────────────────────────────────
    if(app->wt) {
        furi_event_flag_set(app->ev, EV_STOP);
        furi_thread_join(app->wt);
        furi_thread_free(app->wt);
    }
    if(app->fhttp) flipper_http_free(app->fhttp);

    view_dispatcher_remove_view(app->vd, VIEW_TEXT_INPUT);
    view_dispatcher_remove_view(app->vd, VIEW_MAIN);
    text_input_free(app->text_input);
    view_free(app->main_view);
    view_dispatcher_free(app->vd);

    furi_record_close(RECORD_GUI);
    furi_event_flag_free(app->ev);
    furi_mutex_free(app->mx);
    free(app);

    return 0;
}
