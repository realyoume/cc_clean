import argparse
import gzip
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse

from warcio.archiveiterator import ArchiveIterator


# =========================
# 1. 关键词配置
# =========================

HIGH_CONF_SECURITY_DOMAINS = {
    "nvd.nist.gov",
    "cve.org",
    "mitre.org",
    "attack.mitre.org",
    "owasp.org",
    "portswigger.net",
    "exploit-db.com",
    "packetstormsecurity.com",
    "msrc.microsoft.com",
    "googleprojectzero.blogspot.com",
}

MEDIUM_CONF_SECURITY_DOMAINS = {
    "krebsonsecurity.com",
    "bleepingcomputer.com",
    "thehackernews.com",
    "darkreading.com",
    "securityweek.com",
    "sans.org",
    "rapid7.com",
    "qualys.com",
    "tenable.com",
}

BROAD_TECH_DOMAINS = {
    "microsoft.com",
    "cloudflare.com",
    "blog.google",
    "github.blog",
    "redhat.com",
    "canonical.com",
    "oracle.com",
    "ibm.com",
    "apple.com",
}


SECURITY_PATH_TERMS = [
    "/security/",
    "/security-advisories",
    "/security-advisory",
    "/advisory",
    "/advisories",
    "/vulnerability",
    "/vulnerabilities",
    "/cve",
    "/threat",
    "/malware",
    "/incident",
    "/patch",
    "/zero-day",
    "/0day",
    "/exploit",
    "/research",
    "/threat-intelligence",
    "/blog/security",
]

NON_SECURITY_PATH_TERMS = [
    "/privacy",
    "/privacy-policy",
    "/terms",
    "/terms-of-service",
    "/cookie",
    "/cookies",
    "/login",
    "/signup",
    "/account",
    "/social-security",
    "/food-security",
    "/job-security",
    "/home-security-camera",
]


SECURITY_CATEGORIES = {
    "vulnerability": [
        "cve",
        "vulnerability",
        "vulnerabilities",
        "exploit",
        "exploited",
        "zero-day",
        "0day",
        "remote code execution",
        "rce",
        "privilege escalation",
        "authentication bypass",
        "authorization bypass",
        "buffer overflow",
        "heap overflow",
        "stack overflow",
        "use-after-free",
        "race condition",
        "directory traversal",
        "path traversal",
        "arbitrary file read",
        "arbitrary file write",
        "漏洞",
        "漏洞利用",
        "漏洞复现",
        "远程代码执行",
        "代码执行",
        "命令执行",
        "权限提升",
        "权限绕过",
        "认证绕过",
        "越权",
        "缓冲区溢出",
        "任意文件读取",
        "任意文件写入",
        "目录穿越",
    ],
    "web_security": [
        "xss",
        "cross-site scripting",
        "sql injection",
        "sqli",
        "csrf",
        "ssrf",
        "xxe",
        "file upload vulnerability",
        "deserialization",
        "insecure direct object reference",
        "idor",
        "open redirect",
        "web security",
        "owasp",
        "sql注入",
        "跨站脚本",
        "跨站请求伪造",
        "服务端请求伪造",
        "反序列化",
        "文件上传漏洞",
    ],
    "malware": [
        "malware",
        "ransomware",
        "trojan",
        "botnet",
        "worm",
        "spyware",
        "rootkit",
        "keylogger",
        "backdoor",
        "command and control",
        "c2 server",
        "c2 infrastructure",
        "ioc",
        "indicator of compromise",
        "yara",
        "木马",
        "勒索病毒",
        "恶意软件",
        "恶意代码",
        "僵尸网络",
        "后门",
        "远控",
        "病毒",
        "蠕虫",
        "失陷指标",
    ],
    "pentest_redteam": [
        "penetration testing",
        "pentest",
        "red team",
        "red teaming",
        "blue team",
        "metasploit",
        "burp suite",
        "nmap",
        "sqlmap",
        "reverse shell",
        "payload",
        "shellcode",
        "lateral movement",
        "persistence",
        "post-exploitation",
        "渗透测试",
        "红队",
        "蓝队",
        "内网渗透",
        "横向移动",
        "权限维持",
        "反弹 shell",
        "反弹shell",
        "攻击载荷",
        "免杀",
    ],
    "forensics_incident": [
        "incident response",
        "digital forensics",
        "forensic analysis",
        "memory forensics",
        "log analysis",
        "threat hunting",
        "threat intelligence",
        "apt",
        "threat actor",
        "应急响应",
        "数字取证",
        "内存取证",
        "日志分析",
        "威胁情报",
        "威胁狩猎",
        "apt攻击",
        "攻击组织",
    ],
    "defense_ops": [
        "ids",
        "ips",
        "siem",
        "soc",
        "edr",
        "xdr",
        "firewall",
        "waf",
        "intrusion detection",
        "intrusion prevention",
        "sigma rule",
        "snort rule",
        "suricata",
        "security monitoring",
        "patch",
        "mitigation",
        "hardening",
        "入侵检测",
        "入侵防御",
        "防火墙",
        "安全运营",
        "安全监控",
        "加固",
        "补丁",
        "缓解措施",
        "修复建议",
    ],
    "crypto_protocol": [
        "cryptography",
        "encryption",
        "decryption",
        "tls",
        "ssl",
        "certificate",
        "x.509",
        "cipher suite",
        "key exchange",
        "openssl",
        "加密",
        "解密",
        "密码学",
        "证书",
        "密钥交换",
        "加密套件",
    ],
    "cloud_security": [
        "cloud security",
        "kubernetes security",
        "docker security",
        "container security",
        "iam",
        "aws security",
        "azure security",
        "gcp security",
        "s3 bucket",
        "misconfiguration",
        "云安全",
        "容器安全",
        "kubernetes安全",
        "docker安全",
        "配置错误",
        "访问控制",
    ],
}


HIGH_PRECISION_TERMS = [
    "cve",
    "remote code execution",
    "rce",
    "zero-day",
    "0day",
    "xss",
    "cross-site scripting",
    "sql injection",
    "sqli",
    "ssrf",
    "xxe",
    "csrf",
    "deserialization",
    "privilege escalation",
    "authentication bypass",
    "authorization bypass",
    "buffer overflow",
    "heap overflow",
    "stack overflow",
    "use-after-free",
    "directory traversal",
    "path traversal",
    "arbitrary file read",
    "arbitrary file write",
    "metasploit",
    "sqlmap",
    "reverse shell",
    "shellcode",
    "payload",
    "yara",
    "sigma rule",
    "snort rule",
    "suricata",
    "incident response",
    "threat intelligence",
    "indicator of compromise",
    "ioc",
    "漏洞",
    "漏洞利用",
    "漏洞复现",
    "远程代码执行",
    "代码执行",
    "命令执行",
    "权限提升",
    "权限绕过",
    "认证绕过",
    "越权",
    "缓冲区溢出",
    "任意文件读取",
    "任意文件写入",
    "目录穿越",
    "sql注入",
    "跨站脚本",
    "跨站请求伪造",
    "服务端请求伪造",
    "反序列化",
    "文件上传漏洞",
    "应急响应",
    "威胁情报",
    "失陷指标",
]

WEAK_TERMS = [
    "security",
    "cybersecurity",
    "infosec",
    "attack",
    "attacker",
    "defense",
    "defender",
    "risk",
    "breach",
    "leak",
    "privacy",
    "authentication",
    "authorization",
    "access control",
    "安全",
    "网络安全",
    "攻击",
    "防御",
    "风险",
    "数据泄露",
    "隐私",
    "认证",
    "授权",
    "访问控制",
]

NON_CYBER_PHRASES = [
    "food security",
    "traffic safety",
    "road safety",
    "workplace safety",
    "social security",
    "national security",
    "security guard",
    "home security camera",
    "financial security",
    "job security",
    "public safety",
    "食品安全",
    "交通安全",
    "生产安全",
    "社会保障",
    "国家安全",
    "保安",
    "安防摄像头",
    "就业保障",
]


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)


# =========================
# 2. 正则编译
# =========================

def compile_term_pattern(term: str):
    """
    英文词使用近似词边界；中文词直接 substring。
    """
    has_cjk = any("\u4e00" <= ch <= "\u9fff" for ch in term)

    if has_cjk:
        return re.compile(re.escape(term), re.IGNORECASE)

    escaped = re.escape(term).replace(r"\ ", r"\s+")
    return re.compile(
        r"(?<![A-Za-z0-9])" + escaped + r"(?![A-Za-z0-9])",
        re.IGNORECASE,
    )


CATEGORY_PATTERNS = {
    cat: [(term, compile_term_pattern(term)) for term in terms]
    for cat, terms in SECURITY_CATEGORIES.items()
}

HIGH_PRECISION_PATTERNS = [
    (term, compile_term_pattern(term))
    for term in HIGH_PRECISION_TERMS
]

WEAK_PATTERNS = [
    (term, compile_term_pattern(term))
    for term in WEAK_TERMS
]

NON_CYBER_PATTERNS = [
    (term, compile_term_pattern(term))
    for term in NON_CYBER_PHRASES
]


# =========================
# 3. 基础工具函数
# =========================

def normalize_text(text: str) -> str:
    text = text.replace("\x00", " ")
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def get_domain(url: str) -> str:
    try:
        netloc = urlparse(url).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc
    except Exception:
        return ""


def get_path(url: str) -> str:
    try:
        parsed = urlparse(url)
        return (parsed.path or "").lower()
    except Exception:
        return ""


def domain_in_set(domain: str, domain_set: set[str]) -> bool:
    if not domain:
        return False

    if domain in domain_set:
        return True

    for d in domain_set:
        if domain.endswith("." + d):
            return True

    return False


def get_domain_confidence(domain: str) -> str:
    if domain_in_set(domain, HIGH_CONF_SECURITY_DOMAINS):
        return "high"

    if domain_in_set(domain, MEDIUM_CONF_SECURITY_DOMAINS):
        return "medium"

    if domain_in_set(domain, BROAD_TECH_DOMAINS):
        return "broad_tech"

    return "none"


def get_path_features(url: str):
    path = get_path(url)

    has_security_path = any(t in path for t in SECURITY_PATH_TERMS)
    has_non_security_path = any(t in path for t in NON_SECURITY_PATH_TERMS)

    return {
        "path": path,
        "has_security_path": has_security_path,
        "has_non_security_path": has_non_security_path,
    }


def sha1_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()


def normalize_for_dedup(text: str) -> str:
    text = text.lower()
    text = re.sub(r"https?://\S+", " ", text)
    text = re.sub(r"\d+", "0", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# =========================
# 4. 质量过滤
# =========================

def page_quality_check(text: str, min_page_chars: int, max_page_chars: int):
    """
    页面级质量过滤。
    注意：这里不再用 max_chars=80000 直接丢弃长网页。
    长网页是否有价值，交给后续片段级筛选判断。
    """
    n = len(text)

    if n < min_page_chars:
        return False, "page_too_short"

    if max_page_chars > 0 and n > max_page_chars:
        return False, "page_too_long"

    bad_chars = text.count("�")
    if n > 0 and bad_chars / n > 0.01:
        return False, "too_many_bad_chars"

    visible_chars = sum(
        1 for ch in text
        if ch.isprintable() or ch in "\n\t"
    )
    if n > 0 and visible_chars / n < 0.95:
        return False, "too_many_invisible_chars"

    return True, "ok"


def segment_quality_check(text: str, min_segment_chars: int):
    """
    片段级质量过滤。
    """
    n = len(text)

    if n < min_segment_chars:
        return False, "segment_too_short"

    bad_chars = text.count("�")
    if n > 0 and bad_chars / n > 0.01:
        return False, "too_many_bad_chars"

    url_count = len(URL_RE.findall(text))
    if n > 0 and url_count / max(1, n / 1000) > 20:
        return False, "too_many_urls"

    lines = [line.strip() for line in text.splitlines() if len(line.strip()) >= 20]
    if len(lines) >= 12:
        c = Counter(lines)
        duplicate_lines = sum(v - 1 for v in c.values() if v > 1)
        dup_ratio = duplicate_lines / len(lines)
        if dup_ratio > 0.35:
            return False, "too_many_duplicate_lines"

    visible_chars = sum(
        1 for ch in text
        if ch.isprintable() or ch in "\n\t"
    )
    if n > 0 and visible_chars / n < 0.95:
        return False, "too_many_invisible_chars"

    return True, "ok"


# =========================
# 5. 语料切分
# =========================

def split_long_text_by_chars(text: str, max_chars: int, overlap_chars: int):
    """
    对超长段落做滑窗切分。
    """
    chunks = []
    start = 0
    n = len(text)

    step = max(1, max_chars - overlap_chars)

    while start < n:
        end = min(n, start + max_chars)
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)

        if end >= n:
            break

        start += step

    return chunks


def tail_overlap(text: str, overlap_chars: int) -> str:
    if overlap_chars <= 0:
        return ""

    text = text.strip()
    if len(text) <= overlap_chars:
        return text

    return text[-overlap_chars:]


def split_text_into_segments(
    text: str,
    target_segment_chars: int = 1200,
    max_segment_chars: int = 1800,
    min_segment_chars: int = 300,
    overlap_chars: int = 150,
):
    """
    段落优先切分：
    1. 先按空行切段落；
    2. 普通段落按 target_segment_chars 打包；
    3. 超长段落用滑窗切分；
    4. 相邻片段保留少量 overlap，避免关键词和上下文被切断。

    返回：
    [
        {"segment_index": 0, "text": "..."},
        ...
    ]
    """
    text = normalize_text(text)

    paragraphs = [
        p.strip()
        for p in re.split(r"\n\s*\n+", text)
        if p.strip()
    ]

    # 如果网页没有明显空行，就退化为按行聚合。
    if len(paragraphs) <= 1:
        paragraphs = [
            p.strip()
            for p in text.splitlines()
            if p.strip()
        ]

    segments = []
    current_parts = []

    def flush_current():
        nonlocal current_parts

        if not current_parts:
            return

        seg_text = "\n\n".join(current_parts).strip()
        if seg_text:
            segments.append(seg_text)

        if overlap_chars > 0:
            overlap = tail_overlap(seg_text, overlap_chars)
            current_parts = [overlap] if overlap else []
        else:
            current_parts = []

    for para in paragraphs:
        para = para.strip()
        if not para:
            continue

        # 超长段落：先把当前缓存输出，再滑窗切超长段落。
        if len(para) > max_segment_chars:
            flush_current()

            long_chunks = split_long_text_by_chars(
                para,
                max_chars=max_segment_chars,
                overlap_chars=overlap_chars,
            )

            for chunk in long_chunks:
                if len(chunk) >= min_segment_chars:
                    segments.append(chunk)

            current_parts = []
            continue

        current_text = "\n\n".join(current_parts).strip()
        new_len = len(current_text) + len(para) + 2

        if current_parts and new_len > target_segment_chars and len(current_text) >= min_segment_chars:
            flush_current()

        current_parts.append(para)

        current_text = "\n\n".join(current_parts).strip()
        if len(current_text) >= max_segment_chars:
            flush_current()

    if current_parts:
        seg_text = "\n\n".join(current_parts).strip()
        if seg_text:
            segments.append(seg_text)

    # 二次过滤太短片段
    final_segments = []
    for seg in segments:
        seg = seg.strip()
        if len(seg) >= min_segment_chars:
            final_segments.append(seg)

    return [
        {
            "segment_index": i,
            "text": seg,
        }
        for i, seg in enumerate(final_segments)
    ]


# =========================
# 6. 关键词匹配
# =========================

def collect_matches(content: str):
    """
    只针对一段 content 做匹配。
    用于正文片段，不再把 URL 和正文混在一起。
    """
    matched_by_category = defaultdict(list)
    category_hit_count = defaultdict(int)

    for cat, patterns in CATEGORY_PATTERNS.items():
        for term, pat in patterns:
            matches = list(pat.finditer(content))
            if matches:
                matched_by_category[cat].append(term)
                category_hit_count[cat] += len(matches)

    high_precision_matches = []
    high_precision_hit_count = 0
    for term, pat in HIGH_PRECISION_PATTERNS:
        matches = list(pat.finditer(content))
        if matches:
            high_precision_matches.append(term)
            high_precision_hit_count += len(matches)

    weak_matches = []
    weak_hit_count = 0
    for term, pat in WEAK_PATTERNS:
        matches = list(pat.finditer(content))
        if matches:
            weak_matches.append(term)
            weak_hit_count += len(matches)

    non_cyber_matches = []
    non_cyber_hit_count = 0
    for term, pat in NON_CYBER_PATTERNS:
        matches = list(pat.finditer(content))
        if matches:
            non_cyber_matches.append(term)
            non_cyber_hit_count += len(matches)

    cves = sorted(set(m.group(0).upper() for m in CVE_RE.finditer(content)))

    strong_terms = []
    for terms in matched_by_category.values():
        strong_terms.extend(terms)

    categories = sorted(
        cat for cat, terms in matched_by_category.items()
        if len(terms) > 0
    )

    return {
        "categories": categories,
        "strong_terms": sorted(set(strong_terms)),
        "high_precision_terms": sorted(set(high_precision_matches)),
        "weak_terms": sorted(set(weak_matches)),
        "non_cyber_terms": sorted(set(non_cyber_matches)),
        "cves": cves,
        "category_hit_count": dict(category_hit_count),
        "strong_hit_count": sum(category_hit_count.values()),
        "high_precision_hit_count": high_precision_hit_count,
        "weak_hit_count": weak_hit_count,
        "non_cyber_hit_count": non_cyber_hit_count,
    }


def has_proximity(text: str, terms_a, terms_b, window: int = 200) -> bool:
    """
    判断两组词是否在较短距离内共现。
    这能减少 security / attack / risk 这类泛词带来的误召回。
    """
    if not terms_a or not terms_b:
        return False

    pos_a = []
    pos_b = []

    for term in terms_a:
        pat = compile_term_pattern(term)
        for m in pat.finditer(text):
            pos_a.append(m.start())

    for term in terms_b:
        pat = compile_term_pattern(term)
        for m in pat.finditer(text):
            pos_b.append(m.start())

    if not pos_a or not pos_b:
        return False

    pos_a.sort()
    pos_b.sort()

    j = 0
    for a in pos_a:
        while j < len(pos_b) and pos_b[j] < a - window:
            j += 1

        if j < len(pos_b) and abs(pos_b[j] - a) <= window:
            return True

    return False


# =========================
# 7. 片段级安全粗筛
# =========================

def infer_risk_level(strong_terms, categories, text):
    """
    粗风险分级，只用于观察和后续抽样。
    """
    t = text.lower()

    offensive_markers = [
        "exploit",
        "payload",
        "shellcode",
        "reverse shell",
        "metasploit",
        "sqlmap",
        "privilege escalation",
        "bypass",
        "漏洞利用",
        "反弹shell",
        "攻击载荷",
        "权限提升",
        "免杀",
    ]

    malware_markers = [
        "malware",
        "ransomware",
        "trojan",
        "botnet",
        "c2 server",
        "木马",
        "勒索病毒",
        "恶意软件",
        "僵尸网络",
        "远控",
    ]

    defensive_markers = [
        "patch",
        "mitigation",
        "detection",
        "hardening",
        "incident response",
        "yara",
        "sigma",
        "修复",
        "补丁",
        "缓解",
        "检测",
        "加固",
        "应急响应",
    ]

    if any(m in t for m in malware_markers) or "malware" in categories:
        return "malware_related"

    if any(m in t for m in offensive_markers) or "pentest_redteam" in categories:
        return "dual_use_or_offensive"

    if any(m in t for m in defensive_markers) or "defense_ops" in categories:
        return "defensive"

    return "security_general"


def score_segment(url: str, domain: str, segment_text: str):
    """
    对单个片段打分。
    核心变化：
    1. URL 和正文分开匹配；
    2. 主要依据正文片段，不再让 URL 单独决定；
    3. 片段更短，因此命中要求可以比整页更低；
    4. crypto_protocol 单独命中仍然不放行。
    """
    text_features = collect_matches(segment_text)

    path_features = get_path_features(url)
    domain_confidence = get_domain_confidence(domain)

    text_len = len(segment_text)

    categories = text_features["categories"]
    strong_terms = text_features["strong_terms"]
    high_precision_terms = text_features["high_precision_terms"]
    weak_terms = text_features["weak_terms"]
    non_cyber_terms = text_features["non_cyber_terms"]
    cves = text_features["cves"]

    strong_hit_count = text_features["strong_hit_count"]
    high_precision_hit_count = text_features["high_precision_hit_count"]
    weak_hit_count = text_features["weak_hit_count"]

    high_conf_domain = domain_confidence == "high"
    medium_conf_domain = domain_confidence == "medium"
    broad_tech_domain = domain_confidence == "broad_tech"

    only_crypto = (
        len(categories) == 1
        and categories[0] == "crypto_protocol"
        and not cves
        and len(high_precision_terms) == 0
    )

    score = 0

    # CVE 是最强证据
    score += 8 if cves else 0

    # 域名只做辅助，不再作为主要放行条件
    score += 3 if high_conf_domain else 0
    score += 2 if medium_conf_domain else 0
    score += 1 if broad_tech_domain else 0

    # URL path 也只是辅助
    score += 2 if path_features["has_security_path"] else 0
    score -= 2 if path_features["has_non_security_path"] else 0

    # 正文高精度词
    score += min(len(high_precision_terms), 4) * 3

    # 正文强词
    score += min(len(strong_terms), 6) * 2

    # 弱词只加少量分
    score += min(len(weak_terms), 3) * 1

    # 多类别命中
    score += len(categories) * 2

    # 命中密度：短片段中高密度命中更可信
    evidence_hits = strong_hit_count + high_precision_hit_count
    evidence_density = evidence_hits / max(1.0, text_len / 1000.0)

    if evidence_density >= 4:
        score += 3
    elif evidence_density >= 2:
        score += 2
    elif evidence_density >= 1:
        score += 1

    # 泛词和强证据近邻共现，加分
    proximity_terms_a = ["security", "cybersecurity", "attack", "risk", "安全", "攻击", "风险"]
    proximity_terms_b = high_precision_terms + strong_terms + cves

    if has_proximity(segment_text, proximity_terms_a, proximity_terms_b, window=220):
        score += 2

    # crypto 单独命中容易误召回 HTTPS / TLS / 证书科普
    if only_crypto:
        score -= 5

    # 非 cyber security 语义强惩罚
    if non_cyber_terms and not cves and len(high_precision_terms) == 0 and len(strong_terms) < 3:
        score -= 6

    # 长片段但证据很稀疏，降权
    if text_len > 1500 and evidence_density < 0.5 and not cves and len(high_precision_terms) == 0:
        score -= 3

    # =========================
    # 片段级放行规则
    # =========================
    is_candidate = False

    # 1. 正文片段中有 CVE，直接放行
    if cves:
        is_candidate = True

    # 2. 有高精度词，片段级阈值可以低一些
    elif len(high_precision_terms) >= 1 and score >= 6:
        is_candidate = True

    # 3. 高置信安全域名 + 正文至少一个强安全词
    elif high_conf_domain and len(strong_terms) >= 1 and score >= 6:
        is_candidate = True

    # 4. 安全 URL path + 正文至少一个强安全词
    elif path_features["has_security_path"] and len(strong_terms) >= 1 and score >= 6:
        is_candidate = True

    # 5. 中置信安全域名 + 正文证据稍弱也可以接受
    elif medium_conf_domain and len(strong_terms) >= 1 and score >= 7:
        is_candidate = True

    # 6. 普通网页：片段内至少两个强词即可，不再要求整页级别的多类别
    elif len(strong_terms) >= 2 and len(categories) >= 1 and score >= 7:
        is_candidate = True

    # 7. 片段内强词 + 多个弱词，也可以作为 medium 候选
    elif len(strong_terms) >= 1 and weak_hit_count >= 2 and score >= 8:
        is_candidate = True

    # crypto 单独命中仍然不放行
    if only_crypto:
        is_candidate = False

    # 明显非 cyber security 不放行
    if non_cyber_terms and not cves and len(high_precision_terms) == 0 and len(strong_terms) < 3:
        is_candidate = False

    if score >= 14 or cves or len(high_precision_terms) >= 2:
        confidence = "high"
    elif score >= 8:
        confidence = "medium"
    else:
        confidence = "low"

    risk_level = infer_risk_level(strong_terms, categories, segment_text)

    return {
        "is_candidate": is_candidate,
        "score": score,
        "confidence": confidence,
        "domain_confidence": domain_confidence,
        "security_domain": domain_confidence in {"high", "medium"},
        "has_security_path": path_features["has_security_path"],
        "has_non_security_path": path_features["has_non_security_path"],
        "path": path_features["path"],
        "categories": categories,
        "risk_level": risk_level,
        "strong_terms": strong_terms,
        "high_precision_terms": high_precision_terms,
        "weak_terms": weak_terms,
        "non_cyber_terms": non_cyber_terms,
        "cves": cves[:50],
        "only_crypto": only_crypto,
        "strong_hit_count": strong_hit_count,
        "high_precision_hit_count": high_precision_hit_count,
        "weak_hit_count": weak_hit_count,
        "evidence_density": evidence_density,
    }


# =========================
# 8. 主处理逻辑
# =========================

def count_conversion_records(input_path: str) -> int:
    count = 0
    with gzip.open(input_path, "rb") as f:
        for record in ArchiveIterator(f):
            if record.rec_type == "conversion":
                count += 1
    return count


def process_wet_file(
    input_path: str,
    output_path: str,
    min_page_chars: int = 500,
    max_page_chars: int = 300000,
    min_segment_chars: int = 300,
    target_segment_chars: int = 1200,
    max_segment_chars: int = 1800,
    overlap_chars: int = 150,
    max_docs: int = 0,
    langs: set[str] | None = None,
    no_count: bool = False,
):
    stats = Counter()

    lang_counter = Counter()
    category_counter = Counter()
    risk_counter = Counter()
    confidence_counter = Counter()
    page_quality_drop_counter = Counter()
    segment_quality_drop_counter = Counter()
    domain_conf_counter = Counter()
    score_counter = Counter()

    seen_segment_hashes = set()

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    total_conversion = None
    if not no_count:
        print("正在统计 conversion record 数量...")
        total_conversion = count_conversion_records(input_path)
        print(f"conversion record 数量: {total_conversion}")

    with gzip.open(input_path, "rb") as f, output_file.open("w", encoding="utf-8") as out:
        for record in ArchiveIterator(f):
            stats["records_total"] += 1

            if record.rec_type != "conversion":
                continue

            stats["records_conversion"] += 1

            if max_docs > 0 and stats["records_conversion"] > max_docs:
                break

            url = record.rec_headers.get_header("WARC-Target-URI") or ""
            lang = record.rec_headers.get_header("WARC-Identified-Content-Language") or ""
            domain = get_domain(url)

            if langs and lang and lang.lower() not in langs:
                stats["lang_dropped"] += 1
                continue

            try:
                raw = record.content_stream().read()
                text = raw.decode("utf-8", errors="ignore")
            except Exception:
                stats["read_error"] += 1
                continue

            text = normalize_text(text)

            ok, reason = page_quality_check(
                text,
                min_page_chars=min_page_chars,
                max_page_chars=max_page_chars,
            )

            if not ok:
                stats["page_quality_dropped"] += 1
                page_quality_drop_counter[reason] += 1
                continue

            page_id = sha1_text(url + "\n" + text[:5000])

            segments = split_text_into_segments(
                text,
                target_segment_chars=target_segment_chars,
                max_segment_chars=max_segment_chars,
                min_segment_chars=min_segment_chars,
                overlap_chars=overlap_chars,
            )

            stats["segments_total"] += len(segments)

            page_has_candidate = False

            for seg in segments:
                seg_idx = seg["segment_index"]
                seg_text = seg["text"]

                ok, reason = segment_quality_check(
                    seg_text,
                    min_segment_chars=min_segment_chars,
                )

                if not ok:
                    stats["segment_quality_dropped"] += 1
                    segment_quality_drop_counter[reason] += 1
                    continue

                dedup_key = sha1_text(normalize_for_dedup(seg_text))
                if dedup_key in seen_segment_hashes:
                    stats["segment_duplicate_dropped"] += 1
                    continue

                features = score_segment(
                    url=url,
                    domain=domain,
                    segment_text=seg_text,
                )

                domain_conf_counter[features["domain_confidence"]] += 1

                if not features["is_candidate"]:
                    stats["segment_not_candidate"] += 1
                    continue

                seen_segment_hashes.add(dedup_key)

                stats["segment_candidates"] += 1
                page_has_candidate = True

                lang_counter[lang or "unknown"] += 1
                risk_counter[features["risk_level"]] += 1
                confidence_counter[features["confidence"]] += 1
                score_counter[features["score"]] += 1

                for cat in features["categories"]:
                    category_counter[cat] += 1

                item = {
                    "id": sha1_text(url + "\n" + str(seg_idx) + "\n" + seg_text),
                    "page_id": page_id,
                    "url": url,
                    "domain": domain,
                    "lang": lang,
                    "segment_index": seg_idx,
                    "num_segments": len(segments),
                    "page_text_len": len(text),
                    "segment_text_len": len(seg_text),
                    "score": features["score"],
                    "confidence": features["confidence"],
                    "domain_confidence": features["domain_confidence"],
                    "security_domain": features["security_domain"],
                    "has_security_path": features["has_security_path"],
                    "has_non_security_path": features["has_non_security_path"],
                    "path": features["path"],
                    "categories": features["categories"],
                    "risk_level": features["risk_level"],
                    "strong_terms": features["strong_terms"],
                    "high_precision_terms": features["high_precision_terms"],
                    "weak_terms": features["weak_terms"],
                    "non_cyber_terms": features["non_cyber_terms"],
                    "cves": features["cves"],
                    "only_crypto": features["only_crypto"],
                    "strong_hit_count": features["strong_hit_count"],
                    "high_precision_hit_count": features["high_precision_hit_count"],
                    "weak_hit_count": features["weak_hit_count"],
                    "evidence_density": round(features["evidence_density"], 4),
                    "text": seg_text,
                }

                out.write(json.dumps(item, ensure_ascii=False) + "\n")

            if page_has_candidate:
                stats["pages_with_candidate"] += 1


    print("\n\n处理完成")
    print("-" * 80)
    print("输入文件:", input_path)
    print("输出文件:", output_path)
    print("-" * 80)

    print("总 record 数:", stats["records_total"])
    print("conversion record 数:", stats["records_conversion"])
    print("读取错误:", stats["read_error"])
    print("语言过滤丢弃:", stats["lang_dropped"])
    print("页面质量过滤丢弃:", stats["page_quality_dropped"])
    print("切分片段总数:", stats["segments_total"])
    print("片段质量过滤丢弃:", stats["segment_quality_dropped"])
    print("片段重复丢弃:", stats["segment_duplicate_dropped"])
    print("片段非候选丢弃:", stats["segment_not_candidate"])
    print("候选片段数量:", stats["segment_candidates"])
    print("含候选片段的网页数:", stats["pages_with_candidate"])

    if stats["records_conversion"] > 0:
        page_ratio = stats["pages_with_candidate"] / stats["records_conversion"]
        print(f"网页命中比例: {page_ratio:.4%}")

    if stats["segments_total"] > 0:
        segment_ratio = stats["segment_candidates"] / stats["segments_total"]
        print(f"片段命中比例: {segment_ratio:.4%}")

    print("\n页面质量过滤原因:")
    for k, v in page_quality_drop_counter.most_common():
        print(f"  {k}: {v}")

    print("\n片段质量过滤原因:")
    for k, v in segment_quality_drop_counter.most_common():
        print(f"  {k}: {v}")

    print("\n语言分布:")
    for k, v in lang_counter.most_common(20):
        print(f"  {k}: {v}")

    print("\n域名置信度分布，基于片段级检测:")
    for k, v in domain_conf_counter.most_common():
        print(f"  {k}: {v}")

    print("\n候选置信度分布:")
    for k, v in confidence_counter.most_common():
        print(f"  {k}: {v}")

    print("\n类别分布:")
    for k, v in category_counter.most_common():
        print(f"  {k}: {v}")

    print("\n风险分布:")
    for k, v in risk_counter.most_common():
        print(f"  {k}: {v}")

    print("\n候选 score 分布，Top 20:")
    for k, v in score_counter.most_common(20):
        print(f"  score={k}: {v}")


def parse_langs(lang_args):
    if not lang_args:
        return None

    langs = set()
    for x in lang_args:
        for part in x.split(","):
            part = part.strip().lower()
            if part:
                langs.add(part)

    return langs or None


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        required=True,
        help="输入 .warc.wet.gz 文件路径",
    )

    parser.add_argument(
        "--output",
        default="security_segments_candidates.jsonl",
        help="输出候选安全语料片段 jsonl",
    )

    parser.add_argument(
        "--min-page-chars",
        type=int,
        default=500,
        help="页面最小文本长度，默认 500。",
    )

    parser.add_argument(
        "--max-page-chars",
        type=int,
        default=300000,
        help="页面最大文本长度，默认 300000。设为 0 表示不限制。",
    )

    parser.add_argument(
        "--min-segment-chars",
        type=int,
        default=300,
        help="片段最小长度，默认 300。",
    )

    parser.add_argument(
        "--target-segment-chars",
        type=int,
        default=1200,
        help="片段目标长度，默认 1200。",
    )

    parser.add_argument(
        "--max-segment-chars",
        type=int,
        default=1800,
        help="片段最大长度，默认 1800。",
    )

    parser.add_argument(
        "--overlap-chars",
        type=int,
        default=150,
        help="相邻片段重叠字符数，默认 150。",
    )

    parser.add_argument(
        "--max-docs",
        type=int,
        default=0,
        help="最多处理多少个 conversion record，0 表示不限制。",
    )

    parser.add_argument(
        "--langs",
        nargs="*",
        default=None,
        help="可选语言过滤，例如 --langs eng zho 或 --langs eng,zho。默认不过滤。",
    )

    parser.add_argument(
        "--no-count",
        action="store_true",
        help="不预先统计 conversion 数量。大文件上可以节省一次扫描。",
    )

    args = parser.parse_args()

    langs = parse_langs(args.langs)

    process_wet_file(
        input_path=args.input,
        output_path=args.output,
        min_page_chars=args.min_page_chars,
        max_page_chars=args.max_page_chars,
        min_segment_chars=args.min_segment_chars,
        target_segment_chars=args.target_segment_chars,
        max_segment_chars=args.max_segment_chars,
        overlap_chars=args.overlap_chars,
        max_docs=args.max_docs,
        langs=langs,
        no_count=args.no_count,
    )


if __name__ == "__main__":
    main()