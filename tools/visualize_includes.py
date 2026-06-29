#!/usr/bin/env nix-shell
#! nix-shell -i python3 -p python3 python3Packages.graphviz
# ---------------------------------------------------------------------------
# 文件职责: 解析 data/ 下 include 关系, 生成类别包含关系的可视化图表
# 设计要点:
#   - 只读 data/, 无副作用; 输出到 insights/
#   - 多层级可视化, 避免单图过密:
#       roots      : 全部顶层根 + 其下属顶层分类 (宏观结构, 根节点带中文描述)
#       categories : category-*/geolocation-*/tld-* 之间的相互 include (分类体系骨架)
#       full       : 所有 include 边的全景 (仅含有 include 的节点, 供全局检索)
#       stats.md   : 量化统计 + 全部分类节点语义对照表 (根/枢纽/环检测/规模分布)
#       roots.mmd  : Mermaid 根层级图, 便于在 markdown 中内联渲染
#   - DAG 校验: include 关系必须无环, 否则 v2ray 生成时会无限递归
# 运行:
#   ./tools/visualize_includes.py            # 默认输出到 ./insights
#   ./tools/visualize_includes.py --data data --out insights
# ---------------------------------------------------------------------------
from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from graphviz import Digraph  # type: ignore[import-untyped]

INCLUDE_RE = re.compile(r"^include:([a-z0-9!_\-]+)")
AGGREGATE_PREFIXES = ("category-", "geolocation-", "tld-")

# ---------------------------------------------------------------------------
# 语义字典: 为顶层分类节点提供中文描述 (分类意图, 非内容列举).
# 数据源: 文件名语义 + 文件规模 + 真实头注释 + include 的子类综合判断.
# 说明: 原文件首行注释质量参差 (有误填域名如 "ntRRR"/"Game"/"chromium"),
#       故由人工归纳, 仅覆盖顶层 category-/geolocation-/tld- 及 17 个根.
# 凡未列入此字典的节点 (普通公司/品牌叶子) 不显示描述, 因其名称本身已自解释.
# ---------------------------------------------------------------------------
SEMANTICS: dict[str, str] = {
    # === 地理 / 政治分块 (项目最顶层入口) ===
    "geolocation-!cn": "非中国大陆可达域名 (项目主根)",
    "geolocation-cn": "中国大陆有接入点的域名 (与 !cn 互补)",
    "cn": "geosite:cn 兼容入口 (= tld-cn + geolocation-cn)",
    "tld-cn": ".cn 及中国相关顶级域",
    "tld-!cn": "非中国大陆的顶级域 (大量 ccTLD/gTLD)",
    "tld-ru": ".ru 及俄罗斯相关顶级域",
    "tld-opennic": "OpenNIC 替代 DNS 体系的顶级域",
    # === 国家 / 地区聚合 (按地区归拢本地站点) ===
    "category-ru": "俄罗斯域名总聚合",
    "category-ir": "伊朗域名总聚合",
    "category-tm": "土库曼斯坦域名",
    # === 反审查 / 隐私 ===
    "category-anticensorship": "反审查 / 翻墙 / 规避工具",
    "category-proxy-tunnels": "代理与隧道服务",
    "category-vpnservices": "VPN 服务商",
    # === 广告 / 追踪 ===
    "category-ads": "广告投放与广告技术",
    "category-ads-all": "全部广告/追踪域名 (含厂商)",
    "category-ads-ir": "伊朗广告",
    "category-consent-management": "Cookie/GDPR 同意管理平台",
    # === 网络基础设施 ===
    "category-cdn-!cn": "海外 CDN",
    "category-cdn-cn": "国内 CDN",
    "category-ddns": "动态 DNS 服务",
    "category-doh": "DNS over HTTPS 解析器",
    "category-httpdns-cn": "国内 HTTPDNS 服务",
    "category-ntp": "NTP 时间同步服务器",
    "category-ntp-cn": "国内 NTP",
    "category-ntp-jp": "日本 NTP",
    "category-stun": "STUN / TURN (NAT 穿透)",
    "category-ip-geo-detect": "IP 地理位置探测 API",
    "category-cas": "证书颁发机构 (CA)",
    "category-speedtest": "网速测试服务",
    # === AI ===
    "category-ai-!cn": "海外 AI / 大模型服务",
    "category-ai-cn": "国内 AI / 大模型服务",
    "category-ai-chat-!cn": "海外 AI 对话产品 (兼容入口)",
    # === 通讯 / 协作 ===
    "category-communication": "即时通讯 / 通话",
    "category-browser-!cn": "海外浏览器产品",
    "category-voip": "网络电话 (VoIP)",
    "category-collaborate-cn": "国内团队协作平台",
    "category-documents-cn": "国内在线文档",
    "category-remote-control": "远程控制软件",
    "category-mobile-repair": "手机维修工具",
    # === 安全 / 凭据 ===
    "category-antivirus": "杀毒 / 安全软件",
    "category-cryptocurrency": "加密货币 / 交易所",
    "category-password-management": "密码管理器",
    "category-network-security-cn": "国内网络安全厂商",
    "category-number-verification-cn": "国内运营商一键登录/号码验证 SDK",
    # === 金融 / 商业 ===
    "category-finance": "金融 / 财经 (通用)",
    "category-bank-cn": "国内银行",
    "category-bank-jp": "日本银行",
    "category-bank-ir": "伊朗银行",
    "category-bank-ru": "俄罗斯银行",
    "category-bank-mm": "缅甸银行",
    "category-securities-cn": "国内证券 / 券商",
    "category-insurance-ir": "伊朗保险",
    "category-payment-ir": "伊朗支付网关",
    "category-bourse-ir": "伊朗证券交易所",
    "category-ecommerce": "电商 (通用)",
    "category-ecommerce-ru": "俄罗斯电商",
    "category-shopping-ir": "伊朗购物",
    "category-retail-ru": "俄罗斯零售",
    "category-enterprise-query-platform-cn": "国内企业信息查询",
    # === 内容 / 媒体 ===
    "category-media": "媒体 / 新闻 (通用)",
    "category-media-cn": "国内媒体",
    "category-media-ir": "伊朗媒体",
    "category-media-ru": "俄罗斯本土媒体",
    "category-media-ru-blocked": "被俄官方屏蔽的媒体",
    "category-tech-media": "科技媒体",
    "category-social-media-!cn": "海外社交媒体",
    "category-social-media-cn": "国内社交媒体",
    "category-social-media-ir": "伊朗社交媒体",
    "category-news-ir": "伊朗新闻",
    "category-web-archive": "网页存档服务",
    "category-urlshortner": "短链接服务",
    "category-forums": "论坛 / 社区",
    "category-forums-ir": "伊朗论坛",
    "category-blog-cn": "国内博客",
    "category-wiki-cn": "国内 Wiki / 百科",
    # === 娱乐 / 游戏 ===
    "category-entertainment": "海外娱乐 (音视频/播客)",
    "category-entertainment-cn": "国内娱乐 (音视频/播客)",
    "category-entertainment-ru": "俄罗斯娱乐",
    "category-games": "游戏 (cn + !cn 合并入口)",
    "category-games-!cn": "海外游戏厂商/服务",
    "category-games-cn": "国内游戏",
    "category-game-platforms-download": "游戏平台与商店下载",
    "category-game-accelerator-cn": "国内网游加速器",
    "category-android-app-download": "安卓应用商店",
    "category-enhance-gaming": "游戏增强 / 反作弊",
    "category-acg": "ACG (二次元) 相关",
    "category-novel": "被墙的中文盗版小说站",
    "category-porn": "色情内容",
    # === P2P / 文件分发 ===
    "category-pt": "PT 私有种子站",
    "category-public-tracker": "公开 BT Tracker",
    "category-netdisk-!cn": "海外网盘",
    "category-netdisk-cn": "国内网盘",
    "category-ipfs": "IPFS 网关",
    "category-container": "容器 / 镜像仓库",
    # === 学术 / 教育 ===
    "category-scholar-!cn": "海外学术站点",
    "category-scholar-cn": "国内学术站点",
    "category-scholar-hk": "香港学术站点",
    "category-scholar-uk": "英国学术站点",
    "category-scholar-ir": "伊朗学术站点",
    "category-education-cn": "国内教育 / 考试",
    "category-education-ir": "伊朗教育",
    "category-mooc-cn": "国内 MOOC 平台",
    "category-olympiad-in-informatics": "信息学奥赛相关",
    # === 行业 / 区域杂项 ===
    "category-automobile-cn": "国内汽车厂商",
    "category-electronic-cn": "国内电子/数码厂商",
    "category-food-cn": "国内餐饮/食品",
    "category-hospital-cn": "国内医院/医疗",
    "category-logistics-cn": "国内物流",
    "category-outsource-cn": "国内外包平台",
    "category-gov-ir": "伊朗政府站点",
    "category-gov-ru": "俄罗斯政府站点",
    "category-betting-ru": "俄罗斯博彩",
    "category-travel-ru": "俄罗斯旅行",
    "category-travel-ir": "伊朗旅行",
    "category-tech-ir": "伊朗科技",
    "category-medicine-ru": "俄罗斯医药",
    # === 开发者 / 组织 ===
    "category-dev": "开发者工具与服务 (海外)",
    "category-dev-cn": "国内开发者服务",
    "category-companies": "海外科技/网络公司",
    "category-orgs": "海外非营利组织",
    "category-emby": "Emby 媒体服务器生态",
    # === 17 根中的兼容别名 (向后兼容旧 geosite 名) ===
    "x": "X (原 Twitter) 别名 = twitter + xai",
    "archive": "geosite:archive 兼容入口 → web-archive",
    "google-gemini": "geosite:google-gemini 兼容 → deepmind",
    "mailru": "geosite:mailru 兼容 → mailru-group",
    "speedtest": "geosite:speedtest 兼容入口",
}


@dataclass(frozen=True)
class Graph:
    """include 关系构成的有向图. 边 (a -> b) 表示 'a 包含 b'."""

    files: frozenset[str]
    nodes: frozenset[str]
    edges: list[tuple[str, str]]
    in_deg: dict[str, int] = field(default_factory=dict)
    out_deg: dict[str, int] = field(default_factory=dict)


def build_graph(data_dir: Path) -> Graph:
    files = frozenset(p.stem for p in data_dir.iterdir() if p.is_file())
    edges: list[tuple[str, str]] = []
    for f in sorted(files):
        text = (data_dir / f).read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            m = INCLUDE_RE.match(line.strip())
            if m:
                edges.append((f, m.group(1)))
    nodes = frozenset(n for e in edges for n in e)
    return Graph(
        files=files,
        nodes=nodes,
        edges=edges,
        in_deg=dict(Counter(b for _, b in edges)),
        out_deg=dict(Counter(a for a, _ in edges)),
    )


def find_cycles(g: Graph) -> list[list[str]]:
    """DFS 三色标记法检测环. 期望返回空列表 (DAG 不应有环)."""
    sys.setrecursionlimit(max(10000, len(g.nodes) * 2))
    adj: dict[str, list[str]] = defaultdict(list)
    for a, b in g.edges:
        adj[a].append(b)
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = defaultdict(lambda: WHITE)
    cycles: list[list[str]] = []

    def dfs(n: str, stack: list[str]) -> None:
        color[n] = GRAY
        stack.append(n)
        for m in adj.get(n, []):
            if color[m] == GRAY:
                i = stack.index(m)
                cycles.append(stack[i:] + [m])
            elif color[m] == WHITE:
                dfs(m, stack)
        stack.pop()
        color[n] = BLACK

    for n in list(adj.keys()):
        if color[n] == WHITE:
            dfs(n, [])
    return cycles


def roots(g: Graph) -> list[str]:
    """根节点: 有出度但无入度 (没有任何列表 include 它, 但它 include 别人)."""
    return sorted(
        [n for n in g.nodes if g.out_deg.get(n, 0) > 0 and g.in_deg.get(n, 0) == 0],
        key=lambda x: (-g.out_deg[x], x),
    )


def root_layer_nodes(g: Graph) -> set[str]:
    """根层级节点集: 全部根 + 各根直接 include 的顶层分类 (category-/geolocation-/tld-).

    render_roots 与 render_mermaid 共享此逻辑 (DRY), 避免过滤规则两处重复维护.
    """
    rts_set = set(roots(g))
    return rts_set | {b for a, b in g.edges
                      if a in rts_set and b.startswith(AGGREGATE_PREFIXES)}


def subtree_sizes(g: Graph) -> dict[str, int]:
    """对每个节点计算其传递闭包的叶子数 (子树规模). 用于在根节点上标注.

    注意: 若 include 图存在环, 该节点子树规模按其无环近似估算 (GRAY 节点不再递归).
    """
    adj: dict[str, list[str]] = defaultdict(list)
    for a, b in g.edges:
        adj[a].append(b)
    memo: dict[str, int] = {}
    state: dict[str, int] = defaultdict(int)  # 0=white,1=gray,2=black

    def size(n: str) -> int:
        if state[n] == 1:  # 环: 截断
            return 0
        if state[n] == 2:
            return memo[n]
        state[n] = 1
        children = adj.get(n, [])
        total = sum(size(c) for c in children) if children else 1
        state[n] = 2
        memo[n] = total
        return total

    return {n: size(n) for n in g.nodes}


def style_node(n: str, g: Graph) -> dict[str, str]:
    if n.startswith(AGGREGATE_PREFIXES):
        return {"shape": "box", "style": "rounded,filled", "fillcolor": "#ffd27f"}
    if g.out_deg.get(n, 0) > 0:
        return {"shape": "ellipse", "style": "filled", "fillcolor": "#b8e0d2"}
    return {"shape": "ellipse", "style": "filled", "fillcolor": "#d9d9d9"}


def node_label(n: str, sizes: dict[str, int], show_size: bool, *, sep: str = "\\n") -> str:
    """统一构造节点 label (DRY: 三个 SVG 图 + Mermaid 共享同一规则).

    规则单一: 凡 SEMANTICS 中有描述的节点, 描述一律写入 label 直接可见;
    无描述的叶子节点只显示名称. show_size=True 时附加子树规模行.
    sep 用于适配不同后端 ('\\n' for graphviz, '<br/>' for mermaid).
    消除原先'根节点 label 显示 / 非根节点仅 tooltip'的不一致.
    """
    desc = SEMANTICS.get(n)
    parts = [n]
    if show_size:
        parts.append(f"({sizes.get(n, 0)} leaves)")
    if desc:
        parts.append(desc)
    return sep.join(parts)


def render_roots(g: Graph, sizes: dict[str, int], out: Path) -> Path:
    """根层级图: 全部顶层根 + 其下属顶层分类节点 (过滤普通公司叶子).

    所有节点统一用 node_label: 有描述则直接显示在 label (无 hover 依赖).
    根节点额外标注子树规模. 输出 roots.svg.
    """
    rts = roots(g)
    keep = root_layer_nodes(g)
    sub = Digraph("roots", format="svg")
    sub.attr(rankdir="LR", bgcolor="white", fontname="Helvetica",
             label="\\n根节点 (橙) → 其下属顶层分类. 标注: 子树传递闭包规模 + 分类意图")
    sub.attr("node", fontname="Helvetica", fontsize="10")
    sub.attr("edge", arrowsize="0.6", color="#888888")
    for n in sorted(keep):
        attrs = style_node(n, g)
        attrs["label"] = node_label(n, sizes, show_size=(n in rts))
        if n in rts:
            attrs["fontsize"] = "11"
        sub.node(n, **attrs)
    for a, b in g.edges:
        if a in keep and b in keep:
            sub.edge(a, b)
    path = out / "roots"
    sub.render(path, cleanup=True)
    return path.with_suffix(".svg")


def render_categories(g: Graph, sizes: dict[str, int], out: Path) -> Path:
    """分类体系图: 仅 category-*/geolocation-*/tld-* 之间的相互 include.

    所有节点统一用 node_label (名称+规模+描述), 反映"分类法"内部如何嵌套聚合.
    输出 categories.svg.
    """
    top = {n for n in g.nodes if n.startswith(AGGREGATE_PREFIXES)}
    c = Digraph("categories", format="svg")
    c.attr(rankdir="LR", bgcolor="white", fontname="Helvetica",
           label="\\n分类体系内部: category-*/geolocation-*/tld-* 之间的包含关系 (名称+规模+意图)")
    c.attr("node", fontname="Helvetica", fontsize="10", shape="box",
           style="rounded,filled", fillcolor="#ffe699")
    c.attr("edge", arrowsize="0.6", color="#555555")
    for n in sorted(top):
        c.node(n, label=node_label(n, sizes, show_size=True))
    for a, b in g.edges:
        if a in top and b in top:
            c.edge(a, b)
    path = out / "categories"
    c.render(path, cleanup=True)
    return path.with_suffix(".svg")


def render_full(g: Graph, sizes: dict[str, int], out: Path) -> Path:
    """完整图: 所有含 include 的节点全景. 供全局检索, 非首览.

    顶层分类节点带描述 (统一规则), 普通公司叶子仅显示名称. 输出 full.svg.
    """
    sk = Digraph("full", format="svg")
    sk.attr(rankdir="LR", bgcolor="white", fontname="Helvetica")
    sk.attr("node", fontname="Helvetica", fontsize="8")
    sk.attr("edge", arrowsize="0.4", color="#aaaaaa")
    for n in sorted(g.nodes):
        attrs = style_node(n, g)
        attrs["label"] = node_label(n, sizes, show_size=False)
        sk.node(n, **attrs)
    for a, b in g.edges:
        sk.edge(a, b)
    path = out / "full"
    sk.render(path, cleanup=True)
    return path.with_suffix(".svg")


def render_mermaid(g: Graph, sizes: dict[str, int], out: Path) -> Path:
    """Mermaid 根层级图: 全部根 + 其顶层分类子节点. 可嵌入 markdown. 输出 roots.mmd."""
    rts = roots(g)
    rts_set = set(rts)
    keep = root_layer_nodes(g)
    edges = sorted((a, b) for a, b in g.edges if a in rts_set and b in keep)

    def safe(s: str) -> str:
        return s.replace("!", "_").replace("-", "_")

    # 防御: 若未来出现含 '_' 的文件名, 不同节点会映射到同一 mermaid ID, 显式失败
    dup_ids = [k for k, c in Counter(safe(n) for n in keep).items() if c > 1]
    if dup_ids:
        sys.exit(f"mermaid ID 碰撞, 需改进 safe() 转义: {dup_ids}")

    lines = ["%%{init: {'flowchart': {'nodeSpacing': 30, 'rankSpacing': 60}}}%%",
             "graph LR"]
    for n in sorted(keep):
        shape = "[" if n.startswith(AGGREGATE_PREFIXES) else "("
        close = "]" if n.startswith(AGGREGATE_PREFIXES) else ")"
        label = node_label(n, sizes, show_size=(n in rts_set), sep="<br/>")
        lines.append(f'  {safe(n)}{shape}"{label}"{close}')
    for a, b in edges:
        lines.append(f"  {safe(a)} --> {safe(b)}")
    path = out / "roots.mmd"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def render_stats(g: Graph, sizes: dict[str, int], cycles: list[list[str]], out: Path) -> Path:
    """量化统计 + 全部分类节点语义对照表. 输出 stats.md."""
    rts = roots(g)
    hubs = sorted(g.nodes, key=lambda x: (-g.in_deg.get(x, 0), x))[:20]
    orphans = sorted(g.files - g.nodes)
    # 所有顶层分类节点, 按子树规模降序
    top_nodes = sorted(
        [n for n in g.nodes if n.startswith(AGGREGATE_PREFIXES)],
        key=lambda x: (-sizes.get(x, 0), x),
    )
    missing = [n for n in top_nodes if n not in SEMANTICS]
    lines = [
        "# Insights: data/ include 关系统计",
        "",
        f"- 数据文件总数       : {len(g.files)}",
        f"- 参与 include 的节点: {len(g.nodes)}",
        f"- include 边总数     : {len(g.edges)}",
        f"- 顶层根节点 (无入度): {len(rts)}",
        f"- 叶子节点 (无出度)  : {sum(1 for n in g.nodes if g.out_deg.get(n,0)==0 and g.in_deg.get(n,0)>0)}",
        f"- 孤立文件 (无 include 关系): {len(orphans)}",
        f"- 环检测             : {'OK (DAG)' if not cycles else f'FAILED: {len(cycles)} cycles'}",
        f"- 顶层分类节点已标注 : {len(top_nodes) - len(missing)} / {len(top_nodes)}",
        "",
        "## 17 个顶层根节点",
        "",
        "| 根 | 分类意图 | 直接 include | 子树规模 |",
        "|----|---------|-------------:|---------:|",
        *[f"| `{r}` | {SEMANTICS.get(r, '')} | {g.out_deg[r]} | {sizes.get(r, 0)} |"
          for r in rts],
        "",
        "## 全部分类节点语义对照 (category-*/geolocation-*/tld-*)",
        "",
        "| 节点 | 分类意图 | 子树规模 |",
        "|------|---------|---------:|",
        *[f"| `{n}` | {SEMANTICS.get(n, '（未标注）')} | {sizes.get(n, 0)} |"
          for n in top_nodes],
        "",
        "## Top 20 被引用最多的枢纽",
        "",
        "| 节点 | 被引用数 |",
        "|------|---------:|",
        *[f"| `{n}` | {g.in_deg.get(n,0)} |" for n in hubs],
    ]
    if missing:
        lines += ["", f"> 注: 以下 {len(missing)} 个顶层分类尚未在 SEMANTICS 字典中标注描述: "
                 + ", ".join(f"`{n}`" for n in missing), ""]
    if cycles:
        lines += ["", "## 检测到的环 (需修复)", ""]
        for c in cycles[:10]:
            lines.append("- `" + "` -> `".join(c) + "`")
    path = out / "stats.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, default=Path("data"),
                    help="数据目录 (默认: data)")
    ap.add_argument("--out", type=Path, default=Path("insights"),
                    help="输出目录 (默认: insights)")
    args = ap.parse_args()

    if not args.data.is_dir():
        print(f"error: data dir not found: {args.data}", file=sys.stderr)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)

    g = build_graph(args.data)
    cycles = find_cycles(g)

    print(f"files         : {len(g.files)}")
    print(f"include edges : {len(g.edges)}")
    print(f"nodes in graph: {len(g.nodes)}")
    print(f"roots         : {len(roots(g))}")
    print(f"cycles        : {len(cycles)}")

    sizes = subtree_sizes(g)
    renders = [
        render_roots(g, sizes, args.out),
        render_categories(g, sizes, args.out),
        render_full(g, sizes, args.out),
        render_mermaid(g, sizes, args.out),
        render_stats(g, sizes, cycles, args.out),
    ]
    for p in renders:
        print(f"wrote {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
