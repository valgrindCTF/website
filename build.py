from staticjinja import Site
from datetime import datetime, date
from dataclasses import dataclass
import frontmatter
import markdown
import os
from pathlib import Path
from typing import List, Literal, Optional
import shutil
from PIL import Image
from tqdm import tqdm
import argparse
import hashlib
import requests

@dataclass
class Social:
    fa: str
    url: str
    name: str

@dataclass
class Member:
    name: str
    specialties: List[Literal['rev', 'misc', 'web', 'crypto', 'pwn', 'forensics', 'reversing', 'hardware', 'networking', 'osint', 'stego', 'trivia', 'programming', 'TODO']]
    image: str
    bio: str
    facts: List[str]
    socials: List[Social]
    countries: List[str]

MEMBERS = [
    Member(
        name="VXXDXX",
        specialties=["web", "forensics", "misc"],
        image="VXXDXX.webp",
        bio="Skid wannabe hacker",
        facts=["Formerly known as quantum", "Insomniac", "It's pronounced \"Voodoo\"", "Dark mode only"],
        socials=[
            Social(fa="fa fa-globe", url="https://shellunease.github.io/", name="Website"),
            Social(fa="fab fa-github", url="https://github.com/ShellUnease", name="GitHub"),
            Social(fa="fab fa-discord", url="https://discord.com/users/1193905666876768286", name="Discord"),
            Social(fa="fas fa-cube", url="https://app.hackthebox.com/users/1689134", name="HTB"),
        ],
        countries=["pol"]
    ),
    Member(
        name="N3rdL0rd",
        specialties=["rev", "web", "forensics", "misc"],
        image="n3rdl0rd.webp",
        bio="ADHD-fueled maniac pretending to be sane",
        facts=["I made this website!", "I do lockpicking as a hobby.", "Crazy? I was crazy once. They locked me in a room."],
        socials=[
            Social(fa="fab fa-github", url="https://github.com/N3rdL0rd", name="GitHub"),
            Social(fa="fab fa-discord", url="https://discord.com/users/710879687211089992", name="Discord"),
            Social(fa="fas fa-envelope", url="mailto:n3rdl0rd@proton.me", name="Email"),
            Social(fa="fas fa-book-open", url="https://github.com/N3rdL0rd/writeups", name="Writeups"),
        ],
        countries=["can", "usa"]
    ),
    Member(
        name="acters",
        specialties=["osint", "stego"],
        image="acters.webp",
        bio="Living in 45° C weather, and has GPT girlfriends. 🤖 ",
        facts=["Likes light mode for some horrible reason.", "You're Not Better Than A Stegosaurus. 🦕"],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/156840430099496960", name="Discord"),
        ],
        countries=["usa", "per", "pol"]
    ),
    Member(
        name="ed",
        specialties=["pwn", "rev", "web"],
        image="ed.webp",
        bio="evolved to kagura",
        facts=["Saying thanks to gpt wastes 0.003 kWh"],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/881495305638535209", name="Discord"),
        ],
        countries=["prk"]
    ),
    Member(
        name="nolang",
        specialties=["rev", "pwn", "web"],
        image="nolang.webp",
        bio="im pretty bad at describing myself tbh",
        facts=["Type 'nolang' on this page and see what happens."],
        socials=[
            Social(fa="fa fa-globe", url="https://nolangilardi.github.io/", name="Website"),
            Social(fa="fab fa-github", url="https://github.com/nolangilardi", name="GitHub"),
            Social(fa="fab fa-discord", url="https://discord.com/users/830070935817158670", name="Discord"),
        ],
        countries=["idn"]
    ),
    Member(
        name="Pyp",
        specialties=["crypto", "pwn", "web", "misc"],
        image="pyp.webp",
        bio="Just a nerd with a special interest in computers.<br>Math for the day, Programming for the night.<br>The original piped Pyper in flesh.",
        facts=["I love art, anime and the occasional music.", "I may have OCD and ADHD, the doctors have not confirmed yet ...", "Occasional CTF player, one day blood"],
        socials=[
            Social(fa="fa fa-globe", url="https://pyp-s-blog.web.app/", name="Website"),
            Social(fa="fab fa-github", url="https://github.com/Pyp-3/", name="GitHub"),
            Social(fa="fab fa-discord", url="https://discord.com/users/1190161788453519422", name="Discord"),
        ],
        countries=["gbr"]
    ),
    Member(
        name="m1t0",
        specialties=["pwn", "rev"],
        image="m1t0.webp",
        bio="Former Security Engineer.<br>Eternal CTF beginner.",
        facts=["I've recently listed some items on Mercari", "My YouTube subscriber count recently reached 321. My immediate goal is to reach 1,000"],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/797313664084082728", name="Discord"),
            Social(fa="fab fa-github", url="https://github.com/mito753", name="GitHub")
        ],
        countries=["jpn"]
    ),
    Member(
        name="Rev",
        specialties=["crypto", "misc", "rev"],
        image="rev.webp",
        bio="Procrastinator final boss, have been using a deadline extension to play CTFs",
        facts=["Addicted to CTFs", "I solved a crypto challenge during a toilet break in the middle of my midterm..."],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/368727891023757312", name="Discord"),
        ],
        countries=["idn", "can"]
    ),
    Member(
        name="gtronous",
        specialties=["forensics", "misc", "osint"],
        image="megatron.webp",
        bio="CTFs addict and Malware Analysis enthusiast",
        facts=["i like to tease ed & nolang", "i might swear at cheaters"],
        socials=[
            Social(fa="fa fa-globe", url="https://gtronous.github.io/", name="Website"),
            Social(fa="fab fa-github", url="https://github.com/gtronous", name="GitHub"),
        ],
        countries=["irl"]
    ),
    Member(
        name="rethinkrubiks",
        specialties=["crypto"],
        image="rethinkrubiks.webp",
        bio="Math one-trick",
        facts=["i play osu", "idk anything fun abt myself 😹"],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/392673710563262474", name="Discord"),
        ],
        countries=["can", "idn"]
    ),
    Member(
        name="Ap4sh",
        specialties=["crypto", "misc", "web", "forensics"],
        image="ap4sh.webp",
        bio="ADHD brain powered by music",
        facts=["my search history would worry a normal person"],
        socials=[
            Social(fa="fa fa-globe", url="https://ap4sh.guru/", name="Website"),
            Social(fa="fab fa-discord", url="https://discord.com/users/1032261229626003537", name="Discord"),
            Social(fa="fas fa-cube", url="https://app.hackthebox.com/users/377742", name="HTB"),
        ],
        countries=["fra"]
    ),
    Member(
        name="stelin41",
        specialties=["ai", "ml", "web", "misc", "crypto"],
        image="stelin.webp",
        bio="Introvert whose parahippocampal cortex is half allocated to computer science",
        facts=["I've been into AI since before it was trendy", "I guessed half of my school's passwords on the first try", "I like anime, nature and books"],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/561244702561665044", name="Discord"),
            Social(fa="fab fa-github", url="https://github.com/stelin41", name="GitHub"),
            Social(fa="fab fa-twitter", url="https://twitter.com/stelin41", name="Twitter"),
            Social(fa="fab fa-mastodon", url="https://ioc.exchange/@stelin41", name="Mastodon (ioc.exchange)"),
            Social(fa="fab fa-youtube", url="https://youtube.com/@stelin41", name="Youtube"),
            Social(fa="fa fa-globe", url="https://stelin41.github.io/", name="Website"),
            Social(fa="fas fa-cube", url="https://app.hackthebox.com/profile/951417", name="HTB"),
        ],
        countries=["esp"]
    ),
]

@dataclass
class Post:
    title: str
    date: date
    excerpt: str
    url: str
    content: str
    tags: List[str]
    author: Optional[str] = None

markdowner = markdown.Markdown(
    output_format="html5",
    extensions=['fenced_code', 'codehilite', 'mdx_math', 'tables', 'extra', 'admonition', 'toc'],
    extension_configs={
        'codehilite': {
            'guess_lang': False
        }
    }
)

def md_context(template):
    post = frontmatter.load(template.filename)
    content_html = markdowner.convert(post.content)
    
    return {
        "post": Post(
            title=post.metadata.get('title', 'Untitled'),
            date=post.metadata.get('date', datetime.now().date()),
            excerpt=post.metadata.get('excerpt', ''),
            url=f"/posts/{Path(template.name).stem}",
            content=content_html,
            tags=post.metadata.get('tags', []),
            author=post.metadata.get('author', None)
        )
    }

def render_post_md(site, template, **kwargs):
    stem = Path(template.name).stem
    out = site.outpath / Path("posts/") / Path(stem) / Path("index.html")
    os.makedirs(out.parent, exist_ok=True)
    site.get_template("_post.html").stream(**kwargs).dump(str(out), encoding="utf-8")

def render_page_md(site, template, **kwargs):
    stem = Path(template.name).stem
    out = site.outpath / Path(stem) / Path("index.html")
    os.makedirs(out.parent, exist_ok=True)
    site.get_template("_page.html").stream(**kwargs).dump(str(out), encoding="utf-8")

def render_html(site, template, **kwargs):
    if template.name in ["index.html", "404.html"]:
        out = site.outpath / Path(template.name)
    else:
        stem = Path(template.name).stem
        out = site.outpath / Path(stem) / Path("index.html")
    os.makedirs(out.parent, exist_ok=True)
    template.stream(**kwargs).dump(str(out), encoding="utf-8")

def load_posts(posts_dir='src/posts'):
    posts = []
    for post_path in Path(posts_dir).glob('*.md'):
        post = frontmatter.load(post_path)
        content = markdowner.convert(post.content)
        
        posts.append(Post(
            title=post.metadata.get('title', 'Untitled'),
            date=post.metadata.get('date', datetime.now().date()),
            excerpt=post.metadata.get('excerpt', ''),
            url=f"/posts/{post_path.stem}/",
            content=content,
            tags=post.metadata.get('tags', [])
        ))
    return sorted(posts, key=lambda x: x.date, reverse=True)

POSTS = load_posts()

def generate_tag_pages(site, posts):
    tags = {}
    for post in posts:
        for tag in post.tags:
            if tag not in tags:
                tags[tag] = []
            tags[tag].append(post)
    
    for tag, tagged_posts in tags.items():
        out = site.outpath / Path("posts/tag") / Path(tag) / Path("index.html")
        os.makedirs(out.parent, exist_ok=True)
        site.get_template("_tag.html").stream(tag=tag, posts=tagged_posts).dump(str(out), encoding="utf-8")

        def ordinal(n: int) -> str:
            if 10 <= n % 100 <= 20:
                suffix = "th"
            else:
                suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
            return f"{n}{suffix}"

r = requests.get("https://ctftime.org/api/v1/teams/355817/")
if r.status_code == 200:
    team_data = r.json()
    rating = team_data['rating'][str(datetime.now().year)]["rating_place"]

def ordinal(n: int) -> str:
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"

ENV_GLOBALS = {
    "year": str(datetime.now().year),
    "recent_posts": POSTS[:5],
    "posts": POSTS,
    "members": MEMBERS,
    "ctftime_global_rank": ordinal(rating)
}

def compress_static(max_width=2000, max_height=2000):
    shutil.rmtree("build/static", ignore_errors=True)
    os.makedirs("build/static", exist_ok=True)
    
    cache_dir = Path(".img_cache")
    cache_dir.mkdir(exist_ok=True)
    
    source_path = Path("src/static")
    png_files = list(source_path.rglob("*.png"))
    
    for png_file in tqdm(png_files, desc="Converting images"):
        try:
            rel_path = png_file.relative_to(source_path)
            out_path = Path("build/static") / rel_path.parent
            out_path.mkdir(parents=True, exist_ok=True)
            
            with open(png_file, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            
            cache_key = f"{file_hash}_{max_width}x{max_height}"
            cache_path = cache_dir / f"{cache_key}.webp"
            webp_path = (out_path / rel_path.stem).with_suffix('.webp')
            
            if cache_path.exists():
                shutil.copy2(cache_path, webp_path)
            else:
                image = Image.open(png_file)
                width, height = image.size
                
                if width > max_width or height > max_height:
                    scale = min(max_width / width, max_height / height)
                    new_width = int(width * scale)
                    new_height = int(height * scale)
                    
                    image = image.resize((new_width, new_height), Image.LANCZOS)
                    print(f"Resized {png_file.name}: {width}x{height} → {new_width}x{new_height}")
                
                image.save(webp_path, 'WEBP', quality=90)
                shutil.copy2(webp_path, cache_path)
                
        except Exception as e:
            print(f"Error converting {png_file}: {e}")
    
    for item in source_path.rglob('*'):
        if item.is_file() and item.suffix.lower() != '.png':
            rel_path = item.relative_to(source_path)
            dest_path = Path("build/static") / rel_path
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, dest_path)

def skip_render(*args, **kwargs):
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the static site.")
    parser.add_argument("--no-compress", action="store_true", help="Skip image compression")
    args = parser.parse_args()
    
    shutil.rmtree("build", ignore_errors=True)
    site = Site.make_site(
        searchpath="src",
        outpath="build",
        staticpaths=["static"],
        contexts=[(r".*\.md", md_context)],
        rules=[
            (r"achievements\.md", render_page_md),
            (r"posts/.*\.md", render_post_md),
            (r".*\.html", render_html),
        ],
        env_globals=ENV_GLOBALS,
    )
    site.render()
    generate_tag_pages(site, POSTS)
    if not args.no_compress:
        compress_static()
