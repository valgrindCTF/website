from staticjinja import Site
from datetime import datetime, date
from dataclasses import dataclass
import frontmatter
import markdown
import os
from pathlib import Path
from typing import List, Literal
import shutil
from PIL import Image
from tqdm import tqdm

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

MEMBERS = [
    Member(
        name="quantum",
        specialties=["web", "forensics", "misc"],
        image="quantum.webp",
        bio="Skid wannabe hacker",
        facts=["Insomniac", "I like bland food", "Dark mode only"],
        socials=[
            Social(fa="fab fa-github", url="https://github.com/ShellUnease", name="GitHub"),
            Social(fa="fab fa-discord", url="https://discord.com/users/1193905666876768286", name="Discord"),
            Social(fa="fa fa-globe", url="https://qv4.xyz/", name="Website"),
        ]
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
        ]
    ),
    Member(
        name="acters",
        specialties=["osint"],
        image="acters.webp",
        bio="that spicy bell pepper lol",
        facts=["Likes light mode for some horrible reason."],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/156840430099496960", name="Discord"),
        ]
    ),
    Member(
        name="ed",
        specialties=["pwn", "rev"],
        image="ed.webp",
        bio="evolved to kagura",
        facts=["Saying thanks to gpt wastes 0.003 kWh"],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/881495305638535209", name="Discord"),
        ]
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
        ]
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
        ]
    ),
    Member(
        name="m1t0",
        specialties=["TODO"],
        image="looking_for_logo.webp",
        bio="TODO",
        facts=["TODO"],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/797313664084082728", name="Discord"),
        ]
    ),
    Member(
        name="Rev",
        specialties=["crypto", "misc", "rev"],
        image="rev.webp",
        bio="Procrastinator final boss, have been using a deadline extension to play CTFs",
        facts=["Addicted to CTFs", "I solved a crypto challenge during a toilet break in the middle of my midterm..."],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/368727891023757312", name="Discord"),
        ]
    ),
    Member(
        name="rethinkrubiks",
        specialties=["crypto"],
        image="rethinkrubiks.webp",
        bio="Math one-trick",
        facts=["i play osu", "idk anything fun abt myself 😹"],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/392673710563262474", name="Discord"),
        ]
    ),
    Member(
        name="gtronous",
        specialties=["forensics", "misc", "osint"],
        image="gtronous.webp",
        bio="CTFs addict and Malware Analysis enthusiast",
        facts=["i like to tease ed & nolang", "i might swear at cheaters"],
        socials=[
            Social(fa="fa fa-globe", url="https://gtronous.github.io/", name="Website"),
            Social(fa="fab fa-github", url="https://github.com/gtronous", name="GitHub"),
        ]
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

markdowner = markdown.Markdown(output_format="html5")

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
            tags=post.metadata.get('tags', [])
        )
    }

def render_md(site, template, **kwargs):
    stem = Path(template.name).stem
    out = site.outpath / Path("posts/") / Path(stem) / Path("index.html")
    os.makedirs(out.parent, exist_ok=True)
    site.get_template("_post.html").stream(**kwargs).dump(str(out), encoding="utf-8")

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

ENV_GLOBALS = {
    "year": str(datetime.now().year),
    "recent_posts": POSTS[:5],
    "posts": POSTS,
    "members": MEMBERS
}

def compress_static():
    shutil.rmtree("build/static", ignore_errors=True)
    os.makedirs("build/static", exist_ok=True)
    
    source_path = Path("src/static")
    png_files = list(source_path.rglob("*.png"))
    
    for png_file in tqdm(png_files, desc="Converting images"):
        try:
            rel_path = png_file.relative_to(source_path)
            out_path = Path("build/static") / rel_path.parent
            out_path.mkdir(parents=True, exist_ok=True)
            image = Image.open(png_file)
            webp_path = (out_path / rel_path.stem).with_suffix('.webp')
            image.save(webp_path, 'WEBP', quality=80)
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
    shutil.rmtree("build", ignore_errors=True)
    site = Site.make_site(
        searchpath="src",
        outpath="build",
        staticpaths=["static"],
        contexts=[(r".*\.md", md_context)],
        rules=[
            (r".*\.md", render_md),
            (r".*\.html", render_html),            
        ],
        env_globals=ENV_GLOBALS,
    )
    site.render()
    generate_tag_pages(site, POSTS)  # Generate tag pages after rendering the site
    compress_static()
