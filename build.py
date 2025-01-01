from staticjinja import Site
from datetime import datetime, date
from dataclasses import dataclass
import frontmatter
import markdown
import os
from pathlib import Path
from typing import List, Literal
import shutil

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
        specialties=['TODO'],
        image="quantum.png",
        bio="TODO",
        facts=["TODO"],
        socials=[
            Social(fa="fab fa-github", url="https://github.com/ShellUnease", name="GitHub"),
            Social(fa="fab fa-discord", url="https://discord.com/users/1193905666876768286", name="Discord"),
        ]
    ),
    Member(
        name="N3rdL0rd",
        specialties=["rev", "web", "forensics", "misc"],
        image="n3rdl0rd.png",
        bio="ADHD-fueled maniac pretending to be sane.",
        facts=["I made this website!", "Don't mention the Australian psychedelic rock band King Gizzard & The Lizard Wizard around me unless you want me to talk for the next hour.", "I do lockpicking as a hobby."],
        socials=[
            Social(fa="fab fa-github", url="https://github.com/N3rdL0rd", name="GitHub"),
            Social(fa="fab fa-discord", url="https://discord.com/users/710879687211089992", name="Discord"),
            Social(fa="fas fa-envelope", url="mailto:n3rdl0rd@proton.me", name="Email"),
            Social(fa="fas fa-book-open", url="https://github.com/N3rdL0rd/writeups", name="Writeups"),
        ]
    ),
    Member(
        name="acters",
        specialties=["TODO"],
        image="acters.png",
        bio="TODO",
        facts=["Likes light mode for some horrible reason."],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/156840430099496960", name="Discord"),
        ]
    ),
    Member(
        name="ed",
        specialties=["TODO"],
        image="ed.png",
        bio="TODO",
        facts=["TODO"],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/881495305638535209", name="Discord"),
        ]
    ),
    Member(
        name="nolang",
        specialties=["TODO"],
        image="nolang.png",
        bio="Unofficial team mascot.",
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
        image="pyp.png",
        bio="Just a nerd with a special interest in computers.<br>Math for the day, Programming for the night.<br>The original piped Pyper in flesh.",
        facts=["I love art, anime and the occassional music.", "I may have OCD and ADHD, the doctors have not confirmed yet ...", "Occasional CTF player, one day blood"],
        socials=[
            Social(fa="fa fa-globe", url="https://pyp-s-blog.web.app/", name="Website"),
            Social(fa="fab fa-github", url="https://github.com/Pyp-3/", name="GitHub"),
            Social(fa="fab fa-discord", url="https://discord.com/users/1190161788453519422", name="Discord"),
        ]
    ),
    Member(
        name="m1t0",
        specialties=["TODO"],
        image="looking_for_logo.png",
        bio="TODO",
        facts=["TODO"],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/797313664084082728", name="Discord"),
        ]
    ),
    Member(
        name="Rev",
        specialties=["TODO"],
        image="looking_for_logo.png",
        bio="TODO",
        facts=["TODO"],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/368727891023757312", name="Discord"),
        ]
    ),
    Member(
        name="rethinkrubiks",
        specialties=["TODO"],
        image="rethinkrubiks.png",
        bio="TODO",
        facts=["TODO"],
        socials=[
            Social(fa="fab fa-discord", url="https://discord.com/users/392673710563262474", name="Discord"),
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
            content=content_html
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
            content=content
        ))
    return sorted(posts, key=lambda x: x.date, reverse=True)

POSTS = load_posts()
ENV_GLOBALS = {
    "year": str(datetime.now().year),
    "recent_posts": POSTS[:5],
    "posts": POSTS,
    "members": MEMBERS
}

if __name__ == "__main__":
    shutil.rmtree("build", ignore_errors=True)
    site = Site.make_site(
        searchpath="src",
        outpath="build",
        staticpaths=['static'],
        contexts=[(r".*\.md", md_context)],
        rules=[
            (r".*\.md", render_md),
            (r".*\.html", render_html)  # Add rule for HTML files
        ],
        env_globals=ENV_GLOBALS,
    )
    site.render()