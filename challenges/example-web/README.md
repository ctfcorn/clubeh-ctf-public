# example-web — the flag is in the page source

**Category:** Web · **Difficulty:** ⭐ · **Points:** 50

## Description (paste into CTFd)
A staff-only portal politely tells you to go away. But a web page is just text
your browser was sent, and your browser only *renders* part of it. Read what
the server actually sent.

```
http://10.0.0.4:30001/
```

## Intended solution (walkthrough)

1. Open the page. It says access is restricted. Nothing useful is on screen.
2. View the source, not the page:
   - Firefox / Chrome: **Ctrl+U** (macOS: **Cmd+Option+U**)
   - or right-click → **View Page Source**
   - or from a terminal: `curl http://HOST:30001/`
3. Near the bottom is an HTML comment the developer left behind:

```html
<!--
  dev note: temporary bypass code for testing, REMOVE BEFORE LAUNCH
  clubeh{page_source!}
-->
```

A browser never draws `<!-- ... -->`, so it is invisible on the page and
perfectly visible in the source.

## Hints (for CTFd)
1. Nothing on the rendered page will help you. Look at what the server actually
   sent: **Ctrl+U** (Cmd+Option+U on a Mac), or right-click → View Page Source.
2. From a terminal, `curl http://HOST:30001/` prints the raw HTML. Read the
   comments - the ones inside `<!-- -->` never appear on screen.

## Lesson
"Hidden" in a web page means hidden from the *rendering*, not from the visitor.
Comments, disabled buttons and commented-out code all still ship to the client.
