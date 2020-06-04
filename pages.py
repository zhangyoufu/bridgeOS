#!/usr/bin/env python3
import html
import os
import requests

def get_releases(repo, token=None):
    releases = []
    headers = {'Authorization': f'token {token}'} if token else None
    url = f'https://api.github.com/repos/{repo}/releases?per_page=100'
    while 1:
        rsp = requests.get(url=url, headers=headers, allow_redirects=False)
        assert rsp.status_code == 200
        releases.extend(rsp.json())
        if 'next' not in rsp.links:
            break
        url = rsp.links['next']['url']
    return releases

def dedup(releases):
    collections = {}
    for release in releases:
        if '/untagged-' in release['html_url']:
            continue
        collections.setdefault(release['name'], []).append((
            release['body'].strip('`'),
            release['html_url'],
        ))
    return collections

def main():
    releases = get_releases(
        repo=os.environ['GITHUB_REPOSITORY'],
        token=os.environ['GITHUB_TOKEN'],
    )
    collections = sorted(dedup(releases).items(), reverse=True)

    print('''\
<!DOCTYPE html>
<head>
  <title>bridgeOS Update Archive</title>
  <style>
.collection + .collection {
  margin-top: 1em;
}

.monospace {
  font-family: monospace;
}
  </style>
</head>
<body>''')
    for title, releases in collections:
        print('  <div class="collection">')
        print(f'    <strong>{html.escape(title)}</strong>')
        for date, url in sorted(releases):
            print('    <br>')
            print(f'    <a class="monospace" href="{html.escape(url)}">{html.escape(date)}</a>')
        print('  </div>')
        print('</body>')
        print('</html>')

if __name__ == '__main__':
    main()
