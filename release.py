#!/usr/bin/env python3
import hashlib
import json
import logging
import os
import pathlib
import plistlib
import re
import requests
import struct
import subprocess
import sys

v1_prod_pubkey = 0xC3E748CAD9CD384329E10E25A91E43E1A762FF529ADE578C935BDDF9B13F2179D4855E6FC89E9E29CA12517D17DFA1EDCE0BEBF0EA7B461FFE61D94E2BDF72C196F89ACD3536B644064014DAE25A15DB6BB0852ECBD120916318D1CCDEA3C84C92ED743FC176D0BACA920D3FCF3158AFF731F88CE0623182A8ED67E650515F75745909F07D415F55FC15A35654D118C55A462D37A3ACDA08612F3F3F6571761EFCCBCC299AEE99B3A4FD6212CCFFF5EF37A2C334E871191F7E1C31960E010A54E86FA3F62E6D6905E1CD57732410A3EB0C6B4DEFDABE9F59BF1618758C751CD56CEF851D1C0EAA1C558E37AC108DA9089863D20E2E7E4BF475EC66FE6B3EFDCF
# v2_prod_pubkey = 0xCB45C5E53217D4499FB80B2D96AA4F964EB551F1DA4EBFA4F5E23F87BFE82FC113590E536757F329D6EAD1F267771EE342F5A5E61514DD3D3383187E663929D577D94648F262EBA1157E152DB5273D10AE3A6A058CB9CD64D01267DAC82ED3B7BC1631D078C911414129CDAAA0FFB0A8E2A7ADD6F32FB09A7E98D259BFF6ED10808D1BDA58CAF7355DFF1A085A18B11657D2617447BF657140D599364E5AC8E626276AC03BC2417831D9E61B25154AFE9F2D8271E9CE22D2783803083A5A7A575774688721097DC5E4B32D118CF6317A7083BA15BA608430A8C8C6B7DA2D932D81F571603A9363AC0197AB670242D9C9180D97A10900F11FE3D9246CF14F0883
# v2_dev_pubkey  = 0xB372CEC9E05E71FB3FAA08C34E3256FB312EA821638A243EF8A5DEA46FCDA33F00F88FC2933FB276D37B914F89BAD5B5D75771E342265B771995AE8F43B4DFF3F21A877FE777A8B419587C8718D36204FA1922A575AD5207D5D6B8C10F84DDCA661B731E7E7601D64D4A894F487FE1AA1DDC2A1697A3553B1DD85D5750DF2AA9D988E83C4C70BBBE4747219F9B92B199FECB16091896EBB441606DEC20F446249D5568BB51FC87BA7F85E6295FBE811B0A314408CD31921C360608A0FF7F87BD733560FE1C96E472834CAB6BE016C35727754273125089BE043FD3B26F0B2DE141E05990CE922F1702DA0A2F4E9F8760D0FA712DDB9928E0CDAC14501ED5E2C3

ChunkListHeader = struct.Struct('<4sIBBBxQQQ')
assert ChunkListHeader.size == 0x24

Chunk = struct.Struct('<I32s')
assert Chunk.size == 0x24

XarHeader = struct.Struct('>4sHHQQI')
assert XarHeader.size == 28

def parse_chunklist(path):
    with open(path, 'rb') as f:
        hash_ctx = hashlib.sha256()
        data = f.read(ChunkListHeader.size)
        hash_ctx.update(data)
        magic, header_size, file_version, chunk_method, signature_method, chunk_count, chunk_offset, signature_offset = ChunkListHeader.unpack(data)
        assert magic == b'CNKL'
        assert header_size == ChunkListHeader.size
        assert file_version == 1
        assert chunk_method == 1
        assert signature_method in [1, 2]
        assert chunk_count > 0
        assert chunk_offset == 0x24
        assert signature_offset == chunk_offset + Chunk.size * chunk_count
        for i in range(chunk_count):
            data = f.read(Chunk.size)
            hash_ctx.update(data)
            chunk_size, chunk_sha256 = Chunk.unpack(data)
            yield chunk_size, chunk_sha256
        digest = hash_ctx.digest()
        if signature_method == 1:
            data = f.read(256)
            assert len(data) == 256
            signature = int.from_bytes(data, 'little')
            plaintext = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d0609608648016503040201050004200000000000000000000000000000000000000000000000000000000000000000 | int.from_bytes(digest, 'big')
            assert pow(signature, 0x10001, v1_prod_pubkey) == plaintext
        elif signature_method == 2:
            data = f.read(32)
            assert data == digest
        else:
            raise NotImplementedError
        assert f.read(1) == b''

def check_chunklist(path, chunklist_path):
    with open(path, 'rb') as f:
        for chunk_size, chunk_sha256 in parse_chunklist(chunklist_path):
            chunk = f.read(chunk_size)
            assert len(chunk) == chunk_size
            assert hashlib.sha256(chunk).digest() == chunk_sha256
        assert f.read(1) == b''

def check_xar_checksum(path, digest):
    assert len(digest) == 20
    with open(path, 'rb') as f:
        magic, size, version, toc_length_compressed, toc_length_uncompressed, cksum_alg = XarHeader.unpack(f.read(XarHeader.size))
        assert magic == b'xar!'
        assert size == XarHeader.size
        assert version == 1
        assert cksum_alg == 1 # SHA1
        f.seek(toc_length_compressed, os.SEEK_CUR)
        assert f.read(20) == digest # assume checksum always comes first

def get_filename(url):
    return url.rsplit('/', 1)[-1]

def parse_distribution(path):
    with open(path, 'rb') as f:
        data = f.read()
    title = re.search(br'(?<="SU_TITLE" = ")[^"]+', data).group().decode()
    m = re.search(br'(?s)<auxinfo>(.*)</auxinfo>', data)
    if m:
        auxinfo = plistlib.loads(m.expand(br'<plist>\1</plist>'))
        if 'macOSProductBuildVersion' not in auxinfo:
            if title.startswith('Install '):
                title = title[8:]
            title += ' ' + auxinfo['VERSION']
            build = auxinfo['BUILD']
        else:
            build = auxinfo['macOSProductBuildVersion']
    else:
        build = re.search(br'(?<=\.)\d+[A-Z]\d+[a-z]?(?=")', data).group().decode()
    return f'{title} ({build})'

class LimitedReader:
    def __init__(self, f, length):
        self._file = f
        self._length = length

    def __len__(self):
        return self._length

    def __iter__(self):
        f = self._file
        n = self._length
        while n > 0:
            chunk = f.read(min(n, 65536))
            if not chunk:
                raise EOFError('unexpected EOF')
            yield chunk
            n -= len(chunk)

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)s] %(message)s',
    )

    GITHUB_TOKEN = os.environ['GITHUB_TOKEN']
    GITHUB_REPOSITORY = os.environ['GITHUB_REPOSITORY']
    GITHUB_BRANCH = re.fullmatch(r'refs/heads/(.*)', os.environ['GITHUB_REF']).group(1)
    GITHUB_TAG = f'tag_{GITHUB_BRANCH}'

    logging.info('Parsing product.json...')
    product = json.load(open('product.json'))
    version = product.pop('Version')
    post_date = product.pop('PostDate')
    packages = product.pop('Packages')
    assert not product

    aria2c_input = []

    digest_dict = {}
    integrity_dict = {}
    size_dict = {}
    for package in packages:
        url = package.pop('URL')
        aria2c_input.append(url)
        filename = get_filename(url)
        path = pathlib.PurePath(filename)
        filename.rsplit('.', 1)
        size_dict[filename] = package.pop('Size')
        if 'Digest' in package:
            digest = package.pop('Digest')
            assert len(digest) == 40
            digest_dict[filename] = bytes.fromhex(digest)
        url = package.pop('IntegrityDataURL', None)
        if url:
            aria2c_input.append(url)
            integrity_filename = get_filename(url)
            size_dict[integrity_filename] = package.pop('IntegrityDataSize')
            integrity_dict[filename] = integrity_filename
        url = package.pop('MetadataURL', None)
        if url:
            aria2c_input.append(url)
        assert not package

    download_dir = pathlib.Path('download').resolve()
    download_dir.mkdir(exist_ok=True)
    os.chdir(download_dir)

    logging.info('Downloading...')
    subprocess.run(
        [
            'aria2c',
            '--auto-save-interval=0',
            '--connect-timeout=5',
            '--console-log-level=warn',
            '--continue',
            '--enable-mmap',
            '--input-file=-',
            '--max-connection-per-server=5',
            '--max-tries=0',
            '--show-console-readout=false',
            '--stderr',
            '--timeout=5',
        ],
        input='\n'.join(aria2c_input),
        encoding='ascii',
        check=True,
    )
    # Note: --lowest-speed-limit abort connections instead of retry
    #       see https://github.com/aria2/aria2/issues/897

    logging.info('Checking file size...')
    for filename, size in size_dict.items():
        logging.info(f'Processing {filename}...')
        assert os.stat(filename).st_size == size

    logging.info('Checking xar digest...')
    # Note: xar is not fully verified
    #       see https://mackyle.github.io/xar/howtosign.html
    for filename, digest in digest_dict.items():
        logging.info(f'Processing {filename}...')
        check_xar_checksum(filename, digest)

    logging.info('Checking integrity data v1...')
    for filename, integrity_filename in integrity_dict.items():
        logging.info(f'Processing {integrity_filename}...')
        check_chunklist(filename, integrity_filename)
        os.unlink(integrity_filename)

    logging.info('Generating SHA256SUM...')
    subprocess.run('shasum --algorithm 256 --binary * >SHA256SUM', shell=True, check=True)

    distribution = f'bridgeOS {version}'
    logging.info(f'Distribution: {distribution}')

    logging.info('Creating GitHub release...')
    rsp = requests.post(f'https://api.github.com/repos/{GITHUB_REPOSITORY}/releases',
        headers={'Authorization': f'token {GITHUB_TOKEN}'},
        json={
            'tag_name': GITHUB_TAG,
            'target_commitish': 'empty',
            'name': distribution,
            'body': f'`{post_date}`',
            'draft': True,
        },
        allow_redirects=False,
    )
    assert rsp.status_code == 201, f'{rsp.status_code} {rsp.reason}\n{rsp.text}'

    try:
        release = rsp.json()
        upload_url = release['upload_url'].split('{', 1)[0]
        logging.info('Uploading GitHub release assets...')
        chunk_limit = 2147483647 # 2GiB - 1B
        for filename in sorted(os.listdir('.')):
            logging.info(f'Sending {filename}...')
            size = os.stat(filename).st_size
            num_chunks = (size + chunk_limit-1) // chunk_limit
            with open(filename, 'rb') as f:
                for chunk_idx in range(num_chunks):
                    while 1:
                        if num_chunks > 1:
                            logging.info(f'Sending chunk #{chunk_idx+1}...')
                            name = f'{filename}.{chunk_idx+1}'
                            f.seek(chunk_idx * chunk_limit)
                            if chunk_idx == num_chunks - 1:
                                length = (size-1) % chunk_limit + 1
                            else:
                                length = chunk_limit
                            data = LimitedReader(f, length)
                        else:
                            name = filename
                            f.seek(0)
                            data = f
                        try:
                            rsp = requests.post(upload_url,
                                params={'name': name},
                                headers={
                                    'Authorization': f'token {GITHUB_TOKEN}',
                                    'Content-Type': 'application/octet-stream',
                                },
                                data=data,
                                allow_redirects=False,
                            )
                            if rsp.status_code == 201:
                                break
                            logging.error(f'{rsp.status_code} {rsp.reason}\n{rsp.text}')
                            if rsp.status_code == 422:
                                # assume {"resource":"ReleaseAsset","code":"already_exists","field":"name"}
                                delete_asset(release['assets_url'], name, token=GITHUB_TOKEN)
                            else:
                                assert rsp.status_code in [500, 502, 504], 'unexpected HTTP status code'
                        except requests.ConnectionError:
                            pass
                        logging.error('Upload failed, retry')

        # find and remove previous release
        rsp = requests.get(f'https://api.github.com/repos/{GITHUB_REPOSITORY}/releases/tags/{GITHUB_TAG}',
            headers={'Authorization': f'token {GITHUB_TOKEN}'},
            allow_redirects=False,
        )
        if rsp.status_code == 200:
            previous_release_url = rsp.json()['url']
            logging.info('Previous GitHub release found')
            rsp = requests.delete(previous_release_url,
                headers={'Authorization': f'token {GITHUB_TOKEN}'},
                allow_redirects=False,
            )
            assert rsp.status_code == 204, f'{rsp.status_code} {rsp.reason}\n{rsp.text}'
            logging.info('Previous GitHub release removed')
        else:
            assert rsp.status_code == 404, f'{rsp.status_code} {rsp.reason}\n{rsp.text}'
    except BaseException:
        logging.exception('Release aborted')
        rsp = requests.delete(release['url'],
            headers={'Authorization': f'token {GITHUB_TOKEN}'},
            allow_redirects=False,
        )
        assert rsp.status_code != 204, f'{rsp.status_code} {rsp.reason}\n{rsp.text}'
        sys.exit(1)
    else:
        # publish draft
        rsp = requests.patch(release['url'],
            headers={'Authorization': f'token {GITHUB_TOKEN}'},
            json={'draft': False},
            allow_redirects=False,
        )
        assert rsp.status_code == 200, f'{rsp.status_code} {rsp.reason}\n{rsp.text}'

    logging.info('Done')

if __name__ == '__main__':
    main()
