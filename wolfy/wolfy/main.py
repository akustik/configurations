import click
import yaml
import time
import base64
import os.path

from wolfcrypt.ciphers import Aes, ChaCha, MODE_CBC 
from wolfcrypt.hashes import Sha512
from wolfcrypt.random import Random

@click.group()
def cli():
    pass

@cli.command()
@click.option('--password', type=str)
@click.option('--rounds', type=int)
@click.option('-a', '--alg', type=click.Choice(['AES', 'CHACHA']), default='CHACHA')
@click.option('-k', '--key', required=True, type=str)
@click.option('-v', '--value', required=True, type=str)
@click.option('-o', '--output', default='-', type=str)
@click.option('-i', '--input', type=str)
def put(password, alg, rounds, key, value, input, output):
    algorithm = _key_algorithm_for(alg, password, rounds or 0)
    data = _load_data_from_input(algorithm, input)
    updated = False

    for entry in data:
        if entry['key'] == key:
            entry['value'] = value
            entry['last_updated'] = time.ctime() 
            updated = True
            break

    if not updated:
        data.append({
            "key": key,
            "value": value,
            "last_updated": time.ctime()  
        })

    _dump_data_to_output(algorithm, output, data)

@cli.command()
@click.option('--password', type=str)
@click.option('--rounds', type=int)
@click.option('-a', '--alg', type=click.Choice(['AES', 'CHACHA']), default='CHACHA')
@click.option('-p', '--pattern', required=True, type=str)
@click.option('-i', '--input', default='-', type=str)
def query(password, alg, rounds, pattern, input):
    algorithm = _key_algorithm_for(alg, password, rounds or 0)
    data = _load_data_from_input(algorithm, input)
    matches = list(filter(lambda x: pattern in x['key'] or pattern in x['value'], data))
    for m in matches:
        click.echo(f'{m}')


def _load_data_from_input(algorithm, input):
    if not input:
        return []

    with click.open_file(input, 'rb') as f:
        file_content = f.read()
    iv = base64.b64decode(file_content.split(b'.')[0])
    cipher_text = base64.b64decode(file_content.split(b'.')[1])

    algorithm.set_iv(iv)
    yaml_data = algorithm.decrypt(cipher_text)
    data = yaml.safe_load(yaml_data)
    return data


def _dump_data_to_output(algorithm, output, data):
    yaml_data = yaml.dump(data)
    algorithm.init_iv()
    cipher_text = algorithm.encrypt(yaml_data)
    file_content = base64.b64encode(algorithm.get_iv()) + b'.' + base64.b64encode(cipher_text)

    with click.open_file(output, 'wb') as f:
        f.write(file_content)


class KeyAlgorithm:
    def __init__(self, password, rounds, key_length, iv_length):
        self.key = _derive(password, key_length, rounds)
        self.key_length = key_length
        self.iv_length = iv_length

    def encrypt(self, plain_text):
        pass 

    def decrypt(self, encrypted_text):
        pass 

    def get_iv(self):
        return self.iv

    def set_iv(self, iv):
        self.iv = iv

    def init_iv(self):
        self.iv = Random().bytes(self.iv_length)


class AESAlgorithm(KeyAlgorithm):
    def __init__(self, password, rounds):
        super().__init__(password, max(rounds, 1024 * 1024), 32, 16)

    def encrypt(self, plain_text):
        partial = len(plain_text) % 16
        if partial != 0:
            plain_text = plain_text + (" " * (16 - partial)) 
        return Aes(self.key, MODE_CBC, self.iv).encrypt(plain_text) 

    def decrypt(self, cipher_text):
        return Aes(self.key, MODE_CBC, self.iv).decrypt(cipher_text) 

class ChaChaAlgorithm(KeyAlgorithm):
    def __init__(self, password, rounds):
        super().__init__(password, max(rounds, 1024 * 1024), 32, 16)

    def encrypt(self, plain_text):
        cipher = ChaCha(self.key, self.key_length)
        cipher.set_iv(self.iv)
        # FIXME: Remove once it stops failing
        cipher.mode = 'unused'
        return cipher.encrypt(plain_text) 

    def decrypt(self, cipher_text):
        cipher = ChaCha(self.key, self.key_length)
        cipher.set_iv(self.iv)
        # FIXME: Remove once it stops failing
        cipher.mode = 'unused'
        return cipher.decrypt(cipher_text)         

def _key_algorithm_for(alg, password, rounds):
    if alg == 'CHACHA':
        return ChaChaAlgorithm(password, rounds)
    elif alg == 'AES':
        return AESAlgorithm(password, rounds)
    else:
        raise Exception("Unknown algorithm")

def _derive(input, length, rounds): 
    for i in range(0,rounds):
        input = Sha512(input).digest()
    return Sha512(input).hexdigest()[0: length]


if __name__ == '__main__':
    cli(auto_envvar_prefix='WOLFY')

