import click
import yaml
import time
import base64
import os.path

from wolfcrypt.hashes import Sha256
from wolfcrypt.ciphers import Aes, MODE_CBC 

@click.group()
def cli():
    pass

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
@click.option('--iv', prompt=True, hide_input=True)
@click.option('--alg', type=click.Choice(['AES'], case_sensitive=False), default='AES')
@click.option('--key', required=True, type=str)
@click.option('--value', required=True, type=str)
@click.argument('container')
def put(password, iv, alg, key, value, container):
    data = _load_file_to_data(password, iv, container)
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

    _dump_data_to_file(password, iv, container, data)

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
@click.option('--iv', prompt=True, hide_input=True)
@click.option('--alg', type=click.Choice(['AES'], case_sensitive=False), default='AES')
@click.option('--pattern', required=True, type=str)
@click.argument('container')
def query(password, iv, alg, pattern, container):
    data = _load_file_to_data(password, iv, container)
    matches = list(filter(lambda x: pattern in x['key'] or pattern in x['value'], data))
    for m in matches:
        click.echo(f'{m}')


def _load_file_to_data(password, iv, container):
    if os.path.isfile(container):
        cipher = Aes(password.encode(), MODE_CBC, iv.encode())
        with open(container, "rb") as f:
            file_content = f.read()

        cipher_text = base64.b64decode(file_content)
        yaml_data = cipher.decrypt(cipher_text)
        data = yaml.safe_load(yaml_data)
        return data
    else:
        return []

def _dump_data_to_file(password, iv, container, data):
    cipher = Aes(password.encode(), MODE_CBC, iv.encode())
    yaml_data = yaml.dump(data)
    partial = len(yaml_data) % 16
    if partial != 0:
        yaml_data = yaml_data + (" " * (16 - partial)) 

    cipher_text = cipher.encrypt(yaml_data)
    file_content = base64.b64encode(cipher_text)
    with open(container, "wb") as f:
        f.write(file_content)

if __name__ == '__main__':
    cli()

