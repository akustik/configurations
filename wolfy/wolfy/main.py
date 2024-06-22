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
@click.option('--password', type=str)
@click.option('--iv', type=str)
@click.option('-a', '--alg', type=click.Choice(['AES'], case_sensitive=False), default='AES')
@click.option('-k', '--key', required=True, type=str)
@click.option('-v', '--value', required=True, type=str)
@click.option('-o', '--output', default='-', type=str)
@click.option('-i', '--input', type=str)
def put(password, iv, alg, key, value, input, output):
    data = _load_data_from_input(password, iv, input)
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

    _dump_data_to_output(password, iv, output, data)

@cli.command()
@click.option('--password', type=str)
@click.option('--iv', type=str)
@click.option('-a', '--alg', type=click.Choice(['AES'], case_sensitive=False), default='AES')
@click.option('-p', '--pattern', required=True, type=str)
@click.option('-i', '--input', default='-', type=str)
def query(password, iv, alg, pattern, input):
    data = _load_data_from_input(password, iv, input)
    matches = list(filter(lambda x: pattern in x['key'] or pattern in x['value'], data))
    for m in matches:
        click.echo(f'{m}')


def _load_data_from_input(password, iv, input):
    if not input:
        return []

    with click.open_file(input, 'rb') as f:
        file_content = f.read()
     
    cipher = Aes(password.encode(), MODE_CBC, iv.encode())
    cipher_text = base64.b64decode(file_content)
    yaml_data = cipher.decrypt(cipher_text)
    data = yaml.safe_load(yaml_data)
    return data


def _dump_data_to_output(password, iv, output, data):
    cipher = Aes(password.encode(), MODE_CBC, iv.encode())
    yaml_data = yaml.dump(data)
    partial = len(yaml_data) % 16
    if partial != 0:
        yaml_data = yaml_data + (" " * (16 - partial)) 

    cipher_text = cipher.encrypt(yaml_data)
    file_content = base64.b64encode(cipher_text)

    with click.open_file(output, 'wb') as f:
        f.write(file_content)

if __name__ == '__main__':
    cli(auto_envvar_prefix='WOLFY')

