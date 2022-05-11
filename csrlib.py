import pathlib

# Auth
token = '5355692174:AAFsP4FuCY3Aui_qKyiRAeWHIE5ttfcc9Q8'

# Some functions


def convert(data):
    if isinstance(data, bytes):
        return data.decode('ascii')

    if isinstance(data, dict):
        return dict(map(convert, data.items()))

    if isinstance(data, tuple):
        return map(convert, data)

    return data


def csrCheck(csr_file, file_info):
    if file_info.file_path.endswith('.csr'):
        print('.csr found!')
        strFile = convert(csr_file).splitlines()
        if strFile[0] == "-----BEGIN CERTIFICATE REQUEST-----":
            print('start is OK')
            if strFile[len(strFile) - 1] == "-----END CERTIFICATE REQUEST-----":
                print('end is OK')
                return True
            else:
                raise Exception(f'Окончание запроса на сертификат некорректно!\n{strFile[len(strFile) - 1]}')
        else:
            raise Exception(f'Начало запроса на сертификат некорректно!\n{strFile[0]}')
    else:
        raise Exception(f'У файла, который ты прислал, расширение не .CSR, а "{pathlib.Path(file_info.file_path).suffix}"')