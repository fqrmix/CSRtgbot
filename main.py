import telebot
import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM

token = 'mytoken'

bot = telebot.TeleBot(token)


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
                print('end is not OK!')
                return False
        else:
            print('start is not OK')
    else:
        print('Invalid extension of file!')
        return False


@bot.message_handler(content_types=["text"])
def repeat_all_messages(message):
    bot.send_message(message.chat.id, message.text)


@bot.message_handler(content_types=['document'])
def handle_docs_photo(message):
    try:
        chat_id = message.chat.id
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        print('Checking CSR...')

        if csrCheck(downloaded_file, file_info):
            req = load_certificate_request(FILETYPE_PEM, downloaded_file)
            key = req.get_pubkey()
            key_type = 'RSA' if key.type() == OpenSSL.crypto.TYPE_RSA else 'DSA'
            subject = req.get_subject()
            components = dict(subject.get_components())
            str_components = convert(components)
            bot.reply_to(message, f"Common name: {str_components ['CN']}\n"
                                  f"Organisation: {str_components ['O']}\n"
                                  f"State/province: {str_components ['ST']}\n"
                                  f"Country: {str_components ['C']}\n"
                                  f"Key algorithm: {key_type}\n"
                                  f"Key size: {key.bits()}")
        else:
            raise Exception('Invalid CSR!')

    except Exception as e:
        bot.reply_to(message, e)


if __name__ == '__main__':
    bot.infinity_polling()
